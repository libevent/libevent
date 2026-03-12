# 第 6 课：evbuffer —— 高效缓冲区管理

> **前置要求**：完成第 4 课（event 管理），了解 bufferevent 的基本概念
> **本课目标**：深入理解 evbuffer 的链式内存设计，掌握零拷贝操作，学会用 evbuffer 实现协议解析

---

## 1. 为什么需要 evbuffer

网络编程中，缓冲区管理是最繁琐的工作之一：

```c
// 手动管理缓冲区的问题（裸 socket 编程）
char buf[4096];
int received = 0;

// 问题 1：数据可能分多次到达，拼接很麻烦
while (received < expected_size) {
    int n = read(fd, buf + received, sizeof(buf) - received);
    if (n <= 0) break;
    received += n;
}

// 问题 2：要发送大数据，write() 可能写不完
int sent = 0;
while (sent < total_size) {
    int n = write(fd, data + sent, total_size - sent);
    if (n <= 0) break;
    sent += n;
}

// 问题 3：动态大小的数据（HTTP 响应体、流式数据）难以管理
// 问题 4：频繁 malloc/free 造成内存碎片
// 问题 5：数据在多个模块间传递时，不断拷贝
```

evbuffer 解决这些问题的核心思路：
- **链式内存块**：按需分配，避免大块连续内存的要求
- **零拷贝**：通过链表操作转移数据所有权，而非 memcpy
- **引用计数**：相同数据可被多个 evbuffer 引用，无需复制

---

## 2. evbuffer 的内部结构

### 2.1 struct evbuffer 总体布局

`evbuffer-internal.h` 第 80~158 行：

```c
struct evbuffer {
    // ── 链式内存块 ────────────────────────────────────────────────
    struct evbuffer_chain *first;          // 链表头（最旧的数据）
    struct evbuffer_chain *last;           // 链表尾（用于追加数据）
    struct evbuffer_chain **last_with_datap; // 指向最后一个有数据的 chain

    // ── 统计信息 ──────────────────────────────────────────────────
    size_t total_len;   // 缓冲区中所有字节的总数（O(1) 查询）
    size_t max_read;    // 单次从 fd 读取的最大字节数（默认 4096）

    // ── 回调通知 ──────────────────────────────────────────────────
    size_t n_add_for_cb;   // 自上次触发回调以来添加的字节数
    size_t n_del_for_cb;   // 自上次触发回调以来删除的字节数
    LIST_HEAD(...) callbacks;  // 变化通知回调函数列表

    // ── 并发控制 ──────────────────────────────────────────────────
    void *lock;             // 互斥锁（启用后）
    unsigned freeze_start : 1;  // 禁止从头部删除（正在被 fd 读取时）
    unsigned freeze_end   : 1;  // 禁止向尾部追加（正在被 fd 写出时）

    // ── 引用计数 ──────────────────────────────────────────────────
    int refcnt;             // 当前引用数，降至 0 时释放
    struct bufferevent *parent;  // 所属的 bufferevent（如果有）
};
```

### 2.2 struct evbuffer_chain：真正存数据的地方

`evbuffer-internal.h` 第 173~216 行：

```c
struct evbuffer_chain {
    struct evbuffer_chain *next;  // 下一个 chain（单链表）

    size_t buffer_len;    // buffer 的总分配大小
    ev_misalign_t misalign; // buffer 开头已被读取/跳过的字节数
    size_t off;           // buffer[misalign..misalign+off) 是有效数据

    unsigned flags;       // EVBUFFER_REFERENCE / EVBUFFER_IMMUTABLE / ...
    int refcnt;           // 引用计数（multicast 时多个 evbuffer 共享）

    unsigned char *buffer; // 实际存储数据的内存
    // 通常 buffer 指向 (evbuffer_chain + 1)，即紧跟结构体的内存
    // 特殊情况下（引用外部内存）指向外部地址
};
```

### 2.3 chain 的内存布局图

```
单个 evbuffer_chain 在内存中的布局（标准分配时）：

┌──────────────────────────────────────────────────────────┐
│  struct evbuffer_chain（约 48 字节）                       │
│    next        = 指向下一个 chain                          │
│    buffer_len  = 1024  ← 总分配大小                        │
│    misalign    = 200   ← 已消费（drain）的字节数            │
│    off         = 300   ← 有效数据长度                      │
│    buffer      = ─────────────────────────────────────┐  │
└──────────────────────────────────────────────────────┼──┘
                                                        │
┌─────────────────────────────────────────────────────▼──┐
│  实际数据区（1024 字节）                                   │
│  [0..199]   已消费，misalign 指针跳过这段               │
│  [200..499] 有效数据（off=300）← 实际读取区域           │
│  [500..1023] 空闲空间，可继续写入                        │
└─────────────────────────────────────────────────────────┘

evbuffer_drain(N) 的工作：
  不 memmove，只把 misalign += N，off -= N → O(1)！

evbuffer_add(data, len) 的工作：
  如果空闲空间够：memcpy 到 buffer[misalign+off]，off += len
  如果不够：新建一个 chain，追加到链表尾部
```

### 2.4 多个 chain 的链式结构

```
evbuffer（total_len = 700）

first ─→ chain_A                chain_B                chain_C
         buffer_len=1024        buffer_len=512         buffer_len=512
         misalign=200           misalign=0             misalign=0
         off=300                off=256                off=144
         [有效200字节 ... 300字节有效 ... 空闲524字节]
         ↑读从这里开始           ↑第二段数据             ↑最后一段数据
                                                        ↑写追加到这里
last ────────────────────────────────────────────────→ chain_C
last_with_datap ─────────────────────────────────────→ &chain_C
```

---

## 3. 基础操作 API

### 3.1 创建与释放

```c
struct evbuffer *evbuffer_new(void);  // 分配空 evbuffer
void evbuffer_free(struct evbuffer *buf);  // 释放（减引用计数，降为 0 时实际释放）

// 查询总字节数（O(1)，直接读 total_len 字段）
size_t evbuffer_get_length(const struct evbuffer *buf);

// 查询第一个 chain 中的连续可读字节数（避免 pullup）
size_t evbuffer_get_contiguous_space(const struct evbuffer *buf);
```

### 3.2 写入数据

```c
// 追加原始字节（memcpy 到末尾）
int evbuffer_add(struct evbuffer *buf, const void *data, size_t datlen);

// 格式化写入（类似 sprintf，但写入到 evbuffer）
int evbuffer_add_printf(struct evbuffer *buf, const char *fmt, ...);
int evbuffer_add_vprintf(struct evbuffer *buf, const char *fmt, va_list ap);

// 前置插入（写入到缓冲区头部，不常用）
int evbuffer_prepend(struct evbuffer *buf, const void *data, size_t datlen);
```

`buffer.c` 第 1756 行 `evbuffer_add` 的核心逻辑：

```c
// 快路径：最后一个 chain 有足够空间
if (remain >= datlen) {
    memcpy(chain->buffer + chain->misalign + chain->off, data, datlen);
    chain->off += datlen;
    // 仅一次 memcpy + 一次指针更新，非常快
}
// 慢路径：需要新建 chain
else {
    // 新 chain 的大小 = max(旧 chain 大小 * 2, datlen)
    to_alloc = chain->buffer_len;
    if (to_alloc <= EVBUFFER_CHAIN_MAX_AUTO_SIZE/2)
        to_alloc <<= 1;  // 翻倍增长
    if (datlen > to_alloc)
        to_alloc = datlen;
    // ...新建 chain 并追加...
}
```

### 3.3 读取与消费数据

```c
// 读取并消耗（数据从缓冲区移除）
int evbuffer_remove(struct evbuffer *buf, void *data_out, size_t datlen);

// 只读不消耗（数据仍保留在缓冲区）
ev_ssize_t evbuffer_copyout(struct evbuffer *buf, void *data_out, size_t datlen);

// 从指定位置读取（不消耗）
ev_ssize_t evbuffer_copyout_from(struct evbuffer *buf,
    const struct evbuffer_ptr *pos, void *data_out, size_t datlen);

// 仅消耗（丢弃前 N 字节，不需要数据内容）
int evbuffer_drain(struct evbuffer *buf, size_t len);
```

`evbuffer_remove` 的实现（buffer.c 第 1196 行）非常简洁：

```c
int evbuffer_remove(struct evbuffer *buf, void *data_out, size_t datlen)
{
    ev_ssize_t n;
    EVBUFFER_LOCK(buf);
    n = evbuffer_copyout_from(buf, NULL, data_out, datlen);  // 先拷贝
    if (n > 0)
        evbuffer_drain(buf, n);  // 再消费
    EVBUFFER_UNLOCK(buf);
    return (int)n;
}
```

`evbuffer_drain` 的关键优化（buffer.c 第 1127 行）：

```c
// drain 不做 memmove！只调整 misalign 指针
chain->misalign += remaining;  // 跳过 remaining 字节
chain->off -= remaining;       // 有效数据减少
// O(1) 操作，即使 drain 几兆字节也很快
```

### 3.4 预分配缓冲区空间

```c
// 提前分配，避免多次小额分配
int evbuffer_expand(struct evbuffer *buf, size_t datlen);

// 示例：已知要写入 100KB 数据
evbuffer_expand(buf, 100 * 1024);  // 一次分配到位
for (int i = 0; i < 100; i++) {
    evbuffer_add(buf, chunk[i], 1024);  // 不再触发重新分配
}
```

---

## 4. 面向行的读取：协议解析基础

网络协议（HTTP、Redis RESP、SMTP）大量使用行分隔符。evbuffer 内置了高效的行读取支持。

### 4.1 evbuffer_readln：读取一行

```c
char *evbuffer_readln(struct evbuffer *buffer,
                      size_t *n_read_out,
                      enum evbuffer_eol_style eol_style);
// 返回：堆分配的 NUL 终止字符串（调用者负责 free()）
// n_read_out：如果非 NULL，填入读取的字节数（含换行符）
// 返回 NULL：缓冲区中没有完整的行
```

`evbuffer_eol_style` 枚举（buffer.h 第 423~443 行）：

```c
EVBUFFER_EOL_ANY         // \r、\n、\r\n 任意组合（最宽松）
EVBUFFER_EOL_CRLF        // \n 或 \r\n（HTTP 标准）
EVBUFFER_EOL_CRLF_STRICT // 严格 \r\n（最严格）
EVBUFFER_EOL_LF          // 仅 \n（Unix 文本）
EVBUFFER_EOL_NUL         // NUL 字节（\0）作为分隔符
```

### 4.2 HTTP 请求行解析示例

```c
// 解析 HTTP 请求的第一行："GET /path HTTP/1.1\r\n"
void parse_http_request(struct evbuffer *input)
{
    char *line;
    size_t len;

    // 尝试读取请求行
    line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF);
    if (line == NULL) {
        // 数据还没到齐，等待更多数据
        return;
    }

    // 解析方法、路径、版本
    char method[16], path[256], version[16];
    if (sscanf(line, "%15s %255s %15s", method, path, version) == 3) {
        printf("方法: %s, 路径: %s, 版本: %s\n", method, path, version);
    }
    free(line);  // 必须释放！

    // 继续读取头部字段
    while ((line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF)) != NULL) {
        if (len == 0) {
            free(line);
            break;  // 空行，头部结束
        }
        printf("Header: %s\n", line);
        free(line);
    }
}
```

### 4.3 evbuffer_search：搜索子串

```c
struct evbuffer_ptr evbuffer_search(struct evbuffer *buffer,
    const char *what, size_t len, const struct evbuffer_ptr *start);
// 返回 evbuffer_ptr，pos 字段为找到的位置（-1 表示未找到）

struct evbuffer_ptr evbuffer_search_range(struct evbuffer *buffer,
    const char *what, size_t len,
    const struct evbuffer_ptr *start, const struct evbuffer_ptr *end);

// evbuffer_ptr 的用法
struct evbuffer_ptr pos = evbuffer_search(buf, "\r\n\r\n", 4, NULL);
if (pos.pos >= 0) {
    // 找到了 HTTP 头部结束标志
    printf("HTTP 头部在字节 %zd 结束\n", (size_t)pos.pos);
}
```

### 4.4 evbuffer_ptr_set：移动搜索游标

```c
int evbuffer_ptr_set(struct evbuffer *buf, struct evbuffer_ptr *pos,
                     size_t position, enum evbuffer_ptr_how how);
// how: EVBUFFER_PTR_SET（绝对位置）或 EVBUFFER_PTR_ADD（相对偏移）

// 示例：从当前位置向后跳过 10 字节
evbuffer_ptr_set(buf, &pos, 10, EVBUFFER_PTR_ADD);

// 示例：从头部跳到第 100 字节
evbuffer_ptr_set(buf, &pos, 100, EVBUFFER_PTR_SET);
```

---

## 5. 零拷贝操作

### 5.1 evbuffer_add_buffer：O(1) 的缓冲区合并

将一个 evbuffer 的所有数据"转移"到另一个 evbuffer，**不进行任何 memcpy**：

```c
int evbuffer_add_buffer(struct evbuffer *outbuf, struct evbuffer *inbuf);
// 效果：inbuf 的所有 chain 链表接到 outbuf 末尾
// inbuf 变为空，outbuf 拥有全部数据
// 复杂度：O(1)（仅指针操作）
```

`buffer.c` 第 992 行的核心实现：

```c
// 当 outbuf 为空时：直接把 inbuf 的 first/last 指针复制过来
COPY_CHAIN(outbuf, inbuf);

// 当 outbuf 非空时：把 inbuf->first 接到 outbuf->last->next
APPEND_CHAIN(outbuf, inbuf);

// 最后：清空 inbuf 的指针
// 没有任何 memcpy！
```

**使用场景**：bufferevent 在转发数据时的核心操作。

```c
// 代理场景：把从客户端读到的数据转发给服务端
struct evbuffer *client_input = bufferevent_get_input(client_bev);
struct evbuffer *server_output = bufferevent_get_output(server_bev);

// O(1) 转移，不论数据有多大
evbuffer_add_buffer(server_output, client_input);
```

### 5.2 evbuffer_remove_buffer：部分转移

```c
int evbuffer_remove_buffer(struct evbuffer *src, struct evbuffer *dst,
                           size_t datlen);
// 从 src 转移最多 datlen 字节到 dst
// 尽量避免拷贝（以 chain 为单位转移，边界处才拷贝）
```

### 5.3 evbuffer_add_reference：引用外部内存

不拷贝数据，只在 evbuffer 中记录一个指向外部内存的引用：

```c
int evbuffer_add_reference(struct evbuffer *outbuf,
    const void *data, size_t datlen,
    evbuffer_ref_cleanup_cb cleanupfn, void *cleanupfn_arg);

// cleanupfn：数据不再被引用时的清理回调
// cleanupfn_arg：传给 cleanupfn 的参数
```

**典型用场**：发送静态资源（如内存中的图片、配置数据）：

```c
// 内存中的静态 HTML 页面（程序生命周期内有效）
static const char *html_404 = "HTTP/1.1 404 Not Found\r\n\r\nNot Found";
static const size_t html_404_len = 38;

void cleanup_static(const void *data, size_t len, void *arg)
{
    // 静态数据不需要释放，什么都不做
    (void)data; (void)len; (void)arg;
}

void send_404(struct bufferevent *bev)
{
    struct evbuffer *output = bufferevent_get_output(bev);
    // 不拷贝！直接引用全局变量
    evbuffer_add_reference(output, html_404, html_404_len,
                           cleanup_static, NULL);
}
```

动态分配的内存场景：

```c
void send_dynamic_data(struct bufferevent *bev, char *data, size_t len)
{
    struct evbuffer *output = bufferevent_get_output(bev);
    // evbuffer 接管 data 的生命周期
    evbuffer_add_reference(output, data, len, free, NULL);
    // 当数据被发送完毕，free(data) 自动被调用
    // 调用者不再负责 data 的释放
}
```

### 5.4 evbuffer_reserve_space / evbuffer_commit_space：直接写入

scatter/gather IO 模式——先拿到写入空间的指针，直接写入，再通知 evbuffer：

```c
// 步骤 1：预留空间
struct evbuffer_iovec vec[2];
int n = evbuffer_reserve_space(buf, 1024, vec, 2);
// n = 返回的 iovec 数量（1 或 2）
// vec[i].iov_base = 可写入的内存地址
// vec[i].iov_len  = 该段可用的字节数

// 步骤 2：直接写入（零拷贝）
for (int i = 0; i < n; i++) {
    size_t to_write = MIN(remaining, vec[i].iov_len);
    memcpy(vec[i].iov_base, data + offset, to_write);
    vec[i].iov_len = to_write;  // 修改为实际写入的量
    offset += to_write;
    remaining -= to_write;
}

// 步骤 3：提交
evbuffer_commit_space(buf, vec, n);
// 只有 commit 后，数据才对读者可见
```

**为什么这是"零拷贝"**？调用者直接写入 evbuffer 内部内存，省去了先写到临时 buffer 再 `evbuffer_add` 的中间拷贝。

典型用场：接收网络数据时（read/recv 直接写入 evbuffer）：

```c
void read_into_evbuffer(evutil_socket_t fd, struct evbuffer *buf)
{
    struct evbuffer_iovec vec[2];
    int n = evbuffer_reserve_space(buf, 4096, vec, 2);

    // readv：一次系统调用，数据直接读入 evbuffer 内部
    struct iovec iov[2];
    for (int i = 0; i < n; i++) {
        iov[i].iov_base = vec[i].iov_base;
        iov[i].iov_len  = vec[i].iov_len;
    }
    ssize_t bytes_read = readv(fd, iov, n);

    if (bytes_read > 0) {
        // 调整实际读入的大小
        size_t remaining = bytes_read;
        for (int i = 0; i < n && remaining > 0; i++) {
            vec[i].iov_len = MIN(vec[i].iov_len, remaining);
            remaining -= vec[i].iov_len;
        }
        evbuffer_commit_space(buf, vec, n);
    }
}
```

### 5.5 evbuffer_peek：零拷贝读

获取 evbuffer 内部数据的直接指针，不拷贝，不消耗：

```c
int evbuffer_peek(struct evbuffer *buffer, ev_ssize_t len,
    struct evbuffer_ptr *start_at,
    struct evbuffer_iovec *vec, int n_vec);
// len：想要查看的最大字节数（-1 表示全部）
// start_at：从哪里开始（NULL = 从头）
// vec/n_vec：返回的 iovec 数组
// 返回值：填充了数据的 iovec 数量
```

`buffer.c` 第 2813 行的实现很清晰——直接返回各 chain 内部 buffer 的指针：

```c
vec[idx].iov_base = (void *)(chain->buffer + chain->misalign);
vec[idx].iov_len = chain->off;
// 没有任何 memcpy！
```

**使用示例**：零拷贝解析协议头部

```c
// 检查前 4 字节是否是协议魔数，不消耗数据
int check_magic(struct evbuffer *buf)
{
    if (evbuffer_get_length(buf) < 4) return 0;  // 数据不够

    struct evbuffer_iovec vec[1];
    int n = evbuffer_peek(buf, 4, NULL, vec, 1);

    if (n > 0 && vec[0].iov_len >= 4) {
        uint32_t magic = *(uint32_t *)vec[0].iov_base;
        return (ntohl(magic) == 0xDEADBEEF);
    }

    // 数据跨越 chain 边界，需要 pullup 才能连续访问
    unsigned char *p = evbuffer_pullup(buf, 4);
    return p && (ntohl(*(uint32_t *)p) == 0xDEADBEEF);
}
```

---

## 6. evbuffer_pullup：强制连续化

evbuffer 的数据可能分散在多个 chain 中，某些场景需要连续内存（如调用 SSL 加密函数）：

```c
unsigned char *evbuffer_pullup(struct evbuffer *buf, ev_ssize_t size);
// 确保前 size 字节在连续内存中
// 返回指向这段连续内存的指针（NULL 表示失败）
// size = -1：强制整个 buffer 连续化
```

**注意**：`pullup` 可能触发 `memmove` 和内存重分配，代价较高。仅在确实需要时使用：

```c
// 不好的写法：每次都 pullup（可能触发大量内存移动）
unsigned char *p = evbuffer_pullup(buf, -1);  // 强制所有数据连续

// 好的写法：先用 peek 尝试，只在跨越 chain 边界时才 pullup
struct evbuffer_iovec vec[1];
int n = evbuffer_peek(buf, header_size, NULL, vec, 1);
unsigned char *header;
if (n == 1 && vec[0].iov_len >= header_size) {
    header = vec[0].iov_base;  // 已经连续，直接使用
} else {
    header = evbuffer_pullup(buf, header_size);  // 只在必要时 pullup
}
```

---

## 7. 与 fd 的直接 IO

evbuffer 支持直接从 fd 读取数据或向 fd 写入数据，libevent 的 bufferevent 内部使用这些函数：

```c
// 从 fd 读取数据到 evbuffer（最多 howmuch 字节）
int evbuffer_read(struct evbuffer *buffer, evutil_socket_t fd, int howmuch);
// 内部使用 readv（如果可用），配合 reserve_space 直接读入 chain 内部

// 把 evbuffer 中的数据写到 fd，写完的数据自动 drain
int evbuffer_write(struct evbuffer *buffer, evutil_socket_t fd);

// 最多写 howmuch 字节
int evbuffer_write_atmost(struct evbuffer *buffer, evutil_socket_t fd,
                          ev_ssize_t howmuch);
```

这两个函数是 bufferevent 内部自动收发数据的基础，直接用 evbuffer 写简单 IO 循环时也很有用。

---

## 8. 文件发送：evbuffer_add_file

```c
int evbuffer_add_file(struct evbuffer *outbuf, int fd,
                      ev_off_t offset, ev_off_t length);
```

libevent 会尽可能使用最高效的方式：
1. **sendfile**（Linux）：内核直接从文件 fd 到 socket fd，数据不经过用户空间
2. **mmap**：将文件映射到虚拟内存，避免 read/write 的拷贝
3. **普通 read/write**：兜底方案

```c
// 发送静态文件（HTTP 文件服务器的核心）
void send_file(struct bufferevent *bev, const char *filepath)
{
    int fd = open(filepath, O_RDONLY);
    struct stat st;
    fstat(fd, &st);

    struct evbuffer *output = bufferevent_get_output(bev);
    // libevent 会选择 sendfile/mmap/read，最高效地发送
    evbuffer_add_file(output, fd, 0, st.st_size);
    // fd 的生命周期交给 evbuffer 管理，发送完自动 close
}
```

---

## 9. evbuffer 的回调通知

当 evbuffer 的内容发生变化（添加或删除字节）时，可以触发回调：

```c
// 注册变化回调
struct evbuffer_cb_entry *evbuffer_add_cb(
    struct evbuffer *buffer,
    evbuffer_cb_func cb,
    void *cbarg);

// 回调函数签名
typedef void (*evbuffer_cb_func)(struct evbuffer *buffer,
    const struct evbuffer_cb_info *info, void *arg);

struct evbuffer_cb_info {
    size_t orig_size;  // 变化前的大小
    size_t n_added;    // 添加了多少字节
    size_t n_deleted;  // 删除了多少字节
};

// 注销回调
int evbuffer_remove_cb(struct evbuffer *buffer,
                       evbuffer_cb_func cb, void *cbarg);
int evbuffer_remove_cb_entry(struct evbuffer *buffer,
                             struct evbuffer_cb_entry *ent);
```

bufferevent 内部用这个机制实现水位回调（readcb/writecb 的触发时机）。

---

## 10. API 速查表

| 函数 | 类别 | 说明 |
|------|------|------|
| `evbuffer_new/free` | 生命周期 | 创建/释放 |
| `evbuffer_get_length` | 查询 | 总字节数（O(1)） |
| `evbuffer_get_contiguous_space` | 查询 | 第一个 chain 的连续字节数 |
| `evbuffer_add` | 写入 | memcpy 追加 |
| `evbuffer_add_printf` | 写入 | 格式化追加 |
| `evbuffer_prepend` | 写入 | 前置插入 |
| `evbuffer_remove` | 读取 | 读取并消耗 |
| `evbuffer_copyout` | 读取 | 只读不消耗 |
| `evbuffer_drain` | 消费 | 丢弃前 N 字节（O(1)） |
| `evbuffer_readln` | 协议 | 读取一行（带换行符处理） |
| `evbuffer_search` | 协议 | 搜索子串 |
| `evbuffer_add_buffer` | 零拷贝 | O(1) 合并两个 evbuffer |
| `evbuffer_remove_buffer` | 零拷贝 | 部分转移 |
| `evbuffer_add_reference` | 零拷贝 | 引用外部内存 |
| `evbuffer_reserve_space` | 零拷贝 | 预留写入空间 |
| `evbuffer_commit_space` | 零拷贝 | 提交写入 |
| `evbuffer_peek` | 零拷贝 | 获取内部指针（不消耗） |
| `evbuffer_pullup` | 连续化 | 强制前 N 字节连续 |
| `evbuffer_read` | fd IO | 从 fd 读入 |
| `evbuffer_write` | fd IO | 写出到 fd |
| `evbuffer_add_file` | fd IO | 高效发送文件（sendfile/mmap） |
| `evbuffer_expand` | 预分配 | 提前分配空间 |

---

## 11. 完整实战示例

### 11.1 行协议解析器（类 Redis RESP 简化版）

```c
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 简单命令协议：每行一条命令
// PING → 回复 PONG
// ECHO <msg> → 回复 <msg>
// SET <key> <val> → 回复 OK
// GET <key> → 回复 VALUE

#define MAX_KEY_LEN 64
#define MAX_VAL_LEN 256

struct kv_entry {
    char key[MAX_KEY_LEN];
    char val[MAX_VAL_LEN];
    struct kv_entry *next;
};

static struct kv_entry *g_kv_store = NULL;

const char *kv_get(const char *key)
{
    for (struct kv_entry *e = g_kv_store; e; e = e->next)
        if (strcmp(e->key, key) == 0) return e->val;
    return NULL;
}

void kv_set(const char *key, const char *val)
{
    for (struct kv_entry *e = g_kv_store; e; e = e->next) {
        if (strcmp(e->key, key) == 0) {
            strncpy(e->val, val, MAX_VAL_LEN-1);
            return;
        }
    }
    struct kv_entry *e = malloc(sizeof(*e));
    strncpy(e->key, key, MAX_KEY_LEN-1);
    strncpy(e->val, val, MAX_VAL_LEN-1);
    e->key[MAX_KEY_LEN-1] = e->val[MAX_VAL_LEN-1] = '\0';
    e->next = g_kv_store;
    g_kv_store = e;
}

void handle_command(struct bufferevent *bev, const char *line)
{
    struct evbuffer *output = bufferevent_get_output(bev);

    if (strcasecmp(line, "PING") == 0) {
        evbuffer_add_printf(output, "PONG\r\n");
    } else if (strncasecmp(line, "ECHO ", 5) == 0) {
        evbuffer_add_printf(output, "%s\r\n", line + 5);
    } else if (strncasecmp(line, "SET ", 4) == 0) {
        char key[MAX_KEY_LEN], val[MAX_VAL_LEN];
        if (sscanf(line + 4, "%63s %255s", key, val) == 2) {
            kv_set(key, val);
            evbuffer_add_printf(output, "OK\r\n");
        } else {
            evbuffer_add_printf(output, "ERROR: usage: SET <key> <val>\r\n");
        }
    } else if (strncasecmp(line, "GET ", 4) == 0) {
        char key[MAX_KEY_LEN];
        if (sscanf(line + 4, "%63s", key) == 1) {
            const char *val = kv_get(key);
            if (val)
                evbuffer_add_printf(output, "%s\r\n", val);
            else
                evbuffer_add_printf(output, "NIL\r\n");
        } else {
            evbuffer_add_printf(output, "ERROR: usage: GET <key>\r\n");
        }
    } else {
        evbuffer_add_printf(output, "ERROR: unknown command: %s\r\n", line);
    }
}

void read_cb(struct bufferevent *bev, void *arg)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    char *line;

    // 循环读取所有完整的行
    // evbuffer_readln 只要缓冲区有完整行就返回，否则返回 NULL
    while ((line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF)) != NULL) {
        if (strlen(line) > 0) {
            handle_command(bev, line);
        }
        free(line);  // 必须 free！
    }
}

void event_cb(struct bufferevent *bev, short events, void *arg)
{
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
    }
}

void accept_cb(struct evconnlistener *lev, evutil_socket_t fd,
               struct sockaddr *sa, int salen, void *arg)
{
    struct event_base *base = arg;
    struct bufferevent *bev = bufferevent_socket_new(
        base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, read_cb, NULL, event_cb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    // 发送欢迎消息
    struct evbuffer *output = bufferevent_get_output(bev);
    evbuffer_add_printf(output, "Welcome! Commands: PING, ECHO, GET, SET\r\n");
}

int main(void)
{
    struct event_base *base = event_base_new();
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(6380),
    };
    struct evconnlistener *lev = evconnlistener_new_bind(
        base, accept_cb, base,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr *)&sin, sizeof(sin));

    printf("KV 服务器启动，端口 6380\n");
    printf("测试: telnet 127.0.0.1 6380\n");
    event_base_dispatch(base);

    evconnlistener_free(lev);
    event_base_free(base);
    return 0;
}
```

编译运行：

```bash
gcc kv_server.c -I/root/libevent/include \
    -L/root/libevent/build/lib -levent -o kv_server
LD_LIBRARY_PATH=/root/libevent/build/lib ./kv_server &

telnet 127.0.0.1 6380
# 输入：PING → 收到 PONG
# 输入：SET name Alice → 收到 OK
# 输入：GET name → 收到 Alice
```

### 11.2 对比 evbuffer_add 与 evbuffer_add_reference 的内存行为

```c
#include <event2/buffer.h>
#include <stdio.h>
#include <stdlib.h>

void demo_add_vs_reference(void)
{
    char *heap_data = malloc(1024 * 1024);  // 1MB 数据
    memset(heap_data, 'A', 1024 * 1024);

    // 方案 1：evbuffer_add（拷贝）
    struct evbuffer *buf1 = evbuffer_new();
    evbuffer_add(buf1, heap_data, 1024 * 1024);
    // heap_data 被完整复制到 buf1 内部
    // 此时内存占用：1MB（heap_data）+ 1MB（buf1 内部）= 2MB
    printf("add 后 buf1 大小: %zu\n", evbuffer_get_length(buf1));

    // 方案 2：evbuffer_add_reference（零拷贝）
    struct evbuffer *buf2 = evbuffer_new();
    evbuffer_add_reference(buf2, heap_data, 1024 * 1024, free, heap_data);
    // buf2 只存了一个指针指向 heap_data
    // 此时内存占用：1MB（heap_data，被 buf2 引用）
    printf("reference 后 buf2 大小: %zu\n", evbuffer_get_length(buf2));

    // 释放 buf1：释放内部拷贝的 1MB
    evbuffer_free(buf1);
    // heap_data 还在，因为 buf2 还在引用

    // 释放 buf2：触发 cleanup 回调（free(heap_data)）
    evbuffer_free(buf2);
    // heap_data 现在已被 free
    printf("heap_data 已被自动 free\n");
}
```

---

## 12. 动手实践

### 练习 1：实现一个 evbuffer 的 printf 计数器

```c
// 往 evbuffer 里写入 100 次 "Hello, World!\n"
// 比较 evbuffer_add_printf（100次）vs
//      先格式化到临时 buffer 再 evbuffer_add 的内存分配次数
// 提示：使用 valgrind --tool=massif 分析内存使用
```

### 练习 2：用 evbuffer 解析简单的 TLV 协议

```
TLV（Type-Length-Value）格式：
  [1字节 Type][2字节 Length（大端）][Length字节 Value]

实现解析器：
  - 检查 evbuffer 中是否有完整的 TLV 消息（至少 3 字节头 + Length 字节体）
  - 如果完整，读出并返回；否则等待更多数据
  - 使用 evbuffer_copyout 先读头部，再用 evbuffer_remove 读完整消息
```

### 练习 3：零拷贝 vs 拷贝的性能对比

```c
// 创建两个测试：
// A：用 evbuffer_add_buffer 转移 100MB 数据（1个 evbuffer → 另一个）
// B：用 evbuffer_remove + evbuffer_add 拷贝 100MB 数据
// 用 clock_gettime 测量两者的时间差
// 预期：A 快很多（仅指针操作 O(1) vs memcpy O(N)）
```

### 练习 4：阅读源码，回答问题

1. `evbuffer_drain` 为什么比 `evbuffer_remove` 快？（提示：看两者对 misalign 的处理）
2. `evbuffer_add_buffer` 在什么情况下会有 O(1) 以外的操作？（提示：看 PINNED 相关逻辑）
3. `evbuffer_pullup(buf, -1)` 有什么潜在的性能风险？
4. `evbuffer_peek` 返回多个 iovec 的原因是什么？何时会只返回 1 个？

---

## 13. 本课小结

| 概念 | 核心要点 |
|------|---------|
| `evbuffer_chain` | 链式内存块，misalign 实现 O(1) drain，off 记录有效数据 |
| `struct evbuffer` | 链表头尾指针 + total_len（O(1) 查询）+ 回调机制 |
| `evbuffer_add` | memcpy 到末尾 chain，空间不足时分配新 chain（翻倍增长）|
| `evbuffer_drain` | 移动 misalign 指针，O(1)，不 memmove |
| `evbuffer_readln` | 搜索换行符，返回堆分配字符串（调用者 free）|
| `evbuffer_add_buffer` | 链表拼接，O(1) 合并，不 memcpy |
| `evbuffer_add_reference` | 零拷贝引用外部内存，带 cleanup 回调 |
| `reserve/commit_space` | 直接写入 evbuffer 内部，省去中间 buffer |
| `evbuffer_peek` | 获取内部指针，完全零拷贝读取 |
| `evbuffer_pullup` | 强制连续化，可能触发 memmove，谨慎使用 |
| `evbuffer_add_file` | 自动选择 sendfile/mmap，高效发送文件 |

**三句话总结本课**：
1. evbuffer 是链式内存块（chain）的集合，drain 操作通过移动 `misalign` 指针实现 O(1)，避免了频繁的 memmove
2. `evbuffer_add_buffer` 通过链表指针操作实现 O(1) 的缓冲区合并，是高吞吐代理/转发的关键
3. `reserve_space + commit_space` 和 `peek` 提供了真正的零拷贝读写接口，适合需要极致性能的场景

---

## 附：练习 4 答案

1. **drain 比 remove 快的原因**：`evbuffer_drain` 只移动 `misalign` 指针（`chain->misalign += n; chain->off -= n`），不进行任何数据拷贝；而 `evbuffer_remove` 在内部先调用 `evbuffer_copyout_from`（执行 memcpy 将数据拷贝到用户 buffer），再调用 `evbuffer_drain`。如果只是丢弃数据（不需要内容），应用 `evbuffer_drain` 而不是 `evbuffer_remove`。

2. **evbuffer_add_buffer 不是纯 O(1) 的情况**：当 `inbuf` 中有 PINNED 的 chain（正在被 fd 读写操作固定），需要调用 `PRESERVE_PINNED` 先处理这些 pinned chain，这部分是 O(pinned_chains)。在普通场景（没有活跃 IO 操作）下是 O(1)。

3. **pullup(-1) 的性能风险**：会强制将所有 chain 的数据合并到一个 chain 中，触发大块内存分配和全量 memmove。对于 MB 级别的数据，这会造成明显的延迟和内存峰值（同时存在原始 chain 数据 + 新连续块）。

4. **peek 返回多个 iovec 的原因**：evbuffer 的数据可能分散在多个 chain 中。`peek` 会遍历 chain 链表，每个 chain 对应一个 iovec。如果所有请求的数据恰好都在第一个 chain 里，就返回 1 个。跨越 chain 边界时返回多个。这就是 scatter/gather IO 的思想。

---

**下一课预告**：第 7 课深入 bufferevent 基础 —— 在 evbuffer 之上的异步 IO 抽象，readcb/writecb/eventcb 三类回调的触发时机，以及水位控制（watermark）的工作原理。
