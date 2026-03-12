# 第 7 课：bufferevent 基础 —— 异步读写抽象

> **前置要求**：完成第 6 课，理解 evbuffer 的链式结构与零拷贝操作
> **本课目标**：掌握 bufferevent 的设计思想、三个回调的触发机制、水位控制与流量管理，能独立实现 echo server 和简单代理

---

## 1. 为什么需要 bufferevent

第 4 课学了 `event`，让我们能监听 fd 的读写就绪事件。但裸 `event` 处理网络 IO 时有几个繁琐的问题：

### 1.1 裸 event 的痛点

```c
// 用裸 event 处理网络读写（繁琐写法）
void read_cb(evutil_socket_t fd, short events, void *arg) {
    char buf[4096];
    ssize_t n;

    // 问题 1：必须手动循环读，处理 EAGAIN
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        process(buf, n);
    }
    if (n == -1 && errno != EAGAIN) {
        // 错误处理...
    }
}

void write_cb(evutil_socket_t fd, short events, void *arg) {
    // 问题 2：必须自己维护输出缓冲区
    // 问题 3：必须跟踪已发送了多少字节
    // 问题 4：发送完毕后要手动 event_del 写事件
}
```

每个使用者都要重复实现这些逻辑。libevent 把这些样板代码封装成 **bufferevent**：

- 自动维护输入/输出两个 evbuffer
- 自动在 fd 可读时读取数据到 input buffer
- 自动把 output buffer 中的数据写出到 fd
- 通过**水位（watermark）**控制何时触发回调
- 统一的 eventcb 处理 EOF、错误、超时

### 1.2 bufferevent 的核心抽象

```
┌─────────────────────────────────────────────────────────────────┐
│                       bufferevent                               │
│                                                                 │
│  ┌──────────────┐    readcb 触发              ┌─────────────┐  │
│  │ input buffer │ ─────────────────────────→  │  你的代码   │  │
│  │  (evbuffer)  │  数据累积到 low watermark    │             │  │
│  └──────────────┘                             │  处理请求   │  │
│                                               │             │  │
│  ┌──────────────┐    writecb 触发              │  产生响应   │  │
│  │ output buffer│ ←───────────────────────── │             │  │
│  │  (evbuffer)  │  数据低于 low watermark      └─────────────┘  │
│  └──────┬───────┘                                              │
│         │                                                      │
│    libevent 自动发送                                             │
│         ↓                                                      │
│      网络 fd                                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. struct bufferevent 内部结构

### 2.1 公开结构体（`include/event2/bufferevent_struct.h` 第 52 行）

```c
struct bufferevent {
    struct event_base *ev_base;       // 所属的事件循环

    const struct bufferevent_ops *be_ops; // 后端操作表（vtable）

    struct event ev_read;             // 监听 fd 可读的 event
    struct event ev_write;            // 监听 fd 可写的 event

    struct evbuffer *input;           // 输入缓冲区（fd → 你的代码）
    struct evbuffer *output;          // 输出缓冲区（你的代码 → fd）

    struct event_watermark wm_read;   // 读水位：{ low, high }
    struct event_watermark wm_write;  // 写水位：{ low, high }

    bufferevent_data_cb   readcb;     // 读回调
    bufferevent_data_cb   writecb;    // 写回调
    bufferevent_event_cb  errorcb;    // 事件回调（EOF/错误/超时）
    void *cbarg;                      // 回调参数

    struct timeval timeout_read;      // 读超时
    struct timeval timeout_write;     // 写超时

    short enabled;                    // EV_READ | EV_WRITE 当前已启用的
};
```

### 2.2 私有扩展（`bufferevent-internal.h`）

```c
struct bufferevent_private {
    struct bufferevent bev;           // 公开部分（必须是第一个字段）

    struct evbuffer_cb_entry *read_watermarks_cb; // 高水位回调
    ev_uint32_t readcb_pending;       // 待触发的读回调标志
    ev_uint32_t writecb_pending;      // 待触发的写回调标志

    unsigned own_lock : 1;            // 是否持有自己的锁
    unsigned readcb_running : 1;      // 读回调是否正在运行
    unsigned writecb_running : 1;

    struct event_callback deferred;   // DEFER_CALLBACKS 时使用的延迟回调
    // ...
};
```

### 2.3 后端操作表 vtable

```c
// bufferevent-internal.h
struct bufferevent_ops {
    const char *type;            // 类型名，如 "socket"、"filter"、"pair"
    off_t mem_offset;            // struct bufferevent_private 的偏移

    int (*enable)(struct bufferevent *, short);   // 启用读/写监听
    int (*disable)(struct bufferevent *, short);  // 禁用读/写监听
    void (*unlink)(struct bufferevent *);
    void (*destruct)(struct bufferevent *);
    int (*adj_timeouts)(struct bufferevent *);    // 重置超时
    int (*flush)(struct bufferevent *, short, enum bufferevent_flush_mode);
    int (*ctrl)(struct bufferevent *, enum bufferevent_ctrl_op, ...);
};
```

socket 后端实现（`bufferevent_sock.c` 第 547 行）：

```c
const struct bufferevent_ops bufferevent_ops_socket = {
    "socket",
    evutil_offsetof(struct bufferevent_private, bev),
    be_socket_enable,
    be_socket_disable,
    NULL,                    /* unlink */
    be_socket_destruct,
    be_socket_adj_timeouts,
    be_socket_flush,
    be_socket_ctrl,
};
```

---

## 3. 创建与配置

### 3.1 bufferevent_socket_new

```c
// include/event2/bufferevent.h
struct bufferevent *bufferevent_socket_new(
    struct event_base *base,
    evutil_socket_t fd,
    int options           // BEV_OPT_* 标志的组合
);
```

**options 参数详解**：

```c
enum bufferevent_options {
    BEV_OPT_CLOSE_ON_FREE    = (1<<0),  // free 时自动关闭 fd
    BEV_OPT_THREADSAFE       = (1<<1),  // 为每个操作加锁（多线程安全）
    BEV_OPT_DEFER_CALLBACKS  = (1<<2),  // 延迟回调到下一轮事件循环
    BEV_OPT_UNLOCK_CALLBACKS = (1<<3),  // 回调期间释放锁（避免死锁）
};
```

**内部实现**（`bufferevent_sock.c` 第 118 行）：

```c
struct bufferevent *bufferevent_socket_new(
    struct event_base *base, evutil_socket_t fd, int options)
{
    struct bufferevent_private *bufev_p;
    struct bufferevent *bufev;

    bufev_p = mm_calloc(1, sizeof(struct bufferevent_private));
    bufev = &bufev_p->bev;

    if (bufferevent_init_common_(bufev_p, base, &bufferevent_ops_socket,
        options) < 0) {
        mm_free(bufev_p);
        return NULL;
    }

    // 为读事件和写事件注册，带 EV_PERSIST | EV_FINALIZE
    event_assign(&bufev->ev_read, base, fd,
        EV_READ | EV_PERSIST | EV_FINALIZE, bufferevent_readcb, bufev);
    event_assign(&bufev->ev_write, base, fd,
        EV_WRITE | EV_PERSIST | EV_FINALIZE, bufferevent_writecb, bufev);

    evbuffer_add_cb(bufev->output, bufferevent_socket_outbuf_cb, bufev);
    evbuffer_freeze(bufev->input, 0);   // 禁止从外部写入 input
    evbuffer_freeze(bufev->output, 1);  // 禁止从外部读取 output
    return bufev;
}
```

注意 `EV_PERSIST | EV_FINALIZE` 的组合：
- `EV_PERSIST`：每次就绪后不自动删除，持续监听
- `EV_FINALIZE`：安全地处理 event 析构（见第 4 课）

### 3.2 设置回调

```c
void bufferevent_setcb(
    struct bufferevent *bufev,
    bufferevent_data_cb  readcb,   // 可读回调（可为 NULL）
    bufferevent_data_cb  writecb,  // 可写回调（可为 NULL）
    bufferevent_event_cb eventcb,  // 事件回调（可为 NULL）
    void *cbarg                    // 传给所有回调的参数
);

// 回调函数签名
typedef void (*bufferevent_data_cb)(struct bufferevent *bev, void *ctx);
typedef void (*bufferevent_event_cb)(struct bufferevent *bev,
                                     short events, void *ctx);
```

`events` 参数的取值（可以是多个标志的组合）：

```c
#define BEV_EVENT_READING   0x01  // 错误发生在读操作中
#define BEV_EVENT_WRITING   0x02  // 错误发生在写操作中
#define BEV_EVENT_EOF       0x10  // 对端关闭连接（读到 EOF）
#define BEV_EVENT_ERROR     0x20  // 底层发生错误（查 errno 或 evutil_socket_geterror）
#define BEV_EVENT_TIMEOUT   0x40  // 读写超时
#define BEV_EVENT_CONNECTED 0x80  // 连接建立成功（connect 完成）
```

典型用法：

```c
void eventcb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_EOF) {
        printf("对端关闭了连接\n");
    } else if (events & BEV_EVENT_ERROR) {
        printf("发生错误: %s\n",
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    } else if (events & BEV_EVENT_TIMEOUT) {
        if (events & BEV_EVENT_READING)
            printf("读超时\n");
        if (events & BEV_EVENT_WRITING)
            printf("写超时\n");
    } else if (events & BEV_EVENT_CONNECTED) {
        printf("连接成功\n");
    }
    bufferevent_free(bev);
}
```

### 3.3 启用和禁用

```c
int bufferevent_enable(struct bufferevent *bufev, short event);   // event = EV_READ|EV_WRITE
int bufferevent_disable(struct bufferevent *bufev, short event);
short bufferevent_get_enabled(struct bufferevent *bufev);
```

**重要**：bufferevent 创建后，读写监听默认**未启用**。必须显式调用 `bufferevent_enable`。

```c
struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
bufferevent_setcb(bev, readcb, writecb, eventcb, NULL);
bufferevent_enable(bev, EV_READ | EV_WRITE);   // 开始监听读写
```

---

## 4. 三个回调的触发机制

这是理解 bufferevent 的核心。三个回调的触发时机完全不同：

### 4.1 readcb（读回调）

**触发条件**：input buffer 中的数据量 **≥ wm_read.low**（默认为 0）

```c
// bufferevent_sock.c: bufferevent_readcb（简化版）
static void bufferevent_readcb(evutil_socket_t fd, short event, void *arg)
{
    struct bufferevent *bufev = arg;
    struct bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    struct evbuffer *input = bufev->input;
    int res = 0;
    short what = BEV_EVENT_READING;
    ev_ssize_t howmuch = -1;

    // 计算本次最多读多少字节（受高水位限制）
    if (bufev->wm_read.high != 0) {
        howmuch = bufev->wm_read.high - evbuffer_get_length(input);
        if (howmuch <= 0) {
            // 已达高水位，暂停读取
            bufferevent_unsuspend_read_(bufev, BEV_SUSPEND_WM);
            goto done;
        }
    }

    // 从 fd 读数据到 input buffer
    res = evbuffer_read(input, fd, (int)howmuch);

    if (res == -1) {
        int err = evutil_socket_geterror(fd);
        if (EVUTIL_ERR_RW_RETRIABLE(err))
            goto reschedule;   // EAGAIN，正常，下次再试
        what |= BEV_EVENT_ERROR;
        goto error;
    } else if (res == 0) {
        what |= BEV_EVENT_EOF;
        goto error;
    }

    // 触发读回调的条件：数据量达到低水位
    if (evbuffer_get_length(input) >= bufev->wm_read.low)
        bufferevent_run_readcb_(bufev, 0);

    goto done;
error:
    bufferevent_run_eventcb_(bufev, what, 0);
done:
    ;
}
```

**低水位（wm_read.low）的作用**：

```
默认 low=0 时：只要有数据就触发 readcb
设置 low=1024 时：input buffer 积累到 1024 字节才触发 readcb
                  适用于需要完整数据包才能处理的协议
```

**高水位（wm_read.high）的作用**（流量控制）：

```
设置 high=65536 时：input buffer 超过 64KB 就暂停读取（防止内存膨胀）
数据被消费后，自动恢复读取
```

### 4.2 writecb（写回调）

**触发条件**：output buffer 中的数据量 **≤ wm_write.low**（默认为 0）

```c
// bufferevent_sock.c: bufferevent_writecb（简化版）
static void bufferevent_writecb(evutil_socket_t fd, short event, void *arg)
{
    struct bufferevent *bufev = arg;
    short what = BEV_EVENT_WRITING;
    int res = 0;

    // 把 output buffer 中的数据写出去
    if (evbuffer_get_length(bufev->output)) {
        res = evbuffer_write(bufev->output, fd);
        if (res == -1) {
            int err = evutil_socket_geterror(fd);
            if (!EVUTIL_ERR_RW_RETRIABLE(err)) {
                what |= BEV_EVENT_ERROR;
                goto error;
            }
        } else if (res == 0) {
            what |= BEV_EVENT_EOF;
            goto error;
        }
    }

    // output buffer 数据量降至低水位，触发写回调
    if (evbuffer_get_length(bufev->output) <= bufev->wm_write.low)
        bufferevent_run_writecb_(bufev, 0);

    // output buffer 为空，不再需要监听写事件
    if (evbuffer_get_length(bufev->output) == 0 &&
        bufev->wm_write.high != 0)
        event_del(&bufev->ev_write);
    goto done;
error:
    bufferevent_run_eventcb_(bufev, what, 0);
done:
    ;
}
```

**writecb 的典型用途**：

```c
// 当 output buffer 数据发送完毕时，关闭连接
void writecb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *output = bufferevent_get_output(bev);
    if (evbuffer_get_length(output) == 0) {
        bufferevent_free(bev);  // 数据发完了，关闭
    }
}
```

### 4.3 eventcb（事件回调）

由 `bufferevent_run_eventcb_` 触发，用于处理连接级别的状态变化：

```c
void eventcb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_CONNECTED) {
        // connect() 完成（对客户端有用）
        printf("Connected!\n");
        bufferevent_enable(bev, EV_READ | EV_WRITE);
    } else if (events & BEV_EVENT_EOF) {
        // 对端关闭（read 返回 0）
        printf("Connection closed\n");
        bufferevent_free(bev);
    } else if (events & BEV_EVENT_ERROR) {
        // IO 错误
        printf("Error: %s\n",
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        bufferevent_free(bev);
    } else if (events & BEV_EVENT_TIMEOUT) {
        // 读或写超时
        if (events & BEV_EVENT_READING)
            printf("Read timeout\n");
        if (events & BEV_EVENT_WRITING)
            printf("Write timeout\n");
        bufferevent_free(bev);
    }
}
```

---

## 5. 读写操作 API

### 5.1 写数据

```c
// 把 data 拷贝进 output buffer（之后 libevent 自动发送）
int bufferevent_write(struct bufferevent *bufev,
                      const void *data, size_t size);

// 把 buf 中所有数据移入 output buffer（零拷贝，O(1) 链表操作）
int bufferevent_write_buffer(struct bufferevent *bufev,
                             struct evbuffer *buf);
```

**推荐使用 `bufferevent_write_buffer`**：

```c
struct evbuffer *tmp = evbuffer_new();
evbuffer_add_printf(tmp, "HTTP/1.1 200 OK\r\n");
evbuffer_add_printf(tmp, "Content-Length: %zu\r\n\r\n", body_len);
evbuffer_add(tmp, body, body_len);
bufferevent_write_buffer(bev, tmp);  // O(1) 转移所有链
evbuffer_free(tmp);
```

### 5.2 读数据

```c
// 从 input buffer 拷贝出最多 size 字节（数据仍保留在 input 中）
int bufferevent_read(struct bufferevent *bufev,
                     void *data, size_t size);

// 把 input buffer 中所有数据移入 buf（零拷贝）
int bufferevent_read_buffer(struct bufferevent *bufev,
                            struct evbuffer *buf);
```

**推荐使用 evbuffer API 直接操作**（避免拷贝）：

```c
void readcb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *input = bufferevent_get_input(bev);

    // 方式 1：读一行（HTTP header 解析）
    char *line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
    if (line) {
        printf("收到: %s\n", line);
        free(line);
    }

    // 方式 2：直接操作 evbuffer（零拷贝转发）
    struct evbuffer *output = bufferevent_get_output(partner_bev);
    evbuffer_add_buffer(output, input);  // O(1) 转移
}
```

### 5.3 获取 input/output buffer

```c
struct evbuffer *bufferevent_get_input(struct bufferevent *bufev);
struct evbuffer *bufferevent_get_output(struct bufferevent *bufev);
```

这两个函数返回内部 evbuffer 的指针，可以直接使用第 6 课学到的所有 evbuffer API。

---

## 6. 水位控制

### 6.1 水位的定义

```c
void bufferevent_setwatermark(
    struct bufferevent *bufev,
    short events,         // EV_READ 或 EV_WRITE
    size_t lowmark,       // 低水位
    size_t highmark       // 高水位（0 表示无限制）
);
```

**读水位语义**：

```
wm_read.low  = 0（默认）：只要有数据就触发 readcb
wm_read.low  = N：input buffer 累积到 N 字节才触发 readcb
wm_read.high = 0（默认）：不限制读取量（input 可无限增长）
wm_read.high = M：input buffer 超过 M 字节时暂停读取（背压）
```

**写水位语义**：

```
wm_write.low  = 0（默认）：output buffer 清空时触发 writecb
wm_write.low  = N：output buffer 降至 N 字节时触发 writecb
wm_write.high = 0（默认）：不限制
wm_write.high = M：配合流量控制使用（见下一节）
```

### 6.2 流量控制实战：le-proxy.c 分析

`sample/le-proxy.c` 是 libevent 官方代理示例，完美展示了双向流量控制：

```c
// le-proxy.c: 代理核心逻辑
#define MAX_OUTPUT (512 * 1024)  // 512KB 高水位

static void readcb(struct bufferevent *bev, void *ctx)
{
    struct bufferevent *partner = ctx;
    struct evbuffer *src = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(src);

    if (!partner) {
        evbuffer_drain(src, len);
        return;
    }

    // 零拷贝转发：把读到的数据直接移入对端的 output buffer
    bufferevent_write_buffer(partner, src);

    // 流量控制：如果对端的 output buffer 积压太多，
    // 暂停从本端读取，防止内存无限增长
    if (evbuffer_get_length(bufferevent_get_output(partner)) >=
        MAX_OUTPUT) {
        bufferevent_setwatermark(partner, EV_WRITE,
            MAX_OUTPUT / 2, MAX_OUTPUT);  // 设置对端写水位
        bufferevent_disable(bev, EV_READ);  // 暂停读本端
    }
}

static void drained_writecb(struct bufferevent *bev, void *ctx)
{
    struct bufferevent *partner = ctx;

    // 对端 output buffer 已降至低水位（MAX_OUTPUT/2）
    // 恢复从 partner 读取
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);  // 清除写水位
    if (partner)
        bufferevent_enable(partner, EV_READ);  // 恢复读取
}
```

**流量控制状态机**：

```
正常状态：
  client_bev 可读 → readcb → 转发到 server_bev output

server output 积压（>= MAX_OUTPUT）：
  设置 server_bev 写水位 = (MAX_OUTPUT/2, MAX_OUTPUT)
  禁用 client_bev 读取

server output 排空（<= MAX_OUTPUT/2）：
  触发 drained_writecb
  清除 server_bev 写水位
  重新启用 client_bev 读取
```

这个模式防止了在慢速下行（server→client）时，大量数据堆积在内存中。

---

## 7. 超时设置

```c
void bufferevent_set_timeouts(
    struct bufferevent *bufev,
    const struct timeval *timeout_read,   // NULL 表示不超时
    const struct timeval *timeout_write   // NULL 表示不超时
);
```

超时是空闲超时（idle timeout）：在 timeout 时间内没有成功读/写任何数据就触发。

```c
// 设置 30 秒读超时，60 秒写超时
struct timeval tv_read  = { 30, 0 };
struct timeval tv_write = { 60, 0 };
bufferevent_set_timeouts(bev, &tv_read, &tv_write);
```

超时触发后，eventcb 会收到 `BEV_EVENT_TIMEOUT | BEV_EVENT_READING` 或 `BEV_EVENT_TIMEOUT | BEV_EVENT_WRITING`。

---

## 8. 主动连接

### 8.1 连接到服务器（已知 IP）

```c
int bufferevent_socket_connect(
    struct bufferevent *bev,
    const struct sockaddr *sa,
    int socklen
);
```

如果 `bev` 没有绑定 fd（`fd = -1`），会自动创建非阻塞 socket。连接建立后触发 `BEV_EVENT_CONNECTED`：

```c
struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
bufferevent_setcb(bev, readcb, NULL, eventcb, NULL);

struct sockaddr_in sin = {0};
sin.sin_family = AF_INET;
sin.sin_addr.s_addr = inet_addr("127.0.0.1");
sin.sin_port = htons(8080);

bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin));
// 注意：此时连接尚未建立！等待 eventcb 收到 BEV_EVENT_CONNECTED
```

### 8.2 通过域名连接（异步 DNS）

```c
int bufferevent_socket_connect_hostname(
    struct bufferevent *bev,
    struct evdns_base *evdns_base,   // DNS 解析器（第 12 课）
    int family,                      // AF_INET, AF_INET6, AF_UNSPEC
    const char *hostname,
    int port
);
```

```c
// 客户端连接示例（异步 DNS 解析）
struct evdns_base *dnsbase = evdns_base_new(base, 1);
struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
bufferevent_setcb(bev, readcb, NULL, eventcb, NULL);

bufferevent_socket_connect_hostname(
    bev, dnsbase, AF_UNSPEC, "example.com", 80);
// DNS 解析和 TCP 连接都是异步的
// 连接成功后触发 BEV_EVENT_CONNECTED
```

---

## 9. 释放 bufferevent

```c
void bufferevent_free(struct bufferevent *bufev);
```

`bufferevent_free` 并不是简单的 `free()`，它的行为取决于选项：

- 如果设置了 `BEV_OPT_CLOSE_ON_FREE`：同时关闭底层 fd
- 如果 output buffer 中还有数据未发送：会等待数据发完（取决于实现）
- 如果设置了 `BEV_OPT_DEFER_CALLBACKS`：延迟执行回调

**重要注意事项**：

```c
// 错误做法：在回调中 free 之后继续使用 bev
void readcb(struct bufferevent *bev, void *ctx) {
    bufferevent_free(bev);
    bufferevent_enable(bev, EV_READ);  // 错误！bev 已被释放
}

// 正确做法：free 后立即返回
void readcb(struct bufferevent *bev, void *ctx) {
    // 处理逻辑...
    bufferevent_free(bev);
    return;  // 立即返回，不再使用 bev
}
```

---

## 10. 综合示例：Echo Server

```c
// echo_server.c：使用 bufferevent 的完整 echo server
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static void readcb(struct bufferevent *bev, void *ctx)
{
    // 把 input 的所有数据原样写回 output
    struct evbuffer *input  = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);
    evbuffer_add_buffer(output, input);  // O(1) 零拷贝
}

static void eventcb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_EOF) {
        printf("Connection closed.\n");
    } else if (events & BEV_EVENT_ERROR) {
        printf("Error: %s\n",
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }
    bufferevent_free(bev);
}

static void accept_conn_cb(
    struct evconnlistener *listener,
    evutil_socket_t fd,
    struct sockaddr *address,
    int socklen,
    void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);

    struct bufferevent *bev = bufferevent_socket_new(
        base, fd, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(bev, readcb, NULL, eventcb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    // 设置 30 秒空闲超时
    struct timeval tv = {30, 0};
    bufferevent_set_timeouts(bev, &tv, NULL);

    // 防止恶意客户端发送大量数据：input buffer 超过 64KB 时暂停读取
    bufferevent_setwatermark(bev, EV_READ, 0, 64 * 1024);
}

static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Accept error %d: %s\n", err,
        evutil_socket_error_to_string(err));
    event_base_loopexit(base, NULL);
}

int main(void)
{
    struct event_base *base = event_base_new();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9999);

    struct evconnlistener *listener = evconnlistener_new_bind(
        base, accept_conn_cb, NULL,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr *)&sin, sizeof(sin));

    evconnlistener_set_error_cb(listener, accept_error_cb);

    printf("Echo server on port 9999\n");
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    return 0;
}
```

编译和测试：

```bash
gcc echo_server.c \
    -I/root/libevent/include \
    -L/root/libevent/build/lib \
    -levent -o echo_server

LD_LIBRARY_PATH=/root/libevent/build/lib ./echo_server &

# 测试 echo
echo "hello libevent" | nc 127.0.0.1 9999
# 输出：hello libevent

# 并发测试
for i in $(seq 10); do
    (echo "client $i" | nc 127.0.0.1 9999) &
done
wait
```

---

## 11. 综合示例：简单 HTTP 客户端

```c
// http_client.c：使用 bufferevent 的 HTTP/1.0 客户端
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

struct http_ctx {
    struct event_base *base;
    int headers_done;
};

static void readcb(struct bufferevent *bev, void *ctx)
{
    struct http_ctx *hctx = ctx;
    struct evbuffer *input = bufferevent_get_input(bev);

    if (!hctx->headers_done) {
        // 读取 HTTP headers（CRLF 行）
        char *line;
        while ((line = evbuffer_readln(input, NULL,
                    EVBUFFER_EOL_CRLF)) != NULL) {
            if (strlen(line) == 0) {
                // 空行 = headers 结束
                hctx->headers_done = 1;
                free(line);
                break;
            }
            printf("Header: %s\n", line);
            free(line);
        }
    }

    if (hctx->headers_done) {
        // 打印 body
        size_t len = evbuffer_get_length(input);
        if (len > 0) {
            char *buf = malloc(len + 1);
            evbuffer_remove(input, buf, len);
            buf[len] = '\0';
            printf("Body (%zu bytes):\n%s\n", len, buf);
            free(buf);
        }
    }
}

static void eventcb(struct bufferevent *bev, short events, void *ctx)
{
    struct http_ctx *hctx = ctx;

    if (events & BEV_EVENT_CONNECTED) {
        // 连接成功，发送 HTTP 请求
        struct evbuffer *output = bufferevent_get_output(bev);
        evbuffer_add_printf(output,
            "GET / HTTP/1.0\r\n"
            "Host: example.com\r\n"
            "Connection: close\r\n"
            "\r\n");
        bufferevent_enable(bev, EV_READ);
    } else if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (events & BEV_EVENT_ERROR)
            printf("Error: %s\n",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        bufferevent_free(bev);
        event_base_loopexit(hctx->base, NULL);
        free(hctx);
    }
}

int main(void)
{
    struct event_base *base = event_base_new();
    struct http_ctx *hctx = calloc(1, sizeof(*hctx));
    hctx->base = base;

    struct bufferevent *bev = bufferevent_socket_new(
        base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, readcb, NULL, eventcb, hctx);

    // 连接到 93.184.216.34:80（example.com）
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    inet_aton("93.184.216.34", &sin.sin_addr);

    bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin));

    event_base_dispatch(base);
    event_base_free(base);
    return 0;
}
```

---

## 12. 动手实践

### 练习 1：理解回调触发时机

修改 echo server，在 readcb 中打印当前 input buffer 的长度：

```c
void readcb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *input = bufferevent_get_input(bev);
    printf("readcb triggered, input length = %zu\n",
           evbuffer_get_length(input));
    // ... echo 逻辑
}
```

然后用 `bufferevent_setwatermark(bev, EV_READ, 100, 0)` 设置低水位 = 100。
观察：发送少于 100 字节时，readcb 是否触发？

### 练习 2：实现超时踢出

在 echo server 中，如果客户端 10 秒内没有发送任何数据，主动断开连接：

```c
// 提示：使用 bufferevent_set_timeouts 和 BEV_EVENT_TIMEOUT
```

### 练习 3：阅读 le-proxy.c 并扩展

阅读 `sample/le-proxy.c`，理解双向代理的完整实现，然后：
1. 添加连接数统计
2. 添加流量统计（上行/下行字节数）
3. 添加最大连接数限制（超过时拒绝新连接）

### 练习 4：回答问题

1. 为什么 bufferevent 内部的读写事件用 `EV_PERSIST` 而不是普通事件？
2. `BEV_OPT_DEFER_CALLBACKS` 有什么用途？在哪些场景下必须使用它？
3. 如果在 eventcb 中既收到了 `BEV_EVENT_EOF` 又有未读完的数据在 input buffer 中，应该怎么处理？

---

## 13. 本课小结

| 概念 | 关键点 |
|------|--------|
| bufferevent | 在 evbuffer 之上封装了自动 IO 的高级接口 |
| readcb | input buffer 数据量达到 wm_read.low 时触发（默认 0 = 有数据就触发）|
| writecb | output buffer 数据量降至 wm_write.low 时触发（默认 0 = 清空时触发）|
| eventcb | 连接状态变化：EOF / ERROR / TIMEOUT / CONNECTED |
| wm_read.high | 读高水位：超过时暂停读取，防止内存积压 |
| wm_write | 写水位：配合 disable/enable 实现背压流量控制 |
| BEV_OPT_CLOSE_ON_FREE | free 时自动关闭 fd（最常用选项）|
| bufferevent_write_buffer | 零拷贝写入，推荐替代 bufferevent_write |
| bufferevent_get_input/output | 直接操作内部 evbuffer，避免数据拷贝 |

**三句话总结**：

1. bufferevent = input evbuffer + output evbuffer + 三个回调 + 自动 IO
2. readcb 在数据到达时触发，writecb 在数据发出时触发，eventcb 在连接状态变化时触发
3. 水位控制是防止内存无限增长的关键机制，le-proxy.c 是最佳参考实现

---

## 附：练习 4 答案

1. **为什么用 EV_PERSIST**？
   因为 bufferevent 需要持续监听 fd 的读写，不能每次触发后自动删除事件。每次 IO 就绪后，bufferevent 内部决定是否继续监听（通过 enable/disable），而不是每次手动重新 add。

2. **BEV_OPT_DEFER_CALLBACKS 的用途**：
   在回调中修改 bufferevent 状态时（如 free、setcb），可能导致回调重入。DEFER 选项把回调推迟到当前事件处理完毕后，在下一轮 event_base_loop 迭代中执行，避免重入问题。多线程场景中与 `BEV_OPT_UNLOCK_CALLBACKS` 配合使用，防止持锁时调用用户回调导致死锁。

3. **EOF 时 input 中还有数据**：
   在处理 EOF 之前，应先把 input buffer 中的剩余数据处理完毕：
   ```c
   void eventcb(struct bufferevent *bev, short events, void *ctx) {
       if (events & BEV_EVENT_EOF) {
           struct evbuffer *input = bufferevent_get_input(bev);
           // 先处理剩余数据
           size_t remaining = evbuffer_get_length(input);
           if (remaining > 0) {
               process_remaining_data(input);
           }
           // 然后释放
           bufferevent_free(bev);
       }
   }
   ```

---

**下一课预告**：第 8 课深入 `evconnlistener` —— TCP 监听器的内部实现，多个监听器的管理，以及如何处理 accept 错误和连接限流。
