# 第 8 课：bufferevent 进阶 —— 过滤器、pair 与限速

> **前置要求**：完成第 7 课，掌握 bufferevent 基本使用与水位控制
> **本课目标**：理解 bufferevent 的可组合管道设计，掌握 filter / pair / rate-limit 三大进阶特性

---

## 1. bufferevent 的可组合设计

第 7 课看到的 `bufferevent_socket_new` 是最常用的"叶子节点"，直接绑定一个网络 fd。但 libevent 还提供了可以叠加在任意 bufferevent 之上的"变换层"：

```
应用代码
   ↕
bufferevent_filtered（数据变换：压缩、加密、ROT13...）
   ↕
bufferevent_socket（或其他底层 bufferevent）
   ↕
网络 fd
```

以及不需要任何 fd 的进程内管道：

```
应用代码 A             应用代码 B
   ↕                       ↕
bufferevent_pair[0]  ←→  bufferevent_pair[1]
（纯内存，无 fd，无系统调用）
```

这三种类型都通过同一套 `struct bufferevent_ops` vtable 实现，对调用者完全透明。

---

## 2. bufferevent_filter：数据变换管道

### 2.1 基本概念

filter 是叠加在"底层 bufferevent"之上的变换层。它拦截数据的流入和流出，允许你在读到应用之前和写出到网络之前任意修改数据：

```
读方向（网络 → 应用）：
  fd → [底层 bev input] → input_filter → [filter bev input] → readcb

写方向（应用 → 网络）：
  writecb → [filter bev output] → output_filter → [底层 bev output] → fd
```

### 2.2 filter 回调签名

`bufferevent_filter.c` 第 80 行定义的 `struct bufferevent_filtered`：

```c
struct bufferevent_filtered {
    struct bufferevent_private bev;    // 公开的 bufferevent（第一个字段）
    struct bufferevent *underlying;    // 底层 bufferevent（真正做 IO 的）
    struct evbuffer_cb_entry *inbuf_cb;
    struct evbuffer_cb_entry *outbuf_cb;
    unsigned got_eof;

    void (*free_context)(void *);      // 析构时释放 ctx
    bufferevent_filter_cb process_in;  // 读方向变换函数
    bufferevent_filter_cb process_out; // 写方向变换函数
    void *context;                     // 传给变换函数的用户数据
};
```

过滤器回调的签名（`include/event2/bufferevent.h` 第 738 行）：

```c
typedef enum bufferevent_filter_result (*bufferevent_filter_cb)(
    struct evbuffer *src,        // 数据来源（要消费）
    struct evbuffer *dst,        // 数据目标（要写入）
    ev_ssize_t dst_limit,        // 建议的最大写入量（-1=无限）
    enum bufferevent_flush_mode mode,  // BEV_NORMAL / BEV_FLUSH / BEV_FINISH
    void *ctx                    // 用户上下文
);
```

**返回值的含义**（`include/event2/bufferevent.h` 第 708 行）：

```c
enum bufferevent_filter_result {
    BEV_OK       = 0,  // 处理了一些数据，可以继续
    BEV_NEED_MORE = 1, // 需要更多输入才能产生输出（如 gzip 块头未完整）
    BEV_ERROR    = 2,  // 发生不可恢复的错误
};
```

**flush mode 的含义**：

| mode | 含义 | 触发时机 |
|------|------|----------|
| `BEV_NORMAL` | 正常模式，按高水位限制写入 | 日常数据流 |
| `BEV_FLUSH` | 尽量多写，不受限制 | 调用 `bufferevent_flush` 时 |
| `BEV_FINISH` | 写完所有数据并发出 EOF 标记 | 连接即将关闭时 |

### 2.3 创建 filter

```c
// include/event2/bufferevent.h 第 756 行
struct bufferevent *bufferevent_filter_new(
    struct bufferevent *underlying,         // 底层 bufferevent
    bufferevent_filter_cb input_filter,     // 读方向变换（NULL = 透传）
    bufferevent_filter_cb output_filter,    // 写方向变换（NULL = 透传）
    int options,                            // BEV_OPT_* 同第 7 课
    void (*free_context)(void *),           // ctx 的析构函数（可为 NULL）
    void *ctx                               // 传给 filter 回调的用户数据
);
```

**内部实现要点**（`bufferevent_filter.c` 第 168~225 行）：

```c
struct bufferevent *bufferevent_filter_new(
    struct bufferevent *underlying, ...) {

    // 1. 分配 bufferevent_filtered 结构体
    bufev_f = mm_calloc(1, sizeof(struct bufferevent_filtered));

    // 2. NULL filter 替换为透传函数 be_null_filter
    if (!input_filter)  input_filter  = be_null_filter;
    if (!output_filter) output_filter = be_null_filter;

    // 3. 把底层 bufferevent 的回调接管为 filter 的内部回调
    bufferevent_setcb(underlying,
        be_filter_readcb, be_filter_writecb, be_filter_eventcb, bufev_f);

    // 4. 暂停底层的读取，改由 filter 自行驱动
    bufferevent_suspend_read_(underlying, BEV_SUSPEND_FILT_READ);

    // 5. 增加底层 bufferevent 的引用计数
    bufferevent_incref_(underlying);

    return downcast(bufev_f);
}
```

### 2.4 数据流转原理

**读方向**（`be_filter_process_input`，第 297~333 行）：

```c
// 当底层 bufferevent 的 input 有数据时，be_filter_readcb 被调用
// be_filter_readcb 调用 be_filter_process_input：

do {
    // 把底层 input 的数据喂给 process_in
    res = bevf->process_in(
        bevf->underlying->input,  // src：从底层 input 读
        bev->input,               // dst：写入 filter 自己的 input
        limit, state, bevf->context);

    // BEV_OK 且底层还有数据 → 继续循环
} while (res == BEV_OK &&
         (bev->enabled & EV_READ) &&
         evbuffer_get_length(bevf->underlying->input) &&
         !be_readbuf_full(bevf, state));
```

数据处理完后，触发 filter 层自己的 readcb。

**写方向**（`be_filter_process_output`，第 336~413 行）：

```c
// 当 filter 的 output 有数据时，be_pair_outbuf_cb 被触发
// 调用 be_filter_process_output：

res = bevf->process_out(
    downcast(bevf)->output,       // src：从 filter 自己的 output 读
    bevf->underlying->input,      // dst：写入底层 bufferevent 的 input
    ...);
```

### 2.5 实战：ROT13 过滤器

```c
// rot13_filter.c：一个将所有字母做 ROT13 变换的过滤器

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <string.h>
#include <stdio.h>

// ROT13 变换：字母偏移 13 位，非字母不变
static void rot13_transform(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        if (c >= 'A' && c <= 'Z')
            data[i] = 'A' + (c - 'A' + 13) % 26;
        else if (c >= 'a' && c <= 'z')
            data[i] = 'a' + (c - 'a' + 13) % 26;
    }
}

// 过滤器回调：对 src 中的数据做 ROT13，写入 dst
static enum bufferevent_filter_result
rot13_filter(struct evbuffer *src, struct evbuffer *dst,
             ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
             void *ctx)
{
    size_t len = evbuffer_get_length(src);
    if (len == 0)
        return BEV_NEED_MORE;

    // 控制每次最大处理量
    if (dst_limit >= 0 && (ev_ssize_t)len > dst_limit)
        len = (size_t)dst_limit;

    // 方式：先从 src 拷贝出来，变换后写入 dst
    unsigned char *buf = malloc(len);
    if (!buf) return BEV_ERROR;

    evbuffer_remove(src, buf, len);
    rot13_transform(buf, len);
    evbuffer_add(dst, buf, len);
    free(buf);

    return BEV_OK;
}

// 使用：在 accept 回调中包装 bufferevent
static void accept_cb(struct evconnlistener *lev, evutil_socket_t fd,
                      struct sockaddr *addr, int socklen, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(lev);

    // 1. 创建底层（裸 socket）bufferevent
    struct bufferevent *underlying = bufferevent_socket_new(
        base, fd, BEV_OPT_CLOSE_ON_FREE);

    // 2. 在其上叠加 ROT13 过滤器（双向变换）
    struct bufferevent *bev = bufferevent_filter_new(
        underlying,
        rot13_filter,    // input filter：收到的数据做 ROT13
        rot13_filter,    // output filter：发出的数据做 ROT13
        BEV_OPT_CLOSE_ON_FREE,  // 释放时同时释放 underlying
        NULL, NULL);

    // 3. 应用层只看到 bev（filter 层），不感知底层
    bufferevent_setcb(bev, readcb, NULL, eventcb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}
```

### 2.6 flush 接口

```c
// 强制把 filter 中积压的数据推出
int bufferevent_flush(
    struct bufferevent *bufev,
    short iotype,                           // EV_READ 或 EV_WRITE
    enum bufferevent_flush_mode mode        // BEV_FLUSH 或 BEV_FINISH
);
```

当 filter 返回 `BEV_NEED_MORE` 积累数据时（如加密协议等待完整块），可用 `BEV_FINISH` 强制冲刷所有积压数据。

---

## 3. bufferevent_pair：进程内内存管道

### 3.1 基本概念

`bufferevent_pair` 创建两个互联的 bufferevent，无需 socket、pipe 或任何系统调用。写入 `pair[0]` 的数据可以从 `pair[1]` 读出，反之亦然：

```
pair[0] ←──→ pair[1]
 output        input
 input         output
（纯内存链表操作，O(1)，无系统调用）
```

典型用途：
- 同一进程内不同组件之间传递数据
- 配合 filter 链构建处理管道
- 单元测试：模拟网络连接，无需真实 socket

### 3.2 创建 pair

```c
// include/event2/bufferevent.h 第 776 行
int bufferevent_pair_new(
    struct event_base *base,
    int options,                        // BEV_OPT_* 标志
    struct bufferevent *pair[2]         // 输出：两个互联的 bufferevent
);
// 返回 0 成功，-1 失败

// 获取另一端（如果仍存在）
struct bufferevent *bufferevent_pair_get_partner(struct bufferevent *bev);
```

### 3.3 内部实现：共享锁与数据转移

`bufferevent_pair.c` 第 112~148 行 `bufferevent_pair_new` 的关键代码：

```c
int bufferevent_pair_new(struct event_base *base, int options,
    struct bufferevent *pair[2]) {

    // pair 强制使用 DEFER_CALLBACKS（防止回调重入）
    options |= BEV_OPT_DEFER_CALLBACKS;

    bufev1 = bufferevent_pair_elt_new(base, options);
    bufev2 = bufferevent_pair_elt_new(base, options & ~BEV_OPT_THREADSAFE);

    // 多线程时，两端共享同一把锁（避免死锁）
    if (options & BEV_OPT_THREADSAFE)
        bufferevent_enable_locking_(bufev2, bufev1->bev.lock);

    bufev1->partner = bufev2;
    bufev2->partner = bufev1;

    pair[0] = downcast(bufev1);
    pair[1] = downcast(bufev2);
    return 0;
}
```

**数据转移核心函数** `be_pair_transfer`（第 150~190 行）：

```c
static void be_pair_transfer(struct bufferevent *src,
                              struct bufferevent *dst, int ignore_wm)
{
    // 解冻 output/input 的冻结（pair 创建时冻结防止外部乱用）
    evbuffer_unfreeze(src->output, 1);
    evbuffer_unfreeze(dst->input, 0);

    if (dst->wm_read.high) {
        // 受高水位限制：只转移 dst 能接受的量
        n = dst->wm_read.high - evbuffer_get_length(dst->input);
        evbuffer_remove_buffer(src->output, dst->input, n);
    } else {
        // 无限制：O(1) 链表操作，直接把 src->output 所有链移给 dst->input
        evbuffer_add_buffer(dst->input, src->output);
    }

    // 触发 dst 的 readcb 和 src 的 writecb
    bufferevent_trigger_nolock_(dst, EV_READ, 0);
    bufferevent_trigger_nolock_(src, EV_WRITE, 0);

    evbuffer_freeze(src->output, 1);
    evbuffer_freeze(dst->input, 0);
}
```

数据转移是纯内存操作（evbuffer 链表拼接），不经过任何系统调用，延迟极低。

### 3.4 触发时机

`be_pair_outbuf_cb`（第 202~220 行）监听 output evbuffer 的变化：

```c
static void be_pair_outbuf_cb(struct evbuffer *outbuf,
    const struct evbuffer_cb_info *info, void *arg)
{
    if (info->n_added > info->n_deleted && partner) {
        // output 中有新数据 且 对端开着读 → 立即转移
        if (be_pair_wants_to_talk(bev_pair, partner))
            be_pair_transfer(downcast(bev_pair), downcast(partner), 0);
    }
}
```

**关键函数** `be_pair_wants_to_talk`（第 192~200 行）：三个条件缺一不可：

```c
static inline int be_pair_wants_to_talk(
    struct bufferevent_pair *src, struct bufferevent_pair *dst) {

    return (downcast(src)->enabled & EV_WRITE) &&  // src 启用了写
           (downcast(dst)->enabled & EV_READ) &&    // dst 启用了读
           !dst->bev.read_suspended &&              // dst 没有被挂起
           evbuffer_get_length(downcast(src)->output); // src 有数据
}
```

### 3.5 实战：进程内双向管道

```c
// pair_demo.c：用 bufferevent_pair 模拟两个"协程"互相通信

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <stdio.h>

static int round_count = 0;

// 角色 A：收到消息后回一条
static void a_readcb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *input = bufferevent_get_input(bev);
    char *line = evbuffer_readln(input, NULL, EVBUFFER_EOL_LF);
    if (!line) return;

    printf("[A] 收到: %s\n", line);
    free(line);

    if (++round_count < 5) {
        struct evbuffer *output = bufferevent_get_output(bev);
        evbuffer_add_printf(output, "A says round %d\n", round_count);
    } else {
        // 5 轮后关闭
        struct event_base *base = ctx;
        event_base_loopbreak(base);
    }
}

// 角色 B：收到消息后回一条
static void b_readcb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *input = bufferevent_get_input(bev);
    char *line = evbuffer_readln(input, NULL, EVBUFFER_EOL_LF);
    if (!line) return;

    printf("[B] 收到: %s\n", line);
    free(line);

    struct evbuffer *output = bufferevent_get_output(bev);
    evbuffer_add_printf(output, "B says round %d\n", round_count);
}

int main(void) {
    struct event_base *base = event_base_new();

    // 创建一对互联的 bufferevent
    struct bufferevent *pair[2];
    bufferevent_pair_new(base, 0, pair);

    // pair[0] = 角色 A，pair[1] = 角色 B
    bufferevent_setcb(pair[0], a_readcb, NULL, NULL, base);
    bufferevent_setcb(pair[1], b_readcb, NULL, NULL, NULL);
    bufferevent_enable(pair[0], EV_READ | EV_WRITE);
    bufferevent_enable(pair[1], EV_READ | EV_WRITE);

    // A 先发一条消息
    bufferevent_write(pair[0], "A says round 0\n", 15);

    event_base_dispatch(base);

    bufferevent_free(pair[0]);
    bufferevent_free(pair[1]);
    event_base_free(base);
    return 0;
}
```

---

## 4. 限速（Rate Limiting）：令牌桶算法

### 4.1 令牌桶原理

libevent 的限速基于**令牌桶（Token Bucket）**算法：

```
令牌桶示意图：

每个 tick（默认 1 秒）自动补充 rate 个令牌
最多持有 burst 个令牌（上限）

读/写数据时消耗令牌：
  消耗 n 字节 = 消耗 n 个读/写令牌
  桶空了 → 暂停 IO，等下一个 tick 补充
```

**rate vs burst 的区别**：

```
read_rate  = 1024 字节/tick（每秒平均最多读 1KB）
read_burst = 4096 字节/tick（单 tick 内最多爆发读 4KB）

效果：长期平均速率 ≤ 1KB/s，短暂爆发允许 4KB/s
```

### 4.2 令牌桶实现分析

`bufferevent_ratelim.c` 第 49~111 行：

```c
// 初始化：桶的初始令牌量 = rate（不是 burst）
int ev_token_bucket_init_(struct ev_token_bucket *bucket,
    const struct ev_token_bucket_cfg *cfg,
    ev_uint32_t current_tick, int reinitialize)
{
    if (reinitialize) {
        // 重新配置时：只能向下截断（不能凭空增加令牌）
        if (bucket->read_limit > cfg->read_maximum)
            bucket->read_limit = cfg->read_maximum;
    } else {
        bucket->read_limit  = cfg->read_rate;   // 初始 = 速率
        bucket->write_limit = cfg->write_rate;
        bucket->last_updated = current_tick;
    }
}

// 每个 tick 更新：增加令牌（带溢出保护）
int ev_token_bucket_update_(struct ev_token_bucket *bucket,
    const struct ev_token_bucket_cfg *cfg, ev_uint32_t current_tick)
{
    unsigned n_ticks = current_tick - bucket->last_updated;
    if (n_ticks == 0 || n_ticks > INT_MAX) return 0;

    // 防溢出写法（相比 bucket->limit += n_ticks * rate 更安全）
    if ((cfg->read_maximum - bucket->read_limit) / n_ticks < cfg->read_rate)
        bucket->read_limit = cfg->read_maximum;   // 直接打满，不溢出
    else
        bucket->read_limit += n_ticks * cfg->read_rate;

    bucket->last_updated = current_tick;
    return 1;
}
```

**tick 的计算**（第 126~140 行）：

```c
ev_uint32_t ev_token_bucket_get_tick_(const struct timeval *tv,
    const struct ev_token_bucket_cfg *cfg)
{
    // tick = 毫秒时间 / 每 tick 毫秒数
    ev_uint64_t msec = (ev_uint64_t)tv->tv_sec * 1000 + tv->tv_usec / 1000;
    return (unsigned)(msec / cfg->msec_per_tick);
}
```

### 4.3 单 bufferevent 限速

```c
// 创建速率配置
struct ev_token_bucket_cfg *ev_token_bucket_cfg_new(
    size_t read_rate,    // 每 tick 平均读字节数
    size_t read_burst,   // 每 tick 最大读字节数（突发）
    size_t write_rate,   // 每 tick 平均写字节数
    size_t write_burst,  // 每 tick 最大写字节数
    const struct timeval *tick_len  // NULL = 默认 1 秒
);

void ev_token_bucket_cfg_free(struct ev_token_bucket_cfg *cfg);

// 设置/取消单个 bufferevent 的速率限制
int bufferevent_set_rate_limit(
    struct bufferevent *bev,
    struct ev_token_bucket_cfg *cfg  // NULL = 取消限速
);
```

**注意**：`ev_token_bucket_cfg` 不是引用计数的，在有 bufferevent 使用它时不能 free。

### 4.4 单 bufferevent 限速实战

```c
// 限制单个连接读写速率为 64KB/s（突发允许 128KB）
struct timeval one_sec = {1, 0};
struct ev_token_bucket_cfg *cfg = ev_token_bucket_cfg_new(
    64 * 1024,   // read_rate:  64KB/s
    128 * 1024,  // read_burst: 128KB/s
    64 * 1024,   // write_rate: 64KB/s
    128 * 1024,  // write_burst: 128KB/s
    &one_sec     // tick = 1 秒
);

struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
bufferevent_set_rate_limit(bev, cfg);  // 应用限速

// ... 正常使用 bev ...

// 清理（注意：先确保 bev 不再使用 cfg）
bufferevent_set_rate_limit(bev, NULL);  // 先解除
ev_token_bucket_cfg_free(cfg);
```

### 4.5 多 bufferevent 共享限速组

限速组让多个 bufferevent 共享一个总带宽配额，常用于实现总出口/入口带宽控制：

```c
// 创建限速组（base 用于内部定时器）
struct bufferevent_rate_limit_group *bufferevent_rate_limit_group_new(
    struct event_base *base,
    const struct ev_token_bucket_cfg *cfg
);

// 修改组的速率配置
int bufferevent_rate_limit_group_set_cfg(
    struct bufferevent_rate_limit_group *grp,
    const struct ev_token_bucket_cfg *cfg
);

// 设置每个 bev 单次分配的最小量（防止某个 bev 被饿死）
int bufferevent_rate_limit_group_set_min_share(
    struct bufferevent_rate_limit_group *grp,
    size_t min_share
);

// 加入/退出组
int bufferevent_add_to_rate_limit_group(
    struct bufferevent *bev,
    struct bufferevent_rate_limit_group *grp
);
int bufferevent_remove_from_rate_limit_group(struct bufferevent *bev);

// 销毁组（必须先移出所有 bev）
void bufferevent_rate_limit_group_free(struct bufferevent_rate_limit_group *grp);
```

### 4.6 共享限速实战：服务器总带宽限制

```c
// bandwidth_server.c：限制所有连接合计最大 1MB/s 下行速率

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

struct server_ctx {
    struct event_base *base;
    struct bufferevent_rate_limit_group *grp;
};

static void readcb(struct bufferevent *bev, void *ctx) {
    // echo 回去（受到组限速的约束）
    struct evbuffer *input  = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);
    evbuffer_add_buffer(output, input);
}

static void eventcb(struct bufferevent *bev, short events, void *ctx) {
    struct server_ctx *sctx = ctx;
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_remove_from_rate_limit_group(bev);
        bufferevent_free(bev);
    }
}

static void accept_cb(struct evconnlistener *lev, evutil_socket_t fd,
                      struct sockaddr *addr, int socklen, void *ctx)
{
    struct server_ctx *sctx = ctx;

    struct bufferevent *bev = bufferevent_socket_new(
        sctx->base, fd, BEV_OPT_CLOSE_ON_FREE);

    // 加入共享限速组
    bufferevent_add_to_rate_limit_group(bev, sctx->grp);

    bufferevent_setcb(bev, readcb, NULL, eventcb, sctx);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

int main(void) {
    struct event_base *base = event_base_new();

    // 配置限速：总计 1MB/s 读写，突发允许 2MB
    struct timeval one_sec = {1, 0};
    struct ev_token_bucket_cfg *cfg = ev_token_bucket_cfg_new(
        1 * 1024 * 1024,  // read_rate
        2 * 1024 * 1024,  // read_burst
        1 * 1024 * 1024,  // write_rate
        2 * 1024 * 1024,  // write_burst
        &one_sec
    );

    struct bufferevent_rate_limit_group *grp =
        bufferevent_rate_limit_group_new(base, cfg);

    // 组内每个 bev 单次最少分配 4KB（防止小连接被饿死）
    bufferevent_rate_limit_group_set_min_share(grp, 4096);

    struct server_ctx sctx = { base, grp };

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9999);

    struct evconnlistener *lev = evconnlistener_new_bind(
        base, accept_cb, &sctx,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr *)&sin, sizeof(sin));

    event_base_dispatch(base);

    bufferevent_rate_limit_group_free(grp);
    ev_token_bucket_cfg_free(cfg);
    evconnlistener_free(lev);
    event_base_free(base);
    return 0;
}
```

### 4.7 查询当前速率限制状态

```c
// 查询单个 bufferevent 的剩余令牌
ev_ssize_t bufferevent_get_read_limit(struct bufferevent *bev);
ev_ssize_t bufferevent_get_write_limit(struct bufferevent *bev);

// 查询组的剩余令牌
ev_ssize_t bufferevent_rate_limit_group_get_read_limit(
    struct bufferevent_rate_limit_group *grp);
ev_ssize_t bufferevent_rate_limit_group_get_write_limit(
    struct bufferevent_rate_limit_group *grp);

// 手动减少令牌（用于计量非 bufferevent 产生的流量）
int bufferevent_decrement_read_limit(struct bufferevent *bev, ev_ssize_t decr);
int bufferevent_decrement_write_limit(struct bufferevent *bev, ev_ssize_t decr);

// 查询累计读写字节数（统计用）
void bufferevent_rate_limit_group_get_totals(
    struct bufferevent_rate_limit_group *grp,
    ev_uint64_t *total_read_out, ev_uint64_t *total_written_out);
```

---

## 5. filter + pair 组合：构建处理管道

```
网络数据流
   ↓
bufferevent_socket（raw socket IO）
   ↓
bufferevent_filter（解压缩：zlib inflate）
   ↓
bufferevent_filter（解密：AES decrypt）
   ↓
bufferevent_pair[0]  ←→  bufferevent_pair[1]
                          ↓
                      应用层处理逻辑
```

```c
// 构建两层 filter 管道的示意代码
struct bufferevent *raw_bev = bufferevent_socket_new(base, fd,
    BEV_OPT_CLOSE_ON_FREE);

// 第一层：解密
struct bufferevent *decrypt_bev = bufferevent_filter_new(
    raw_bev,
    decrypt_input_filter,   // 收到数据 → 解密
    encrypt_output_filter,  // 发送数据 → 加密
    BEV_OPT_CLOSE_ON_FREE,
    decrypt_ctx_free, decrypt_ctx);

// 第二层：解压
struct bufferevent *decomp_bev = bufferevent_filter_new(
    decrypt_bev,
    decompress_filter,      // 收到数据 → 解压
    compress_filter,        // 发送数据 → 压缩
    BEV_OPT_CLOSE_ON_FREE,
    NULL, NULL);

// 应用层只操作最顶层 decomp_bev
bufferevent_setcb(decomp_bev, app_readcb, NULL, app_eventcb, NULL);
bufferevent_enable(decomp_bev, EV_READ | EV_WRITE);
```

---

## 6. 动手实践

### 练习 1：实现 Base64 编码过滤器

实现一个 filter，接收原始数据输出 Base64 编码（输出方向），接收 Base64 解码输出原始数据（输入方向）：

```c
// 提示：
// 输出 filter：每 3 字节 → 4 个 Base64 字符 + 换行
// 输入 filter：每 4 个 Base64 字符 → 3 字节
// 注意 BEV_NEED_MORE：当 src 数据不足 3/4 字节时返回
```

### 练习 2：用 bufferevent_pair 做单元测试

不需要 TCP 连接，用 pair 测试你的协议解析逻辑：

```c
// 提示：
struct bufferevent *pair[2];
bufferevent_pair_new(base, 0, pair);
// pair[0] 模拟"网络端"，pair[1] 模拟"应用端"
// 向 pair[0] 写数据，在 pair[1] 的 readcb 中验证解析结果
```

### 练习 3：测量限速效果

```bash
# 编译限速服务器后，用 iperf 测量实际带宽
iperf3 -c 127.0.0.1 -p 9999
# 观察：实际带宽是否接近设定的 1MB/s？
```

---

## 7. 本课小结

| 特性 | 用途 | 关键 API |
|------|------|----------|
| `bufferevent_filter` | 数据变换：加密、压缩、编解码 | `bufferevent_filter_new` |
| filter 回调返回值 | 控制数据流 | `BEV_OK` / `BEV_NEED_MORE` / `BEV_ERROR` |
| flush mode | 控制积压数据的冲刷力度 | `BEV_NORMAL` / `BEV_FLUSH` / `BEV_FINISH` |
| `bufferevent_pair` | 进程内内存管道，无 fd 无系统调用 | `bufferevent_pair_new` |
| pair 数据转移 | O(1) evbuffer 链表操作 | `be_pair_transfer` 内部 |
| 令牌桶限速 | 控制单个或多个 bev 的带宽 | `ev_token_bucket_cfg_new` |
| 限速组 | 多个 bev 共享总带宽配额 | `bufferevent_rate_limit_group_new` |

**三句话总结**：

1. filter 是叠加层：在底层 bufferevent 上透明地变换数据，支持链式叠加构成管道
2. pair 是内存管道：纯 evbuffer 链表操作，无 fd、无系统调用，适合进程内通信和单元测试
3. 限速用令牌桶：rate 控制平均速率，burst 允许突发，group 实现多连接共享带宽

---

## 附：filter 回调编写注意事项

1. **必须消费 src 中的数据**：如果 `process_in` 返回 `BEV_OK` 但没有 `evbuffer_remove`/`evbuffer_drain` src，会死循环。

2. **BEV_NEED_MORE 的正确使用**：
   ```c
   // 示例：需要积累够 4 字节才能解码
   if (evbuffer_get_length(src) < 4)
       return BEV_NEED_MORE;   // 不消费 src，等更多数据到来
   ```

3. **dst_limit 的遵守**：如果忽略 dst_limit，可能导致写入 dst 的数据超过高水位，触发不必要的流量控制。

4. **flush 时的处理**：`BEV_FINISH` 模式下，即使 src 不足以完成一个完整的处理单元，也应尽量输出已处理的部分，并返回 `BEV_OK`（而不是 `BEV_NEED_MORE`）。

---

**下一课预告**：第 9 课深入 `evconnlistener` —— TCP 监听器的内部实现、多端口监听、accept 错误处理，以及 `evutil` 网络工具函数的完整使用指南。
