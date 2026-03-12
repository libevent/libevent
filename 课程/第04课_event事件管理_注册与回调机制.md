# 第 4 课：event 事件管理 —— 注册、激活、回调机制

> **前置要求**：完成第 3 课，理解 event_base 的生命周期和事件循环流程
> **本课目标**：掌握 struct event 的完整生命周期，理解事件从注册到回调触发的全链路

---

## 1. 从一个问题出发

第 3 课我们知道 `event_base_loop()` 内部会调用 `event_process_active()` 执行就绪事件的回调。但这个过程中有几个问题还没有回答：

1. `event_new()` 创建的 event 到底存在哪里？
2. `event_add()` 之后，libevent 怎么知道要监听哪个 fd 的哪种事件？
3. epoll 报告某个 fd 可读时，libevent 如何找到对应的回调函数？
4. `EV_PERSIST` 和普通事件有什么本质区别？

本课从 `struct event` 的内部结构出发，沿着 `event_new → event_add → 触发 → 回调 → event_del` 这条主线，逐一回答这些问题。

---

## 2. 事件标志（EV_* flags）

在注册事件之前，先要理解可以监听什么类型的事件。

`include/event2/event.h` 第 946~1000 行定义了所有事件标志：

```c
// 基础 IO 事件
#define EV_TIMEOUT   0x01   // 超时（通常隐式，通过 event_add 的 timeout 参数）
#define EV_READ      0x02   // fd 可读（或有新连接）
#define EV_WRITE     0x04   // fd 可写
#define EV_SIGNAL    0x08   // 信号到来（此时 ev_fd 存放信号号，非 fd）
#define EV_PERSIST   0x10   // 持久事件：触发后自动重新注册，否则触发一次即删除
#define EV_ET        0x20   // 边缘触发（需后端支持 EV_FEATURE_ET）
#define EV_FINALIZE  0x40   // 安全释放标志（见第 9 节）
#define EV_CLOSED    0x80   // 连接关闭事件（需后端支持 EV_FEATURE_EARLY_CLOSE）
```

### 2.1 标志组合规则

```c
// 常见合法组合
EV_READ                     // 一次性读事件
EV_READ  | EV_PERSIST       // 持久读事件（每次可读都触发）
EV_WRITE | EV_PERSIST       // 持久写事件
EV_READ  | EV_WRITE         // 同时监听读和写（共享同一回调）
EV_SIGNAL| EV_PERSIST       // 持久信号监听（通常加 PERSIST）
EV_READ  | EV_ET            // 边缘触发读（需确保一次读完）

// 不合法组合（运行时会报错）
EV_READ  | EV_SIGNAL        // 不能同时是 IO 和信号事件
EV_TIMEOUT                  // 不能直接传给 event_new，通过 event_add 的 timeout 参数控制
```

### 2.2 EV_PERSIST 的关键含义

没有 `EV_PERSIST` 的事件触发一次后会自动从 event_base 中删除（但对象本身不释放）。这是 libevent 的默认行为——**"一次性通知"**。

```
没有 PERSIST：
  event_add() → 等待 → fd 可读 → 触发回调 → 自动 event_del → 不再监听

有 PERSIST：
  event_add() → 等待 → fd 可读 → 触发回调 → 自动 event_add → 继续等待 → ...
```

对于定时器（timer），`EV_PERSIST` 的行为稍有不同——下一节会详细说明。

---

## 3. struct event 内部结构解析

`include/event2/event_struct.h` 第 123 行定义了 `struct event`。**应用代码不应直接访问其字段**，但理解它是读懂 libevent 源码的关键：

```c
struct event {
    // ── 回调信息 ──────────────────────────────────────────────────
    struct event_callback ev_evcallback;
    // 展开后是：
    //   TAILQ_ENTRY(event_callback) evcb_active_next;  // 活跃队列链表节点
    //   short evcb_flags;                              // 状态标志 EVLIST_*
    //   ev_uint8_t evcb_pri;                           // 优先级（0 = 最高）
    //   ev_uint8_t evcb_closure;                       // 关闭类型（决定触发后行为）
    //   union { event_callback_fn evcb_callback; ... } // 实际回调函数指针
    //   void *evcb_arg;                                // 传给回调的参数

    // ── 定时器位置 ────────────────────────────────────────────────
    union {
        TAILQ_ENTRY(event) ev_next_with_common_timeout;
        size_t min_heap_idx;   // 在最小堆中的索引，-1 表示不在堆中
    } ev_timeout_pos;

    // ── fd / 信号号 ───────────────────────────────────────────────
    evutil_socket_t ev_fd;     // IO 事件：文件描述符
                               // 信号事件：信号号（如 SIGINT）
                               // 定时器事件：-1

    // ── 监听的事件类型 ────────────────────────────────────────────
    short ev_events;           // EV_READ | EV_WRITE | EV_SIGNAL | EV_PERSIST | EV_ET...
    short ev_res;              // 本次触发的具体事件（传给回调的 events 参数）

    // ── 所属的 event_base ─────────────────────────────────────────
    struct event_base *ev_base;

    // ── 链表节点（IO 链表 或 信号链表）──────────────────────────────
    union {
        struct {
            LIST_ENTRY(event) ev_io_next;  // 同一 fd 的事件链表节点
            struct timeval ev_timeout;     // 相对超时时间
        } ev_io;
        struct {
            LIST_ENTRY(event) ev_signal_next;
            short ev_ncalls;        // 信号触发时需要调用回调的次数
            short *ev_pncalls;
        } ev_signal;
    } ev_;

    // ── 超时（绝对时间）──────────────────────────────────────────
    struct timeval ev_timeout;  // 插入最小堆时转换为绝对时间
};
```

### 3.1 状态标志 EVLIST_*

`event_struct.h` 第 90 行定义了事件状态机的所有状态：

```c
#define EVLIST_TIMEOUT         0x01  // 在超时队列（最小堆）中
#define EVLIST_INSERTED        0x02  // 已注册到后端（通过 evmap）
#define EVLIST_SIGNAL          0x04  // 在信号列表中
#define EVLIST_ACTIVE          0x08  // 在活跃队列中（等待执行回调）
#define EVLIST_INTERNAL        0x10  // 内部使用（如 th_notify_fd 事件）
#define EVLIST_ACTIVE_LATER    0x20  // 延迟激活（不在当前轮次执行）
#define EVLIST_FINALIZING      0x40  // 正在执行 finalize 清理
#define EVLIST_INIT            0x80  // 已通过 event_assign/event_new 初始化
```

**事件状态转换图**：

```
                    event_assign/event_new
                           │
                           ▼
                     [EVLIST_INIT]
                           │
                    event_add()
                     ┌─────┴────────────────────────────┐
                     ▼                                   ▼
              [EVLIST_INSERTED]                  [EVLIST_TIMEOUT]
              （向后端注册 fd）                 （插入最小堆）
                     │                                   │
              fd 就绪时                         超时到期时
              后端调用 evmap_io_active_         timeout_process()
                     │                                   │
                     └──────────────┬────────────────────┘
                                    ▼
                            [EVLIST_ACTIVE]
                            （加入活跃队列）
                                    │
                       event_process_active() 执行回调
                                    │
                    ┌───────────────┴───────────────┐
                    │  有 EV_PERSIST                 │  无 EV_PERSIST
                    ▼                               ▼
             重新加入 INSERTED/TIMEOUT          [EVLIST_INIT]
             （自动重注册）                      （已从各队列移除）
```

---

## 4. 事件的创建：event_new 与 event_assign

### 4.1 回调函数签名

所有事件的回调函数都遵循同一个签名：

```c
typedef void (*event_callback_fn)(evutil_socket_t fd, short events, void *arg);

// fd：触发事件的文件描述符（定时器为 -1，信号事件为信号号）
// events：实际触发的事件类型（EV_READ / EV_WRITE / EV_TIMEOUT / EV_SIGNAL）
// arg：注册时传入的用户数据
```

### 4.2 event_new —— 堆分配

```c
struct event *event_new(struct event_base *base, evutil_socket_t fd,
                        short events, event_callback_fn callback,
                        void *callback_arg);
```

`event.c` 第 1755 行的实现很简单：

```c
struct event *event_new(struct event_base *base, evutil_socket_t fd,
    short events, void (*cb)(evutil_socket_t, short, void *), void *arg)
{
    struct event *ev;
    ev = mm_malloc(sizeof(struct event));   // 堆分配
    if (ev == NULL)
        return (NULL);
    if (event_assign(ev, base, fd, events, cb, arg) < 0) {
        mm_free(ev);
        return (NULL);
    }
    return (ev);
}
```

`event_new` 只是 `mm_malloc` + `event_assign` 的封装。

### 4.3 event_assign —— 栈/自定义内存分配

```c
int event_assign(struct event *ev, struct event_base *base,
                 evutil_socket_t fd, short events,
                 event_callback_fn callback, void *callback_arg);
```

`event_assign` 适合将 event 嵌入其他结构体，避免额外的堆分配：

```c
// event_assign 的实际用途：把 event 嵌入连接结构体
struct connection {
    evutil_socket_t fd;
    struct event read_ev;    // 嵌入，不是指针
    struct event write_ev;   // 嵌入，不是指针
    char read_buf[4096];
};

struct connection *conn = malloc(sizeof(*conn));
event_assign(&conn->read_ev, base, conn->fd, EV_READ | EV_PERSIST, read_cb, conn);
event_assign(&conn->write_ev, base, conn->fd, EV_WRITE, write_cb, conn);
```

`event.c` 第 1715 行的 `event_assign` 核心逻辑：

```c
int event_assign(struct event *ev, struct event_base *base,
    evutil_socket_t fd, short events, void (*callback)(evutil_socket_t, short, void *), void *arg)
{
    // ... 参数校验 ...

    ev->ev_base = base;
    ev->ev_callback = callback;
    ev->ev_arg = arg;
    ev->ev_fd = fd;
    ev->ev_events = events;
    ev->ev_res = 0;
    ev->ev_flags = EVLIST_INIT;          // 初始状态
    ev->ev_ncalls = 0;
    ev->ev_pncalls = NULL;

    // 设置关闭类型（决定触发后的行为）
    if (events & EV_SIGNAL) {
        if ((events & (EV_READ|EV_WRITE|EV_CLOSED)) != 0) {
            // 信号事件不能同时是 IO 事件
            return -1;
        }
        ev->ev_closure = EV_CLOSURE_EVENT_SIGNAL;
    } else {
        if (events & EV_PERSIST) {
            evutil_timerclear(&ev->ev_io_timeout);
            ev->ev_closure = EV_CLOSURE_EVENT_PERSIST;  // 持久事件
        } else {
            ev->ev_closure = EV_CLOSURE_EVENT;          // 一次性事件
        }
    }

    min_heap_elem_init_(ev);    // 初始化最小堆索引为 -1（不在堆中）
    ev->ev_priority = base->nactivequeues / 2;  // 默认优先级：中间

    return 0;
}
```

关键字段 `ev_closure` 的三种取值：

| `ev_closure` 值 | 触发后行为 |
|----------------|-----------|
| `EV_CLOSURE_EVENT` | 一次性：触发后从各队列移除，不重注册 |
| `EV_CLOSURE_EVENT_PERSIST` | 持久：触发后调用 `event_persist_closure`，自动重注册 |
| `EV_CLOSURE_EVENT_SIGNAL` | 信号：多次触发累积，批量处理 |

### 4.4 event_self_cbarg —— 将事件自身作为参数

```c
void *event_self_cbarg(void);
```

这是个特殊魔法值，用于把事件自身的指针作为 `callback_arg`：

```c
// 在 event_read_fifo.c 中的用法
static void fifo_read(evutil_socket_t fd, short event, void *arg)
{
    struct event *ev = arg;  // arg 就是事件自身
    // ...
    event_add(ev, NULL);
}

// 创建时使用 event_self_cbarg()
struct event *ev = event_new(base, fd, EV_READ,
                             fifo_read, event_self_cbarg());
// event_self_cbarg() 返回一个特殊哨兵值
// event_new 内部识别到这个哨兵值，会把 ev 自身的地址填入 ev_arg
```

`event.c` 中的实现（大约第 1789 行）：

```c
void *event_self_cbarg(void) {
    return &event_self_cbarg;   // 返回自身函数地址作为哨兵值
}

// event_new 中的特殊处理：
if (callback_arg == &event_self_cbarg)
    ev->ev_arg = ev;   // 把事件自身赋值为参数
```

---

## 5. 事件的注册：event_add 深度解析

```c
int event_add(struct event *ev, const struct timeval *timeout);
// timeout：NULL 表示永不超时；非 NULL 表示超时时间（相对时间）
// 返回：0 成功，-1 失败
```

### 5.1 整体流程

`event.c` 中 `event_add` 调用 `event_add_nolock_`，核心逻辑（第 2628 行起）：

```c
static int event_add_nolock_(struct event *ev, const struct timeval *tv,
    int tv_is_absolute)
{
    struct event_base *base = ev->ev_base;
    int res = 0;

    // ── 步骤 1：向后端注册 fd ─────────────────────────────────────
    if ((ev->ev_events & (EV_READ|EV_WRITE|EV_CLOSED|EV_SIGNAL)) &&
        !(ev->ev_flags & (EVLIST_INSERTED|EVLIST_ACTIVE|EVLIST_ACTIVE_LATER))) {
        // 还未注册到后端，执行注册
        if (ev->ev_events & EV_SIGNAL)
            res = evmap_signal_add_(base, (int)ev->ev_fd, ev);
        else
            res = evmap_io_add_(base, ev->ev_fd, ev);
        // evmap_io_add_ 内部调用 epoll_ctl(EPOLL_CTL_ADD)

        if (res != -1)
            event_queue_insert_inserted(base, ev);  // 标记为 EVLIST_INSERTED
    }

    // ── 步骤 2：处理超时 ─────────────────────────────────────────
    if (res != -1 && tv != NULL) {
        struct timeval now;
        // 计算绝对超时时间
        gettime(base, &now);
        evutil_timeradd(&now, tv, &ev->ev_timeout);
        // 插入最小堆或 common timeout 链表
        event_queue_insert_timeout(base, ev);  // 标记为 EVLIST_TIMEOUT
    }

    // ── 步骤 3：唤醒事件循环 ────────────────────────────────────
    // 如果这是从其他线程调用，需要唤醒 epoll_wait
    if (res != -1 && notify)
        evthread_notify_base(base);

    return (res < 0) ? -1 : 0;
}
```

### 5.2 evmap_io_add_：fd 到 event 的映射

`evmap.c` 第 213 行实现了 `evmap_io_add_`：

```c
// 每个 fd 在 io map 中对应一个 evmap_io 结构
struct evmap_io {
    struct event_dlist events;  // 监听这个 fd 的所有事件（链表）
    ev_uint16_t nread;          // 监听 EV_READ 的事件数量
    ev_uint16_t nwrite;         // 监听 EV_WRITE 的事件数量
    ev_uint16_t nclose;         // 监听 EV_CLOSED 的事件数量
};

int evmap_io_add_(struct event_base *base, evutil_socket_t fd, struct event *ev)
{
    // 获取（或创建）这个 fd 对应的 evmap_io
    GET_IO_SLOT_AND_CTOR(ctx, map, fd, evmap_io, evmap_io_init, base->evsignal.sh_signalfd);

    // 记录变化前的状态
    old_ev = 0;
    if (ctx->nread)  old_ev |= EV_READ;
    if (ctx->nwrite) old_ev |= EV_WRITE;
    if (ctx->nclose) old_ev |= EV_CLOSE;

    // 更新引用计数
    if (ev->ev_events & EV_READ)  ++ctx->nread;
    if (ev->ev_events & EV_WRITE) ++ctx->nwrite;
    if (ev->ev_events & EV_CLOSED) ++ctx->nclose;

    // 计算新状态
    new_ev = 0;
    if (ctx->nread)  new_ev |= EV_READ;
    if (ctx->nwrite) new_ev |= EV_WRITE;
    if (ctx->nclose) new_ev |= EV_CLOSE;

    // 只有状态变化时才调用后端（减少系统调用）
    if (new_ev != old_ev) {
        if (base->evsel->add(base, fd, old_ev, new_ev, extra) == -1)
            return -1;
        // 最终调用 epoll_ctl(EPOLL_CTL_ADD) 或 epoll_ctl(EPOLL_CTL_MOD)
    }

    // 把 event 插入这个 fd 的事件链表
    LIST_INSERT_HEAD(&ctx->events, ev, ev_.ev_io.ev_io_next);
    return 0;
}
```

**引用计数的意义**：同一个 fd 可以被多个 event 监听。只有第一个 `EV_READ` event 注册时才调用 `epoll_ctl(ADD)`，后续的只是增加计数。这避免了重复的 `epoll_ctl` 调用。

```
fd=5 的 evmap_io：
  nread = 2   ← 两个事件都监听 EV_READ
  nwrite = 1  ← 一个事件监听 EV_WRITE
  events → [event_A(READ)] → [event_B(READ|WRITE)]

  epoll 中 fd=5 的状态：EPOLLIN | EPOLLOUT（已合并）
```

### 5.3 超时事件的存储

带 timeout 的 `event_add` 会将 event 插入最小堆（`event_queue_insert_timeout`，`event.c` 第 2960 行）：

```c
// 最小堆存储绝对超时时间
// event_base_loop 每轮循环调用 timeout_next() 计算到期时间
// 然后以此作为 epoll_wait 的 timeout 参数

// 最小堆顶 = 最近要到期的事件
// epoll_wait 超时后，timeout_process() 处理到期事件
```

---

## 6. 事件触发：从 epoll_wait 到回调

完整的触发链路：

```
epoll_wait 返回（有 fd 就绪）
  │
  ▼
epoll_dispatch()（epoll.c 第 413 行）
  │  遍历 epoll_wait 返回的就绪事件数组
  │
  ▼
evmap_io_active_(base, fd, res)（evmap.c 第 330 行）
  │  根据 fd 查找 evmap_io，遍历该 fd 的所有事件
  │
  ▼
event_active_nolock_(ev, res, 1)（event.c 第 3141 行）
  │  ev->ev_res = res（记录触发原因）
  │  event_queue_insert_active(base, ev)
  │    → ev->ev_flags |= EVLIST_ACTIVE
  │    → 按优先级加入 base->activequeues[ev->ev_priority]
  │
  ▼
event_process_active()（event.c 第 1553 行）
  │  遍历 activequeues，从最高优先级开始
  │
  ▼
event_process_active_single_queue()（event.c 第 1494 行）
  │
  ├── 根据 ev_closure 决定行为：
  │
  ├── EV_CLOSURE_EVENT（一次性）：
  │     event_del_nolock_()   先删除
  │     (*callback)(fd, res, arg)  再执行回调
  │
  ├── EV_CLOSURE_EVENT_PERSIST（持久）：
  │     event_persist_closure()
  │       如果是定时器：重新计算下次触发时间并 event_add
  │       (*callback)(fd, res, arg)
  │
  └── EV_CLOSURE_EVENT_SIGNAL（信号）：
        处理 ncalls 次重复信号
        (*callback)(fd, res, arg)
```

### 6.1 evmap_io_active_：fd 到多个回调

`evmap.c` 第 330 行的 `evmap_io_active_`：

```c
void evmap_io_active_(struct event_base *base, evutil_socket_t fd, short events)
{
    struct evmap_io *ctx;
    struct event *ev;

    // 获取这个 fd 对应的 evmap_io
    GET_IO_SLOT(ctx, &base->io, fd, evmap_io);

    // 遍历监听这个 fd 的所有 event
    LIST_FOREACH(ev, &ctx->events, ev_.ev_io.ev_io_next) {
        // 只激活感兴趣的事件
        if (ev->ev_events & events)
            event_active_nolock_(ev, ev->ev_events & events, 1);
    }
}
```

这就是为什么同一个 fd 可以有多个 event 同时监听：每个 event 都会被独立激活。

### 6.2 EV_PERSIST 定时器的特殊处理

`event.c` 第 1464 行的 `event_persist_closure`：

```c
static void event_persist_closure(struct event_base *base, struct event *ev)
{
    // 对于持久定时器，重新计算下一次触发时间
    if (ev->ev_io_timeout.tv_sec || ev->ev_io_timeout.tv_usec) {
        // 基于上次预期触发时间 + interval，而不是当前时间 + interval
        // 这避免了累积误差（抖动）
        struct timeval run_at, relative_to, delay, now;
        ev_uint32_t usec_mask = 0;

        gettime(base, &now);
        // 计算下次触发的绝对时间
        evutil_timeradd(&ev->ev_timeout, &ev->ev_io_timeout, &run_at);

        // 如果已经过期，则立即再次触发
        if (evutil_timercmp(&run_at, &now, <)) {
            evutil_timeradd(&now, &ev->ev_io_timeout, &run_at);
        }

        event_add_nolock_(ev, &run_at, 1);  // 重新加入最小堆
    }

    // 执行回调
    (*ev->ev_evcallback.evcb_callback)(ev->ev_fd, ev->ev_res, ev->ev_evcallback.evcb_arg);
}
```

**关键**：持久定时器基于"上次预期时间 + 间隔"而非"当前时间 + 间隔"，从而避免累积漂移。

---

## 7. 事件的注销：event_del

```c
int event_del(struct event *ev);
int event_del_block(struct event *ev);  // 等待正在执行的回调完成后再删除
```

`event.c` 第 2870 行的 `event_del_nolock_` 核心逻辑：

```c
static int event_del_nolock_(struct event *ev, int blocking)
{
    struct event_base *base;

    // 未初始化的事件不能删除
    if (ev->ev_base == NULL)
        return (-1);

    base = ev->ev_base;

    // 从活跃队列移除
    if (ev->ev_flags & EVLIST_ACTIVE)
        event_queue_remove_active(base, event_to_event_callback(ev));
    else if (ev->ev_flags & EVLIST_ACTIVE_LATER)
        event_queue_remove_active_later(base, event_to_event_callback(ev));

    // 从超时堆移除
    if (ev->ev_flags & EVLIST_TIMEOUT)
        event_queue_remove_timeout(base, ev);

    // 从后端注销 fd
    if (ev->ev_flags & EVLIST_INSERTED) {
        event_queue_remove_inserted(base, ev);
        if (ev->ev_events & EV_SIGNAL)
            ret = evmap_signal_del_(base, (int)ev->ev_fd, ev);
        else
            ret = evmap_io_del_(base, ev->ev_fd, ev);
        // evmap_io_del_ 减少引用计数，计数为 0 时调用 epoll_ctl(DEL)
    }

    return (ret);
}
```

### 7.1 evmap_io_del_：引用计数递减

```c
// evmap.c: evmap_io_del_
// 减少 nread/nwrite，当计数归零时才通知后端

if (ev->ev_events & EV_READ)  --ctx->nread;
if (ev->ev_events & EV_WRITE) --ctx->nwrite;

// 如果某个方向的计数从非零变为零，需要更新 epoll
if (new_ev != old_ev) {
    if (new_ev == 0)
        base->evsel->del(base, fd, old_ev, 0, extra);  // epoll_ctl(DEL)
    else
        base->evsel->del(base, fd, old_ev, new_ev, extra);  // epoll_ctl(MOD)
}

// 从链表中移除
LIST_REMOVE(ev, ev_.ev_io.ev_io_next);
```

---

## 8. 手动激活事件：event_active

```c
void event_active(struct event *ev, int res, short ncalls);
// res：传给回调的 events 参数（EV_READ / EV_WRITE / EV_TIMEOUT）
// ncalls：信号事件专用，通常传 1
```

`event_active` 绕过后端，直接将事件加入活跃队列。常见用途：

```c
// 1. 在一个事件的回调中延迟触发另一个事件
// 2. 跨线程通知（但更推荐使用 event_base_once）
// 3. 单元测试中模拟事件触发

void some_callback(evutil_socket_t fd, short events, void *arg)
{
    struct event *next_ev = arg;
    // 处理完当前事件后，立即激活下一个
    event_active(next_ev, EV_READ, 1);
}
```

`event.c` 第 3126 行：

```c
void event_active(struct event *ev, int res, short ncalls)
{
    if (EVUTIL_FAILURE_CHECK(!ev->ev_base)) {
        event_warnx("%s: event has no event_base set.", __func__);
        return;
    }

    EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);
    event_debug_assert_is_setup_(ev);
    event_active_nolock_(ev, res, ncalls);
    EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);
}
```

---

## 9. event_finalize：多线程安全释放

在多线程环境下，普通的 `event_free` 不安全——事件可能正在另一个线程的 `event_process_active` 中执行回调。`event_finalize` 提供了安全的异步释放机制：

```c
int event_finalize(unsigned flags, struct event *ev, event_finalize_callback_fn cb);
int event_free_finalize(unsigned flags, struct event *ev, event_finalize_callback_fn cb);
// flags 目前只有 0
// cb：完成清理后的回调（在事件循环线程中调用）
// event_free_finalize 在 cb 返回后自动调用 event_free

// 回调签名
typedef void (*event_finalize_callback_fn)(struct event *, void *);
```

**工作原理**：

```c
// event_finalize 的过程：
// 1. 设置 EVLIST_FINALIZING 标志
// 2. 从所有队列中移除事件
// 3. 将 finalize 回调作为一个 EVLIST_ACTIVE_LATER 事件排入队列
// 4. 事件循环在下一轮调用 finalize 回调
// 5. 此时可以安全地调用 event_free

// 典型用法
void on_connection_close(struct bufferevent *bev, short events, void *ctx)
{
    struct my_conn *conn = ctx;
    event_free_finalize(0, conn->timer_ev, cleanup_callback);
}

void cleanup_callback(struct event *ev, void *arg) {
    // 此时 ev 已安全，可以访问关联资源
    struct my_conn *conn = arg;
    free(conn);
}
```

---

## 10. 事件状态查询

```c
// 检查事件是否处于某种等待状态
int event_pending(const struct event *ev, short events, struct timeval *tv);
// events：检查的标志（EV_READ | EV_WRITE | EV_TIMEOUT | EV_SIGNAL）
// tv：如果不为 NULL 且事件有超时，填入超时时间
// 返回值：实际处于等待状态的事件标志（0 表示不在等待状态）

// 示例
if (event_pending(ev, EV_READ, NULL)) {
    printf("fd 正在监听可读事件\n");
}

struct timeval tv;
if (event_pending(ev, EV_TIMEOUT, &tv)) {
    printf("将在 %ld.%06ld 秒后超时\n", tv.tv_sec, tv.tv_usec);
}
```

其他查询函数：

```c
int event_initialized(const struct event *ev);  // 是否已初始化（EVLIST_INIT）
evutil_socket_t event_get_fd(const struct event *ev);      // 获取 fd
struct event_base *event_get_base(const struct event *ev);  // 获取 base
short event_get_events(const struct event *ev);             // 获取注册的事件类型
event_callback_fn event_get_callback(const struct event *ev);
void *event_get_callback_arg(const struct event *ev);
int event_get_priority(const struct event *ev);
```

`event_pending` 的实现（`event.c` 第 2473 行）：

```c
int event_pending(const struct event *ev, short event, struct timeval *tv)
{
    int flags = 0;

    if (ev->ev_flags & EVLIST_INSERTED)
        flags |= (ev->ev_events & (EV_READ|EV_WRITE|EV_CLOSED|EV_SIGNAL));
    if (ev->ev_flags & EVLIST_ACTIVE)
        flags |= ev->ev_res;
    if (ev->ev_flags & EVLIST_TIMEOUT)
        flags |= EV_TIMEOUT;

    event &= (EV_TIMEOUT|EV_READ|EV_WRITE|EV_CLOSED|EV_SIGNAL);

    // 如果请求超时信息，填入超时时间
    if (tv != NULL && (flags & event & EV_TIMEOUT)) {
        struct timeval now;
        gettime(ev->ev_base, &now);
        evutil_timersub(&ev->ev_timeout, &now, tv);
        if (tv->tv_sec < 0) {
            tv->tv_sec = 0;
            tv->tv_usec = 0;
        }
    }

    return (flags & event);
}
```

---

## 11. 完整代码示例

### 11.1 官方示例：event-read-fifo.c 精读

`sample/event-read-fifo.c` 展示了事件的完整生命周期：

```c
#include <event2/event.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// 定义超时时间：5 秒
static const struct timeval FIVE_SECONDS = { 5, 0 };

// 从 FIFO 读取数据的回调
static void fifo_read(evutil_socket_t fd, short event, void *arg)
{
    char buf[255];
    int len;
    struct event *ev = arg;  // 通过 event_self_cbarg() 传入的自身

    // 处理超时
    if (event & EV_TIMEOUT) {
        printf("超时，退出\n");
        event_del(ev);
        return;
    }

    // 读取数据
    len = read(fd, buf, sizeof(buf) - 1);
    if (len <= 0) {
        if (len == 0) {
            printf("FIFO 关闭，退出\n");
        } else {
            perror("read");
        }
        event_del(ev);
        return;
    }

    buf[len] = '\0';
    printf("读到: %s", buf);

    // 重新添加事件（带超时）
    // 注意：EV_PERSIST + 超时时，每次触发后超时会自动重置
    event_add(ev, &FIVE_SECONDS);
}

int main(int argc, char **argv)
{
    struct event_base *base;
    struct event *ev;
    int fd;

    if (argc != 2) {
        fprintf(stderr, "用法: %s <fifo_path>\n", argv[0]);
        return 1;
    }

    // 打开 FIFO（非阻塞）
    fd = open(argv[1], O_RDONLY | O_NONBLOCK, 0);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // 创建 event_base
    base = event_base_new();

    // 创建读事件，用 event_self_cbarg() 把 ev 自身作为参数
    ev = event_new(base, fd, EV_READ | EV_PERSIST,
                   fifo_read, event_self_cbarg());
    // 注意：虽然用了 EV_PERSIST，但每次回调手动调用 event_add
    // 因为我们要重置超时时间

    // 注册事件，设置 5 秒超时
    event_add(ev, &FIVE_SECONDS);

    // 启动事件循环
    event_base_dispatch(base);

    // 清理
    event_free(ev);
    event_base_free(base);
    close(fd);
    return 0;
}
```

编译和运行：

```bash
mkfifo /tmp/myfifo
gcc event_read_fifo.c -I/root/libevent/include \
    -L/root/libevent/build/lib -levent -o event_read_fifo
LD_LIBRARY_PATH=/root/libevent/build/lib ./event_read_fifo /tmp/myfifo &

# 另一个终端写入数据
echo "hello libevent" > /tmp/myfifo
echo "second message" > /tmp/myfifo

# 5 秒不写入数据 → 超时退出
```

### 11.2 多事件监听同一 fd

```c
#include <event2/event.h>
#include <stdio.h>
#include <unistd.h>

// 两个 event 监听同一个 fd 的 EV_READ
void read_cb_1(evutil_socket_t fd, short events, void *arg)
{
    char buf[64];
    int n = read(fd, buf, sizeof(buf));
    if (n > 0) buf[n] = '\0';
    printf("[回调1] 读到: %s\n", n > 0 ? buf : "(empty)");
}

void read_cb_2(evutil_socket_t fd, short events, void *arg)
{
    printf("[回调2] 同一个 fd 也触发了\n");
    // 注意：read_cb_1 已经读走了数据，这里可能读到 EAGAIN
}

int main(void)
{
    struct event_base *base = event_base_new();

    // stdin (fd=0) 的两个监听者
    struct event *ev1 = event_new(base, STDIN_FILENO, EV_READ | EV_PERSIST,
                                  read_cb_1, NULL);
    struct event *ev2 = event_new(base, STDIN_FILENO, EV_READ | EV_PERSIST,
                                  read_cb_2, NULL);

    event_add(ev1, NULL);
    event_add(ev2, NULL);

    // evmap_io 中 fd=0 的状态：
    //   nread = 2（两个事件都监听 READ）
    //   epoll 中 fd=0：EPOLLIN（只注册一次）
    //   events 链表: [ev2] → [ev1]（头插法）

    event_base_dispatch(base);

    event_free(ev1);
    event_free(ev2);
    event_base_free(base);
    return 0;
}
```

### 11.3 完整的定时器示例

```c
#include <event2/event.h>
#include <stdio.h>
#include <time.h>

// 每 1 秒打印一次时间的持久定时器
void timer_cb(evutil_socket_t fd, short events, void *arg)
{
    time_t now = time(NULL);
    printf("[持久定时器] %s", ctime(&now));
    // EV_PERSIST 定时器：自动重新等待，无需手动 event_add
}

// 5 秒后退出的一次性定时器
void exit_timer_cb(evutil_socket_t fd, short events, void *arg)
{
    struct event_base *base = arg;
    printf("[退出定时器] 5 秒到，退出事件循环\n");
    event_base_loopbreak(base);
}

int main(void)
{
    struct event_base *base = event_base_new();

    // 持久定时器：每 1 秒触发
    struct timeval one_sec = { 1, 0 };
    struct event *tick = event_new(base, -1, EV_PERSIST, timer_cb, NULL);
    event_add(tick, &one_sec);

    // 一次性定时器：5 秒后退出
    struct timeval five_sec = { 5, 0 };
    struct event *timeout = event_new(base, -1, 0, exit_timer_cb, base);
    event_add(timeout, &five_sec);

    printf("启动事件循环，每秒打印时间，5秒后退出...\n");
    event_base_dispatch(base);

    event_free(tick);
    event_free(timeout);
    event_base_free(base);
    return 0;
}
```

---

## 12. 事件优先级设置

```c
int event_priority_set(struct event *ev, int priority);
// priority：0 = 最高优先级，nactivequeues-1 = 最低优先级
// 必须在 event_add 之前调用（事件未激活时）
// 默认优先级：nactivequeues / 2（中间）
```

使用场景：

```c
// 创建高优先级事件（处理控制命令）
struct event *cmd_ev = event_new(base, cmd_fd, EV_READ | EV_PERSIST, cmd_cb, NULL);
event_priority_set(cmd_ev, 0);   // 最高优先级
event_add(cmd_ev, NULL);

// 创建低优先级事件（处理普通数据）
struct event *data_ev = event_new(base, data_fd, EV_READ | EV_PERSIST, data_cb, NULL);
event_priority_set(data_ev, 2);  // 较低优先级
event_add(data_ev, NULL);

// 如果两者同时就绪，cmd_ev 的回调先执行
```

---

## 13. 实践练习

### 练习 1：观察事件状态变化

```c
// 编写程序，在以下时刻打印事件的 event_pending() 状态：
// 1. event_new() 之后
// 2. event_add() 之后
// 3. 在回调函数中
// 4. 回调函数返回后（无 EV_PERSIST）
// 5. event_del() 之后
```

### 练习 2：实现 echo server（不使用 bufferevent）

```c
// 要求：
// - evconnlistener 接收连接
// - 为每个连接创建 EV_READ | EV_PERSIST 事件
// - 在读回调中：read() 数据后立即 write() 回去
// - 客户端断开时（read() 返回 0）：event_del + close(fd)
// 目标：理解 EV_PERSIST 在 IO 事件中的用法
```

### 练习 3：超时检测

```c
// 实现连接空闲超时机制：
// - 服务器接受连接，注册 EV_READ | EV_PERSIST 事件，超时 10 秒
// - 每次有数据到来时，重新调用 event_add(ev, &timeout) 重置超时
// - 10 秒无数据 → 触发超时（events & EV_TIMEOUT）→ 关闭连接
// 关键点：同一个 event 可以同时有 EV_READ 和 EV_TIMEOUT
```

### 练习 4：阅读源码，回答问题

阅读 `event.c` 和 `evmap.c`，思考：

1. 如果对同一个 fd 先 `event_add(ev1, NULL)`，再 `event_add(ev2, NULL)`，epoll 会被调用几次 `EPOLL_CTL_ADD`？
2. `event_del(ev1)` 之后，fd 的监听状态如何变化？
3. `EV_PERSIST` 定时器和非 PERSIST 定时器，在 `event_persist_closure` 中的区别是什么？
4. 为什么 `event_del` 需要检查 `EVLIST_ACTIVE`？

---

## 14. 本课小结

| 概念 | 核心要点 |
|------|---------|
| `struct event` | 封装 fd/信号号、事件类型、回调、超时、所属 base |
| `EVLIST_*` 状态标志 | INIT → (INSERTED + TIMEOUT) → ACTIVE → INIT |
| `EV_PERSIST` | 触发后自动重注册（通过 `EV_CLOSURE_EVENT_PERSIST`）|
| `event_new` | 堆分配，内部调用 `event_assign` |
| `event_assign` | 核心初始化，设置 `ev_closure`，适用于嵌入式 event |
| `event_add` | 向 evmap 注册 fd + 插入最小堆（如有超时）|
| `evmap_io_add_` | 引用计数管理，避免重复的 `epoll_ctl` |
| `evmap_io_active_` | fd 就绪时，遍历链表激活所有关注该 fd 的事件 |
| `event_del` | 从 evmap + 最小堆 + 活跃队列全部移除 |
| `event_active` | 手动激活，跳过后端直接进入活跃队列 |
| `event_pending` | 通过 `EVLIST_*` 标志查询事件当前状态 |
| `event_self_cbarg` | 把事件自身作为回调参数的哨兵技巧 |
| `event_finalize` | 多线程安全的异步释放机制 |

**三句话总结本课**：
1. `struct event` 是 libevent 的原子单元，通过 `ev_flags`（EVLIST_*）追踪自身在哪些队列中
2. `event_add` 做两件事：向 evmap 注册 fd（最终调用 epoll_ctl）+ 将超时插入最小堆
3. 当 fd 就绪时，epoll 触发 → evmap 查表 → 遍历 event 链表 → 全部加入活跃队列 → 按优先级执行回调

---

## 附：练习 4 答案

1. **epoll_ctl 调用次数**：只调用一次 `EPOLL_CTL_ADD`。`evmap_io_add_` 中，第一个事件注册时 `nread` 从 0 变 1，调用 `epoll_ctl(ADD)`；第二个事件注册时 `nread` 从 1 变 2，但 `old_ev == new_ev`（都是 `EV_READ`），不调用 `epoll_ctl`。

2. **event_del(ev1) 后的状态**：`nread` 减为 1，仍非零，所以不调用 `epoll_ctl(DEL)`，只调用 `epoll_ctl(MOD)` 保持 EPOLLIN。fd 继续被 epoll 监听，ev2 还会收到事件。

3. **持久 vs 非持久定时器的区别**：持久定时器（有 `ev_io_timeout`）在 `event_persist_closure` 中会重新计算绝对触发时间并调用 `event_add_nolock_` 重注册；非持久定时器不会重注册，触发后进入 `EVLIST_INIT` 状态。

4. **event_del 检查 EVLIST_ACTIVE 的原因**：即使 fd 已经就绪并且事件已在活跃队列中，也需要从活跃队列中移除，否则 `event_process_active` 会执行一个已经被 del 的事件的回调，造成 use-after-free 或逻辑错误。

---

**下一课预告**：第 5 课深入定时器——最小堆的实现细节（`minheap-internal.h`）、common timeout 优化、定时器精度问题，以及如何实现周期性任务调度。
