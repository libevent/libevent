# 第 3 课：event_base 深入 —— 事件循环的心脏

> **前置要求**：完成第 2 课，能运行 hello-world 示例
> **本课目标**：完整掌握 event_base 的创建、配置、循环控制和调试，读懂 `event_base_loop` 的真实源码

---

## 1. event_base 的生命周期

一个 event_base 从创建到销毁的完整过程：

```
全局初始化（可选）
  event_enable_debug_mode()
  event_set_mem_functions()
  event_set_log_callback()
  evthread_use_pthreads()        ← 多线程时必须
         ↓
创建配置（可选）
  event_config_new()
  event_config_avoid_method()
  event_config_require_features()
  event_config_set_flag()
         ↓
创建 event_base
  event_base_new()               ← 使用默认配置
  event_base_new_with_config()   ← 使用自定义配置
  event_config_free()            ← 配置用完就可以释放
         ↓
注册事件（循环进行）
  event_new() + event_add()
  evconnlistener_new_bind()
  bufferevent_socket_new()
         ↓
启动事件循环（阻塞）
  event_base_dispatch()
  event_base_loop()
         ↓
退出循环
  event_base_loopexit()          ← 延迟退出
  event_base_loopbreak()         ← 立即中断
         ↓
清理资源
  event_free() / bufferevent_free() / ...
  event_base_free()              ← 最后释放 base
```

---

## 2. 全局初始化函数

这些函数必须在创建任何 event_base **之前**调用：

### 2.1 调试模式

```c
// event.c 第 577 行
void event_enable_debug_mode(void);
```

开启后会检测以下错误：
- 对未初始化的 event 调用任何函数
- 将一个已 add 的 event 重新 assign（会破坏内部数据结构）

```c
// 最早调用（甚至在 main() 的第一行）
event_enable_debug_mode();

// 配合调试日志
event_enable_debug_logging(EVENT_DBG_ALL);
```

**注意**：debug mode 为每个 `event_new/event_assign` 的 event 分配追踪内存，长时间运行的程序若不调用 `event_debug_unassign`，内存会持续增长。仅在开发阶段使用。

### 2.2 日志回调

```c
typedef void (*event_log_cb)(int severity, const char *msg);
void event_set_log_callback(event_log_cb cb);

// severity 取值：
// EVENT_LOG_DEBUG (0) / EVENT_LOG_MSG (1)
// EVENT_LOG_WARN  (2) / EVENT_LOG_ERR  (3)
```

示例——将 libevent 的日志接入自己的日志系统：

```c
static void my_log_cb(int severity, const char *msg) {
    const char *level[] = {"DBG", "MSG", "WRN", "ERR"};
    fprintf(stderr, "[libevent][%s] %s\n", level[severity], msg);
}

// main() 最开始
event_set_log_callback(my_log_cb);
```

### 2.3 内存分配器替换

```c
void event_set_mem_functions(
    void *(*malloc_fn)(size_t sz),
    void *(*realloc_fn)(void *ptr, size_t sz),
    void (*free_fn)(void *ptr)
);
```

适用场景：使用 jemalloc/tcmalloc 等替代系统 malloc，或在嵌入式环境中使用自定义内存池。

```c
// 使用 jemalloc（需链接 -ljemalloc）
#include <jemalloc/jemalloc.h>
event_set_mem_functions(je_malloc, je_realloc, je_free);
```

### 2.4 致命错误回调

```c
typedef void (*event_fatal_cb)(int err);
void event_set_fatal_callback(event_fatal_cb cb);
```

默认行为是 `exit(1)`。替换后可以打印更多上下文信息，或触发 core dump：

```c
static void my_fatal_cb(int err) {
    fprintf(stderr, "libevent fatal error: %d\n", err);
    abort();  // 生成 core dump
}
event_set_fatal_callback(my_fatal_cb);
```

---

## 3. event_config：配置对象

`event_config` 是创建高度定制化 `event_base` 的入口：

```c
struct event_config *event_config_new(void);
void event_config_free(struct event_config *cfg);

struct event_base *event_base_new_with_config(const struct event_config *cfg);
```

### 3.1 排除特定后端

```c
int event_config_avoid_method(struct event_config *cfg, const char *method);
```

```c
struct event_config *cfg = event_config_new();
event_config_avoid_method(cfg, "epoll");   // 不使用 epoll
event_config_avoid_method(cfg, "kqueue");  // 不使用 kqueue
struct event_base *base = event_base_new_with_config(cfg);
printf("使用: %s\n", event_base_get_method(base)); // poll 或 select
event_config_free(cfg);
```

### 3.2 要求特定特性

```c
int event_config_require_features(struct event_config *cfg, int feature);
```

`feature` 是 `event_method_feature` 枚举的组合（来自 `event.h` 第 513 行）：

```c
enum event_method_feature {
    EV_FEATURE_ET         = 0x01,  // 支持边缘触发（ET）
    EV_FEATURE_O1         = 0x02,  // O(1) 事件检测（排除 select/poll）
    EV_FEATURE_FDS        = 0x04,  // 支持任意 fd（不仅是 socket）
    EV_FEATURE_EARLY_CLOSE = 0x08, // 支持 EV_CLOSED（检测连接关闭）
};
```

示例——强制要求 ET 支持（即要求 epoll 或 kqueue）：

```c
struct event_config *cfg = event_config_new();
event_config_require_features(cfg, EV_FEATURE_ET | EV_FEATURE_O1);
struct event_base *base = event_base_new_with_config(cfg);
if (!base) {
    // 当前平台不支持 ET，降级
    event_config_require_features(cfg, 0);
    base = event_base_new_with_config(cfg);
}
event_config_free(cfg);
```

### 3.3 设置行为标志

```c
int event_config_set_flag(struct event_config *cfg, int flag);
```

`flag` 是 `event_base_config_flag` 枚举（来自 `event.h` 第 541 行）：

| 标志 | 含义 | 使用场景 |
|------|------|----------|
| `EVENT_BASE_FLAG_NOLOCK` | 不分配锁 | 确定单线程，节省锁开销 |
| `EVENT_BASE_FLAG_IGNORE_ENV` | 忽略 `EVENT_NO*` 环境变量 | 线上环境防止误操作 |
| `EVENT_BASE_FLAG_NO_CACHE_TIME` | 每次回调后都重新取时间 | 需要精确时间戳时 |
| `EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST` | 批量提交 epoll 变更 | 高频 add/del 时性能优化（注意 dup fd 的 bug）|
| `EVENT_BASE_FLAG_PRECISE_TIMER` | 使用高精度单调时钟 | 需要亚毫秒精度的定时器 |
| `EVENT_BASE_FLAG_EPOLL_DISALLOW_TIMERFD` | 禁用 timerfd（epoll 专用） | 特定内核版本有 timerfd bug 时 |
| `EVENT_BASE_FLAG_USE_SIGNALFD` | 使用 signalfd 处理信号 | Linux 特有，信号处理更可靠 |

```c
// 例：单线程 + 高精度定时器
struct event_config *cfg = event_config_new();
event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK
                         | EVENT_BASE_FLAG_PRECISE_TIMER);
struct event_base *base = event_base_new_with_config(cfg);
event_config_free(cfg);
```

### 3.4 限制单次 dispatch 的执行时间

```c
int event_config_set_max_dispatch_interval(
    struct event_config *cfg,
    const struct timeval *max_interval,  // 最长执行时间（NULL = 无限制）
    int max_callbacks,                   // 最多执行回调数（-1 = 无限制）
    int min_priority                     // 对 >= min_priority 的事件生效
);
```

用途：防止低优先级事件的大量回调饿死高优先级事件（优先级饥饿问题）。

```c
// 每次 dispatch 最多执行 10 个回调，或最多执行 100ms
struct timeval tv = {0, 100000};  // 100ms
event_config_set_max_dispatch_interval(cfg, &tv, 10, 1);
```

---

## 4. event_base_loop：事件循环的精确流程

这是整个 libevent 最核心的函数。先看源码（`event.c` 第 1975 行），再逐段解析：

```c
int event_base_loop(struct event_base *base, int flags)
{
    const struct eventop *evsel = base->evsel;
    struct timeval *tv_p;
    int res, done, retval = 0;

    EVBASE_ACQUIRE_LOCK(base, th_base_lock);   // 加锁

    if (base->running_loop) {                  // 防止重入
        event_warnx("reentrant invocation...");
        EVBASE_RELEASE_LOCK(base, th_base_lock);
        return -1;
    }
    base->running_loop = 1;
    clear_time_cache(base);

    base->event_gotterm = base->event_break = 0;  // 重置退出标志

    while (!done) {
        base->event_continue = 0;

        // ── 检查退出标志 ──────────────────────────────────────────
        if (base->event_gotterm) break;
        if (base->event_break)   break;

        // ── 计算 epoll_wait 的超时值 ──────────────────────────────
        tv_p = &tv;
        if (!N_ACTIVE_CALLBACKS(base) && !(flags & EVLOOP_NONBLOCK)) {
            timeout_next(base, &tv_p);   // 取最近定时器的到期时间
        } else {
            evutil_timerclear(&tv);       // 有活跃事件 → 超时设 0，立即返回
        }

        // ── 无事件且无 NO_EXIT_ON_EMPTY 标志 → 退出 ──────────────
        if (0 == (flags & EVLOOP_NO_EXIT_ON_EMPTY) &&
            !event_haveevents(base) && !N_ACTIVE_CALLBACKS(base)) {
            retval = 1;
            goto done;
        }

        event_queue_make_later_events_active(base);

        // ── 调用 prepare watchers（2.2 新特性）────────────────────
        TAILQ_FOREACH(watcher, &base->watchers[EVWATCH_PREPARE], next) {
            (*watcher->callback.prepare)(watcher, &prepare_info, watcher->arg);
        }

        clear_time_cache(base);

        // ── 核心：调用后端 dispatch（epoll_wait 等）────────────────
        res = evsel->dispatch(base, tv_p);   // 阻塞，直到有事件或超时

        update_time_cache(base);

        // ── 调用 check watchers（2.2 新特性）─────────────────────
        TAILQ_FOREACH(watcher, &base->watchers[EVWATCH_CHECK], next) {
            (*watcher->callback.check)(watcher, &check_info, watcher->arg);
        }

        // ── 处理到期定时器 ────────────────────────────────────────
        timeout_process(base);

        // ── 执行活跃事件的回调 ────────────────────────────────────
        if (N_ACTIVE_CALLBACKS(base)) {
            int n = event_process_active(base);
            if ((flags & EVLOOP_ONCE) && N_ACTIVE_CALLBACKS(base) == 0 && n != 0)
                done = 1;
        } else if (flags & EVLOOP_NONBLOCK)
            done = 1;
    }

done:
    clear_time_cache(base);
    base->running_loop = 0;
    EVBASE_RELEASE_LOCK(base, th_base_lock);
    return retval;
}
```

### 4.1 循环的七个步骤

```
每次循环迭代：

① 检查退出标志（event_gotterm / event_break）
      ↓
② timeout_next()：计算最近定时器到期时间 → 作为 epoll_wait 超时
      ↓
③ 无事件且无 NO_EXIT_ON_EMPTY → 自然退出（返回 1）
      ↓
④ 调用 prepare watchers（epoll_wait 前的钩子）
      ↓
⑤ evsel->dispatch()：epoll_wait / kevent 等待
      ↓ 就绪事件被放入 activequeues
⑥ 调用 check watchers（epoll_wait 后、回调前的钩子）
   timeout_process()：处理到期定时器，放入 activequeues
      ↓
⑦ event_process_active()：按优先级执行 activequeues 中的回调
```

### 4.2 event_process_active 的优先级处理

`event_process_active`（`event.c` 第 1804 行）从高优先级（数字小）到低优先级（数字大）扫描：

```c
for (i = 0; i < base->nactivequeues; ++i) {
    if (TAILQ_FIRST(&base->activequeues[i]) != NULL) {
        base->event_running_priority = i;
        activeq = &base->activequeues[i];
        c = event_process_active_single_queue(...);
        if (c > 0)
            break;  // 执行了真实事件后，不再处理更低优先级
    }
}
```

关键点：执行完任意优先级的一批事件后，**返回 while 循环顶部，再次从最高优先级开始检查**。低优先级事件只有在高优先级队列为空时才会被执行——这是严格优先级，会产生低优先级饥饿。

---

## 5. 循环控制 API

### 5.1 四种启动方式

```c
// 方式 1（最常用）：等同于 event_base_loop(base, 0)
int event_base_dispatch(struct event_base *base);
// 行为：运行直到没有事件，或 loopexit/loopbreak 被调用

// 方式 2：细粒度控制
int event_base_loop(struct event_base *base, int flags);
```

`flags` 的三个值：

| flags | 含义 | 类比 |
|-------|------|------|
| `0` | 运行直到无事件或被明确停止 | `while(有事件) { 等待; 处理; }` |
| `EVLOOP_ONCE` | 等待一次事件，处理完返回 | `等待; 处理一次; return` |
| `EVLOOP_NONBLOCK` | 不阻塞，只处理已就绪的事件 | `if(有就绪) { 处理; } return` |
| `EVLOOP_NO_EXIT_ON_EMPTY` | 无事件时也不退出 | `while(true) { 等待; 处理; }` |

```c
// EVLOOP_ONCE 使用场景：嵌入其他事件循环（如 GUI 框架）
while (gui_running) {
    gui_handle_events();                        // GUI 事件处理
    event_base_loop(base, EVLOOP_ONCE);         // 处理一次网络事件
}

// EVLOOP_NONBLOCK 使用场景：游戏主循环
while (game_running) {
    game_update();                              // 游戏逻辑
    event_base_loop(base, EVLOOP_NONBLOCK);     // 非阻塞处理网络
    render();
}
```

### 5.2 三种退出方式

```c
// 方式 A：延迟退出（最常用）
int event_base_loopexit(struct event_base *base, const struct timeval *tv);
// tv = NULL → 本轮活跃回调执行完后退出
// tv = &delay → delay 时间后，再执行完当前轮，退出

// 方式 B：立即中断（类似 break）
int event_base_loopbreak(struct event_base *base);
// 当前 dispatch 调用立即返回，不再处理剩余活跃回调

// 方式 C：继续重新扫描（类似 continue）
int event_base_loopcontinue(struct event_base *base);
// 回调中调用：当前回调完成后立即跳回循环顶部重新扫描
```

**loopexit vs loopbreak 的关键区别**（来自源码 `event.c` 第 1879~1925 行）：

```c
// loopexit 的实现：注册一个定时器事件
int event_base_loopexit(struct event_base *base, const struct timeval *tv) {
    return event_base_once(base, -1, EV_TIMEOUT, event_loopexit_cb, base, tv);
}
// event_loopexit_cb 只是设置 base->event_gotterm = 1
// → 下次循环迭代顶部的 if(event_gotterm) break 才生效
// → 当前轮的所有活跃回调会全部执行完

// loopbreak 的实现：直接设置标志
int event_base_loopbreak(struct event_base *base) {
    base->event_break = 1;
    if (EVBASE_NEED_NOTIFY(base))
        evthread_notify_base(base);  // 唤醒正在等待的 epoll_wait
    return 0;
}
// event_break = 1 → 下次循环迭代顶部立即 break
// → 当前已激活但未执行的回调会被丢弃
```

图示对比：

```
                loopexit(NULL)         loopbreak()
                ─────────────────────────────────
dispatch 调用:   执行完当前轮回调        立即返回
未执行的回调:    全部执行                丢弃
下次 dispatch:  正常运行               正常运行
```

### 5.3 退出状态查询

```c
// 查询是否因 loopexit 退出（每次 dispatch 开始时重置）
int event_base_got_exit(struct event_base *base);

// 查询是否因 loopbreak 退出
int event_base_got_break(struct event_base *base);
```

---

## 6. 优先级系统

### 6.1 初始化优先级

```c
// 必须在 event_base_dispatch() 之前调用
int event_base_priority_init(struct event_base *base, int npriorities);
// npriorities: 1 ~ EVENT_MAX_PRIORITIES（256）
// 默认只有 1 个优先级

int event_base_get_npriorities(struct event_base *base);  // 查询当前优先级数
```

### 6.2 为事件设置优先级

```c
// 优先级编号：0 = 最高，npriorities-1 = 最低
int event_priority_set(struct event *ev, int priority);
int event_get_priority(const struct event *ev);
```

**注意**：
- `event_priority_set` 必须在 `event_add` **之前**调用（或在非 pending/active 状态下调用）
- 新创建的事件默认优先级是中间值：`npriorities / 2`

### 6.3 优先级使用示例

```c
// 设置 3 个优先级：0（高）/ 1（中）/ 2（低）
event_base_priority_init(base, 3);

// 心跳事件 → 最高优先级
struct event *heartbeat = event_new(base, -1, 0, heartbeat_cb, NULL);
event_priority_set(heartbeat, 0);
struct timeval tv = {1, 0};
event_add(heartbeat, &tv);

// 业务事件 → 中等优先级（默认）
struct event *biz_ev = event_new(base, client_fd, EV_READ|EV_PERSIST, biz_cb, NULL);
// event_priority_set(biz_ev, 1);  // 可省略，默认就是 1
event_add(biz_ev, NULL);

// 日志刷盘事件 → 最低优先级
struct event *log_ev = event_new(base, log_fd, EV_WRITE, log_cb, NULL);
event_priority_set(log_ev, 2);
event_add(log_ev, NULL);

event_base_dispatch(base);
```

---

## 7. 诊断与调试 API

### 7.1 查询已注册事件数量

```c
int event_base_get_num_events(struct event_base *base, unsigned int flags);
// flags:
// EVENT_BASE_COUNT_ACTIVE  → 当前活跃（回调即将执行）的事件数
// EVENT_BASE_COUNT_ADDED   → 已注册（pending）的事件总数
// EVENT_BASE_COUNT_VIRTUAL → 虚拟事件数（内部使用）

// 历史峰值
int event_base_get_max_events(struct event_base *base, unsigned int flags, int clear);
// clear = 1 → 同时重置峰值记录
```

```c
// 监控事件循环负载
printf("活跃: %d  已注册: %d  历史峰值: %d\n",
    event_base_get_num_events(base, EVENT_BASE_COUNT_ACTIVE),
    event_base_get_num_events(base, EVENT_BASE_COUNT_ADDED),
    event_base_get_max_events(base, EVENT_BASE_COUNT_ADDED, 0));
```

### 7.2 打印所有注册事件（调试神器）

```c
void event_base_dump_events(struct event_base *base, FILE *fp);
```

输出示例：

```
Inserted events:
  0x55a3b2c0d010: [fd 5] Read Persist [pri 1] timeout={never}
  0x55a3b2c0d090: [fd 7] Read Write [pri 1] timeout={10.000000}
  0x55a3b2c0d110: [fd -1] Timeout [pri 0] timeout={1.000000}
Active events:
  (none)
```

使用场景：程序挂起时打印所有事件，快速定位哪些 fd 被监听了但没有触发。

### 7.3 查询当前时间

```c
// 从 base 的时间缓存中获取（效率高，精度低）
int event_base_gettimeofday_cached(struct event_base *base, struct timeval *tv);

// 从单调时钟获取（精度更高）
int event_gettime_monotonic(struct event_base *base, struct timeval *tp);
```

libevent 在每次 dispatch 调用前后刷新时间缓存（`clear_time_cache` / `update_time_cache`），这意味着同一轮回调内调用 `gettimeofday_cached` 得到的是同一个时间值——节省了 syscall，但牺牲了微秒级精度。

### 7.4 获取版本信息

```c
const char *event_get_version(void);           // "2.2.1-alpha"
ev_uint32_t event_get_version_number(void);    // 0x02020100

// 编译期宏（头文件版本）
printf("编译版本: %s\n", LIBEVENT_VERSION);
printf("运行版本: %s\n", event_get_version());
```

---

## 8. fork 后的重初始化

`fork()` 后，子进程继承了父进程的 epoll fd，但父子进程的 epoll 实例是共享的，这会导致子进程的事件处理出现异常。

```c
int event_reinit(struct event_base *base);
// 返回 0 表示成功，-1 表示部分事件无法重新注册
```

**正确的 fork 用法**：

```c
pid_t pid = fork();
if (pid == 0) {
    // 子进程
    event_reinit(base);     // 必须！重新创建 epoll fd，重新注册所有事件
    event_base_dispatch(base);
    exit(0);
} else {
    // 父进程继续
    event_base_dispatch(base);
}
```

`epoll.c` 中 `epollops` 定义了 `need_reinit = 1`，这告诉 libevent 该后端在 fork 后必须重新初始化。`event_reinit` 会重新调用 `evsel->init(base)` 并重新注册所有已添加的事件。

---

## 9. event_base_once：一次性回调

无需手动创建和释放 event，注册一个只执行一次的回调：

```c
int event_base_once(struct event_base *base,
                    evutil_socket_t fd,
                    short events,
                    void (*callback)(evutil_socket_t, short, void *),
                    void *arg,
                    const struct timeval *tv);
```

源码（`event.c` 第 2123 行）内部分配 `struct event_once`，回调执行完后自动 `mm_free`。

```c
// 延迟 1 秒后执行一次（不需要 EV_PERSIST）
struct timeval one_sec = {1, 0};
event_base_once(base, -1, EV_TIMEOUT, my_cb, my_arg, &one_sec);

// 立即在下一次循环中执行（tv = NULL 或 tv = {0,0}）
event_base_once(base, -1, EV_TIMEOUT, my_cb, my_arg, NULL);

// 等 fd 可读时执行一次
event_base_once(base, fd, EV_READ, read_once_cb, arg, NULL);
```

常用于：跨线程投递任务到事件循环（第 14 课会详细讲解）。

---

## 10. 环境变量控制

libevent 支持通过环境变量在运行时调整行为，无需修改代码：

| 环境变量 | 效果 |
|----------|------|
| `EVENT_NOEPOLL=1` | 禁用 epoll 后端 |
| `EVENT_NOKQUEUE=1` | 禁用 kqueue 后端 |
| `EVENT_NOPOLL=1` | 禁用 poll 后端 |
| `EVENT_NOSELECT=1` | 禁用 select 后端 |
| `EVENT_SHOW_METHOD=1` | 启动时打印所使用的后端 |
| `EVENT_PRECISE_TIMER=1` | 强制使用高精度计时器 |
| `EVENT_EPOLL_USE_CHANGELIST=1` | 启用 epoll changelist 优化 |

```bash
# 测试时禁用 epoll，强制使用 poll
EVENT_NOEPOLL=1 ./my_server

# 查看使用的后端
EVENT_SHOW_METHOD=1 ./my_server
# 输出：libevent using: poll
```

使用 `EVENT_BASE_FLAG_IGNORE_ENV` 可以让 event_base 忽略这些环境变量（用于线上环境防止误操作）：

```c
struct event_config *cfg = event_config_new();
event_config_set_flag(cfg, EVENT_BASE_FLAG_IGNORE_ENV);
struct event_base *base = event_base_new_with_config(cfg);
event_config_free(cfg);
```

---

## 11. event_base_free 的注意事项

```c
void event_base_free(struct event_base *base);
```

**重要**：`event_base_free` 不会自动释放注册在 base 上的 event。在调用 `event_base_free` 之前，必须手动释放或 del 所有事件：

```c
// 正确的清理顺序
event_del(ev1);
event_free(ev1);
event_del(ev2);
event_free(ev2);
evconnlistener_free(listener);   // 内部自动 del
bufferevent_free(bev);           // 内部自动 del（若设了 CLOSE_ON_FREE 也关 fd）
event_base_free(base);           // 最后释放 base
```

若有遗留未释放的 event，`event_base_free` 会打印警告（debug 模式下会更详细）：
```
[warn] n events were still set in base
```

---

## 12. 完整示例：综合运用本课所有特性

```c
// base_demo.c
#include <event2/event.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

// 自定义日志回调
static void my_log(int severity, const char *msg) {
    const char *lvl[] = {"DBG","MSG","WRN","ERR"};
    if (severity >= 2)  // 只打印 WARN 以上
        fprintf(stderr, "[libevent][%s] %s\n", lvl[severity], msg);
}

// 周期性打印事件统计
static void stats_cb(evutil_socket_t fd, short what, void *arg) {
    struct event_base *base = arg;
    printf("[stats] active=%d added=%d\n",
        event_base_get_num_events(base, EVENT_BASE_COUNT_ACTIVE),
        event_base_get_num_events(base, EVENT_BASE_COUNT_ADDED));
}

// 5 秒后触发的一次性事件
static void shutdown_cb(evutil_socket_t fd, short what, void *arg) {
    struct event_base *base = arg;
    printf("[5s] 准备退出...\n");
    event_base_dump_events(base, stdout);    // 打印当前所有事件
    event_base_loopbreak(base);             // 立即中断
}

// SIGINT 处理
static void sigint_cb(evutil_socket_t sig, short what, void *arg) {
    struct event_base *base = arg;
    struct timeval tv = {1, 0};
    printf("[SIGINT] 1 秒后优雅退出\n");
    event_base_loopexit(base, &tv);         // 延迟退出（处理完当前轮）
}

int main(void) {
    // ── 全局初始化 ───────────────────────────────────────────────
    event_enable_debug_mode();
    event_set_log_callback(my_log);

    // ── 创建配置：要求 O(1) 后端，使用高精度定时器 ──────────────
    struct event_config *cfg = event_config_new();
    event_config_require_features(cfg, EV_FEATURE_O1);
    event_config_set_flag(cfg, EVENT_BASE_FLAG_PRECISE_TIMER
                             | EVENT_BASE_FLAG_IGNORE_ENV);

    struct event_base *base = event_base_new_with_config(cfg);
    event_config_free(cfg);

    if (!base) {
        fprintf(stderr, "无法创建 event_base\n");
        return 1;
    }

    printf("后端: %s  特性: 0x%x\n",
        event_base_get_method(base),
        event_base_get_features(base));

    // ── 设置 3 个优先级 ──────────────────────────────────────────
    event_base_priority_init(base, 3);

    // ── 注册 SIGINT 信号（优先级 0）─────────────────────────────
    struct event *sig_ev = evsignal_new(base, SIGINT, sigint_cb, base);
    event_priority_set(sig_ev, 0);
    event_add(sig_ev, NULL);

    // ── 每 1 秒打印统计（优先级 2）──────────────────────────────
    struct event *stats_ev = event_new(base, -1, EV_PERSIST, stats_cb, base);
    event_priority_set(stats_ev, 2);
    struct timeval one_sec = {1, 0};
    event_add(stats_ev, &one_sec);

    // ── 5 秒后自动退出（一次性，使用 event_base_once）───────────
    struct timeval five_sec = {5, 0};
    event_base_once(base, -1, EV_TIMEOUT, shutdown_cb, base, &five_sec);

    printf("事件循环启动（按 Ctrl+C 提前退出）...\n");
    int ret = event_base_dispatch(base);
    printf("事件循环退出，返回值: %d\n", ret);
    printf("因 exit=%d  因 break=%d\n",
        event_base_got_exit(base),
        event_base_got_break(base));

    // ── 清理 ─────────────────────────────────────────────────────
    event_del(stats_ev);
    event_free(stats_ev);
    event_del(sig_ev);
    event_free(sig_ev);
    event_base_free(base);

    return 0;
}
```

编译运行：

```bash
gcc base_demo.c \
    -I/root/libevent/include \
    -L/root/libevent/build/lib \
    -levent -o base_demo

LD_LIBRARY_PATH=/root/libevent/build/lib ./base_demo
```

预期输出：
```
后端: epoll  特性: 0xb
事件循环启动（按 Ctrl+C 提前退出）...
[stats] active=0 added=3
[stats] active=0 added=3
[stats] active=0 added=3
[stats] active=0 added=3
[5s] 准备退出...
Inserted events:
  ...
事件循环退出，返回值: 0
因 exit=0  因 break=1
```

---

## 13. 动手练习

### 练习 1：观察 event_base_loop 的不同 flags 行为

```c
// 写一个程序，分别用以下方式调用，观察输出差异：
// 1. event_base_dispatch(base)           - 无事件时退出
// 2. event_base_loop(base, EVLOOP_ONCE)  - 处理一次后返回
// 3. event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY)  - 永不自然退出
```

### 练习 2：实现严格优先级

```c
// 场景：同一时刻触发 3 个定时器（高/中/低优先级）
// 期望：高优先级总是先执行
// 验证：打印每次回调的时间戳和优先级标识
struct timeval zero = {0, 0};
// 同时激活三个定时器：
event_add(high_timer, &zero);   // priority=0
event_add(mid_timer, &zero);    // priority=1
event_add(low_timer, &zero);    // priority=2
event_base_loop(base, EVLOOP_NONBLOCK);
// 观察执行顺序
```

### 练习 3：loopexit vs loopbreak 对比

```c
// 注册 5 个定时器（间隔 0ms，同时触发）
// 在第 3 个回调中分别调用 loopexit(NULL) 和 loopbreak()
// 观察第 4、5 个回调是否被执行
```

### 练习 4：阅读 event_base_loop 源码，找到 EVLOOP_ONCE 的退出时机

在 `event.c` 第 2079~2082 行找到这段代码，分析其执行条件：

```c
if ((flags & EVLOOP_ONCE)
    && N_ACTIVE_CALLBACKS(base) == 0
    && n != 0)
    done = 1;
```

思考：为什么是 `n != 0`？如果所有执行的都是内部事件（`EVLIST_INTERNAL`），`n` 会是 0 还是非零？

---

## 14. 本课小结

| API | 作用 | 关键细节 |
|-----|------|----------|
| `event_base_new()` | 创建默认配置的 base | 自动选择最优后端 |
| `event_base_new_with_config()` | 自定义配置 | cfg 用完即可 free |
| `event_base_dispatch()` | 启动循环 | 等价于 `loop(base, 0)` |
| `event_base_loop(flags)` | 细粒度循环控制 | ONCE/NONBLOCK/NO_EXIT |
| `event_base_loopexit(tv)` | 延迟退出 | 当前轮回调全部执行完 |
| `event_base_loopbreak()` | 立即中断 | 未执行的回调被丢弃 |
| `event_base_priority_init(n)` | 设置优先级数 | dispatch 前调用 |
| `event_base_dump_events()` | 打印所有事件 | 调试利器 |
| `event_reinit()` | fork 后重初始化 | 子进程必须调用 |
| `event_base_once()` | 一次性回调 | 无需手动 free |
| `event_base_free()` | 释放 base | 先 free 所有 event |

**两句话总结**：
1. `event_base_loop` 的核心是一个 `while` 循环：计算超时 → epoll_wait → 处理定时器 → 执行回调
2. loopexit 是"完成当前轮再退出"，loopbreak 是"立即停下"，对应 loop 顶部两个不同的退出检查点

---

**下一课预告**：第 4 课深入 `event` 的注册与回调机制——event_new/event_add 的实现、事件的四种状态（未初始化/pending/active/两者皆有）、EV_PERSIST 的内部处理，以及 evmap 如何将 fd 映射到事件列表。
