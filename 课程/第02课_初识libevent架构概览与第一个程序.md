# 第 2 课：初识 libevent —— 架构概览与第一个程序

> **前置要求**：完成第 1 课，理解 epoll 工作原理
> **本课目标**：建立 libevent 的全局视图，完成编译安装，读懂并运行第一个程序

---

## 1. libevent 是什么

先看官方的一句话定义（来自 `include/event2/event.h` 第 35 行）：

```
Libevent is an event notification library for developing scalable network servers.
The Libevent API provides a mechanism to execute a callback function when a specific
event occurs on a file descriptor or after a timeout has been reached.
```

两个核心关键词：

- **event notification**（事件通知）：某件事发生时，通知你的代码
- **callback**（回调）：你的代码以函数指针的形式注册，事件发生时被调用

libevent 并不"帮你做事"，而是帮你**等待事情发生**，然后**调用你写的函数**。

---

## 2. 整体架构

### 2.1 三层结构

```
┌─────────────────────────────────────────────────────────────────┐
│  应用代码（你写的）                                               │
│  event_base_new() / event_new() / bufferevent_socket_new() ...   │
└───────────────────────────┬─────────────────────────────────────┘
                            │ 公开 API
┌───────────────────────────▼─────────────────────────────────────┐
│  libevent 核心层                                                  │
│  event_base（事件循环）  event（事件描述）  evbuffer（缓冲区）     │
│  bufferevent（带缓冲的IO）  evdns  evhttp  evconnlistener ...     │
└───────────────────────────┬─────────────────────────────────────┘
                            │ struct eventop（后端接口）
┌───────────────────────────▼─────────────────────────────────────┐
│  后端实现层（平台相关）                                           │
│  epoll.c  kqueue.c  select.c  poll.c  devpoll.c  evport.c        │
└─────────────────────────────────────────────────────────────────┘
```

应用代码只和中间层打交道，从不直接调用 epoll_ctl / kevent 这类系统调用。

### 2.2 五个核心模块

| 模块 | 头文件 | 职责 |
|------|--------|------|
| 事件循环 | `event2/event.h` | `event_base`、`event`、定时器、信号 |
| 缓冲 IO | `event2/buffer.h`、`event2/bufferevent.h` | 自动读写缓冲区 |
| DNS | `event2/dns.h` | 异步 DNS 解析 |
| HTTP | `event2/http.h` | 嵌入式 HTTP 服务器/客户端 |
| 线程 | `event2/thread.h` | 多线程支持 |
| 工具 | `event2/util.h` | 跨平台工具函数 |

### 2.3 三个核心概念

学完本课要牢牢记住这三个东西，后续 13 课都在它们上面展开：

**① event_base —— 事件循环的容器**

类比：一个永不停歇的调度员，坐在那里等待事情发生，然后分配任务。

```c
struct event_base *base = event_base_new();
event_base_dispatch(base);   // 调度员开始工作，阻塞在这里
```

**② event —— 对一件事情的描述**

类比：一张工单，写着"当 fd=5 可读时，调用函数 read_cb"。

```c
struct event *ev = event_new(base, fd, EV_READ | EV_PERSIST, read_cb, arg);
event_add(ev, NULL);   // 把工单交给调度员
```

**③ callback —— 事情发生时执行的函数**

```c
void read_cb(evutil_socket_t fd, short events, void *arg) {
    // 事件发生，在这里处理
}
```

三者关系：

```
event_base
  │
  ├── event (fd=5, EV_READ) → read_cb
  ├── event (fd=7, EV_READ|EV_WRITE) → rw_cb
  ├── event (fd=-1, timeout=3s) → timer_cb
  └── event (signal=SIGINT) → signal_cb
```

---

## 3. 头文件组织

libevent 的所有公开头文件都在 `include/event2/` 目录下：

```
include/event2/
├── event.h           ← 最重要：event_base、event、定时器
├── event_struct.h    ← struct event 的内部布局（不建议直接使用）
├── event_compat.h    ← 1.x 兼容 API（避免使用）
├── buffer.h          ← evbuffer：动态缓冲区
├── bufferevent.h     ← bufferevent：带缓冲的异步 IO
├── bufferevent_ssl.h ← SSL/TLS 支持
├── listener.h        ← evconnlistener：TCP 监听器
├── dns.h             ← 异步 DNS 解析
├── http.h            ← HTTP 服务器/客户端
├── thread.h          ← 多线程支持
├── util.h            ← 跨平台工具（socket、地址、随机数等）
└── watch.h           ← prepare/check 钩子（2.2 新增）
```

**使用规则**：
- 只 `#include <event2/event.h>`（新 API，2.x 起）
- 不要直接 `#include <event.h>`（旧 API，已废弃）
- 不要直接使用 `event_struct.h` 中的结构体字段

---

## 4. 编译安装

### 4.1 依赖安装（Ubuntu/Debian）

```bash
sudo apt-get install cmake gcc make
# 可选：SSL 支持
sudo apt-get install libssl-dev
# 可选：运行测试
sudo apt-get install zlib1g-dev python3
```

### 4.2 编译

```bash
cd /root/libevent
mkdir -p build && cd build

# 基础编译（禁用 OpenSSL 简化依赖）
cmake .. -DEVENT__DISABLE_OPENSSL=ON

# 或完整编译（含 SSL 支持）
cmake ..

make -j$(nproc)
```

### 4.3 运行测试（可选）

```bash
make verify
# 或单独运行 regress
./test/regress --no-fork
```

### 4.4 安装到系统（可选）

```bash
sudo make install
# 默认安装到 /usr/local/lib 和 /usr/local/include/event2/
sudo ldconfig
```

### 4.5 生成的产物说明

```
build/
├── lib/
│   ├── libevent.so          ← 完整库（含 DNS、HTTP 等）
│   ├── libevent_core.so     ← 核心库（event、bufferevent，不含协议）
│   ├── libevent_extra.so    ← 扩展库（DNS、HTTP、RPC）
│   └── libevent_pthreads.so ← pthread 支持库
└── sample/
    ├── hello-world          ← 今天要运行的第一个程序
    ├── http-server
    └── ...
```

**链接选项**：
```bash
gcc myprogram.c -levent          # 链接完整库
gcc myprogram.c -levent_core     # 只需要核心功能时
```

---

## 5. 第一个程序：hello-world.c 精读

`sample/hello-world.c` 是官方提供的入门示例——一个 TCP 服务器，每当有客户端连接时，发送一行 "Hello, World!\n" 然后关闭连接。

### 5.1 完整源码（带注释）

```c
// sample/hello-world.c（原始文件加注释版）

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

static const char MESSAGE[] = "Hello, World!\n";
static const unsigned short PORT = 9995;

// ── 回调函数声明 ──────────────────────────────────────────────────
static void listener_cb(struct evconnlistener *, evutil_socket_t,
    struct sockaddr *, int socklen, void *);
static void conn_writecb(struct bufferevent *, void *);
static void conn_eventcb(struct bufferevent *, short, void *);
static void signal_cb(evutil_socket_t, short, void *);

int main(int argc, char **argv)
{
    // ── 步骤 1：创建事件循环 ──────────────────────────────────────
    struct event_base *base = event_base_new();
    // base 是整个程序的核心，所有事件都注册在它上面

    // ── 步骤 2：创建 TCP 监听器 ──────────────────────────────────
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    // sin.sin_addr.s_addr = 0  → 监听所有网卡（INADDR_ANY）

    struct evconnlistener *listener = evconnlistener_new_bind(
        base,                                  // 所属的 event_base
        listener_cb,                           // 有新连接时调用此函数
        (void *)base,                          // 传递给回调的参数
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,  // 选项
        -1,                                    // backlog，-1 = 自动选择
        (struct sockaddr*)&sin, sizeof(sin)    // 绑定地址
    );
    // evconnlistener 内部自动完成：socket → setsockopt → bind → listen → 注册 EV_READ

    // ── 步骤 3：注册信号事件（优雅退出）─────────────────────────
    struct event *signal_event = evsignal_new(base, SIGINT, signal_cb, (void *)base);
    event_add(signal_event, NULL);
    // 按 Ctrl+C 后会调用 signal_cb，而不是直接中断程序

    // ── 步骤 4：启动事件循环（阻塞在这里，直到退出）─────────────
    event_base_dispatch(base);
    // dispatch 内部不断调用 epoll_wait，有事件就处理，无事件就等待

    // ── 步骤 5：清理资源 ─────────────────────────────────────────
    evconnlistener_free(listener);
    event_free(signal_event);
    event_base_free(base);

    return 0;
}

// ── 回调 1：有新 TCP 连接时触发 ───────────────────────────────────
static void listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
    struct event_base *base = user_data;

    // 为这个连接创建 bufferevent（带输入/输出缓冲区的 IO 包装）
    struct bufferevent *bev = bufferevent_socket_new(
        base, fd, BEV_OPT_CLOSE_ON_FREE);
    // BEV_OPT_CLOSE_ON_FREE：bufferevent_free() 时自动关闭 fd

    // 设置回调：
    // - 读回调（NULL）：不关心读事件，因为我们只写不读
    // - 写回调（conn_writecb）：output 缓冲区写完时调用
    // - 事件回调（conn_eventcb）：连接断开/错误时调用
    bufferevent_setcb(bev, NULL, conn_writecb, conn_eventcb, NULL);

    bufferevent_enable(bev, EV_WRITE);    // 启用写监听
    bufferevent_disable(bev, EV_READ);    // 不需要读监听

    // 把要发送的消息写入 output 缓冲区（不立即发送，由 libevent 自动发送）
    bufferevent_write(bev, MESSAGE, strlen(MESSAGE));
}

// ── 回调 2：output 缓冲区数据全部发出后触发 ───────────────────────
static void conn_writecb(struct bufferevent *bev, void *user_data)
{
    struct evbuffer *output = bufferevent_get_output(bev);
    if (evbuffer_get_length(output) == 0) {
        // 缓冲区已空，说明 "Hello, World!\n" 已发送完毕
        printf("flushed answer\n");
        bufferevent_free(bev);   // 关闭连接，释放资源
    }
}

// ── 回调 3：连接发生 EOF 或错误时触发 ─────────────────────────────
static void conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    if (events & BEV_EVENT_EOF) {
        printf("Connection closed.\n");
    } else if (events & BEV_EVENT_ERROR) {
        printf("Got an error on the connection: %s\n", strerror(errno));
    }
    bufferevent_free(bev);
}

// ── 回调 4：收到 SIGINT（Ctrl+C）时触发 ───────────────────────────
static void signal_cb(evutil_socket_t sig, short events, void *user_data)
{
    struct event_base *base = user_data;
    struct timeval delay = { 2, 0 };   // 等 2 秒后退出

    printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");
    event_base_loopexit(base, &delay); // 通知事件循环：2 秒后退出
}
```

### 5.2 程序的生命周期图

```
main()
  │
  ├─ event_base_new()             创建事件循环
  │
  ├─ evconnlistener_new_bind()    监听 TCP 端口
  │   └─ 内部注册 EV_READ 到 event_base
  │
  ├─ evsignal_new() + event_add() 监听 SIGINT 信号
  │
  └─ event_base_dispatch()        启动事件循环（阻塞）
        │
        │  ← epoll_wait() 等待
        │
        ├── 有新连接 ─→ listener_cb()
        │               └─ bufferevent_socket_new()
        │               └─ bufferevent_write(MESSAGE)
        │
        ├── 写完成   ─→ conn_writecb()
        │               └─ bufferevent_free()  关闭连接
        │
        ├── 连接断开 ─→ conn_eventcb()
        │               └─ bufferevent_free()
        │
        └── SIGINT   ─→ signal_cb()
                        └─ event_base_loopexit()
                              2秒后退出 dispatch()
                              回到 main() 清理资源
```

### 5.3 运行和测试

```bash
# 在 build 目录下
cd /root/libevent/build
./sample/hello-world &
# 输出：(无，后台运行，等待连接)

# 测试：连接后立即收到 Hello, World!
nc 127.0.0.1 9995
# 输出：Hello, World!

# 多个客户端同时连接
for i in $(seq 5); do nc 127.0.0.1 9995 & done
# 服务器输出：flushed answer（5次）

# 优雅退出
kill -SIGINT %1
# 服务器输出：Caught an interrupt signal; exiting cleanly in two seconds.
# 2 秒后输出：done
```

---

## 6. 深入内核：struct event_base 是什么

现在我们有了感性认识，来看 libevent 内部是如何组织这一切的。

### 6.1 struct event_base 的关键字段

`event-internal.h` 第 255 行定义了 `struct event_base`，挑选最重要的字段：

```c
struct event_base {
    // ── 后端（epoll/kqueue/select...）────────────────────────────
    const struct eventop *evsel;   // 指向当前使用的后端操作表
    void *evbase;                  // 后端私有数据（如 epollop 结构体）

    // ── 事件注册表 ───────────────────────────────────────────────
    struct event_io_map io;        // fd → event 的映射（数组或哈希表）
    struct event_signal_map sigmap;// 信号 → event 的映射

    // ── 活跃事件队列 ─────────────────────────────────────────────
    struct evcallback_list *activequeues; // 按优先级分级的就绪回调队列
    int nactivequeues;

    // ── 定时器堆 ─────────────────────────────────────────────────
    struct min_heap timeheap;      // 最小堆，存放所有有超时的事件

    // ── 循环控制 ─────────────────────────────────────────────────
    int event_gotterm;             // 置 1 → 本轮处理完后退出
    int event_break;               // 置 1 → 立即退出

    // ── 多线程支持 ───────────────────────────────────────────────
    void *th_base_lock;            // 互斥锁
    evutil_socket_t th_notify_fd[2]; // 用于唤醒 epoll_wait 的 pipe

    // ── 时间缓存 ─────────────────────────────────────────────────
    struct timeval tv_cache;       // 缓存当前时间，避免频繁 gettimeofday
};
```

可以把 `event_base` 想象成一个"调度中心"，它持有：
1. 一个后端（epoll fd 等）用于等待 IO 就绪
2. 一套注册表用于记录哪些 fd/信号被监听
3. 一个就绪队列用于收集本轮需要执行的回调
4. 一个定时器堆用于管理超时

### 6.2 struct event 的内部结构

`include/event2/event_struct.h` 第 123 行定义了 `struct event`：

```c
struct event {
    struct event_callback ev_evcallback;  // 回调函数和标志位

    // 定时器相关（在最小堆中的位置 或 common timeout 链表节点）
    union {
        TAILQ_ENTRY(event) ev_next_with_common_timeout;
        size_t min_heap_idx;
    } ev_timeout_pos;

    evutil_socket_t ev_fd;     // 监听的文件描述符（信号事件为信号号，定时器为 -1）
    short ev_events;           // 感兴趣的事件类型：EV_READ | EV_WRITE | EV_SIGNAL...
    short ev_res;              // 实际触发的事件（传给回调的 events 参数）
    struct event_base *ev_base;// 所属的 event_base

    union {
        struct { LIST_ENTRY(event) ev_io_next; struct timeval ev_timeout; } ev_io;
        struct { LIST_ENTRY(event) ev_signal_next; short ev_ncalls; short *ev_pncalls; } ev_signal;
    } ev_;

    struct timeval ev_timeout;  // 超时时间（绝对时间）
};
```

### 6.3 后端如何被选择

`event.c` 第 107 行定义了后端数组，按优先级从高到低排列：

```c
static const struct eventop *eventops[] = {
    &evportops,   // Solaris event ports（最优先）
    &kqops,       // kqueue（macOS/BSD）
    &epollops,    // epoll（Linux）
    &devpollops,  // /dev/poll（Solaris）
    &pollops,     // poll（通用）
    &selectops,   // select（最低优先级）
    NULL
};
```

`event_base_new_with_config()` 第 683 行的核心逻辑：

```c
for (i = 0; eventops[i] && !base->evbase; i++) {
    // 跳过被 event_config_avoid_method() 禁用的后端
    if (event_config_is_avoided_method(cfg, eventops[i]->name))
        continue;
    // 跳过不满足 require_features 的后端
    if ((eventops[i]->features & cfg->require_features) != cfg->require_features)
        continue;
    // 跳过被环境变量禁用的后端（如 EVENT_NOEPOLL=1）
    if (event_is_method_disabled(eventops[i]->name))
        continue;

    base->evsel = eventops[i];
    base->evbase = base->evsel->init(base);   // 初始化后端
}
```

逻辑很简单：从优先级最高的后端开始尝试，第一个成功 init 的就用它。

### 6.4 后端接口 struct eventop

所有后端都实现同一个接口（`event-internal.h` 第 87 行）：

```c
struct eventop {
    const char *name;          // 后端名称，如 "epoll"
    void *(*init)(...);        // 初始化（如 epoll_create）
    int (*add)(...);           // 注册 fd（如 EPOLL_CTL_ADD）
    int (*del)(...);           // 注销 fd（如 EPOLL_CTL_DEL）
    int (*dispatch)(...);      // 等待事件（如 epoll_wait）
    void (*dealloc)(...);      // 销毁
    int need_reinit;           // fork 后是否需要重新初始化
    enum event_method_feature features;  // 支持的特性（ET、O1等）
    size_t fdinfo_len;         // 每个 fd 附加数据的大小
};
```

这是一个典型的**策略模式**：接口固定，实现可替换。第 15 课精读 `epoll.c` 时，会看到 `epollops` 如何实现这五个函数。

---

## 7. 事件循环的内部流程（初步）

虽然第 3 课会深入讲 event_base，这里先给出一个宏观印象。

`event_base_dispatch()` 最终调用 `event_base_loop()`，其核心是这个循环：

```
event_base_loop() 的简化伪代码：

while (true) {
    if (event_gotterm || event_break) break;

    // 1. 计算最近定时器的到期时间 → 作为 epoll_wait 的超时值
    timeout = timeout_next(base);

    // 2. 调用后端 dispatch（epoll_wait / kevent / ...）
    //    阻塞，直到有 IO 事件或超时
    evsel->dispatch(base, timeout);

    // 3. 处理到期的定时器
    timeout_process(base);

    // 4. 执行所有活跃事件的回调函数
    event_process_active(base);
}
```

这个循环会在第 3 课完整展开，现在只需知道：
- **dispatch** 是等待的地方（阻塞）
- **event_process_active** 是执行的地方（调用你的 callback）

---

## 8. 头文件与链接速查

### 8.1 最小可用程序模板

```c
#include <event2/event.h>    // 必须

int main(void) {
    // 全局初始化（多线程时必须最先调用）
    // evthread_use_pthreads();  // 多线程时取消注释

    struct event_base *base = event_base_new();

    // ... 注册事件 ...

    event_base_dispatch(base);

    event_base_free(base);
    return 0;
}
```

编译：

```bash
gcc myprogram.c -levent -o myprogram
# 或指定路径
gcc myprogram.c -I/root/libevent/include \
    -L/root/libevent/build/lib \
    -levent -o myprogram
```

### 8.2 常用头文件 → 功能映射

```c
#include <event2/event.h>        // event_base, event, 定时器, 信号
#include <event2/buffer.h>       // evbuffer（缓冲区）
#include <event2/bufferevent.h>  // bufferevent（带缓冲的异步 IO）
#include <event2/listener.h>     // evconnlistener（TCP 监听）
#include <event2/dns.h>          // evdns（异步 DNS）
#include <event2/http.h>         // evhttp（HTTP 服务端/客户端）
#include <event2/thread.h>       // 多线程支持
#include <event2/util.h>         // 工具函数
```

---

## 9. 动手实践

### 练习 1：确认后端

```c
// backends.c
#include <event2/event.h>
#include <stdio.h>

int main(void) {
    // 列出所有支持的后端
    const char **methods = event_get_supported_methods();
    printf("所有可用后端：\n");
    for (int i = 0; methods[i]; i++)
        printf("  [%d] %s\n", i, methods[i]);

    // 创建默认 event_base，查看实际使用的后端
    struct event_base *base = event_base_new();
    printf("\n当前使用：%s\n", event_base_get_method(base));

    // 查看后端支持的特性
    int features = event_base_get_features(base);
    printf("支持特性：");
    if (features & EV_FEATURE_ET)   printf("ET(边缘触发) ");
    if (features & EV_FEATURE_O1)   printf("O(1)操作 ");
    if (features & EV_FEATURE_FDS)  printf("任意FD ");
    printf("\n");

    event_base_free(base);
    return 0;
}
```

```bash
gcc backends.c -I/root/libevent/include -L/root/libevent/build/lib -levent -o backends
LD_LIBRARY_PATH=/root/libevent/build/lib ./backends
```

预期输出（Linux）：
```
所有可用后端：
  [0] epoll
  [1] poll
  [2] select

当前使用：epoll
支持特性：ET(边缘触发) O(1)操作
```

### 练习 2：禁用 epoll，强制使用 poll

```c
// force_poll.c
#include <event2/event.h>
#include <stdio.h>

int main(void) {
    struct event_config *cfg = event_config_new();
    event_config_avoid_method(cfg, "epoll");   // 排除 epoll

    struct event_base *base = event_base_new_with_config(cfg);
    printf("使用后端：%s\n", event_base_get_method(base));  // 预期：poll

    event_config_free(cfg);
    event_base_free(base);
    return 0;
}
```

### 练习 3：运行 hello-world 并观察行为

```bash
# 启动服务器
cd /root/libevent/build
./sample/hello-world

# 另一个终端：连接并观察
nc 127.0.0.1 9995        # 应收到 "Hello, World!"
nc 127.0.0.1 9995        # 再次连接，再次收到

# 并发测试：50 个客户端同时连接
for i in $(seq 50); do (nc 127.0.0.1 9995; echo "client $i done") & done
wait
# 所有客户端都应收到响应

# 优雅退出
# 在服务器终端按 Ctrl+C
# 观察：打印提示，2 秒后退出，输出 "done"
```

### 练习 4：阅读源码，回答问题

阅读 `sample/hello-world.c`，思考以下问题（答案见本课末尾）：

1. 为什么 `bufferevent_enable(bev, EV_WRITE)` 后不需要手动调用 write 系统调用？
2. `conn_writecb` 里为什么要检查 `evbuffer_get_length(output) == 0`？
3. 如果多个客户端同时连接，每个客户端的 `bufferevent` 是独立的还是共享的？
4. `event_base_loopexit` 和 `event_base_loopbreak` 有什么区别？

---

## 10. 本课小结

| 概念 | 一句话解释 |
|------|-----------|
| `event_base` | 事件循环的核心，管理所有事件，调用 epoll_wait 等待 |
| `event` | 描述"监听谁、等什么、发生时调用谁"的结构体 |
| `bufferevent` | 带输入/输出缓冲区的异步 IO，自动处理读写 |
| `evconnlistener` | TCP 监听器，自动 accept 并回调 |
| `eventop` | 后端抽象接口，屏蔽 epoll/kqueue 等的差异 |
| `event_base_dispatch` | 启动事件循环，阻塞直到调用 loopexit/loopbreak |

**三句话记忆整个架构**：
1. `event_base` 是调度中心，持有后端（epoll）和所有注册的事件
2. `event` 是一张工单，描述"当 X 发生时，调用函数 Y"
3. `event_base_dispatch` 启动无限循环：等待 → 激活就绪事件 → 执行回调 → 重复

---

## 附：练习 4 答案

1. **为什么不需要手动调用 write？**
   `bufferevent_write()` 把数据放入 output 缓冲区，libevent 检测到 fd 可写时自动调用 write 系统调用发送数据。这正是 bufferevent"自动管理 IO"的含义。

2. **为什么要检查缓冲区是否为空？**
   `conn_writecb` 在"output 缓冲区低于写水位（默认 0）"时触发，不一定代表全部发完。严格判断 `evbuffer_get_length == 0` 确保数据真正发完后再关闭连接。

3. **bufferevent 是独立的还是共享的？**
   每个连接一个独立的 bufferevent，在 `listener_cb` 中为每个新 fd 调用 `bufferevent_socket_new()` 创建，互不影响。

4. **loopexit vs loopbreak 的区别？**
   - `event_base_loopexit(base, tv)`：**延迟退出**，处理完当前一轮活跃事件后退出（或等待 tv 时间后退出）
   - `event_base_loopbreak(base)`：**立即中断**，当前 dispatch 调用立刻返回，不再处理剩余活跃事件

---

**下一课预告**：第 3 课深入 `event_base`——配置选项、循环控制、优先级、fork 后重初始化，以及如何在 `event.c` 中追踪完整的事件循环流程。
