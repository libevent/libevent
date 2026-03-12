# 第 9 课：evconnlistener 与 TCP Server 完整模式

> **前置要求**：完成第 7、8 课，掌握 bufferevent 的基本与进阶使用
> **本课目标**：深入理解 evconnlistener 的内部实现，掌握完整的 TCP Server 开发范式，熟悉 evutil 跨平台网络工具函数

---

## 1. 为什么需要 evconnlistener

裸 socket 建立 TCP 监听服务器需要五步：

```c
// 裸 socket 监听（跨平台问题多、重复代码多）
int fd = socket(AF_INET, SOCK_STREAM, 0);
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
fcntl(fd, F_SETFL, O_NONBLOCK);        // 非阻塞
bind(fd, (struct sockaddr *)&addr, sizeof(addr));
listen(fd, 128);
// 然后还需要注册 EV_READ|EV_PERSIST 事件，在回调里循环 accept...
```

`evconnlistener` 把这一切封装成一个调用：

```c
struct evconnlistener *lev = evconnlistener_new_bind(
    base, accept_cb, ctx,
    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
    (struct sockaddr *)&sin, sizeof(sin));
```

内部自动完成：`socket → fcntl(NONBLOCK) → setsockopt(REUSEADDR) → bind → listen → event_add(EV_READ|EV_PERSIST)`。

---

## 2. struct evconnlistener 内部结构

### 2.1 公开抽象层（`listener.c` 第 82~97 行）

```c
struct evconnlistener {
    const struct evconnlistener_ops *ops;  // vtable（策略模式）
    void *lock;                            // 线程锁
    evconnlistener_cb cb;                  // accept 成功时的回调
    evconnlistener_errorcb errorcb;        // 不可重试错误时的回调
    void *user_data;                       // 传给回调的参数
    unsigned flags;                        // LEV_OPT_* 标志
    short refcnt;                          // 引用计数
    int accept4_flags;                     // accept4 的标志（NONBLOCK|CLOEXEC）
    unsigned enabled : 1;                  // 是否在监听中
};

// 基于 event 的实现（Unix 平台）
struct evconnlistener_event {
    struct evconnlistener base;
    struct event listener;    // EV_READ|EV_PERSIST 事件，监听 accept
};
```

### 2.2 vtable（操作接口）

```c
struct evconnlistener_ops {
    int (*enable)(struct evconnlistener *);          // event_add
    int (*disable)(struct evconnlistener *);         // event_del
    void (*destroy)(struct evconnlistener *);        // 清理
    void (*shutdown)(struct evconnlistener *);       // 优雅关闭
    evutil_socket_t (*getfd)(struct evconnlistener *);
    struct event_base *(*getbase)(struct evconnlistener *);
};
```

在 Unix 上使用 `evconnlistener_event_ops`；在 Windows + IOCP 上使用 `evconnlistener_iocp` 异步接受。这是**策略模式**的又一次应用。

---

## 3. evconnlistener_new_bind 的创建流程

### 3.1 完整流程（`listener.c` 第 216~309 行）

```c
struct evconnlistener *evconnlistener_new_bind(
    struct event_base *base, evconnlistener_cb cb, void *ptr,
    unsigned flags, int backlog,
    const struct sockaddr *sa, int socklen)
{
    int family = sa ? sa->sa_family : AF_UNSPEC;
    // 1. 创建非阻塞 socket
    int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK;
    if (flags & LEV_OPT_CLOSE_ON_EXEC)
        socktype |= EVUTIL_SOCK_CLOEXEC;
    fd = evutil_socket_(family, socktype, 0);

    // 2. 设置 TCP keepalive（非 Unix socket 时）
    if (family != AF_UNIX)
        evutil_set_tcp_keepalive(fd, 1, 300);

    // 3. 按 flags 设置 socket 选项
    if (flags & LEV_OPT_REUSEABLE)
        evutil_make_listen_socket_reuseable(fd);     // SO_REUSEADDR
    if (flags & LEV_OPT_REUSEABLE_PORT)
        evutil_make_listen_socket_reuseable_port(fd); // SO_REUSEPORT
    if (flags & LEV_OPT_DEFERRED_ACCEPT)
        evutil_make_tcp_listen_socket_deferred(fd);   // TCP_DEFER_ACCEPT
    if (flags & LEV_OPT_BIND_IPV6ONLY)
        evutil_make_listen_socket_ipv6only(fd);       // IPV6_V6ONLY=1
    if (flags & LEV_OPT_BIND_IPV4_AND_IPV6)
        evutil_make_listen_socket_not_ipv6only(fd);   // IPV6_V6ONLY=0

    // 4. bind
    bind(fd, sa, socklen);

    // 5. 调用 evconnlistener_new 继续
    return evconnlistener_new(base, cb, ptr, flags, backlog, fd);
}
```

### 3.2 evconnlistener_new（第 162~214 行）

```c
struct evconnlistener *evconnlistener_new(
    struct event_base *base, evconnlistener_cb cb, void *ptr,
    unsigned flags, int backlog, evutil_socket_t fd)
{
    // backlog < 0 使用默认值 128
    if (backlog > 0)
        listen(fd, backlog);
    else if (backlog < 0)
        listen(fd, 128);

    lev = mm_calloc(1, sizeof(struct evconnlistener_event));
    lev->base.ops = &evconnlistener_event_ops;
    lev->base.cb  = cb;
    lev->base.user_data = ptr;
    lev->base.flags = flags;
    lev->base.refcnt = 1;

    // accept4 标志：新连接自动设置 NONBLOCK / CLOEXEC
    if (!(flags & LEV_OPT_LEAVE_SOCKETS_BLOCKING))
        lev->base.accept4_flags |= EVUTIL_SOCK_NONBLOCK;
    if (flags & LEV_OPT_CLOSE_ON_EXEC)
        lev->base.accept4_flags |= EVUTIL_SOCK_CLOEXEC;

    // 线程安全锁
    if (flags & LEV_OPT_THREADSAFE)
        EVTHREAD_ALLOC_LOCK(lev->base.lock, EVTHREAD_LOCKTYPE_RECURSIVE);

    // 注册 EV_READ|EV_PERSIST 事件（核心！）
    event_assign(&lev->listener, base, fd,
        EV_READ | EV_PERSIST, listener_read_cb, lev);

    // 非 DISABLED 模式则立即启用
    if (!(flags & LEV_OPT_DISABLED))
        evconnlistener_enable(&lev->base);

    return &lev->base;
}
```

**关键点**：监听 socket 本质上就是一个注册了 `EV_READ|EV_PERSIST` 的普通 `event`，fd 可读时说明有新连接排队。

### 3.3 listener_read_cb：核心的 accept 循环（第 435~494 行）

```c
static void listener_read_cb(evutil_socket_t fd, short what, void *p)
{
    struct evconnlistener *lev = p;
    LOCK(lev);

    // 循环 accept，直到 EAGAIN（一次事件可能有多个连接排队）
    while (1) {
        struct sockaddr_storage ss;
        ev_socklen_t socklen = sizeof(ss);

        // 使用 accept4（Linux）一次性设置 NONBLOCK/CLOEXEC
        evutil_socket_t new_fd = evutil_accept4_(fd,
            (struct sockaddr*)&ss, &socklen, lev->accept4_flags);

        if (new_fd < 0)
            break;   // EAGAIN：没有更多连接了

        if (socklen == 0) {
            // 某些老内核 nmap 扫描时会触发，直接关闭
            evutil_closesocket(new_fd);
            continue;
        }

        ++lev->refcnt;   // 防止回调中 free listener
        cb = lev->cb;
        cb(lev, new_fd, (struct sockaddr*)&ss, (int)socklen,
           lev->user_data);  // 调用用户的 accept 回调
        --lev->refcnt;

        if (!lev->enabled) {
            // 回调中可能禁用了 listener（如达到最大连接数）
            UNLOCK(lev);
            return;
        }
    }

    err = evutil_socket_geterror(fd);
    if (EVUTIL_ERR_ACCEPT_RETRIABLE(err)) {
        UNLOCK(lev);
        return;   // EAGAIN / EWOULDBLOCK：正常，下次再说
    }

    // 不可重试的错误：调用 errorcb 或打印警告
    if (lev->errorcb != NULL) {
        errorcb(lev, lev->user_data);
    } else {
        event_sock_warn(fd, "Error from accept() call");
    }
}
```

**注意**：`while(1)` 循环尽可能多地 accept，而不是每次事件只 accept 一个。这对高并发服务器很重要：一个 `epoll_wait` 可能带来几百个新连接，应该全部处理完再返回。

---

## 4. LEV_OPT_* 标志详解

所有标志定义在 `include/event2/listener.h` 第 63~125 行：

| 标志 | 值 | 效果 | 说明 |
|------|----|------|------|
| `LEV_OPT_LEAVE_SOCKETS_BLOCKING` | 1<<0 | 不设 NONBLOCK | 默认会设；极少使用 |
| `LEV_OPT_CLOSE_ON_FREE` | 1<<1 | free 时关闭 socket | **几乎必用** |
| `LEV_OPT_CLOSE_ON_EXEC` | 1<<2 | fork+exec 后关闭 | 推荐加上 |
| `LEV_OPT_REUSEABLE` | 1<<3 | `SO_REUSEADDR` | **几乎必用**，重启时立即可绑定 |
| `LEV_OPT_THREADSAFE` | 1<<4 | 加递归锁 | 多线程时加 |
| `LEV_OPT_DISABLED` | 1<<5 | 创建后不立即监听 | 延迟到 `evconnlistener_enable` |
| `LEV_OPT_DEFERRED_ACCEPT` | 1<<6 | `TCP_DEFER_ACCEPT` | 数据到达后才 accept（减少 accept 次数）|
| `LEV_OPT_REUSEABLE_PORT` | 1<<7 | `SO_REUSEPORT` | 多进程/线程绑同一端口 |
| `LEV_OPT_BIND_IPV6ONLY` | 1<<8 | `IPV6_V6ONLY=1` | 纯 IPv6，不接受 IPv4 连接 |
| `LEV_OPT_BIND_IPV4_AND_IPV6` | 1<<9 | `IPV6_V6ONLY=0` | IPv6 socket 同时接受 IPv4 |

### 4.1 常用标志组合

```c
// 标准服务器（最常用）
LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE

// 多进程端口共享（nginx-style worker 模型）
LEV_OPT_REUSEABLE | LEV_OPT_REUSEABLE_PORT | LEV_OPT_CLOSE_ON_FREE

// 先创建后启用（需要在 accept 回调设置好后再开始监听）
LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_DISABLED

// 高性能：延迟 accept，数据来了才 accept
LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_DEFERRED_ACCEPT
```

### 4.2 LEV_OPT_DEFERRED_ACCEPT 的效果

```
普通 accept（不使用 DEFERRED_ACCEPT）：
  客户端发 SYN → 内核完成三次握手 → accept 返回 fd
  此时 fd 上可能还没有数据，read 会阻塞或 EAGAIN

使用 TCP_DEFER_ACCEPT（Linux 内核特性）：
  客户端发 SYN → 内核完成三次握手
  等待客户端发送第一批数据
  有数据了 → accept 才返回 fd（fd 立即可读）

适用于：客户端连接后立即发送数据的协议（如 HTTP）
不适用于：服务端先说话的协议（如 FTP banner、SSH banner）
```

---

## 5. 完整的 TCP Server 开发范式

### 5.1 标准模板

```c
// tcp_server.c：完整的 TCP Server 模板

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

// ── 连接上下文（每个连接一个）────────────────────────────────────
struct conn_ctx {
    int id;
    // 其他业务状态...
};

static int g_conn_count = 0;

// ── 回调：收到数据 ───────────────────────────────────────────────
static void readcb(struct bufferevent *bev, void *ctx)
{
    struct conn_ctx *cctx = ctx;
    struct evbuffer *input  = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    // 打印客户端地址和接收到的数据量
    size_t len = evbuffer_get_length(input);
    printf("[conn %d] received %zu bytes\n", cctx->id, len);

    // echo：把 input 的数据原样写到 output（零拷贝）
    evbuffer_add_buffer(output, input);
}

// ── 回调：连接状态变化 ────────────────────────────────────────────
static void eventcb(struct bufferevent *bev, short events, void *ctx)
{
    struct conn_ctx *cctx = ctx;

    if (events & BEV_EVENT_EOF) {
        printf("[conn %d] closed by peer\n", cctx->id);
    } else if (events & BEV_EVENT_ERROR) {
        printf("[conn %d] error: %s\n", cctx->id,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    } else if (events & BEV_EVENT_TIMEOUT) {
        printf("[conn %d] timeout\n", cctx->id);
    }

    free(cctx);
    --g_conn_count;
    bufferevent_free(bev);
}

// ── 回调：新连接到来 ─────────────────────────────────────────────
static void accept_cb(
    struct evconnlistener *lev,
    evutil_socket_t fd,
    struct sockaddr *addr,
    int socklen,
    void *ctx)
{
    struct event_base *base = evconnlistener_get_base(lev);

    // 打印客户端地址
    char addrstr[128];
    evutil_inet_ntop(addr->sa_family,
        (addr->sa_family == AF_INET)
            ? (void *)&((struct sockaddr_in *)addr)->sin_addr
            : (void *)&((struct sockaddr_in6 *)addr)->sin6_addr,
        addrstr, sizeof(addrstr));
    int port = (addr->sa_family == AF_INET)
        ? ntohs(((struct sockaddr_in *)addr)->sin_port)
        : ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    printf("New connection from %s:%d (fd=%d)\n", addrstr, port, (int)fd);

    // 创建 bufferevent
    struct bufferevent *bev = bufferevent_socket_new(
        base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        fprintf(stderr, "bufferevent_socket_new failed\n");
        evutil_closesocket(fd);
        return;
    }

    // 创建连接上下文
    struct conn_ctx *cctx = malloc(sizeof(*cctx));
    cctx->id = ++g_conn_count;

    bufferevent_setcb(bev, readcb, NULL, eventcb, cctx);

    // 设置超时：30 秒无数据则断开
    struct timeval tv = {30, 0};
    bufferevent_set_timeouts(bev, &tv, NULL);

    // 防止恶意客户端大量发送数据，input 超过 1MB 暂停读取
    bufferevent_setwatermark(bev, EV_READ, 0, 1024 * 1024);

    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

// ── 回调：accept 错误 ────────────────────────────────────────────
static void accept_error_cb(struct evconnlistener *lev, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(lev);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Fatal accept error %d: %s\n", err,
        evutil_socket_error_to_string(err));

    // 严重错误，退出事件循环
    event_base_loopexit(base, NULL);
}

int main(void)
{
    struct event_base *base = event_base_new();

    // 支持 IPv4
    struct sockaddr_in sin4 = {0};
    sin4.sin_family = AF_INET;
    sin4.sin_port   = htons(9999);
    // sin4.sin_addr.s_addr = 0 → 监听所有网卡

    struct evconnlistener *lev = evconnlistener_new_bind(
        base, accept_cb, NULL,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
        -1,  // backlog：-1 使用默认值 128
        (struct sockaddr *)&sin4, sizeof(sin4));

    if (!lev) {
        perror("evconnlistener_new_bind");
        return 1;
    }

    evconnlistener_set_error_cb(lev, accept_error_cb);

    printf("Server listening on port 9999\n");
    printf("Backend: %s\n", event_base_get_method(base));

    event_base_dispatch(base);

    evconnlistener_free(lev);
    event_base_free(base);
    return 0;
}
```

### 5.2 同时监听 IPv4 和 IPv6

```c
// 方法 1：两个监听器（推荐，兼容性最好）
struct sockaddr_in  sin4 = {0};
sin4.sin_family = AF_INET;
sin4.sin_port   = htons(9999);

struct sockaddr_in6 sin6 = {0};
sin6.sin6_family = AF_INET6;
sin6.sin6_port   = htons(9999);
// sin6.sin6_addr = in6addr_any

struct evconnlistener *lev4 = evconnlistener_new_bind(
    base, accept_cb, NULL,
    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
    (struct sockaddr *)&sin4, sizeof(sin4));

struct evconnlistener *lev6 = evconnlistener_new_bind(
    base, accept_cb, NULL,
    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_BIND_IPV6ONLY, -1,
    (struct sockaddr *)&sin6, sizeof(sin6));

// 方法 2：单个 IPv6 socket 接受 IPv4（IPv4-mapped）
// 注意：此方法在某些系统上（如 OpenBSD）不支持
struct evconnlistener *lev = evconnlistener_new_bind(
    base, accept_cb, NULL,
    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_BIND_IPV4_AND_IPV6, -1,
    (struct sockaddr *)&sin6, sizeof(sin6));
```

### 5.3 从已有 fd 创建监听器

当已经在外部完成 socket/bind/listen（如接管父进程的 fd）：

```c
// 从已有的 listening fd 创建
// fd 必须已经是非阻塞的，且已经 bind+listen
struct evconnlistener *lev = evconnlistener_new(
    base, accept_cb, NULL,
    LEV_OPT_CLOSE_ON_FREE,  // 注意：不加 REUSEABLE，fd 已经配置好
    0,    // backlog=0：不再调用 listen（已经 listen 了）
    existing_fd);
```

---

## 6. 动态控制监听器

```c
// 暂停接受新连接（如达到最大连接数）
evconnlistener_disable(lev);

// 恢复接受
evconnlistener_enable(lev);

// 运行时更换回调
evconnlistener_set_cb(lev, new_accept_cb, new_ctx);

// 获取监听 fd（用于 getsockname 等）
evutil_socket_t fd = evconnlistener_get_fd(lev);

// 获取关联的 event_base
struct event_base *base = evconnlistener_get_base(lev);
```

**限制连接数示例**：

```c
#define MAX_CONNECTIONS 1000
static int active_connections = 0;

static void accept_cb(struct evconnlistener *lev, evutil_socket_t fd,
                      struct sockaddr *addr, int socklen, void *ctx)
{
    if (active_connections >= MAX_CONNECTIONS) {
        // 超过限制：拒绝连接
        evutil_closesocket(fd);
        // 暂停接受，等连接减少后再恢复
        evconnlistener_disable(lev);
        return;
    }

    ++active_connections;
    // ... 创建 bufferevent ...
}

static void eventcb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        --active_connections;
        if (active_connections < MAX_CONNECTIONS) {
            // 连接减少了，恢复接受
            evconnlistener_enable(g_listener);
        }
        bufferevent_free(bev);
    }
}
```

---

## 7. evutil 跨平台工具函数

`include/event2/util.h` 提供了大量跨平台工具，让同一份代码在 Linux/macOS/Windows 上都能编译运行。

### 7.1 Socket 操作

```c
// 设置 socket 为非阻塞（跨平台，Unix 用 fcntl，Windows 用 ioctlsocket）
int evutil_make_socket_nonblocking(evutil_socket_t sock);

// SO_REUSEADDR（允许快速重用端口）
int evutil_make_listen_socket_reuseable(evutil_socket_t sock);

// SO_REUSEPORT（Linux 3.9+，多进程/线程绑同一端口）
int evutil_make_listen_socket_reuseable_port(evutil_socket_t sock);

// FD_CLOEXEC（fork+exec 后关闭）
int evutil_make_socket_closeonexec(evutil_socket_t sock);

// 关闭 socket（跨平台：Unix 用 close，Windows 用 closesocket）
int evutil_closesocket(evutil_socket_t sock);

// 创建 socketpair（跨平台）
int evutil_socketpair(int domain, int type, int protocol, evutil_socket_t sv[2]);
```

### 7.2 地址与 DNS

```c
// IP 地址字符串 ↔ 二进制（跨平台 inet_ntop/inet_pton）
const char *evutil_inet_ntop(int af, const void *src, char *dst, size_t len);
int evutil_inet_pton(int af, const char *src, void *dst);

// 解析 "IP:port" 或 "[IPv6]:port" 格式的字符串
int evutil_parse_sockaddr_port(const char *str, struct sockaddr *out, int *outlen);

// 比较两个 sockaddr（可选是否比较端口）
int evutil_sockaddr_cmp(const struct sockaddr *sa1, const struct sockaddr *sa2,
    int include_port);

// 阻塞的域名解析（跨平台 getaddrinfo 封装）
int evutil_getaddrinfo(const char *nodename, const char *servname,
    const struct evutil_addrinfo *hints, struct evutil_addrinfo **res);
void evutil_freeaddrinfo(struct evutil_addrinfo *ai);
const char *evutil_gai_strerror(int err);
```

### 7.3 错误处理

```c
// 获取最后一个 socket 错误码（跨平台：Unix 用 errno，Windows 用 WSAGetLastError）
#define EVUTIL_SOCKET_ERROR()           // 返回 int
int evutil_socket_geterror(evutil_socket_t sock);

// 错误码转字符串
const char *evutil_socket_error_to_string(int errcode);
```

**使用示例**：

```c
void eventcb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_ERROR) {
        int err = EVUTIL_SOCKET_ERROR();
        fprintf(stderr, "Socket error %d: %s\n", err,
            evutil_socket_error_to_string(err));
        bufferevent_free(bev);
    }
}
```

### 7.4 字符串处理

```c
// 安全的 snprintf（总是写入终止符，返回期望长度而非实际长度）
int evutil_snprintf(char *buf, size_t buflen, const char *format, ...);
int evutil_vsnprintf(char *buf, size_t buflen, const char *format, va_list ap);

// 大小写不敏感的字符串比较（locale 无关）
int evutil_ascii_strcasecmp(const char *str1, const char *str2);
int evutil_ascii_strncasecmp(const char *str1, const char *str2, size_t n);
```

### 7.5 随机数

```c
// 密码学安全的随机字节（内部使用 /dev/urandom 或 BCryptGenRandom）
void evutil_secure_rng_get_bytes(void *buf, size_t n);

// 手动初始化（通常不需要，libevent 会自动初始化）
int evutil_secure_rng_init(void);
```

### 7.6 整数类型（跨平台固定宽度）

```c
// include/event2/util.h 提供的跨平台整数类型
ev_int8_t    ev_uint8_t      // 8 位
ev_int16_t   ev_uint16_t     // 16 位
ev_int32_t   ev_uint32_t     // 32 位
ev_int64_t   ev_uint64_t     // 64 位
ev_ssize_t                   // 有符号的 size_t
evutil_socket_t              // socket 类型（Unix=int，Windows=SOCKET）
```

---

## 8. 完整综合示例：多功能 TCP Server

```c
// multi_server.c：支持连接统计、限速、超时的完整服务器

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define MAX_CONNS    500
#define IDLE_TIMEOUT 60    // 秒
#define READ_LIMIT   (64 * 1024)   // 64KB 高水位

struct server_state {
    struct event_base *base;
    struct evconnlistener *listener;
    int conn_count;
    ev_uint64_t total_bytes_read;
    ev_uint64_t total_bytes_written;
};

struct conn_state {
    struct server_state *server;
    int id;
    char peer_addr[64];
};

static void readcb(struct bufferevent *bev, void *ctx)
{
    struct conn_state *cs = ctx;
    struct evbuffer *input  = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    size_t n = evbuffer_get_length(input);
    cs->server->total_bytes_read += n;

    // echo
    evbuffer_add_buffer(output, input);
}

static void eventcb(struct bufferevent *bev, short events, void *ctx)
{
    struct conn_state *cs = ctx;

    if (events & BEV_EVENT_EOF)
        printf("[%s] closed\n", cs->peer_addr);
    else if (events & BEV_EVENT_ERROR)
        printf("[%s] error: %s\n", cs->peer_addr,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    else if (events & BEV_EVENT_TIMEOUT)
        printf("[%s] idle timeout\n", cs->peer_addr);

    --cs->server->conn_count;

    // 恢复监听（如果之前因超过上限而暂停）
    if (cs->server->conn_count < MAX_CONNS &&
        !evconnlistener_enable(cs->server->listener)) {
        // 已经在监听，不需要额外操作
    }

    free(cs);
    bufferevent_free(bev);
}

static void accept_cb(struct evconnlistener *lev, evutil_socket_t fd,
                      struct sockaddr *addr, int socklen, void *ctx)
{
    struct server_state *srv = ctx;

    if (srv->conn_count >= MAX_CONNS) {
        evutil_closesocket(fd);
        evconnlistener_disable(lev);
        return;
    }

    // 格式化客户端地址
    char addrstr[INET6_ADDRSTRLEN] = "";
    int port = 0;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)addr;
        evutil_inet_ntop(AF_INET, &s4->sin_addr, addrstr, sizeof(addrstr));
        port = ntohs(s4->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)addr;
        evutil_inet_ntop(AF_INET6, &s6->sin6_addr, addrstr, sizeof(addrstr));
        port = ntohs(s6->sin6_port);
    }

    struct bufferevent *bev = bufferevent_socket_new(
        srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) { evutil_closesocket(fd); return; }

    struct conn_state *cs = malloc(sizeof(*cs));
    cs->server = srv;
    cs->id = ++srv->conn_count;
    evutil_snprintf(cs->peer_addr, sizeof(cs->peer_addr),
        "%s:%d", addrstr, port);

    printf("[%s] connected (total: %d)\n", cs->peer_addr, srv->conn_count);

    bufferevent_setcb(bev, readcb, NULL, eventcb, cs);

    // 空闲超时
    struct timeval tv = {IDLE_TIMEOUT, 0};
    bufferevent_set_timeouts(bev, &tv, NULL);

    // 高水位防止内存膨胀
    bufferevent_setwatermark(bev, EV_READ, 0, READ_LIMIT);

    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

static void accept_error_cb(struct evconnlistener *lev, void *ctx)
{
    struct server_state *srv = ctx;
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "accept error: %s\n", evutil_socket_error_to_string(err));
    event_base_loopexit(srv->base, NULL);
}

// 每 10 秒打印统计信息
static void stats_cb(evutil_socket_t fd, short events, void *ctx)
{
    struct server_state *srv = ctx;
    printf("=== Stats: connections=%d, rx=%llu bytes, tx=%llu bytes ===\n",
        srv->conn_count,
        (unsigned long long)srv->total_bytes_read,
        (unsigned long long)srv->total_bytes_written);
}

int main(void)
{
    struct server_state srv = {0};
    srv.base = event_base_new();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9999);

    srv.listener = evconnlistener_new_bind(
        srv.base, accept_cb, &srv,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
        (struct sockaddr *)&sin, sizeof(sin));

    evconnlistener_set_error_cb(srv.listener, accept_error_cb);

    // 定期打印统计
    struct timeval tv = {10, 0};
    struct event *stats_ev = event_new(srv.base, -1,
        EV_PERSIST, stats_cb, &srv);
    event_add(stats_ev, &tv);

    printf("Server started: %s backend, port 9999\n",
        event_base_get_method(srv.base));

    event_base_dispatch(srv.base);

    event_free(stats_ev);
    evconnlistener_free(srv.listener);
    event_base_free(srv.base);
    return 0;
}
```

---

## 9. 从 Unix Socket 到 TCP：evutil_parse_sockaddr_port

```c
// 从字符串解析地址，支持以下格式：
// "127.0.0.1:9999"  → IPv4
// "[::1]:9999"      → IPv6
// "0.0.0.0:0"       → 任意 IPv4 + 随机端口

struct sockaddr_storage ss;
int sslen = sizeof(ss);

const char *addr_str = "127.0.0.1:9999";
if (evutil_parse_sockaddr_port(addr_str, (struct sockaddr *)&ss, &sslen) < 0) {
    fprintf(stderr, "Invalid address: %s\n", addr_str);
    return -1;
}

struct evconnlistener *lev = evconnlistener_new_bind(
    base, accept_cb, NULL,
    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
    (struct sockaddr *)&ss, sslen);
```

---

## 10. 动手实践

### 练习 1：多端口监听

创建一个服务器同时监听 9999（echo 服务）和 8888（大写转换服务）：

```c
// 提示：创建两个 evconnlistener，共享同一个 event_base
// accept_cb 通过 user_data 区分是哪个服务
struct service {
    const char *name;
    void (*handle)(struct bufferevent *bev, struct evbuffer *input);
};
```

### 练习 2：连接数限制

修改上面的 `multi_server.c`，实现：
- 超过 MAX_CONNS 时自动暂停 accept
- 连接关闭后自动恢复 accept
- 打印"rejected N connections"统计

### 练习 3：回答问题

1. `evconnlistener_new_bind` 中的 `backlog=-1` 和 `backlog=0` 有什么区别？
2. `listener_read_cb` 为什么要用 `while(1)` 循环 accept，而不是每次只 accept 一个？
3. `LEV_OPT_DEFERRED_ACCEPT` 为什么只对 `evconnlistener_new_bind` 有效，对 `evconnlistener_new` 无效？

---

## 11. 本课小结

| 概念 | 关键点 |
|------|--------|
| `evconnlistener` | 封装了 socket/bind/listen/accept 全流程 |
| `LEV_OPT_REUSEABLE` | 几乎必加，快速重用端口（SO_REUSEADDR） |
| `LEV_OPT_CLOSE_ON_FREE` | 几乎必加，free 时关闭 socket |
| `LEV_OPT_REUSEABLE_PORT` | SO_REUSEPORT，多进程共享端口（Linux 3.9+）|
| `LEV_OPT_DEFERRED_ACCEPT` | TCP_DEFER_ACCEPT，减少 accept 次数 |
| `listener_read_cb` | while(1) 循环批量 accept，不是一次只 accept 一个 |
| `evutil_inet_ntop` | 跨平台 IP 地址格式化 |
| `EVUTIL_SOCKET_ERROR()` | 跨平台获取错误码 |
| `evutil_parse_sockaddr_port` | 解析 "IP:port" 字符串 |

**三句话总结**：

1. `evconnlistener` 本质是一个注册了 `EV_READ|EV_PERSIST` 的 event，监听 fd 可读时批量 accept
2. 标准模板：`evconnlistener_new_bind` + accept_cb 创建 bufferevent + 设置 readcb/eventcb + enable
3. `evutil` 提供跨平台 socket 操作、地址转换、错误处理，让同一份代码在各平台无缝编译

---

## 附：练习 3 答案

1. **backlog=-1 vs backlog=0**：
   - `backlog=-1`：内部调用 `listen(fd, 128)`，使用默认值
   - `backlog=0`：内部**不调用** `listen()`，假设 fd 已经在 listening 状态（适合接管已有 fd 的场景）
   - `backlog>0`：直接使用该值调用 `listen(fd, backlog)`

2. **为什么用 while(1) 循环**：
   一次 `epoll_wait` 返回的可读事件代表"有新连接"，但可能同时有几十甚至几百个连接排队。如果每次事件只 accept 一个，剩余的连接要等下一次 `epoll_wait` 才能处理，增加延迟。循环 accept 直到 EAGAIN，可以在一轮事件处理中消化所有积压连接。

3. **LEV_OPT_DEFERRED_ACCEPT 只对 new_bind 有效**：
   `TCP_DEFER_ACCEPT` 是一个在 `listen()` 之前必须设置的 socket option（内核在 listen 时初始化延迟参数）。`evconnlistener_new_bind` 在 `listen()` 之前调用 `evutil_make_tcp_listen_socket_deferred()`，所以有效。而 `evconnlistener_new` 接收的 fd 已经完成了 `listen()`，此时再设置无效（所以代码里直接返回错误/忽略）。

---

**下一课预告**：第 10 课深入信号处理 —— `evsignal` 的信号管道机制、`signalfd` 实现，以及 `evutil` 工具函数（随机数、时间、字符串）的完整使用指南。
