#include <stdint.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <unistd.h>

int
epoll_create(int size)
{
	return (syscall(__NR_epoll_create, size));
}

int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{

	return (syscall(__NR_epoll_ctl, epfd, op, fd, event));
}

int
epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	return (syscall(__NR_epoll_wait, epfd, events, maxevents, timeout));
}
