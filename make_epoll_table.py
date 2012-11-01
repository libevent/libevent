#!/usr/bin/python2

def get(old,wc,rc):
    if ('xxx' in (rc, wc)):
        return "0",-1

    if ('add' in (rc, wc)):
        events = []
        if rc == 'add' or (rc != 'del' and 'r' in old):
            events.append("EPOLLIN")
        if wc == 'add' or (wc != 'del' and 'w' in old):
            events.append("EPOLLOUT")

        if old == "0":
            op = "EPOLL_CTL_ADD"
        else:
            op = "EPOLL_CTL_MOD"
        return "|".join(events), op

    if ('del' in (rc, wc)):
        op = "EPOLL_CTL_DEL"
        if rc == 'del':
            if wc == 'del':
                events = "EPOLLIN|EPOLLOUT"
            elif 'w' in old:
                events = "EPOLLOUT"
                op = "EPOLL_CTL_MOD"
            else:
                events = "EPOLLIN"
        else:
            assert wc == 'del'
            if 'r' in old:
                events = "EPOLLIN"
                op = "EPOLL_CTL_MOD"
            else:
                events = "EPOLLOUT"
        return events, op

    return 0, 0


def fmt(op, ev, old, wc, rc):
    entry = "{ %s, %s },"%(op, ev)
    assert len(entry)<=36
    sp = " "*(36-len(entry))
    print "\t%s%s/* old=%2s, write:%3s, read:%3s */" % (
        entry, sp, old, wc, rc)


for old in ('0','r','w','rw'):
    for wc in ('0', 'add', 'del', 'xxx'):
        for rc in ('0', 'add', 'del', 'xxx'):

            op,ev = get(old,wc,rc)

            fmt(op, ev, old, wc, rc)

