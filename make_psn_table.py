#!/usr/bin/python2

def get(old,wc,rc,cc):
    if ('xxx' in (rc, wc, cc)):
        return "0",255

    if ('add' in (rc, wc, cc)):
        events = []
        if rc == 'add' or (rc != 'del' and 'r' in old):
            events.append("SOCK_NOTIFY_REGISTER_EVENT_IN")
        if wc == 'add' or (wc != 'del' and 'w' in old):
            events.append("SOCK_NOTIFY_REGISTER_EVENT_OUT")
        if cc == 'add' or (cc != 'del' and 'c' in old):
            events.append("SOCK_NOTIFY_REGISTER_EVENT_HANGUP")

        if old == "0":
            op = "SOCK_NOTIFY_OP_ENABLE"
        else:
            op = "SOCK_NOTIFY_OP_ENABLE"
        return "|".join(events), op

    if ('del' in (rc, wc, cc)):
        delevents = []
        modevents = []
        op = "SOCK_NOTIFY_OP_REMOVE"

        if 'r' in old:
            modevents.append("SOCK_NOTIFY_REGISTER_EVENT_IN")
        if 'w' in old:
            modevents.append("SOCK_NOTIFY_REGISTER_EVENT_OUT")
        if 'c' in old:
            modevents.append("SOCK_NOTIFY_REGISTER_EVENT_HANGUP")

        for item, event in [(rc,"SOCK_NOTIFY_REGISTER_EVENT_IN"),
                            (wc,"SOCK_NOTIFY_REGISTER_EVENT_OUT"),
                            (cc,"SOCK_NOTIFY_REGISTER_EVENT_HANGUP")]:
            if item == 'del':
                delevents.append(event)
                if event in modevents:
                    modevents.remove(event)

        if modevents:
            return "|".join(modevents), "SOCK_NOTIFY_OP_ENABLE"
        else:
            return "|".join(delevents), "SOCK_NOTIFY_OP_REMOVE"

    return 0, 0


def fmt(op, ev, old, wc, rc, cc):
    entry = "{ %s, %s },"%(op, ev)
    comment = "/* old=%3s, write:%3s, read:%3s, close:%3s */" % (old, wc, rc, cc)
    total = "\t%s\n\t%s" % (comment, entry)
    print(total)
    return len(entry)

for old in ('0','r','w','rw','c','cr','cw','crw'):
    for wc in ('0', 'add', 'del', 'xxx'):
        for rc in ('0', 'add', 'del', 'xxx'):
            for cc in ('0', 'add', 'del', 'xxx'):

                op,ev = get(old,wc,rc,cc)

                fmt(op, ev, old, wc, rc, cc)
