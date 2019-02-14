To enable libevent DTRACE probes, 

*WARNING* This has only been tested on linux using perf tools and bpftrace.

Prereqs
==============================
1. Use linux (testing).
2. Install systemtab SDT dev for proper dtrace macros (`sudo apt install systemtap-sdt-dev`)
3. Add the cmake option `-DEVENT__ENABLE_DTRACE=ON`
4. (optional) Install iovisor bcc tools.

Testing
==============================
1. Install `bpftrace` https://github.com/iovisor/bpftrace
2. Start up anything that is linked to /usr/local/lib/libevent.so
3. run: `bpftrace ./libevent.bt`

You should see output histograms like:

```
sudo bpftrace ./libevent.bt 
event_base_loop inner-dispatch latency
@dispatch_latency[94474611720864]:
[1]                  157 |@@@@@                                               |
[2, 4)               259 |@@@@@@@@@                                           |
[4, 8)                16 |                                                    |
[8, 16)               37 |@                                                   |
[16, 32)            1382 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[32, 64)              28 |@                                                   |
[64, 128)              3 |                                                    |

event_base_loop inner-process_active latency
@proc_active_latency[94474611720864]:
[4, 8)                92 |@@@                                                 |
[8, 16)              197 |@@@@@@@                                             |
[16, 32)             160 |@@@@@                                               |
[32, 64)              11 |                                                    |
[64, 128)              8 |                                                    |
[128, 256)             8 |                                                    |
[256, 512)             7 |                                                    |
[512, 1K)           1398 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1K, 2K)               2 |                                                    |
```

This displays a histogram of latencies of the event-dispatch call (e.g.,
epoll()), and the process_active dispatch (user callbacks).

Here we can see that 1382 epoll calls averaged aroudn 16ns latency to execute,
while process_active had 1398 calls between 512-1000ns.


Other Noteworthy Probes
================================
/usr/local/lib/libevent.so libevent.so:bev_suspend_read___enter
/usr/local/lib/libevent.so libevent.so:bev_suspend_read___return
/usr/local/lib/libevent.so libevent.so:bev_unsuspend_read___enter
/usr/local/lib/libevent.so libevent.so:bev_unsuspend_read___return
/usr/local/lib/libevent.so libevent.so:bev_suspend_write___enter
/usr/local/lib/libevent.so libevent.so:bev_suspend_write___return
/usr/local/lib/libevent.so libevent.so:bev_unsuspend_write___enter
/usr/local/lib/libevent.so libevent.so:bev_unsuspend_write___return
/usr/local/lib/libevent.so libevent.so:bev_run_deferred_callbacks___enter
/usr/local/lib/libevent.so libevent.so:assign__enter
/usr/local/lib/libevent.so libevent.so:assign__return
/usr/local/lib/libevent.so libevent.so:process_active_single_queue__enter
/usr/local/lib/libevent.so libevent.so:process_active_single_queue__return
/usr/local/lib/libevent.so libevent.so:process_active_single_queue___usercb_start
/usr/local/lib/libevent.so libevent.so:process_active_single_queue___usercb_end
/usr/local/lib/libevent.so libevent.so:base_loop___enter
/usr/local/lib/libevent.so libevent.so:base_loop___start
/usr/local/lib/libevent.so libevent.so:base_loop___dispatch___start
/usr/local/lib/libevent.so libevent.so:base_loop___dispatch___end
/usr/local/lib/libevent.so libevent.so:base_loop___timeout_proc_start
/usr/local/lib/libevent.so libevent.so:base_loop___timeout_proc_end
/usr/local/lib/libevent.so libevent.so:base_loop___end
/usr/local/lib/libevent.so libevent.so:timeout_process__enter
/usr/local/lib/libevent.so libevent.so:base_loop___process_active___start
/usr/local/lib/libevent.so libevent.so:process_active___enter
/usr/local/lib/libevent.so libevent.so:process_active___return
/usr/local/lib/libevent.so libevent.so:base_loop___process_active___end
/usr/local/lib/libevent.so libevent.so:timeout_process__return
/usr/local/lib/libevent.so libevent.so:base_loop___return
/usr/local/lib/libevent.so libevent.so:new__enter
/usr/local/lib/libevent.so libevent.so:new__return
/usr/local/lib/libevent.so libevent.so:free__enter
/usr/local/lib/libevent.so libevent.so:free__return


NOTES
==================================

`___` == space
`___enter` == function entry
`___return` == function return
`___start` == start of operation/call
`___end` == end of operation/call
