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
Attaching 6 probes...
Tracing libevent loop/dispatch latencies
@loop_dispatch_lat[15208]: 
[1]                    8 |                                                    |
[2, 4)               323 |@@@@@@@@@@@@@@@@                                    |
[4, 8)                19 |                                                    |
[8, 16)               31 |@                                                   |
[16, 32)            1009 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[32, 64)              10 |                                                    |

event loop process_active latencies
@loop_process_active_lat[15208]: 
[8, 16)                9 |                                                    |
[16, 32)             153 |@@@@@@@                                             |
[32, 64)             174 |@@@@@@@@@                                           |
[64, 128)              8 |                                                    |
[128, 256)            25 |@                                                   |
[256, 512)            21 |@                                                   |
[512, 1K)           1004 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1K, 2K)               6 |                                                    |
[2K, 4K)               1 |                                                    |
```
