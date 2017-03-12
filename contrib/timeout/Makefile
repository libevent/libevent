all: bench bench-wheel.so bench-heap.so

WHEEL_BIT = 6
WHEEL_NUM = 4

CPPFLAGS = -DTIMEOUT_DEBUG
CFLAGS = -O2 -g -Wall -Wextra -Wno-unused-parameter

timeout: CPPFLAGS+=-DWHEEL_BIT=$(WHEEL_BIT) -DWHEEL_NUM=$(WHEEL_NUM)

timeout8: CPPFLAGS+=-DWHEEL_BIT=3 -DWHEEL_NUM=$(WHEEL_NUM)

timeout16: CPPFLAGS+=-DWHEEL_BIT=4 -DWHEEL_NUM=$(WHEEL_NUM)

timeout32: CPPFLAGS+=-DWHEEL_BIT=5 -DWHEEL_NUM=$(WHEEL_NUM)

timeout64: CPPFLAGS+=-DWHEEL_BIT=6 -DWHEEL_NUM=$(WHEEL_NUM)

timeout64 timeout32 timeout16 timeout8 timeout: timeout.c
	$(CC) $(CFLAGS) -o $@ $^ $(CPPFLAGS)

timeout.o: CPPFLAGS=-DWHEEL_BIT=$(WHEEL_BIT) -DWHEEL_NUM=$(WHEEL_NUM)

timeout.o: timeout.c
	$(CC) $(CFLAGS) -c -o $@ $^ $(CPPFLAGS)

bench: bench.c timeout.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -ldl


ifeq ($(shell uname -s), Darwin)
SOFLAGS = -bundle -undefined dynamic_lookup
else
SOFLAGS = -shared
endif

bench-wheel8.so: CPPFLAGS+=-DWHEEL_BIT=3 -DWHEEL_NUM=$(WHEEL_NUM)

bench-wheel8.so: timeout.c

bench-wheel16.so: CPPFLAGS+=-DWHEEL_BIT=4 -DWHEEL_NUM=$(WHEEL_NUM)

bench-wheel16.so: timeout.c

bench-wheel32.so: CPPFLAGS+=-DWHEEL_BIT=5 -DWHEEL_NUM=$(WHEEL_NUM)

bench-wheel32.so: timeout.c

bench-wheel64.so: CPPFLAGS+=-DWHEEL_BIT=6 -DWHEEL_NUM=$(WHEEL_NUM)

bench-wheel64.so: timeout.c

bench-wheel%.so: bench-wheel.c timeout.h
	$(CC) -o $@ $< $(CPPFLAGS) $(CFLAGS) -Wno-unused-function $(SOFLAGS)


bench-wheel.so: CPPFLAGS+=-DWHEEL_BIT=$(WHEEL_BIT) -DWHEEL_NUM=$(WHEEL_NUM)

bench-wheel.so: timeout.c

bench-%.so: bench-%.c timeout.h
	$(CC) -o $@ $< $(CPPFLAGS) $(CFLAGS) -Wno-unused-function $(SOFLAGS)


.PHONY: clean clean~

clean:
	$(RM) -r timeout timeout8 timeout16 timeout32 timeout64 *.dSYM bench *.so *.o

clean~: clean
	$(RM) *~
