all: timeout timeout8 timeout16 timeout32 timeout64

WHEEL_BIT = 6
WHEEL_NUM = 4

CPPFLAGS = -DTIMEOUT_DEBUG -DTIMEOUT_MAIN
CFLAGS = -O2 -g -Wall -Wextra

timeout: CPPFLAGS+=-DWHEEL_BIT=$(WHEEL_BIT) -DWHEEL_NUM=$(WHEEL_NUM)

timeout8: CPPFLAGS+=-DWHEEL_BIT=3 -DWHEEL_NUM=$(WHEEL_NUM)

timeout16: CPPFLAGS+=-DWHEEL_BIT=4 -DWHEEL_NUM=$(WHEEL_NUM)

timeout32: CPPFLAGS+=-DWHEEL_BIT=5 -DWHEEL_NUM=$(WHEEL_NUM)

timeout64: CPPFLAGS+=-DWHEEL_BIT=6 -DWHEEL_NUM=$(WHEEL_NUM)

timeout64 timeout32 timeout16 timeout8 timeout: timeout.c
	$(CC) $(CFLAGS) -o $@ $^ $(CPPFLAGS)




.PHONY: clean clean~

clean:
	$(RM) -r timeout timeout8 timeout16 timeout32 timeout64 *.dSYM

clean~: clean
	$(RM) *~
