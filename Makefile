all: timer

WHEEL_BIT = 6
WHEEL_NUM = 4

CPPFLAGS = -DTIMER_DEBUG -DTIMER_MAIN
CFLAGS = -O2 -g -Wall -Wextra


timer: CPPFLAGS+=-DWHEEL_BIT=$(WHEEL_BIT) -DWHEEL_NUM=$(WHEEL_NUM)

timer8: CPPFLAGS+=-DWHEEL_BIT=3 -DWHEEL_NUM=$(WHEEL_NUM)

timer16: CPPFLAGS+=-DWHEEL_BIT=4 -DWHEEL_NUM=$(WHEEL_NUM)

timer32: CPPFLAGS+=-DWHEEL_BIT=5 -DWHEEL_NUM=$(WHEEL_NUM)

timer64: CPPFLAGS+=-DWHEEL_BIT=6 -DWHEEL_NUM=$(WHEEL_NUM)

timer64 timer32 timer16 timer8 timer: timer.c
	$(CC) $(CFLAGS) -o $@ $^ $(CPPFLAGS)




.PHONY: clean clean!

clean:
	$(RM) -r timer timer8 timer16 timer32 timer64 *.dSYM

clean~: clean
	$(RM) *~
