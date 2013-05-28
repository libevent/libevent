all: timer

WHEEL_BIT = 6
WHEEL_NUM = 4

CPPFLAGS = -DTIMER_DEBUG -DTIMER_MAIN -DWHEEL_BIT=$(WHEEL_BIT) -DWHEEL_NUM=$(WHEEL_NUM)
CFLAGS = -O2 -g -Wall -Wextra


.PHONY: clean clean!

clean:
	$(RM) -r timer *.dSYM

clean~: clean
	$(RM) *~
