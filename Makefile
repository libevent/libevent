all: timer

CPPFLAGS = -DTIMER_DEBUG -DTIMER_MAIN
CFLAGS = -O2 -g -Wall -Wextra


.PHONY: clean clean!

clean:
	$(RM) -r timer *.dSYM

clean~: clean
	$(RM) *~
