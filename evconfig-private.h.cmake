
#ifndef EVCONFIG_PRIVATE_H_INCLUDED_
#define EVCONFIG_PRIVATE_H_INCLUDED_

/* Enable extensions on AIX 3, Interix. Each define is guarded with
 * #ifndef so a system header (e.g. liburing.h on glibc) that
 * pre-defines the same feature macro with a different textual value
 * doesn't trip -Werror=builtin-macro-redefined. Matches the layout the
 * autotools-side evconfig-private.h.in already uses. */
#ifndef _ALL_SOURCE
#cmakedefine _ALL_SOURCE
#endif

/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
#cmakedefine _GNU_SOURCE 1
#endif

/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
#cmakedefine _POSIX_PTHREAD_SEMANTICS 1
#endif

/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
#cmakedefine _TANDEM_SOURCE 1
#endif

/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
#cmakedefine __EXTENSIONS__
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
#cmakedefine _FILE_OFFSET_BITS 1
/* Define for large files, on AIX-style hosts. */
#cmakedefine _LARGE_FILES 1

/* Define to 1 if on MINIX. */
#cmakedefine _MINIX 1

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
#cmakedefine _POSIX_1_SOURCE 1

/* Define to 1 if you need to in order for `stat' and other things to work. */
#cmakedefine _POSIX_SOURCE 1

/* Enable POSIX.2 extensions on QNX for getopt */
#ifdef __QNX__
#cmakedefine __EXT_POSIX2 1
#endif

#endif
