#ifndef __UNISTD_H__
#define __UNISTD_H__

#ifdef __cplusplus
extern "C" {
#endif

extern int opterr;		/* if error message should be printed */
extern int optind;		/* index into parent argv vector */
extern int optopt;		/* character checked for validity */
extern int optreset;		/* reset getopt */
extern char *optarg;		/* argument associated with option */

int getopt(int, char**, const char*);

#ifdef __cplusplus
}
#endif

#endif /* __UNISTD_H__ */
