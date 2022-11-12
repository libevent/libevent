#ifndef SHA1_H
#define SHA1_H

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include "stdint.h"

void builtin_SHA1(char *hash_out, const char *str, int len);

#endif /* SHA1_H */
