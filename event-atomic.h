/*
 * Copyright (c) 2009-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ATOMIC_H_INCLUDED_
#define ATOMIC_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__has_builtin)
#define EV_HAS_BUILTIN(x) __has_builtin(x)
#else
#define EV_HAS_BUILTIN(x) 0
#endif

#if EV_HAS_BUILTIN(__atomic_load_n)
#define EV_ATOMIC_LOAD(x) __atomic_load_n(&x, __ATOMIC_ACQUIRE)
#else
#define EV_ATOMIC_LOAD(x) x
#endif

#if EV_HAS_BUILTIN(__atomic_store_n)
#define EV_ATOMIC_STORE(x, v) __atomic_store_n(&x, v, __ATOMIC_RELEASE)
#else
#define EV_ATOMIC_STORE(x, v) (x = v)
#endif

#ifdef __cplusplus
}
#endif

#endif /* ATOMIC_H_INCLUDED_ */

