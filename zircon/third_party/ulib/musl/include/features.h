#ifndef SYSROOT_FEATURES_H_
#define SYSROOT_FEATURES_H_

#if defined(_ALL_SOURCE) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#if !defined(_BSD_SOURCE)
#define _BSD_SOURCE 1
#endif

#if !defined(_POSIX_SOURCE) && !defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE) && \
    !defined(_GNU_SOURCE) && !defined(_BSD_SOURCE) && !defined(__STRICT_ANSI__)
#define _BSD_SOURCE 1
#define _XOPEN_SOURCE 700
#endif

#if __STDC_VERSION__ >= 199901L
#define __restrict restrict
#elif !defined(__GNUC__)
#define __restrict
#endif

#if __STDC_VERSION__ >= 199901L || defined(__cplusplus)
#define __inline inline
#endif

#if __STDC_VERSION__ >= 201112L
#elif defined(__GNUC__)
#define _Noreturn __attribute__((__noreturn__))
#else
#define _Noreturn
#endif

#ifndef __cplusplus
#ifdef __GNUC__
#define __nothrow_fn __attribute__((__nothrow__))
#else
#define __nothrow_fn
#endif
#elif __cplusplus >= 201710L
#define __nothrow_fn noexcept
#else
#define __nothrow_fn throw()
#endif

#endif  // SYSROOT_FEATURES_H_
