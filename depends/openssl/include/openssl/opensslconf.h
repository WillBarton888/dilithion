/* Minimal opensslconf.h for Windows compilation */
#ifndef HEADER_OPENSSLCONF_H
#define HEADER_OPENSSLCONF_H

#include <openssl/opensslv.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Architecture-specific settings */
#ifdef _WIN64
# define SIXTY_FOUR_BIT
# define BN_LLONG
#else
# define THIRTY_TWO_BIT
#endif

/* Windows-specific defines */
#define OPENSSL_SYS_WINDOWS
#define OPENSSL_EXPORT_VAR_AS_FUNCTION

/* Standard feature flags */
#define OPENSSL_THREADS
#define OPENSSL_NO_STATIC_ENGINE
#define OPENSSL_PIC

/* Minimal configuration - no advanced features needed */
#define NON_EMPTY_TRANSLATION_UNIT static void *dummy = &dummy;

/*
 * Applications should use -DOPENSSL_API_COMPAT=<version> to suppress the
 * declarations of functions deprecated in or before <version>. Otherwise, they
 * still won't see them if the library has been built to disable deprecated
 * functions.
 */
#ifndef DECLARE_DEPRECATED
# define DECLARE_DEPRECATED(f)   f;
# ifdef __GNUC__
#  if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0)
#   undef DECLARE_DEPRECATED
#   define DECLARE_DEPRECATED(f)    f __attribute__ ((deprecated));
#  endif
# elif defined(__SUNPRO_C)
#  if (__SUNPRO_C >= 0x5130)
#   undef DECLARE_DEPRECATED
#   define DECLARE_DEPRECATED(f)    f __attribute__ ((deprecated));
#  endif
# endif
#endif

#ifndef OPENSSL_FILE
# ifdef OPENSSL_NO_FILENAMES
#  define OPENSSL_FILE ""
#  define OPENSSL_LINE 0
# else
#  define OPENSSL_FILE __FILE__
#  define OPENSSL_LINE __LINE__
# endif
#endif

#ifndef OPENSSL_MIN_API
# define OPENSSL_MIN_API 0
#endif

#if !defined(OPENSSL_API_COMPAT) || OPENSSL_API_COMPAT < OPENSSL_MIN_API
# undef OPENSSL_API_COMPAT
# define OPENSSL_API_COMPAT OPENSSL_MIN_API
#endif

/*
 * Do not deprecate things to be deprecated in version 1.2.0 before the
 * OpenSSL version number matches.
 */
#if OPENSSL_VERSION_NUMBER < 0x10200000L
# define DEPRECATEDIN_1_2_0(f)   f;
#elif OPENSSL_API_COMPAT < 0x10200000L
# define DEPRECATEDIN_1_2_0(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_1_2_0(f)
#endif

#if OPENSSL_API_COMPAT < 0x10100000L
# define DEPRECATEDIN_1_1_0(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_1_1_0(f)
#endif

#if OPENSSL_API_COMPAT < 0x10000000L
# define DEPRECATEDIN_1_0_0(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_1_0_0(f)
#endif

#if OPENSSL_API_COMPAT < 0x00908000L
# define DEPRECATEDIN_0_9_8(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_0_9_8(f)
#endif

/* No 386-specific code generation */
#undef I386_ONLY

/* Windows unistd.h equivalent (not used on Windows) */
#define OPENSSL_UNISTD <io.h>

/* RC4 integer type */
#define RC4_INT unsigned int

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_OPENSSLCONF_H */
