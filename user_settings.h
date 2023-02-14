/* user_settings.h
 *
 * Custom configuration for wolfCrypt/wolfSSL.
 * Enabled via WOLFSSL_USER_SETTINGS.
 *
 *
 * Copyright (C) 2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef H_USER_SETTINGS_
#define H_USER_SETTINGS_

/* System */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8
#define BENCH_EMBEDDED
#define NO_WOLFSSL_MEMORY
#define WOLFCRYPT_ONLY

#define WOLFSSL_LWIP
#define WORD64_AVAILABLE
//#define USE_FAST_MATH


/* Debug (very verbose) */
#define DEBUG_WOLFSSH

/* WolfSSH features */
//#define WOLFSSH_SCP
//#define WOLFSSH_SCP_USER_CALLBACKS
#define WOLFSSH_MAX_SFTP_RECV (32 * 1024)
#define WOLFSSH_MAX_SFTP_RW (32 * 1024)
//#define WOLFSSH_SFTP_BUFFER_LIMIT (16*1024)
#define WOLFSSH_LWIP
#define WOLFSSH_NO_TIMESTAMP
#define NO_WOLFSSH_CLIENT
#define WOLFSSH_THREAD

/* SFTP with FATFS */
#define WOLFSSH_SFTP
//#define NO_WOLFSSH_DIR
//#define NO_WOLFSSL_DIR
//#define WOLFSSL_USER_FILESYSTEM
#define WOLFSSH_STOREHANDLE



/* Random seed */
#define HAVE_HASHDRBG

#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_CURRDIR

#define HAVE_ED25519
//#define ED25519_SMALL
#define WOLFSSL_SHA512

#define HAVE_ECC
#define USE_CERT_BUFFERS_256
#define ECC_TIMING_RESISTANT

#define WOLFSSL_SP_MATH_ALL
#define FP_MAX_BITS 8192

#ifndef USE_FAST_MATH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_DH_CONST


/* SP MATH */

#define WOLFSSL_SP_X86_64
//#define WOLFSSL_SP_ASM
//#define WOLFSSL_SP_X86_64_ASM
#define WOLFSSL_SP
#define WOLFSSL_SP_MATH
#define SP_WORD_SIZE 64
#define HAVE___UINT128_T
#endif

/* Curve */
#define HAVE_ECC256

#define HAVE_RSA
#define RSA_LOW_MEM
#define WOLFSSL_HAVE_SP_RSA
#define WC_RSA_BLINDING


#define WOLFSSL_SHA3

#define HAVE_CHACHA
#define HAVE_AESGCM
#define HAVE_AES_ECB
#define HAVE_AES_CBC
#define WOLFSSL_AES_DIRECT
//#define WOLFSSL_AES_COUNTER
#define HAVE_PWDBASED
#define HAVE_POLY1035

/* Disables - For minimum wolfCrypt build */
#define NO_RC4
#define NO_DSA
#define NO_MD4
#define NO_RABBIT
#define NO_SESSION_CACHE
#define NO_HC128
#define NO_DES3
#define WC_RESEED_INTERVAL 200

#define NO_OLD_RNGNAME
#define WOLFSSL_IGNORE_FILE_WARN

#define DEFAULT_HIGHWATER_MARK (1 << 28)

#define BENCH_EMBEDDED
/* Print defines */
#define XPRINTF printf

/* time.h defines for IAR */
#if (defined(__ICCARM__))
#define USE_WOLF_TIMEVAL_T
#define USE_WOLF_SUSECONDS_T
#define WOLFSSL_IAR_ARM_TIME
#endif /* (defined(__ICCARM__)) */


#endif /* !H_USER_SETTINGS_ */
