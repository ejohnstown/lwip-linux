#ifndef SSH_AUTH_INCLUDED
#define SSH_AUTH_INCLUDED
#include "user_settings.h"
#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>

static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}


/* Map user names to passwords */
/* Use arrays for username and p. The password or public key can
 * be hashed and the hash stored here. Then I won't need the type. */
typedef struct PwMap {
    byte type;
    byte username[32];
    word32 usernameSz;
    byte p[WC_SHA256_DIGEST_SIZE];
    struct PwMap* next;
} PwMap;


typedef struct PwMapList {
    PwMap* head;
} PwMapList;

int LoadPasswordBuffer(byte* buf, word32 bufSz, PwMapList* list);
int LoadPublicKeyBuffer(byte* buf, word32 bufSz, PwMapList* list);
int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx);


#endif
