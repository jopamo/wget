/* NTLM code.
 * src/http-ntlm.c
 */

#include "wget.h"

/* NTLM details:

   http://davenport.sourceforge.net/ntlm.html
   http://www.innovation.ch/java/ntlm.html

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "http-ntlm.h"

#include <openssl/evp.h>

/* Define this to make the type-3 message include the NT response message */
#define USE_NTRESPONSES 1

/* Flag bits definitions available at on
   http://davenport.sourceforge.net/ntlm.html */

#define NTLMFLAG_NEGOTIATE_OEM (1 << 1)
#define NTLMFLAG_NEGOTIATE_NTLM_KEY (1 << 9)

/*
  (*) = A "security buffer" is a triplet consisting of two shorts and one
  long:

  1. a 'short' containing the length of the buffer in bytes
  2. a 'short' containing the allocated space for the buffer in bytes
  3. a 'long' containing the offset to the start of the buffer from the
     beginning of the NTLM message, in bytes.
*/

/* return true on success, false otherwise */
bool ntlm_input(struct ntlmdata* ntlm, const char* header) {
  if (0 != strncmp(header, "NTLM", 4))
    return false;

  header += 4;
  while (*header && c_isspace(*header))
    header++;

  if (*header) {
    /* We got a type-2 message here:

       Index   Description         Content
       0       NTLMSSP Signature   Null-terminated ASCII "NTLMSSP"
                                   (0x4e544c4d53535000)
       8       NTLM Message Type   long (0x02000000)
       12      Target Name         security buffer(*)
       20      Flags               long
       24      Challenge           8 bytes
       (32)    Context (optional)  8 bytes (two consecutive longs)
       (40)    Target Information  (optional) security buffer(*)
       32 (48) start of data block
    */
    ssize_t size;
    char buffer[48];  // decode 48 bytes needs ((48 + 2) / 3) * 4 + 1 bytes

    DEBUGP(("Received a type-2 NTLM message.\n"));

    size = wget_base64_decode(header, buffer, sizeof(buffer));
    if (size < 0)
      return false; /* malformed base64 from server */

    ntlm->state = NTLMSTATE_TYPE2; /* we got a type-2 */

    if ((size_t)size >= sizeof(buffer))
      /* the nonce of interest is index [24 .. 31], 8 bytes */
      memcpy(ntlm->nonce, &buffer[24], 8);

    /* at index decimal 20, there's a 32bit NTLM flag field */
  }
  else {
    if (ntlm->state == NTLMSTATE_LAST) {
      DEBUGP(("NTLM auth restarted.\n"));
      /* no return, continue */
    }
    else if (ntlm->state == NTLMSTATE_TYPE3) {
      DEBUGP(("NTLM handshake rejected.\n"));
      ntlm->state = NTLMSTATE_NONE;
      return false;
    }
    else if (ntlm->state >= NTLMSTATE_TYPE1) {
      DEBUGP(("Unexpected empty NTLM message.\n"));
      return false; /* this is an error */
    }

    DEBUGP(("Empty NTLM message, (re)starting transaction.\n"));
    ntlm->state = NTLMSTATE_TYPE1; /* we should sent away a type-1 */
  }

  return true;
}

static unsigned char odd_parity(unsigned char byte) {
  unsigned char v = byte & 0xFE;
  unsigned char parity = 1;

  for (unsigned char b = v; b; b >>= 1)
    parity ^= (b & 1);

  return v | parity;
}

/*
 * Turns a 56 bit key into the 64 bit, odd parity key.
 */
static void setup_des_key(const unsigned char* key_56, unsigned char key[8]) {
  key[0] = key_56[0];
  key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
  key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
  key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
  key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
  key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
  key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
  key[7] = (key_56[6] << 1) & 0xFF;

  for (int i = 0; i < 8; i++)
    key[i] = odd_parity(key[i]);
}

static bool des_ecb_encrypt_block(const unsigned char key[8], const unsigned char* plaintext, unsigned char* results) {
  bool ok = false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  if (!ctx)
    return false;

  if (EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key, NULL) == 1 && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1) {
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, results, &outlen, plaintext, 8) == 1 && outlen == 8) {
      int finallen = 0;
      if (EVP_EncryptFinal_ex(ctx, results + outlen, &finallen) == 1 && finallen == 0)
        ok = true;
    }
  }

  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

/*
 * takes a 21 byte array and treats it as 3 56-bit DES keys. The
 * 8 byte plaintext is encrypted with each key and the resulting 24
 * bytes are stored in the results array.
 */
static bool calc_resp(unsigned char* keys, unsigned char* plaintext, unsigned char* results) {
  unsigned char key[8];

  setup_des_key(keys, key);
  if (!des_ecb_encrypt_block(key, plaintext, results))
    return false;

  setup_des_key(keys + 7, key);
  if (!des_ecb_encrypt_block(key, plaintext, results + 8))
    return false;

  setup_des_key(keys + 14, key);
  return des_ecb_encrypt_block(key, plaintext, results + 16);
}

/*
 * Set up lanmanager and nt hashed passwords
 */
static bool mkhash(const char* password,
                   unsigned char* nonce, /* 8 bytes */
                   unsigned char* lmresp /* must fit 0x18 bytes */
#ifdef USE_NTRESPONSES
                   ,
                   unsigned char* ntresp /* must fit 0x18 bytes */
#endif
) {
  unsigned char lmbuffer[21];
#ifdef USE_NTRESPONSES
  unsigned char ntbuffer[21];
#endif
  unsigned char pw[14];
  static const unsigned char magic[] = {0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
  size_t i, len = strlen(password);

  /* make it fit at least 14 bytes */

  if (len > sizeof(pw))
    len = sizeof(pw);

  for (i = 0; i < len; i++)
    pw[i] = (unsigned char)c_toupper(password[i]);

  for (; i < sizeof(pw); i++)
    pw[i] = 0;

  {
    unsigned char key[8];

    /* create LanManager hashed password */
    setup_des_key(pw, key);
    if (!des_ecb_encrypt_block(key, magic, lmbuffer))
      return false;

    setup_des_key(pw + 7, key);
    if (!des_ecb_encrypt_block(key, magic, lmbuffer + 8))
      return false;

    memset(lmbuffer + 16, 0, 5);
  }
  /* create LM responses */
  if (!calc_resp(lmbuffer, nonce, lmresp))
    return false;

#ifdef USE_NTRESPONSES
  {
    unsigned char pw4[64];

    len = strlen(password);

    if (len > sizeof(pw4) / 2)
      len = sizeof(pw4) / 2;

    for (i = 0; i < len; i++) {
      pw4[2 * i] = (unsigned char)password[i];
      pw4[2 * i + 1] = 0;
    }

    /* create NT hashed password */
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    unsigned int outlen = 0;

    if (!md)
      return false;

    if (EVP_DigestInit_ex(md, EVP_md4(), NULL) != 1 || EVP_DigestUpdate(md, pw4, 2 * len) != 1 || EVP_DigestFinal_ex(md, ntbuffer, &outlen) != 1) {
      EVP_MD_CTX_free(md);
      return false;
    }

    EVP_MD_CTX_free(md);

    memset(ntbuffer + 16, 0, 5);
  }

  if (!calc_resp(ntbuffer, nonce, ntresp))
    return false;
#endif

  return true;
}

#define SHORTPAIR(x) (char)((x) & 0xff), (char)((x) >> 8)
#define LONGQUARTET(x) ((x) & 0xff), (((x) >> 8) & 0xff), (((x) >> 16) & 0xff), ((x) >> 24)

/* this is for creating ntlm header output */
char* ntlm_output(struct ntlmdata* ntlm, const char* user, const char* passwd, bool* ready) {
  const char* domain = ""; /* empty */
  const char* host = "";   /* empty */
  size_t domlen = strlen(domain);
  size_t hostlen = strlen(host);
  size_t hostoff; /* host name offset */
  size_t domoff;  /* domain name offset */
  size_t size;
  char ntlmbuf[256]; /* enough, unless the host/domain is very long */

  /* point to the address of the pointer that holds the string to sent to the
     server, which is for a plain host or for a HTTP proxy */
  char* output = NULL;

  *ready = false;

  /* not set means empty */
  if (!user)
    user = "";

  if (!passwd)
    passwd = "";

  switch (ntlm->state) {
    case NTLMSTATE_TYPE1:
    case NTLMSTATE_NONE:
    case NTLMSTATE_LAST:
      hostoff = 32;
      domoff = hostoff + hostlen;

      DEBUGP(("Creating a type-1 NTLM message.\n"));

      /* Create and send a type-1 message:

      Index Description          Content
      0     NTLMSSP Signature    Null-terminated ASCII "NTLMSSP"
                                 (0x4e544c4d53535000)
      8     NTLM Message Type    long (0x01000000)
      12    Flags                long
      16    Supplied Domain      security buffer(*)
      24    Supplied Workstation security buffer(*)
      32    start of data block

      */

      snprintf(ntlmbuf, sizeof(ntlmbuf),
               "NTLMSSP%c"
               "\x01%c%c%c" /* 32-bit type = 1 */
               "%c%c%c%c"   /* 32-bit NTLM flag field */
               "%c%c"       /* domain length */
               "%c%c"       /* domain allocated space */
               "%c%c"       /* domain name offset */
               "%c%c"       /* 2 zeroes */
               "%c%c"       /* host length */
               "%c%c"       /* host allocated space */
               "%c%c"       /* host name offset */
               "%c%c"       /* 2 zeroes */
               "%s"         /* host name */
               "%s",        /* domain string */
               0,           /* trailing zero */
               0, 0, 0,     /* part of type-1 long */

               LONGQUARTET(NTLMFLAG_NEGOTIATE_OEM |    /*   2 */
                           NTLMFLAG_NEGOTIATE_NTLM_KEY /* 200 */
                           /* equals 0x0202 */
                           ),
               SHORTPAIR(domlen), SHORTPAIR(domlen), SHORTPAIR(domoff), 0, 0, SHORTPAIR(hostlen), SHORTPAIR(hostlen), SHORTPAIR(hostoff), 0, 0, host, domain);

      /* initial packet length */
      size = 32 + hostlen + domlen;

      output = xmalloc(5 + BASE64_LENGTH(size) + 1);
      memcpy(output, "NTLM ", 5);
      wget_base64_encode(ntlmbuf, size, output + 5);

      break;

    case NTLMSTATE_TYPE2:
      /* We received the type-2 already, create a type-3 message:

      Index   Description            Content
      0       NTLMSSP Signature      Null-terminated ASCII "NTLMSSP"
                                     (0x4e544c4d53535000)
      8       NTLM Message Type      long (0x03000000)
      12      LM/LMv2 Response       security buffer(*)
      20      NTLM/NTLMv2 Response   security buffer(*)
      28      Domain Name            security buffer(*)
      36      User Name              security buffer(*)
      44      Workstation Name       security buffer(*)
      (52)    Session Key (optional) security buffer(*)
      (60)    Flags (optional)       long
      52 (64) start of data block

      */

      {
        size_t lmrespoff;
        size_t ntrespoff;
        size_t useroff;
        unsigned char lmresp[0x18]; /* fixed-size */
#ifdef USE_NTRESPONSES
        unsigned char ntresp[0x18]; /* fixed-size */
#endif
        const char* usr;
        size_t userlen;

        DEBUGP(("Creating a type-3 NTLM message.\n"));

        usr = strchr(user, '\\');
        if (!usr)
          usr = strchr(user, '/');

        if (usr) {
          domain = user;
          domlen = (size_t)(usr - domain);
          usr++;
        }
        else
          usr = user;
        userlen = strlen(usr);

        if (!mkhash(passwd, &ntlm->nonce[0], lmresp
#ifdef USE_NTRESPONSES
                    ,
                    ntresp
#endif
                    )) {
          DEBUGP(("Failed to create NTLM hash values.\n"));
          return NULL;
        }

        domoff = 64; /* always */
        useroff = domoff + domlen;
        hostoff = useroff + userlen;
        lmrespoff = hostoff + hostlen;
        ntrespoff = lmrespoff + 0x18;

        /* Create the big type-3 message binary blob */

        snprintf(ntlmbuf, sizeof(ntlmbuf),
                 "NTLMSSP%c"
                 "\x03%c%c%c" /* type-3, 32 bits */

                 "%c%c%c%c" /* LanManager length + allocated space */
                 "%c%c"     /* LanManager offset */
                 "%c%c"     /* 2 zeroes */

                 "%c%c" /* NT-response length */
                 "%c%c" /* NT-response allocated space */
                 "%c%c" /* NT-response offset */
                 "%c%c" /* 2 zeroes */

                 "%c%c" /* domain length */
                 "%c%c" /* domain allocated space */
                 "%c%c" /* domain name offset */
                 "%c%c" /* 2 zeroes */

                 "%c%c" /* user length */
                 "%c%c" /* user allocated space */
                 "%c%c" /* user offset */
                 "%c%c" /* 2 zeroes */

                 "%c%c"         /* host length */
                 "%c%c"         /* host allocated space */
                 "%c%c"         /* host offset */
                 "%c%c%c%c%c%c" /* 6 zeroes */

                 "\xff\xff" /* message length */
                 "%c%c"     /* 2 zeroes */

                 "\x01\x82" /* flags */
                 "%c%c"     /* 2 zeroes */

                 /* domain string */
                 /* user string */
                 /* host string */
                 /* LanManager response */
                 /* NT response */
                 ,
                 0,       /* zero termination */
                 0, 0, 0, /* type-3 long, the 24 upper bits */

                 SHORTPAIR(0x18), /* LanManager response length, twice */
                 SHORTPAIR(0x18), SHORTPAIR(lmrespoff), 0x0, 0x0,

#ifdef USE_NTRESPONSES
                 SHORTPAIR(0x18), /* NT-response length, twice */
                 SHORTPAIR(0x18),
#else
                 0x0, 0x0, 0x0, 0x0,
#endif
                 SHORTPAIR(ntrespoff), 0x0, 0x0,

                 SHORTPAIR(domlen), SHORTPAIR(domlen), SHORTPAIR(domoff), 0x0, 0x0,

                 SHORTPAIR(userlen), SHORTPAIR(userlen), SHORTPAIR(useroff), 0x0, 0x0,

                 SHORTPAIR(hostlen), SHORTPAIR(hostlen), SHORTPAIR(hostoff), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,

                 0x0, 0x0,

                 0x0, 0x0);

        /* size is now 64 */
        size = 64;
        ntlmbuf[62] = ntlmbuf[63] = 0;

        /* Make sure that the user and domain strings fit in the target buffer
           before we copy them there. */
        if ((size + userlen + domlen) >= sizeof(ntlmbuf))
          return NULL;

        memcpy(&ntlmbuf[size], domain, domlen);
        size += domlen;

        memcpy(&ntlmbuf[size], usr, userlen);
        size += userlen;

        /* we append the binary hashes to the end of the blob */
        if (size < (sizeof(ntlmbuf) - 0x18)) {
          memcpy(&ntlmbuf[size], lmresp, 0x18);
          size += 0x18;
        }

#ifdef USE_NTRESPONSES
        if (size < (sizeof(ntlmbuf) - 0x18)) {
          memcpy(&ntlmbuf[size], ntresp, 0x18);
          size += 0x18;
        }
#endif

        ntlmbuf[56] = (char)(size & 0xff);
        ntlmbuf[57] = (char)(size >> 8);

        /* convert the binary blob into base64 */
        output = xmalloc(5 + BASE64_LENGTH(size) + 1);
        memcpy(output, "NTLM ", 5);
        wget_base64_encode(ntlmbuf, size, output + 5);

        ntlm->state = NTLMSTATE_TYPE3; /* we sent a type-3 */
        *ready = true;
      }
      break;

    case NTLMSTATE_TYPE3:
      /* connection is already authenticated,
       * don't send a header in future requests */
      *ready = true;
      output = NULL;
      break;
  }

  return output;
}
