/*************************** HEADER FILES ***************************/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/****************************** CONSTANTS ******************************/
#define INPUT_SIZE 256
#define BLOCK_SIZE 64  // CIPHER outputs a 64 byte digest

/**************************** DATA TYPES ****************************/
typedef uint8_t BYTE;     // 8-bit byte
typedef uint32_t WORD;    // 32-bit word, change to "long" for 16-bit machines
typedef uint64_t DATA_T;  // 64-bit long long

typedef struct {
  WORD datalen;
  DATA_T bitlen;
  WORD state[8];
  BYTE data[64];
} CIPHER_CTX;

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static const BYTE s[64] = {
    0xc,  0x13, 0x19, 0x9,  0x12, 0x1d, 0x1,  0x1e, 0xa,  0x0,  0x16,
    0x5,  0x3,  0x1a, 0x17, 0x2,  0xf,  0x1c, 0xb,  0x15, 0x1f, 0x10,
    0x4,  0x8,  0x1b, 0x14, 0xd,  0x18, 0xe,  0x11, 0x7,  0x6,  0x3d,
    0x38, 0x20, 0x2b, 0x27, 0x36, 0x3c, 0x23, 0x30, 0x39, 0x2c, 0x33,
    0x2a, 0x3b, 0x37, 0x3a, 0x32, 0x31, 0x35, 0x3e, 0x24, 0x2f, 0x22,
    0x26, 0x28, 0x25, 0x21, 0x2e, 0x2d, 0x29, 0x3f, 0x34};

static const BYTE password_hash[] = {
    0x6F, 0x6C, 0x63, 0x21, 0x65, 0x2E, 0x6C, 0x62, 0x2D, 0x66, 0x72,
    0x4E, 0x67, 0x74, 0x76, 0x61, 0x2D, 0x72, 0x4A, 0x61, 0x65, 0x73,
    0x7B, 0x45, 0x6F, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x43, 0x49, 0x00,
    0x00, 0x7D, 0x20, 0x20, 0x20, 0x00, 0x20, 0x20, 0x00, 0x20, 0x20,
    0x20, 0x00, 0x20, 0x00, 0x20, 0x20, 0x20, 0x01, 0x20, 0x20, 0x80,
    0x20, 0x20, 0x20, 0x0A, 0x20, 0x20, 0x20, 0x10, 0x20};

/*********************** FUNCTION DEFINITIONS ***********************/
size_t my_strnlen(const char *s, size_t maxlen) {
  size_t len;

  for (len = 0; len < maxlen; len++, s++) {
    if (!*s) break;
  }
  return (len);
}

int my_memcmp(void *b, void *c, int len) {
  unsigned char *p = b;
  unsigned char *q = c;

  while (len > 0) {
    if (*p != *q) return (*p - *q);
    len--;
    p++;
    q++;
  }
  return 0;
}

void cipher_transform(CIPHER_CTX *ctx, const BYTE data[]) {
  WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; i++) {
    m[i] = data[s[i]];
    t1 = h +
         ((((e) >> (6)) | ((e) << (32 - (6)))) ^
          (((e) >> (11)) | ((e) << (32 - (11)))) ^
          (((e) >> (25)) | ((e) << (32 - (25))))) +
         (((e) & (f)) ^ (~(e) & (g))) + k[i] + m[i];
    t2 = ((((a) >> (2)) | ((a) << (32 - (2)))) ^
          (((a) >> (13)) | ((a) << (32 - (13)))) ^
          (((a) >> (22)) | ((a) << (32 - (22))))) +
         (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;

  for (i = 0; i < 64; i++) {
    ctx->data[i] = m[i];
  }
}

void cipher_init(CIPHER_CTX *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  memset(ctx->data, 0, 64);
}
void cipher_update(CIPHER_CTX *ctx, const BYTE data[], size_t len) {
  WORD i;

  for (i = 0; i < len; ++i) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      cipher_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

void cipher_final(CIPHER_CTX *ctx, BYTE hash[]) {
  WORD i;
  DATA_T *data;

  i = ctx->datalen;
  data = (DATA_T *)ctx->data;

  // Pad whatever data is left in the buffer.
  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0x20;
  } else {
    data[i++] = 0x80;
    while (i < 64) {
      data[i] = ctx->data[i];
      i++;
    }
    cipher_transform(ctx, ctx->data);
  }

  // Append to the padding the total message's length in bits and transform.
  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  cipher_transform(ctx, ctx->data);

  for (i = 0; i < BLOCK_SIZE; i++) {
    hash[i] = ctx->data[i];
  }
}

int main() {
  CIPHER_CTX ctx;
  BYTE buf[BLOCK_SIZE];
  char input[INPUT_SIZE] = {0};
  puts("Please enter your password.");
  if (read(STDIN_FILENO, input, INPUT_SIZE) < 0) {
    puts("Couldn't read from stdin.\n");
    return 1;
  }
  
  cipher_init(&ctx);
  cipher_update(&ctx, (const BYTE *)input, my_strnlen(input, INPUT_SIZE));
  cipher_final(&ctx, buf);

  if (my_memcmp(buf, (void *)password_hash, BLOCK_SIZE) == 0) {
    // Access granted
    setuid(0);
    system("/bin/sh");
  }
  else {
    puts("Password incorrect, exiting...");
  }

  return 0;
}

