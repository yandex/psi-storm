// Hash-to-curve implementation for P-256 using OpenSSL
// Based on RFC 9380: Hashing to Elliptic Curves
// Suite: P256_XMD:SHA-256_SSWU_RO_ and P256_XMD:SHA-256_SSWU_NU_
//
// Optimized: BoringSSL tricks + Montgomery batch inversion

#include "hash_to_curve_p256.h"

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <cstring>

// Precomputed constant: sqrt(10) mod p for P-256
static const uint8_t kP256Sqrt10[] = {
    0xda, 0x53, 0x8e, 0x3b, 0xe1, 0xd8, 0x9b, 0x99, 0xc9, 0x78, 0xfc,
    0x67, 0x51, 0x80, 0xaa, 0xb2, 0x7b, 0x8d, 0x1f, 0xf8, 0x4c, 0x55,
    0xd5, 0xb6, 0x2c, 0xcd, 0x34, 0x27, 0xe4, 0x33, 0xc4, 0x7f};

static const uint8_t kZeros[128] = {0};

// P-256 curve parameters
struct P256Params {
  BIGNUM *p, *A, *B, *Z, *c1, *c2;

  P256Params() : p(nullptr), A(nullptr), B(nullptr), Z(nullptr), c1(nullptr), c2(nullptr) {}

  int init(EC_GROUP *group, BN_CTX *ctx) {
    p = BN_CTX_get(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    Z = BN_CTX_get(ctx);
    c1 = BN_CTX_get(ctx);
    c2 = BN_CTX_get(ctx);
    if (!c2) return 0;

    if (!EC_GROUP_get_curve(group, p, A, B, ctx)) return 0;

    BN_set_word(Z, 10);
    BN_sub(Z, p, Z);

    BN_copy(c1, p);
    BN_sub_word(c1, 3);
    BN_rshift(c1, c1, 2);

    BN_bin2bn(kP256Sqrt10, sizeof(kP256Sqrt10), c2);

    return 1;
  }
};

// expand_message_xmd - RFC 9380 Section 5.3.1
static int expand_message_xmd(const EVP_MD *md, uint8_t *out, size_t out_len,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *dst, size_t dst_len) {
  const size_t b_in_bytes = EVP_MD_size(md);
  const size_t s_in_bytes = EVP_MD_block_size(md);

  if (out_len > 255 * b_in_bytes || dst_len > 255) return 0;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) return 0;

  uint8_t dst_buf[EVP_MAX_MD_SIZE];
  if (dst_len >= 256) {
    static const char kPrefix[] = "H2C-OVERSIZE-DST-";
    if (!EVP_DigestInit_ex(ctx, md, nullptr) ||
        !EVP_DigestUpdate(ctx, kPrefix, sizeof(kPrefix) - 1) ||
        !EVP_DigestUpdate(ctx, dst, dst_len) ||
        !EVP_DigestFinal_ex(ctx, dst_buf, nullptr)) {
      EVP_MD_CTX_free(ctx);
      return 0;
    }
    dst = dst_buf;
    dst_len = b_in_bytes;
  }
  uint8_t dst_len_u8 = (uint8_t)dst_len;

  uint8_t l_i_b_str_zero[3] = {(uint8_t)(out_len >> 8), (uint8_t)out_len, 0};

  uint8_t b_0[EVP_MAX_MD_SIZE];
  if (!EVP_DigestInit_ex(ctx, md, nullptr) ||
      !EVP_DigestUpdate(ctx, kZeros, s_in_bytes) ||
      !EVP_DigestUpdate(ctx, msg, msg_len) ||
      !EVP_DigestUpdate(ctx, l_i_b_str_zero, sizeof(l_i_b_str_zero)) ||
      !EVP_DigestUpdate(ctx, dst, dst_len) ||
      !EVP_DigestUpdate(ctx, &dst_len_u8, 1) ||
      !EVP_DigestFinal_ex(ctx, b_0, nullptr)) {
    EVP_MD_CTX_free(ctx);
    return 0;
  }

  uint8_t b_i[EVP_MAX_MD_SIZE];
  memcpy(b_i, b_0, b_in_bytes);

  uint8_t i = 1;
  while (out_len > 0) {
    if (i == 0) { EVP_MD_CTX_free(ctx); return 0; }
    if (i > 1) {
      for (size_t j = 0; j < b_in_bytes; j++) b_i[j] ^= b_0[j];
    }
    if (!EVP_DigestInit_ex(ctx, md, nullptr) ||
        !EVP_DigestUpdate(ctx, b_i, b_in_bytes) ||
        !EVP_DigestUpdate(ctx, &i, 1) ||
        !EVP_DigestUpdate(ctx, dst, dst_len) ||
        !EVP_DigestUpdate(ctx, &dst_len_u8, 1) ||
        !EVP_DigestFinal_ex(ctx, b_i, nullptr)) {
      EVP_MD_CTX_free(ctx);
      return 0;
    }
    size_t to_copy = (out_len >= b_in_bytes) ? b_in_bytes : out_len;
    memcpy(out, b_i, to_copy);
    out += to_copy;
    out_len -= to_copy;
    i++;
  }

  EVP_MD_CTX_free(ctx);
  return 1;
}

// hash_to_field - RFC 9380 Section 5.2
static int hash_to_field(const BIGNUM *p, const EVP_MD *md, BIGNUM **out,
                         int count, const uint8_t *msg, size_t msg_len,
                         const uint8_t *dst, size_t dst_len, BN_CTX *ctx) {
  static const size_t L = 48;
  const size_t len_in_bytes = count * L;

  uint8_t uniform_bytes[96];
  if (len_in_bytes > sizeof(uniform_bytes)) return 0;

  if (!expand_message_xmd(md, uniform_bytes, len_in_bytes, msg, msg_len, dst, dst_len))
    return 0;

  BIGNUM *e = BN_CTX_get(ctx);
  if (!e) return 0;

  for (int i = 0; i < count; i++) {
    BN_bin2bn(uniform_bytes + L * i, L, e);
    BN_mod(out[i], e, p, ctx);
  }

  return 1;
}

static inline int sgn0(const BIGNUM *x) { return BN_is_odd(x) ? 1 : 0; }

// A=-3 multiplication trick
static inline void mul_A_minus3(BIGNUM *out, const BIGNUM *in, const BIGNUM *p,
                                BIGNUM *tmp, BN_CTX *ctx) {
  BN_lshift1(tmp, in);
  BN_mod_add(tmp, tmp, tmp, p, ctx);
  BN_mod_sub(out, in, tmp, p, ctx);
}

// sqrt_ratio_3mod4 - RFC 9380 Appendix F.2.1.2
static int sqrt_ratio_3mod4(const P256Params *params, BIGNUM *y,
                            const BIGNUM *u, const BIGNUM *v, BN_CTX *ctx) {
  const BIGNUM *p = params->p;
  const BIGNUM *c1 = params->c1;
  const BIGNUM *c2 = params->c2;

  BIGNUM *tv1 = BN_CTX_get(ctx);
  BIGNUM *tv2 = BN_CTX_get(ctx);
  BIGNUM *tv3 = BN_CTX_get(ctx);
  BIGNUM *y1 = BN_CTX_get(ctx);
  BIGNUM *y2 = BN_CTX_get(ctx);
  if (!y2) return -1;

  BN_mod_sqr(tv1, v, p, ctx);
  BN_mod_mul(tv2, u, v, p, ctx);
  BN_mod_mul(tv1, tv1, tv2, p, ctx);
  BN_mod_exp(y1, tv1, c1, p, ctx);
  BN_mod_mul(y1, y1, tv2, p, ctx);
  BN_mod_mul(y2, y1, c2, p, ctx);
  BN_mod_sqr(tv3, y1, p, ctx);
  BN_mod_mul(tv3, tv3, v, p, ctx);

  int isQR = (BN_cmp(tv3, u) == 0) ? 1 : 0;
  BN_copy(y, isQR ? y1 : y2);

  return isQR;
}

// map_to_curve_simple_swu - returns x*divisor, y, and divisor (no inversion)
static int map_to_curve_simple_swu_no_inv(const P256Params *params,
                                          BIGNUM *out_x_times_div, BIGNUM *out_y,
                                          BIGNUM *out_div, const BIGNUM *u, BN_CTX *ctx) {
  const BIGNUM *p = params->p;
  const BIGNUM *B = params->B;
  const BIGNUM *Z = params->Z;

  BIGNUM *tv1 = BN_CTX_get(ctx);
  BIGNUM *tv2 = BN_CTX_get(ctx);
  BIGNUM *tv3 = BN_CTX_get(ctx);
  BIGNUM *tv4 = BN_CTX_get(ctx);
  BIGNUM *tv5 = BN_CTX_get(ctx);
  BIGNUM *tv6 = BN_CTX_get(ctx);
  BIGNUM *x = BN_CTX_get(ctx);
  BIGNUM *y = BN_CTX_get(ctx);
  BIGNUM *y1 = BN_CTX_get(ctx);
  BIGNUM *tmp = BN_CTX_get(ctx);
  BIGNUM *one = BN_CTX_get(ctx);
  if (!one) return 0;

  BN_one(one);

  BN_mod_sqr(tv1, u, p, ctx);
  BN_mod_mul(tv1, Z, tv1, p, ctx);
  BN_mod_sqr(tv2, tv1, p, ctx);
  BN_mod_add(tv2, tv2, tv1, p, ctx);
  BN_mod_add(tv3, tv2, one, p, ctx);
  BN_mod_mul(tv3, B, tv3, p, ctx);

  if (BN_is_zero(tv2)) {
    BN_copy(tv4, Z);
  } else {
    BN_mod_sub(tv4, p, tv2, p, ctx);
  }

  mul_A_minus3(tv4, tv4, p, tmp, ctx);
  BN_mod_sqr(tv2, tv3, p, ctx);
  BN_mod_sqr(tv6, tv4, p, ctx);
  mul_A_minus3(tv5, tv6, p, tmp, ctx);
  BN_mod_add(tv2, tv2, tv5, p, ctx);
  BN_mod_mul(tv2, tv2, tv3, p, ctx);
  BN_mod_mul(tv6, tv6, tv4, p, ctx);
  BN_mod_mul(tv5, B, tv6, p, ctx);
  BN_mod_add(tv2, tv2, tv5, p, ctx);
  BN_mod_mul(x, tv1, tv3, p, ctx);

  int is_gx1_square = sqrt_ratio_3mod4(params, y1, tv2, tv6, ctx);
  if (is_gx1_square < 0) return 0;

  BN_mod_mul(y, tv1, u, p, ctx);
  BN_mod_mul(y, y, y1, p, ctx);

  if (is_gx1_square) {
    BN_copy(x, tv3);
    BN_copy(y, y1);
  }

  if (sgn0(u) != sgn0(y)) {
    BN_mod_sub(y, p, y, p, ctx);
  }

  BN_copy(out_x_times_div, x);
  BN_copy(out_y, y);
  BN_copy(out_div, tv4);

  return 1;
}

// hash_to_curve_p256 - P256_XMD:SHA-256_SSWU_RO_
// Uses Montgomery batch inversion: 2 inversions -> 1 inversion + 3 muls
int hash_to_curve_p256(EC_GROUP *group, EC_POINT *out, const uint8_t *dst,
                       size_t dst_len, const uint8_t *msg, size_t msg_len) {
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) return 0;

  int ret = 0;
  BN_CTX_start(ctx);

  P256Params params;
  if (!params.init(group, ctx)) goto err;

  {
    BIGNUM *u0 = BN_CTX_get(ctx);
    BIGNUM *u1 = BN_CTX_get(ctx);
    BIGNUM *u[2] = {u0, u1};
    if (!u1) goto err;

    if (!hash_to_field(params.p, EVP_sha256(), u, 2, msg, msg_len, dst, dst_len, ctx))
      goto err;

    BIGNUM *x0_times_d0 = BN_CTX_get(ctx);
    BIGNUM *y0 = BN_CTX_get(ctx);
    BIGNUM *d0 = BN_CTX_get(ctx);
    BIGNUM *x1_times_d1 = BN_CTX_get(ctx);
    BIGNUM *y1 = BN_CTX_get(ctx);
    BIGNUM *d1 = BN_CTX_get(ctx);
    if (!d1) goto err;

    if (!map_to_curve_simple_swu_no_inv(&params, x0_times_d0, y0, d0, u0, ctx)) goto err;
    if (!map_to_curve_simple_swu_no_inv(&params, x1_times_d1, y1, d1, u1, ctx)) goto err;

    // Montgomery batch inversion: 2 inversions -> 1 inversion + 3 muls
    BIGNUM *d0_d1 = BN_CTX_get(ctx);
    BIGNUM *inv_d0_d1 = BN_CTX_get(ctx);
    BIGNUM *inv_d0 = BN_CTX_get(ctx);
    BIGNUM *inv_d1 = BN_CTX_get(ctx);
    BIGNUM *x0 = BN_CTX_get(ctx);
    BIGNUM *x1 = BN_CTX_get(ctx);
    if (!x1) goto err;

    BN_mod_mul(d0_d1, d0, d1, params.p, ctx);
    BN_mod_inverse(inv_d0_d1, d0_d1, params.p, ctx);
    BN_mod_mul(inv_d0, d1, inv_d0_d1, params.p, ctx);
    BN_mod_mul(inv_d1, d0, inv_d0_d1, params.p, ctx);

    BN_mod_mul(x0, x0_times_d0, inv_d0, params.p, ctx);
    BN_mod_mul(x1, x1_times_d1, inv_d1, params.p, ctx);

    EC_POINT *Q0 = EC_POINT_new(group);
    EC_POINT *Q1 = EC_POINT_new(group);
    if (!Q0 || !Q1) {
      EC_POINT_free(Q0);
      EC_POINT_free(Q1);
      goto err;
    }

    EC_POINT_set_affine_coordinates(group, Q0, x0, y0, ctx);
    EC_POINT_set_affine_coordinates(group, Q1, x1, y1, ctx);
    EC_POINT_add(group, out, Q0, Q1, ctx);

    EC_POINT_free(Q0);
    EC_POINT_free(Q1);
  }

  ret = 1;

err:
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return ret;
}

