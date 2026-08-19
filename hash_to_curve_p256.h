// Hash-to-curve implementation for P-256 using OpenSSL
// Based on RFC 9380: Hashing to Elliptic Curves
// Suite: P256_XMD:SHA-256_SSWU_RO_

#ifndef HASH_TO_CURVE_P256_H
#define HASH_TO_CURVE_P256_H

#include <openssl/ec.h>
#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// hash_to_curve_p256 implements P256_XMD:SHA-256_SSWU_RO_ from RFC 9380.
// This is the random oracle variant suitable for most applications.
//
// Parameters:
//   group   - Must be P-256 (NID_X9_62_prime256v1)
//   out     - Output point (must be allocated by caller)
//   dst     - Domain separation tag
//   dst_len - Length of DST (must be <= 255)
//   msg     - Input message to hash
//   msg_len - Length of message
//
// Returns 1 on success, 0 on failure.
int hash_to_curve_p256(EC_GROUP *group, EC_POINT *out,
                       const uint8_t *dst, size_t dst_len,
                       const uint8_t *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif // HASH_TO_CURVE_P256_H
