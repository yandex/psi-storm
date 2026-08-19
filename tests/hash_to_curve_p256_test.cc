// Tests for hash-to-curve P-256 implementation
// Verifies against RFC 9380 test vectors

#include "hash_to_curve_p256.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <cstdio>
#include <cstring>
#include <string>

// Helper to convert BIGNUM to hex string (lowercase, padded to 64 chars)
static std::string bn_to_hex(const BIGNUM *bn) {
  char *hex = BN_bn2hex(bn);
  std::string result(hex);
  OPENSSL_free(hex);
  while (result.length() < 64) result = "0" + result;
  for (char &c : result) c = tolower(c);
  return result;
}

struct TestVector {
  std::string msg;
  const char *expected_x;
  const char *expected_y;
};

int main() {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (!group) {
    printf("Failed to create EC_GROUP\n");
    return 1;
  }

  // q128 = "q128_" + 128*"q", a512 = "a512_" + 512*"a"
  std::string q128 = "q128_" + std::string(128, 'q');
  std::string a512 = "a512_" + std::string(512, 'a');

  // P256_XMD:SHA-256_SSWU_RO_ test vectors from RFC 9380 Appendix J.1.1
  const char *dst_ro = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
  TestVector vectors_ro[] = {
      {"", "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
           "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"},
      {"abc", "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
             "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"},
      {"abcdef0123456789", "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
                          "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"},
      {q128, "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
            "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e"},
      {a512, "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
            "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc"},
  };

  printf("P256_XMD:SHA-256_SSWU_RO_ (hash_to_curve)\n");
  printf("=========================================\n");
  int passed_ro = 0;

  // Reuse BN_CTX and point for tests
  BN_CTX *bctx = BN_CTX_new();
  EC_POINT *P = EC_POINT_new(group);
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();

  for (const auto &tv : vectors_ro) {
    hash_to_curve_p256(group, P, (const uint8_t *)dst_ro, strlen(dst_ro),
                       (const uint8_t *)tv.msg.c_str(), tv.msg.length());

    EC_POINT_get_affine_coordinates(group, P, x, y, bctx);

    std::string x_hex = bn_to_hex(x);
    std::string y_hex = bn_to_hex(y);
    bool pass = (x_hex == tv.expected_x) && (y_hex == tv.expected_y);

    std::string msg_display = tv.msg.length() > 20 ? tv.msg.substr(0, 20) + "..." : tv.msg;
    printf("msg=\"%s\": %s\n", msg_display.c_str(), pass ? "PASS" : "FAIL");
    if (pass) passed_ro++;
  }
  printf("Result: %d/%zu passed\n\n", passed_ro, sizeof(vectors_ro)/sizeof(vectors_ro[0]));

  // P256_XMD:SHA-256_SSWU_NU_ test vectors from RFC 9380 Appendix J.1.2
  const char *dst_nu = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_";
  TestVector vectors_nu[] = {
      {"", "f871caad25ea3b59c16cf87c1894902f7e7b2c822c3d3f73596c5ace8ddd14d1",
          "87b9ae23335bee057b99bac1e68588b18b5691af476234b8971bc4f011ddc99b"},
      {"abc", "fc3f5d734e8dce41ddac49f47dd2b8a57257522a865c124ed02b92b5237befa4",
             "fe4d197ecf5a62645b9690599e1d80e82c500b22ac705a0b421fac7b47157866"},
      {"abcdef0123456789", "f164c6674a02207e414c257ce759d35eddc7f55be6d7f415e2cc177e5d8faa84",
                          "3aa274881d30db70485368c0467e97da0e73c18c1d00f34775d012b6fcee7f97"},
      {q128, "324532006312be4f162614076460315f7a54a6f85544da773dc659aca0311853",
            "8d8197374bcd52de2acfefc8a54fe2c8d8bebd2a39f16be9b710e4b1af6ef883"},
      {a512, "5c4bad52f81f39c8e8de1260e9a06d72b8b00a0829a8ea004a610b0691bea5d9",
            "c801e7c0782af1f74f24fc385a8555da0582032a3ce038de637ccdcb16f7ef7b"},
  };

  printf("P256_XMD:SHA-256_SSWU_NU_ (encode_to_curve)\n");
  printf("===========================================\n");
  int passed_nu = 0;
  for (const auto &tv : vectors_nu) {
    encode_to_curve_p256(group, P, (const uint8_t *)dst_nu, strlen(dst_nu),
                         (const uint8_t *)tv.msg.c_str(), tv.msg.length());

    EC_POINT_get_affine_coordinates(group, P, x, y, bctx);

    std::string x_hex = bn_to_hex(x);
    std::string y_hex = bn_to_hex(y);
    bool pass = (x_hex == tv.expected_x) && (y_hex == tv.expected_y);

    std::string msg_display = tv.msg.length() > 20 ? tv.msg.substr(0, 20) + "..." : tv.msg;
    printf("msg=\"%s\": %s\n", msg_display.c_str(), pass ? "PASS" : "FAIL");
    if (pass) passed_nu++;
  }
  printf("Result: %d/%zu passed\n\n", passed_nu, sizeof(vectors_nu)/sizeof(vectors_nu[0]));

  printf("===========================================\n");
  int total_passed = passed_ro + passed_nu;
  size_t total_tests = sizeof(vectors_ro)/sizeof(vectors_ro[0]) + sizeof(vectors_nu)/sizeof(vectors_nu[0]);
  printf("TOTAL: %d/%zu tests passed\n", total_passed, total_tests);

  // Cleanup
  BN_free(x);
  BN_free(y);
  EC_POINT_free(P);
  BN_CTX_free(bctx);
  EC_GROUP_free(group);

  return (total_passed == (int)total_tests) ? 0 : 1;
}
