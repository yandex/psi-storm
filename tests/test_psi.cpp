// Automated test file for PSI implementation
// Compile: g++ -O3 -o test_psi test_psi.cpp ../hash_to_curve_p256.cc -lssl -lcrypto

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include "../hash_to_curve_p256.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <set>

// ============================================================================
// Constants
// ============================================================================

const std::string PSI_BIN = "../psi";
const std::string TEST_PREFIX = "_test_";

// ============================================================================
// Utility functions
// ============================================================================

std::string bytes_to_hex(const unsigned char* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string result(len * 2, '\0');
    for (size_t i = 0; i < len; i++) {
        result[i * 2] = hex[data[i] >> 4];
        result[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    return result;
}

std::string bn_to_hex(const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

std::string generate_private_key() {
    unsigned char key[32];
    RAND_bytes(key, 32);
    return bytes_to_hex(key, 32);
}

std::string read_first_line(const std::string& filename) {
    std::ifstream f(filename);
    std::string line;
    std::getline(f, line);
    return line;
}

// Case-insensitive hex string comparison
bool hex_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(a[i]) != std::tolower(b[i])) return false;
    }
    return true;
}

std::set<std::string> read_file_to_set(const std::string& filename) {
    std::set<std::string> result;
    std::ifstream f(filename);
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) {
            result.insert(line);
        }
    }
    return result;
}

std::set<int> read_file_to_int_set(const std::string& filename) {
    std::set<int> result;
    std::ifstream f(filename);
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) {
            try {
                result.insert(std::stoi(line));
            } catch (...) {}
        }
    }
    return result;
}

size_t count_lines(const std::string& filename) {
    std::ifstream f(filename);
    size_t count = 0;
    std::string line;
    while (std::getline(f, line)) {
        count++;
    }
    return count;
}

void write_range_to_file(const std::string& filename, int start, int end) {
    std::ofstream f(filename);
    for (int i = start; i <= end; i++) {
        f << i << "\n";
    }
}

void write_lines_to_file(const std::string& filename, const std::vector<std::string>& lines) {
    std::ofstream f(filename);
    for (const auto& line : lines) {
        f << line << "\n";
    }
}

// ============================================================================
// Config file management
// ============================================================================

struct PsiConfig {
    std::string private_key;
    std::string step1_input;
    std::string step1_output;
    std::string step2_input;
    std::string step2_output;
    std::string file1_compare;
    std::string file2_compare;
    std::string intersection_file;
    bool shuffle = false;

    void write(const std::string& filename) const {
        std::ofstream f(filename);
        f << "[Keys]\n";
        f << "private_key = " << private_key << "\n";
        f << "[Files]\n";
        f << "step1_input_file = " << step1_input << "\n";
        f << "step1_output_file = " << step1_output << "\n";
        f << "step2_input_file = " << step2_input << "\n";
        f << "step2_output_file = " << step2_output << "\n";
        if (!file1_compare.empty()) {
            f << "our_step2_output = " << file1_compare << "\n";
            f << "partner_step2_output = " << file2_compare << "\n";
            f << "intersection_file = " << intersection_file << "\n";
        }
        f << "shuffle = " << (shuffle ? "true" : "false") << "\n";
    }
};

// ============================================================================
// PSI command execution
// ============================================================================

bool run_psi(const std::string& action, const std::string& config_file) {
    std::string cmd = PSI_BIN + " " + action + " --config " + config_file + " > /dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}

bool run_step1(const std::string& config_file) { return run_psi("step1", config_file); }
bool run_step2(const std::string& config_file) { return run_psi("step2", config_file); }
bool run_compare(const std::string& config_file) { return run_psi("compare", config_file); }

// ============================================================================
// Minimal crypto implementation for verification
// ============================================================================

// Domain separation tag for RFC 9380 hash-to-curve (must match psi.cpp)
static constexpr const char* H2C_DST = "PSI-Yandex-P256_XMD:SHA-256_SSWU_RO_";
static constexpr size_t H2C_DST_LEN = 36;

std::string minimal_step1(const std::string& value, const std::string& private_key_hex) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* private_key = nullptr;
    BN_hex2bn(&private_key, private_key_hex.c_str());

    // Hash-to-curve using RFC 9380 (produces point with unknown discrete log)
    EC_POINT* point = EC_POINT_new(group);
    if (hash_to_curve_p256(group, point,
            reinterpret_cast<const uint8_t*>(H2C_DST), H2C_DST_LEN,
            reinterpret_cast<const uint8_t*>(value.c_str()), value.size()) != 1) {
        std::cerr << "Hash-to-curve failed" << std::endl;
        EC_POINT_free(point);
        BN_free(private_key);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return "";
    }

    // Multiply by private key: R = private_key * H(value)
    EC_POINT* result = EC_POINT_new(group);
    EC_POINT_mul(group, result, nullptr, point, private_key, ctx);

    // Convert to compressed format (33 bytes = 66 hex chars)
    unsigned char compressed[33];
    EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED, compressed, 33, ctx);

    std::string output = bytes_to_hex(compressed, 33);

    EC_POINT_free(result); EC_POINT_free(point);
    BN_free(private_key);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return output;
}

std::string minimal_step2(const std::string& point_hex, const std::string& private_key_hex) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* private_key = nullptr;
    BN_hex2bn(&private_key, private_key_hex.c_str());

    // Convert hex to bytes
    unsigned char compressed[33];
    for (size_t i = 0; i < 33 && i*2+1 < point_hex.size(); i++) {
        unsigned char hi = point_hex[i*2];
        unsigned char lo = point_hex[i*2 + 1];
        hi = (hi >= 'A') ? (hi >= 'a' ? hi - 'a' + 10 : hi - 'A' + 10) : hi - '0';
        lo = (lo >= 'A') ? (lo >= 'a' ? lo - 'a' + 10 : lo - 'A' + 10) : lo - '0';
        compressed[i] = (hi << 4) | lo;
    }

    // Decompress point
    EC_POINT* point = EC_POINT_new(group);
    EC_POINT_oct2point(group, point, compressed, 33, ctx);

    EC_POINT* result = EC_POINT_new(group);
    EC_POINT_mul(group, result, nullptr, point, private_key, ctx);

    BIGNUM* rx = BN_new();
    BIGNUM* ry = BN_new();
    EC_POINT_get_affine_coordinates(group, result, rx, ry, ctx);

    // Convert to bytes (padded to 32 bytes each)
    unsigned char coord_buf[64];
    std::memset(coord_buf, 0, 64);
    BN_bn2bin(rx, coord_buf + (32 - BN_num_bytes(rx)));
    BN_bn2bin(ry, coord_buf + 32 + (32 - BN_num_bytes(ry)));

    // SHA256 hash
    unsigned char hash[32];
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md_ctx, coord_buf, 64);
    unsigned int hash_len;
    EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
    EVP_MD_CTX_free(md_ctx);

    std::string output = bytes_to_hex(hash, 32);

    BN_free(rx); BN_free(ry);
    EC_POINT_free(result); EC_POINT_free(point);
    BN_free(private_key);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return output;
}

// ============================================================================
// Test result reporting
// ============================================================================

void print_pass(const std::string& msg) {
    std::cout << "  PASS: " << msg << std::endl;
}

void print_fail(const std::string& msg) {
    std::cerr << "  FAIL: " << msg << std::endl;
}

void print_int_set_summary(const std::set<int>& values, const std::string& label) {
    std::cout << "  " << label << ":" << std::endl;
    std::cout << "    Lines: " << values.size() << std::endl;

    if (values.empty()) return;

    std::vector<int> v(values.begin(), values.end());

    std::cout << "    First 5: ";
    for (size_t i = 0; i < std::min((size_t)5, v.size()); i++) {
        std::cout << v[i] << " ";
    }
    if (v.size() > 5) std::cout << "...";
    std::cout << std::endl;

    std::cout << "    Last 5: ";
    if (v.size() > 5) std::cout << "... ";
    size_t start = (v.size() > 5) ? v.size() - 5 : 0;
    for (size_t i = start; i < v.size(); i++) {
        std::cout << v[i] << " ";
    }
    std::cout << std::endl;
}

// ============================================================================
// Two-party PSI test helper
// ============================================================================

struct TwoPartyPsiTest {
    std::string key_a, key_b;
    std::string config_a = TEST_PREFIX + "config_a.ini";
    std::string config_b = TEST_PREFIX + "config_b.ini";

    // File paths
    std::string input_a = TEST_PREFIX + "party_a_input.txt";
    std::string input_b = TEST_PREFIX + "party_b_input.txt";
    std::string step1_a = TEST_PREFIX + "a_step1_out.txt";
    std::string step1_b = TEST_PREFIX + "b_step1_out.txt";
    std::string step2_a = TEST_PREFIX + "a_step2_out.txt";
    std::string step2_b = TEST_PREFIX + "b_step2_out.txt";
    std::string intersection_count = TEST_PREFIX + "intersection_count.txt";
    std::string intersection_values = TEST_PREFIX + "intersection_values.txt";

    TwoPartyPsiTest() {
        key_a = generate_private_key();
        key_b = generate_private_key();
    }

    void create_inputs(int a_start, int a_end, int b_start, int b_end) {
        write_range_to_file(input_a, a_start, a_end);
        write_range_to_file(input_b, b_start, b_end);
    }

    void write_configs(bool shuffle, const std::string& intersection_file) {
        PsiConfig cfg_a;
        cfg_a.private_key = key_a;
        cfg_a.step1_input = input_a;
        cfg_a.step1_output = step1_a;
        cfg_a.step2_input = step1_b;
        cfg_a.step2_output = step2_a;
        cfg_a.file1_compare = step2_a;
        cfg_a.file2_compare = step2_b;
        cfg_a.intersection_file = intersection_file;
        cfg_a.shuffle = shuffle;
        cfg_a.write(config_a);

        PsiConfig cfg_b;
        cfg_b.private_key = key_b;
        cfg_b.step1_input = input_b;
        cfg_b.step1_output = step1_b;
        cfg_b.step2_input = step1_a;
        cfg_b.step2_output = step2_b;
        cfg_b.shuffle = shuffle;
        cfg_b.write(config_b);
    }

    bool run_protocol() {
        if (!run_step1(config_a)) { print_fail("Party A step1"); return false; }
        if (!run_step1(config_b)) { print_fail("Party B step1"); return false; }
        if (!run_step2(config_a)) { print_fail("Party A step2"); return false; }
        if (!run_step2(config_b)) { print_fail("Party B step2"); return false; }
        return true;
    }

    bool run_full_protocol_with_compare() {
        if (!run_protocol()) return false;
        if (!run_compare(config_a)) { print_fail("Compare"); return false; }
        return true;
    }
};

// ============================================================================
// Tests
// ============================================================================

bool test_step1_correctness() {
    std::cout << "\n[TEST] Step1 correctness..." << std::endl;

    std::string private_key = generate_private_key();
    std::string test_value = "test_value_123";
    std::string expected = minimal_step1(test_value, private_key);

    write_lines_to_file(TEST_PREFIX + "input.txt", {test_value});

    PsiConfig cfg;
    cfg.private_key = private_key;
    cfg.step1_input = TEST_PREFIX + "input.txt";
    cfg.step1_output = TEST_PREFIX + "output.txt";
    cfg.step2_input = "unused";
    cfg.step2_output = "unused";
    cfg.write(TEST_PREFIX + "config.ini");

    if (!run_step1(TEST_PREFIX + "config.ini")) {
        print_fail("Main app step1 failed to run");
        return false;
    }

    std::string actual = read_first_line(TEST_PREFIX + "output.txt");
    bool pass = hex_equals(expected, actual);

    if (pass) {
        print_pass("Step1 output matches");
    } else {
        print_fail("Step1 output mismatch");
        std::cerr << "    Expected: " << expected << std::endl;
        std::cerr << "    Actual:   " << actual << std::endl;
    }
    return pass;
}

bool test_step2_correctness() {
    std::cout << "\n[TEST] Step2 correctness..." << std::endl;

    std::string private_key = generate_private_key();
    std::string test_value = "another_test_456";

    std::string step1_output = minimal_step1(test_value, private_key);
    std::string expected = minimal_step2(step1_output, private_key);

    write_lines_to_file(TEST_PREFIX + "step2_input.txt", {step1_output});

    PsiConfig cfg;
    cfg.private_key = private_key;
    cfg.step1_input = "unused";
    cfg.step1_output = "unused";
    cfg.step2_input = TEST_PREFIX + "step2_input.txt";
    cfg.step2_output = TEST_PREFIX + "step2_output.txt";
    cfg.shuffle = false;
    cfg.write(TEST_PREFIX + "config.ini");

    if (!run_step2(TEST_PREFIX + "config.ini")) {
        print_fail("Main app step2 failed to run");
        return false;
    }

    std::string actual = read_first_line(TEST_PREFIX + "step2_output.txt");
    bool pass = hex_equals(expected, actual);

    if (pass) {
        print_pass("Step2 output matches");
    } else {
        print_fail("Step2 output mismatch");
        std::cerr << "    Expected: " << expected << std::endl;
        std::cerr << "    Actual:   " << actual << std::endl;
    }
    return pass;
}

bool test_line_count_preservation() {
    std::cout << "\n[TEST] Line count preservation..." << std::endl;

    const int test_lines = 100;
    std::vector<std::string> lines;
    for (int i = 1; i <= test_lines; i++) {
        lines.push_back("line_" + std::to_string(i));
    }
    write_lines_to_file(TEST_PREFIX + "linecount_input.txt", lines);

    PsiConfig cfg;
    cfg.private_key = generate_private_key();
    cfg.step1_input = TEST_PREFIX + "linecount_input.txt";
    cfg.step1_output = TEST_PREFIX + "linecount_output.txt";
    cfg.step2_input = "unused";
    cfg.step2_output = "unused";
    cfg.write(TEST_PREFIX + "config.ini");

    if (!run_step1(TEST_PREFIX + "config.ini")) {
        print_fail("Step1 failed to run");
        return false;
    }

    size_t output_lines = count_lines(TEST_PREFIX + "linecount_output.txt");
    bool pass = (output_lines == test_lines);

    if (pass) {
        print_pass("Input lines = " + std::to_string(test_lines) +
                   ", Output lines = " + std::to_string(output_lines));
    } else {
        print_fail("Input lines = " + std::to_string(test_lines) +
                   ", Output lines = " + std::to_string(output_lines));
    }
    return pass;
}

bool test_deterministic_output() {
    std::cout << "\n[TEST] Deterministic output (same input -> same output)..." << std::endl;

    std::string private_key = generate_private_key();
    write_lines_to_file(TEST_PREFIX + "det_input.txt", {"deterministic_test"});

    PsiConfig cfg;
    cfg.private_key = private_key;
    cfg.step1_input = TEST_PREFIX + "det_input.txt";
    cfg.step2_input = "unused";
    cfg.step2_output = "unused";

    // Run 1
    cfg.step1_output = TEST_PREFIX + "det_output1.txt";
    cfg.write(TEST_PREFIX + "config.ini");
    if (!run_step1(TEST_PREFIX + "config.ini")) {
        print_fail("Step1 run 1 failed");
        return false;
    }
    std::string output1 = read_first_line(TEST_PREFIX + "det_output1.txt");

    // Run 2
    cfg.step1_output = TEST_PREFIX + "det_output2.txt";
    cfg.write(TEST_PREFIX + "config.ini");
    if (!run_step1(TEST_PREFIX + "config.ini")) {
        print_fail("Step1 run 2 failed");
        return false;
    }
    std::string output2 = read_first_line(TEST_PREFIX + "det_output2.txt");

    bool pass = (output1 == output2);
    if (pass) {
        print_pass("Same input produces same output");
    } else {
        print_fail("Outputs differ");
        std::cerr << "    Run 1: " << output1 << std::endl;
        std::cerr << "    Run 2: " << output2 << std::endl;
    }
    return pass;
}

bool test_full_psi_intersection() {
    std::cout << "\n[TEST] Full PSI intersection (1-1000 vs 500-1500)..." << std::endl;

    TwoPartyPsiTest psi;
    psi.create_inputs(1, 1000, 500, 1500);
    psi.write_configs(true, psi.intersection_count);  // shuffle=true for count only

    std::cout << "  Running Party A step1..." << std::endl;
    std::cout << "  Running Party B step1..." << std::endl;
    std::cout << "  Running Party A step2..." << std::endl;
    std::cout << "  Running Party B step2..." << std::endl;
    std::cout << "  Running compare (Party A)..." << std::endl;

    if (!psi.run_full_protocol_with_compare()) return false;

    std::ifstream count_file(psi.intersection_count);
    size_t actual_count = 0;
    count_file >> actual_count;

    const size_t expected = 501;
    std::cout << "  Intersection count file (" << psi.intersection_count << "): " << actual_count << std::endl;

    bool pass = (actual_count == expected);
    if (pass) {
        print_pass("Intersection size = " + std::to_string(actual_count) +
                   " (expected " + std::to_string(expected) + ")");
    } else {
        print_fail("Intersection size = " + std::to_string(actual_count) +
                   " (expected " + std::to_string(expected) + ")");
    }
    return pass;
}

bool test_intersection_values() {
    std::cout << "\n[TEST] Intersection values correctness (1-1000 vs 500-1500)..." << std::endl;

    TwoPartyPsiTest psi;
    psi.create_inputs(1, 1000, 500, 1500);
    psi.write_configs(false, psi.intersection_values);  // shuffle=false for values

    if (!psi.run_full_protocol_with_compare()) return false;

    std::set<int> actual = read_file_to_int_set(psi.intersection_values);

    std::set<int> expected;
    for (int v = 500; v <= 1000; v++) {
        expected.insert(v);
    }

    print_int_set_summary(actual, "Intersection values file (" + psi.intersection_values + ")");

    bool pass = (actual == expected);
    if (pass) {
        print_pass("Intersection values file contains 501 values (500-1000)");
    } else {
        print_fail("Intersection values file mismatch");
        std::cerr << "    Expected: 501 values (500-1000)" << std::endl;
        std::cerr << "    Actual: " << actual.size() << " values" << std::endl;
    }
    return pass;
}

bool test_large_parallel_order() {
    std::cout << "\n[TEST] Large parallel processing order (1-1M vs 500K-1.5M)..." << std::endl;
    std::cout << "  This tests that multi-threaded processing preserves line order." << std::endl;

    TwoPartyPsiTest psi;

    std::cout << "  Generating input files (may take a moment)..." << std::endl;
    psi.create_inputs(1, 1000000, 500000, 1500000);
    psi.write_configs(false, psi.intersection_values);  // shuffle=false to verify order

    std::cout << "  Running Party A step1 (parallel)..." << std::endl;
    std::cout << "  Running Party B step1 (parallel)..." << std::endl;
    std::cout << "  Running Party A step2 (parallel)..." << std::endl;
    std::cout << "  Running Party B step2 (parallel)..." << std::endl;
    std::cout << "  Running compare (Party A)..." << std::endl;

    if (!psi.run_full_protocol_with_compare()) {
        print_fail("Protocol execution failed");
        return false;
    }

    // Read actual intersection values
    std::set<int> actual = read_file_to_int_set(psi.intersection_values);

    // Expected intersection: 500000 to 1000000 (501,001 values)
    const int expected_min = 500000;
    const int expected_max = 1000000;
    const size_t expected_count = expected_max - expected_min + 1;  // 501001

    std::cout << "  Intersection values: " << actual.size() << " (expected " << expected_count << ")" << std::endl;

    if (actual.size() != expected_count) {
        print_fail("Wrong intersection count: " + std::to_string(actual.size()) +
                   " (expected " + std::to_string(expected_count) + ")");
        return false;
    }

    // Check min and max values
    int actual_min = *actual.begin();
    int actual_max = *actual.rbegin();

    std::cout << "  Value range: " << actual_min << " to " << actual_max
              << " (expected " << expected_min << " to " << expected_max << ")" << std::endl;

    if (actual_min != expected_min || actual_max != expected_max) {
        print_fail("Value range mismatch");
        return false;
    }

    // Verify all values are contiguous (500000, 500001, ..., 1000000)
    bool contiguous = true;
    int expected_val = expected_min;
    for (int v : actual) {
        if (v != expected_val) {
            contiguous = false;
            std::cerr << "    Gap or extra value at: expected " << expected_val << ", got " << v << std::endl;
            break;
        }
        expected_val++;
    }

    if (contiguous) {
        print_pass("All " + std::to_string(expected_count) + " intersection values correct (500000-1000000)");
        return true;
    } else {
        print_fail("Intersection values not contiguous - threading may have broken order");
        return false;
    }
}

// ============================================================================
// RFC 9380 Hash-to-Curve Tests
// ============================================================================

// Helper to convert BIGNUM to lowercase padded hex
std::string bn_to_hex_padded(const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    while (result.length() < 64) result = "0" + result;
    for (char& c : result) c = tolower(c);
    return result;
}

bool test_rfc9380_hash_to_curve() {
    std::cout << "\n[TEST] RFC 9380 hash_to_curve (P256_XMD:SHA-256_SSWU_RO_)..." << std::endl;

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        print_fail("Failed to create EC_GROUP");
        return false;
    }

    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* P = EC_POINT_new(group);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    // RFC 9380 test vectors for P256_XMD:SHA-256_SSWU_RO_
    const char* dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

    struct TestVector {
        const char* msg;
        const char* expected_x;
        const char* expected_y;
    };

    TestVector vectors[] = {
        {"",
         "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
         "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"},
        {"abc",
         "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
         "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"},
        {"abcdef0123456789",
         "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
         "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"},
    };

    int passed = 0;
    int total = sizeof(vectors) / sizeof(vectors[0]);

    for (const auto& tv : vectors) {
        int ret = hash_to_curve_p256(group, P,
                                     (const uint8_t*)dst, strlen(dst),
                                     (const uint8_t*)tv.msg, strlen(tv.msg));
        if (ret != 1) {
            std::cerr << "    hash_to_curve_p256 failed for msg=\"" << tv.msg << "\"" << std::endl;
            continue;
        }

        EC_POINT_get_affine_coordinates(group, P, x, y, ctx);

        std::string x_hex = bn_to_hex_padded(x);
        std::string y_hex = bn_to_hex_padded(y);

        if (x_hex == tv.expected_x && y_hex == tv.expected_y) {
            passed++;
        } else {
            std::cerr << "    FAIL for msg=\"" << tv.msg << "\"" << std::endl;
            std::cerr << "      x: " << x_hex << " (expected: " << tv.expected_x << ")" << std::endl;
            std::cerr << "      y: " << y_hex << " (expected: " << tv.expected_y << ")" << std::endl;
        }
    }

    BN_free(x);
    BN_free(y);
    EC_POINT_free(P);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    if (passed == total) {
        print_pass("All " + std::to_string(total) + " RFC 9380 test vectors passed");
        return true;
    } else {
        print_fail(std::to_string(passed) + "/" + std::to_string(total) + " test vectors passed");
        return false;
    }
}

// ============================================================================
// Main
// ============================================================================

void cleanup_test_files() {
    std::string cmd = "rm -f " + TEST_PREFIX + "*.txt " + TEST_PREFIX + "*.ini > /dev/null 2>&1";
    if (system(cmd.c_str())) { /* ignore */ }
}

int main(int argc, char* argv[]) {
    bool keep_files = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--keep-files" || arg == "-k") {
            keep_files = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "Options:\n"
                      << "  --keep-files, -k  Don't delete test files after running\n"
                      << "  --help, -h        Show this help\n";
            return 0;
        }
    }

    std::cout << "========================================" << std::endl;
    std::cout << "PSI Automated Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;

    std::ifstream psi_check(PSI_BIN);
    if (!psi_check.good()) {
        std::cerr << "Error: " << PSI_BIN << " not found. Compile the main app first." << std::endl;
        return 1;
    }
    psi_check.close();

    int passed = 0, failed = 0;

    auto run_test = [&](bool (*test)()) {
        if (test()) passed++; else failed++;
    };

    run_test(test_rfc9380_hash_to_curve);
    run_test(test_step1_correctness);
    run_test(test_step2_correctness);
    run_test(test_line_count_preservation);
    run_test(test_deterministic_output);
    run_test(test_full_psi_intersection);
    run_test(test_intersection_values);
    run_test(test_large_parallel_order);

    if (!keep_files) {
        cleanup_test_files();
    } else {
        std::cout << "\nTest files kept (--keep-files)" << std::endl;
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

    return (failed > 0) ? 1 : 0;
}
