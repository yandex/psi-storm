#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>

#include "hash_to_curve_p256.h"

// Domain separation tag for RFC 9380 hash-to-curve
static constexpr const char* H2C_DST = "PSI-Yandex-P256_XMD:SHA-256_SSWU_RO_";
static constexpr size_t H2C_DST_LEN = 36;

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <set>
#include <map>
#include <queue>
#include <algorithm>
#include <cstring>
#include <thread>
#include <future>
#include <atomic>

#include <unistd.h>

// ============================================================================
// Constants
// ============================================================================

constexpr size_t BUF_SIZE = 1 << 20;              // 1MB I/O buffer
constexpr size_t LARGE_FILE_THRESHOLD = 20000000; // 20M lines
constexpr size_t SHUFFLE_BUFFER_SIZE = 5000000;   // 5M entries (~500MB)
constexpr size_t CHUNK_SIZE = 10000;              // Lines per parallel chunk


// Get number of threads (can be overridden)
inline unsigned int get_num_threads() {
    unsigned int n = std::thread::hardware_concurrency();
    return (n > 0) ? n : 4;
}

// Lookup table for fast hex encoding (uppercase to match OpenSSL output)
static const char HEX_CHARS_UPPER[] = "0123456789ABCDEF";

// ============================================================================
// Utility functions
// ============================================================================

// Fast bytes to hex (uppercase to match OpenSSL)
inline void bytes_to_hex_fast(const unsigned char* data, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = HEX_CHARS_UPPER[data[i] >> 4];
        out[i * 2 + 1] = HEX_CHARS_UPPER[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

inline std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::string result(len * 2, '\0');
    bytes_to_hex_fast(data, len, &result[0]);
    return result;
}

// Trim whitespace from string, returns (start, length) of trimmed content
inline std::pair<size_t, size_t> trim_bounds(const char* s, size_t len) {
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' || s[len-1] == '\r' || s[len-1] == '\n')) {
        len--;
    }
    size_t start = 0;
    while (start < len && (s[start] == ' ' || s[start] == '\t')) {
        start++;
    }
    return {start, len - start};
}

inline std::pair<size_t, size_t> trim_bounds(const std::string& s) {
    return trim_bounds(s.c_str(), s.length());
}

// Flush output buffer if it's getting full
inline void flush_if_full(std::ofstream& out, std::string& buffer, size_t threshold = BUF_SIZE - 256) {
    if (buffer.size() >= threshold) {
        out.write(buffer.data(), buffer.size());
        buffer.clear();
    }
}

// Flush remaining buffer contents
inline void flush_remaining(std::ofstream& out, std::string& buffer) {
    if (!buffer.empty()) {
        out.write(buffer.data(), buffer.size());
        buffer.clear();
    }
}

// Check if file exists and is readable
inline bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

// Estimate number of lines in file based on file size
inline size_t estimate_lines(const std::string& filename, size_t avg_line_bytes) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return 0;
    size_t file_size = file.tellg();
    return file_size / avg_line_bytes;
}

// ============================================================================
// Crypto context - reusable across operations
// ============================================================================

class CryptoContext {
public:
    EC_GROUP* group = nullptr;
    BN_CTX* bn_ctx = nullptr;
    EVP_MD_CTX* md_ctx = nullptr;
    EC_POINT* temp_point = nullptr;
    EC_POINT* result_point = nullptr;
    BIGNUM* result_x = nullptr;
    BIGNUM* result_y = nullptr;
    BIGNUM* private_key_bn = nullptr;
    unsigned char hash_buf[32];
    bool valid = false;

    CryptoContext() {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group) { std::cerr << "Failed to create EC_GROUP" << std::endl; return; }

        bn_ctx = BN_CTX_new();
        if (!bn_ctx) { std::cerr << "Failed to create BN_CTX" << std::endl; return; }

        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) { std::cerr << "Failed to create EVP_MD_CTX" << std::endl; return; }

        result_x = BN_new();
        result_y = BN_new();
        if (!result_x || !result_y) {
            std::cerr << "Failed to create BIGNUMs" << std::endl; return;
        }

        temp_point = EC_POINT_new(group);
        result_point = EC_POINT_new(group);
        if (!temp_point || !result_point) {
            std::cerr << "Failed to create EC_POINTs" << std::endl; return;
        }

        valid = true;
    }

    bool is_valid() const { return valid; }

    // Prevent copying (would cause double-free)
    CryptoContext(const CryptoContext&) = delete;
    CryptoContext& operator=(const CryptoContext&) = delete;

    ~CryptoContext() {
        if (private_key_bn) BN_free(private_key_bn);
        BN_free(result_y);
        BN_free(result_x);
        EC_POINT_free(result_point);
        EC_POINT_free(temp_point);
        EVP_MD_CTX_free(md_ctx);
        BN_CTX_free(bn_ctx);
        EC_GROUP_free(group);
    }

    void set_private_key(const std::string& hex) {
        if (private_key_bn) BN_free(private_key_bn);
        private_key_bn = nullptr;
        BN_hex2bn(&private_key_bn, hex.c_str());
    }

    inline void sha256(const char* data, size_t len) {
        EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(md_ctx, data, len);
        unsigned int out_len;
        EVP_DigestFinal_ex(md_ctx, hash_buf, &out_len);
    }

    // Process a value and output compressed point (33 bytes = 66 hex chars)
    inline bool process_value(const char* value, size_t value_len, std::string& out_point) {
        // Hash-to-curve (RFC 9380): produces point with unknown discrete log
        // This prevents cross-multiplication attacks on step1 output
        if (hash_to_curve_p256(
                group, temp_point,
                reinterpret_cast<const uint8_t*>(H2C_DST), H2C_DST_LEN,
                reinterpret_cast<const uint8_t*>(value), value_len) != 1) {
            return false;
        }

        // Multiply by private key: result = private_key * H(value)
        EC_POINT_mul(group, result_point, nullptr, temp_point, private_key_bn, bn_ctx);

        // Convert to compressed format (33 bytes)
        unsigned char compressed[33];
        size_t len = EC_POINT_point2oct(group, result_point, POINT_CONVERSION_COMPRESSED,
                                        compressed, sizeof(compressed), bn_ctx);
        if (len != 33) {
            return false;
        }

        // Convert to hex (66 chars)
        char hex[67];
        bytes_to_hex_fast(compressed, 33, hex);
        out_point = hex;

        return true;
    }

    // Process a compressed point and output hash
    inline bool process_point(const char* point_hex, size_t hex_len, std::string& out_hash) {
        if (hex_len != 66) {
            return false;  // Compressed point should be 66 hex chars
        }

        // Convert hex to bytes
        unsigned char compressed[33];
        for (size_t i = 0; i < 33; i++) {
            unsigned char hi = point_hex[i*2];
            unsigned char lo = point_hex[i*2 + 1];
            hi = (hi >= 'A') ? (hi >= 'a' ? hi - 'a' + 10 : hi - 'A' + 10) : hi - '0';
            lo = (lo >= 'A') ? (lo >= 'a' ? lo - 'a' + 10 : lo - 'A' + 10) : lo - '0';
            compressed[i] = (hi << 4) | lo;
        }

        // Decompress point
        if (EC_POINT_oct2point(group, temp_point, compressed, 33, bn_ctx) != 1) {
            return false;
        }

        // Multiply by private key
        EC_POINT_mul(group, result_point, nullptr, temp_point, private_key_bn, bn_ctx);

        // Get coordinates and hash them
        EC_POINT_get_affine_coordinates(group, result_point, result_x, result_y, bn_ctx);

        unsigned char coord_buf[64];
        BN_bn2binpad(result_x, coord_buf, 32);
        BN_bn2binpad(result_y, coord_buf + 32, 32);

        EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(md_ctx, coord_buf, 64);
        unsigned int out_len;
        EVP_DigestFinal_ex(md_ctx, hash_buf, &out_len);

        out_hash = bytes_to_hex(hash_buf, 32);
        return true;
    }
};

// ============================================================================
// Key generation
// ============================================================================

std::string generate_private_key() {
    // Generate EC key using high-level EVP API (OpenSSL 3.0+)
    EVP_PKEY* pkey = EVP_EC_gen("prime256v1");
    if (!pkey) {
        return "";
    }

    // Extract private key as BIGNUM (this allocates a copy)
    BIGNUM* priv_bn = NULL;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn)) {
        EVP_PKEY_free(pkey);
        return "";
    }

    // Convert to fixed-length binary (32 bytes for P-256), then to hex
    unsigned char bin[32];
    BN_bn2binpad(priv_bn, bin, 32);
    std::string result = bytes_to_hex(bin, 32);
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);

    BN_free(priv_bn);
    EVP_PKEY_free(pkey);
    return result;
}

// ============================================================================
// Config file parser
// ============================================================================

class Config {
public:
    std::map<std::string, std::map<std::string, std::string>> sections;

    bool load(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) return false;

        std::string line, current_section;

        while (std::getline(file, line)) {
            auto [start, len] = trim_bounds(line);
            if (len == 0) continue;
            line = line.substr(start, len);

            if (line[0] == ';' || line[0] == '#') continue;

            if (line[0] == '[' && line.back() == ']') {
                current_section = line.substr(1, line.length() - 2);
            } else {
                size_t eq_pos = line.find('=');
                if (eq_pos != std::string::npos) {
                    std::string key = line.substr(0, eq_pos);
                    std::string value = line.substr(eq_pos + 1);

                    auto [ks, kl] = trim_bounds(key);
                    auto [vs, vl] = trim_bounds(value);

                    key = (kl > 0) ? key.substr(ks, kl) : "";
                    value = (vl > 0) ? value.substr(vs, vl) : "";

                    sections[current_section][key] = value;
                }
            }
        }
        return true;
    }

    bool save(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        for (const auto& section : sections) {
            file << "[" << section.first << "]\n";
            for (const auto& kv : section.second) {
                file << kv.first << " = " << kv.second << "\n";
            }
            file << "\n";
        }
        return true;
    }

    std::string get(const std::string& section, const std::string& key, const std::string& def = "") {
        auto sit = sections.find(section);
        if (sit != sections.end()) {
            auto kit = sit->second.find(key);
            if (kit != sit->second.end()) return kit->second;
        }
        return def;
    }

    void set(const std::string& section, const std::string& key, const std::string& value) {
        sections[section][key] = value;
    }

    bool get_bool(const std::string& section, const std::string& key, bool def = false) {
        std::string val = get(section, key, def ? "true" : "false");
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        return val == "true" || val == "1" || val == "yes";
    }
};

// ============================================================================
// External merge sort for large files
// ============================================================================

bool write_sorted_chunk(std::vector<std::string>& chunk, const std::string& temp_file) {
    std::sort(chunk.begin(), chunk.end());
    std::ofstream out(temp_file, std::ios::binary);
    if (!out) return false;
    for (const auto& line : chunk) {
        out << line << '\n';
    }
    return true;
}

bool merge_sorted_files(const std::vector<std::string>& temp_files, const std::string& output_file) {
    std::vector<std::ifstream> files(temp_files.size());

    // Priority queue: (line, file_index) - min-heap by line value
    using Entry = std::pair<std::string, size_t>;
    auto cmp = [](const Entry& a, const Entry& b) { return a.first > b.first; };  // greater = min-heap
    std::priority_queue<Entry, std::vector<Entry>, decltype(cmp)> pq(cmp);

    for (size_t i = 0; i < temp_files.size(); i++) {
        files[i].open(temp_files[i], std::ios::binary);
        std::string line;
        if (std::getline(files[i], line)) {
            pq.emplace(std::move(line), i);
        }
    }

    std::ofstream out(output_file, std::ios::binary);
    if (!out) return false;

    // Add I/O buffer for faster writes
    static char out_buf[BUF_SIZE];
    out.rdbuf()->pubsetbuf(out_buf, BUF_SIZE);

    std::string write_buffer;
    write_buffer.reserve(BUF_SIZE);

    while (!pq.empty()) {
        auto [line, idx] = pq.top();
        pq.pop();

        write_buffer += line;
        write_buffer += '\n';
        flush_if_full(out, write_buffer);

        std::string next_line;
        if (std::getline(files[idx], next_line)) {
            pq.emplace(std::move(next_line), idx);
        }
    }

    flush_remaining(out, write_buffer);
    return true;
}

void cleanup_temp_files(const std::vector<std::string>& temp_files) {
    for (const auto& tf : temp_files) {
        unlink(tf.c_str());
    }
}

bool external_merge_sort(const std::string& input_file, const std::string& output_file,
                         size_t chunk_lines = 15000000) {
    std::ifstream fin(input_file, std::ios::binary);
    if (!fin) return false;

    std::vector<std::string> temp_files;
    std::vector<std::string> chunk;
    chunk.reserve(chunk_lines);

    std::string line;
    size_t chunk_idx = 0;

    while (std::getline(fin, line)) {
        auto [start, len] = trim_bounds(line);
        if (len > 0) {
            chunk.push_back(line.substr(start, len));
        }

        if (chunk.size() >= chunk_lines) {
            std::string temp_file = output_file + ".tmp" + std::to_string(chunk_idx++);
            if (!write_sorted_chunk(chunk, temp_file)) {
                cleanup_temp_files(temp_files);
                return false;
            }
            temp_files.push_back(temp_file);
            chunk.clear();
        }
    }

    if (!chunk.empty()) {
        std::string temp_file = output_file + ".tmp" + std::to_string(chunk_idx++);
        if (!write_sorted_chunk(chunk, temp_file)) {
            cleanup_temp_files(temp_files);
            return false;
        }
        temp_files.push_back(temp_file);
        chunk.clear();
    }

    if (temp_files.size() == 1) {
        rename(temp_files[0].c_str(), output_file.c_str());
    } else {
        if (!merge_sorted_files(temp_files, output_file)) {
            cleanup_temp_files(temp_files);
            return false;
        }
        cleanup_temp_files(temp_files);
    }

    return true;
}

// Streaming merge intersection - writes positions to file, returns count
size_t sorted_merge_intersection_to_file(const std::string& sorted_file1,
                                          const std::string& sorted_file2,
                                          const std::string& positions_file) {
    std::ifstream f1(sorted_file1, std::ios::binary);
    std::ifstream f2(sorted_file2, std::ios::binary);
    std::ofstream pos_out(positions_file, std::ios::binary);

    size_t count = 0;
    std::string line1, line2;
    bool have1 = (bool)std::getline(f1, line1);
    bool have2 = (bool)std::getline(f2, line2);
    size_t pos1 = 1;

    while (have1 && have2) {
        int cmp = line1.compare(line2);
        if (cmp == 0) {
            pos_out << pos1 << '\n';
            count++;
            have1 = (bool)std::getline(f1, line1);
            pos1++;
            have2 = (bool)std::getline(f2, line2);
        } else if (cmp < 0) {
            have1 = (bool)std::getline(f1, line1);
            pos1++;
        } else {
            have2 = (bool)std::getline(f2, line2);
        }
    }

    return count;
}

// ============================================================================
// PSI processing functions
// ============================================================================

// Process a chunk of values for step1 (thread-safe, each call creates own CryptoContext)
std::vector<std::string> process_step1_chunk(const std::vector<std::string>& inputs,
                                              const std::string& private_key) {
    std::vector<std::string> results;
    results.reserve(inputs.size());

    CryptoContext ctx;
    if (!ctx.is_valid()) {
        return results;  // Empty on error
    }
    ctx.set_private_key(private_key);

    std::string out_point;
    for (const auto& input : inputs) {
        auto [start, len] = trim_bounds(input);
        if (len == 0) {
            results.push_back("");  // Preserve position for empty lines
            continue;
        }

        if (ctx.process_value(input.c_str() + start, len, out_point)) {
            results.push_back(out_point);
        } else {
            results.push_back("");  // Error case
        }
    }
    return results;
}

// Parallel step1 processing
bool process_step1(const std::string& input_file, const std::string& output_file,
                   const std::string& private_key) {
    std::ifstream fin(input_file, std::ios::binary);
    if (!fin.is_open()) {
        std::cerr << "Cannot open input file: " << input_file << std::endl;
        return false;
    }
    fin.rdbuf()->pubsetbuf(nullptr, BUF_SIZE);

    std::ofstream fout(output_file, std::ios::binary);
    if (!fout.is_open()) {
        std::cerr << "Cannot open output file: " << output_file << std::endl;
        return false;
    }

    const unsigned int num_threads = get_num_threads();
    std::vector<std::future<std::vector<std::string>>> futures;
    futures.reserve(num_threads * 2);  // Keep some futures in flight

    std::string out_buffer;
    out_buffer.reserve(BUF_SIZE);

    std::string line;
    std::vector<std::string> chunk;
    chunk.reserve(CHUNK_SIZE);

    size_t chunks_in_flight = 0;
    const size_t max_in_flight = num_threads * 2;

    auto write_results = [&](std::vector<std::string>& results) {
        for (const auto& result : results) {
            if (!result.empty()) {
                out_buffer += result;
                out_buffer += '\n';
                flush_if_full(fout, out_buffer);
            }
        }
    };

    while (std::getline(fin, line)) {
        chunk.push_back(std::move(line));

        if (chunk.size() >= CHUNK_SIZE) {
            // Launch async processing
            futures.push_back(std::async(std::launch::async,
                process_step1_chunk, std::move(chunk), std::cref(private_key)));
            chunk = std::vector<std::string>();
            chunk.reserve(CHUNK_SIZE);
            chunks_in_flight++;

            // If too many in flight, wait for oldest to complete
            if (chunks_in_flight >= max_in_flight && !futures.empty()) {
                auto results = futures.front().get();
                futures.erase(futures.begin());
                chunks_in_flight--;
                write_results(results);
            }
        }
    }

    // Process remaining chunk
    if (!chunk.empty()) {
        futures.push_back(std::async(std::launch::async,
            process_step1_chunk, std::move(chunk), std::cref(private_key)));
    }

    // Wait for all remaining futures IN ORDER
    for (auto& future : futures) {
        auto results = future.get();
        write_results(results);
    }

    flush_remaining(fout, out_buffer);
    return true;
}

// Parse a compressed point line (just trim whitespace)
inline bool parse_point_line(const std::string& line, const char*& point_hex, size_t& hex_len) {
    auto [start, len] = trim_bounds(line);
    if (len == 0) return false;

    point_hex = line.c_str() + start;
    hex_len = len;
    return true;
}

// Process a chunk of compressed points for step2 (thread-safe)
std::vector<std::string> process_step2_chunk(const std::vector<std::string>& inputs,
                                              const std::string& private_key) {
    std::vector<std::string> results;
    results.reserve(inputs.size());

    CryptoContext ctx;
    if (!ctx.is_valid()) {
        return results;
    }
    ctx.set_private_key(private_key);

    std::string out_hash;
    const char* point_hex;
    size_t hex_len;
    for (const auto& input : inputs) {
        if (!parse_point_line(input, point_hex, hex_len)) {
            results.push_back("");
            continue;
        }

        if (ctx.process_point(point_hex, hex_len, out_hash)) {
            results.push_back(out_hash);
        } else {
            results.push_back("");
        }
    }
    return results;
}

bool process_step2(const std::string& input_file, const std::string& output_file,
                   const std::string& private_key, bool shuffle) {
    std::ifstream fin(input_file, std::ios::binary);
    if (!fin.is_open()) {
        std::cerr << "Cannot open input file: " << input_file << std::endl;
        return false;
    }
    fin.rdbuf()->pubsetbuf(nullptr, BUF_SIZE);

    std::ofstream fout(output_file, std::ios::binary);
    if (!fout.is_open()) {
        std::cerr << "Cannot open output file: " << output_file << std::endl;
        return false;
    }

    // Parallel processing for non-shuffle mode (preserves order)
    if (!shuffle) {
        const unsigned int num_threads = get_num_threads();
        std::vector<std::future<std::vector<std::string>>> futures;
        futures.reserve(num_threads * 2);

        std::string out_buffer;
        out_buffer.reserve(BUF_SIZE);

        std::string line;
        std::vector<std::string> chunk;
        chunk.reserve(CHUNK_SIZE);

        size_t chunks_in_flight = 0;
        const size_t max_in_flight = num_threads * 2;

        auto write_results = [&](std::vector<std::string>& results) {
            for (const auto& result : results) {
                if (!result.empty()) {
                    out_buffer += result;
                    out_buffer += '\n';
                    flush_if_full(fout, out_buffer);
                }
            }
        };

        while (std::getline(fin, line)) {
            chunk.push_back(std::move(line));

            if (chunk.size() >= CHUNK_SIZE) {
                futures.push_back(std::async(std::launch::async,
                    process_step2_chunk, std::move(chunk), std::cref(private_key)));
                chunk = std::vector<std::string>();
                chunk.reserve(CHUNK_SIZE);
                chunks_in_flight++;

                if (chunks_in_flight >= max_in_flight && !futures.empty()) {
                    auto results = futures.front().get();
                    futures.erase(futures.begin());
                    chunks_in_flight--;
                    write_results(results);
                }
            }
        }

        if (!chunk.empty()) {
            futures.push_back(std::async(std::launch::async,
                process_step2_chunk, std::move(chunk), std::cref(private_key)));
        }

        for (auto& future : futures) {
            auto results = future.get();
            write_results(results);
        }

        flush_remaining(fout, out_buffer);
        return true;
    }

    // Shuffle mode: sequential with streaming buffer (order doesn't matter)
    CryptoContext ctx;
    if (!ctx.is_valid()) {
        std::cerr << "Failed to initialize crypto context" << std::endl;
        return false;
    }
    ctx.set_private_key(private_key);

    std::string line, out_hash;
    const char* point_hex;
    size_t hex_len;

    std::vector<std::string> buffer;
    buffer.reserve(SHUFFLE_BUFFER_SIZE);

    std::string write_buffer;
    write_buffer.reserve(BUF_SIZE);

    auto output_random_entry = [&]() {
        if (buffer.empty()) return;

        uint64_t rand_val;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&rand_val), sizeof(rand_val)) != 1) {
            std::cerr << "Failed to generate random bytes" << std::endl;
            return;
        }

        size_t idx = rand_val % buffer.size();
        std::swap(buffer[idx], buffer.back());

        write_buffer += buffer.back();
        write_buffer += '\n';
        buffer.pop_back();

        flush_if_full(fout, write_buffer, BUF_SIZE - 128);
    };

    while (std::getline(fin, line)) {
        if (!parse_point_line(line, point_hex, hex_len)) continue;

        if (ctx.process_point(point_hex, hex_len, out_hash)) {
            if (buffer.size() == SHUFFLE_BUFFER_SIZE) {
                output_random_entry();
            }
            buffer.push_back(std::move(out_hash));
        }
    }

    while (!buffer.empty()) {
        output_random_entry();
    }

    flush_remaining(fout, write_buffer);
    return true;
}

// ============================================================================
// Intersection functions
// ============================================================================

std::unordered_set<std::string> read_file_to_set(const std::string& filename) {
    std::unordered_set<std::string> result;
    result.reserve(1000000);

    std::ifstream file(filename, std::ios::binary);
    file.rdbuf()->pubsetbuf(nullptr, BUF_SIZE);

    std::string line;
    while (std::getline(file, line)) {
        auto [start, len] = trim_bounds(line);
        if (len > 0) {
            result.emplace(line.substr(start, len));
        }
    }
    return result;
}

// Find intersection and write positions to file (streaming, O(1) memory for positions)
// Returns count of intersecting positions
size_t find_intersection_to_file(const std::string& file1, const std::string& file2,
                                  const std::string& positions_file) {
    size_t est_lines1 = estimate_lines(file1, 65);
    size_t est_lines2 = estimate_lines(file2, 65);
    size_t max_lines = std::max(est_lines1, est_lines2);

    if (max_lines >= LARGE_FILE_THRESHOLD) {
        std::string sorted_file1 = file1 + ".sorted";
        std::string sorted_file2 = file2 + ".sorted";

        std::cerr << "Large file detected, using external sort..." << std::endl;

        if (!external_merge_sort(file1, sorted_file1)) {
            std::cerr << "Failed to sort file1" << std::endl;
            return 0;
        }
        if (!external_merge_sort(file2, sorted_file2)) {
            std::cerr << "Failed to sort file2" << std::endl;
            unlink(sorted_file1.c_str());
            return 0;
        }

        size_t count = sorted_merge_intersection_to_file(sorted_file1, sorted_file2, positions_file);

        unlink(sorted_file1.c_str());
        unlink(sorted_file2.c_str());

        return count;
    }

    // Small files: RAM-based approach for hash set, but stream positions to file
    // Load file1 into a set, then iterate file2 to find matching positions
    // file2 positions align with step1_input_file for correct value derivation
    std::unordered_set<std::string> set1 = read_file_to_set(file1);

    std::ifstream f2(file2, std::ios::binary);
    f2.rdbuf()->pubsetbuf(nullptr, BUF_SIZE);

    std::ofstream pos_out(positions_file, std::ios::binary);

    std::string line;
    size_t pos = 0;
    size_t count = 0;

    // Positions written in ascending order (since we iterate sequentially)
    while (std::getline(f2, line)) {
        pos++;
        auto [start, len] = trim_bounds(line);
        if (len > 0 && set1.count(line.substr(start, len))) {
            pos_out << pos << '\n';
            count++;
        }
    }

    return count;
}

void write_intersection_count(size_t count, const std::string& filename) {
    std::ofstream file(filename);
    file << count;
}

// Streaming merge-join: read positions from sorted file, extract matching lines from source
// Both files are read sequentially - O(n) time, O(1) memory
void derive_src_values_streaming(const std::string& positions_file,
                                  const std::string& src_file,
                                  const std::string& output_file) {
    std::ifstream pos_in(positions_file, std::ios::binary);
    std::ifstream fin(src_file, std::ios::binary);
    std::ofstream fout(output_file, std::ios::binary);
    fin.rdbuf()->pubsetbuf(nullptr, BUF_SIZE);

    std::string out_buffer;
    out_buffer.reserve(BUF_SIZE);

    std::string line;
    size_t current_line = 0;
    size_t next_pos = 0;

    // Read first position
    if (!(pos_in >> next_pos)) {
        return;  // No positions, empty intersection
    }

    // Streaming merge-join
    while (std::getline(fin, line)) {
        current_line++;
        if (current_line == next_pos) {
            out_buffer += line;
            out_buffer += '\n';
            flush_if_full(fout, out_buffer);

            // Read next position
            if (!(pos_in >> next_pos)) {
                break;  // No more positions
            }
        }
    }

    flush_remaining(fout, out_buffer);
}

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " <action> [options]\n"
              << "\nActions:\n"
              << "  init     Initialize private key\n"
              << "  step1    Process input file with hashing and encryption\n"
              << "  step2    Process received file with encryption and hashing\n"
              << "  compare  Find intersection between processed files\n"
              << "\nOptions:\n"
              << "  --config <file>      Config file (default: secret-config.ini)\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string action = argv[1];
    std::string config_file = "secret-config.ini";

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            config_file = argv[++i];
        }
    }

    if (config_file != "secret-config.ini") {
        std::cout << "Using provided config " << config_file << std::endl;
    } else {
        std::cout << "Using default secret-config.ini" << std::endl;
    }

    Config config;
    config.load(config_file);
    bool shuffle = config.get_bool("Files", "shuffle", false);

    if (action == "init") {
        std::string private_key = generate_private_key();
        std::cout << "private_key: " << private_key << std::endl;
        config.set("Keys", "private_key", private_key);
        config.save(config_file);

    } else if (action == "step1") {
        std::string private_key = config.get("Keys", "private_key");
        std::string input_file = config.get("Files", "step1_input_file");
        std::string output_file = config.get("Files", "step1_output_file");

        if (private_key.empty()) {
            std::cerr << "private_key is not set in [Keys] section. Run 'init' first." << std::endl;
            return 1;
        }

        if (!file_exists(input_file)) {
            std::cerr << "Input file not found: " << input_file << std::endl;
            return 1;
        }

        if (process_step1(input_file, output_file, private_key)) {
            std::cout << "Values processed and saved in " << output_file << std::endl;
        }

    } else if (action == "step2") {
        std::string private_key = config.get("Keys", "private_key");
        std::string input_file = config.get("Files", "step2_input_file");
        std::string output_file = config.get("Files", "step2_output_file");

        if (!file_exists(input_file)) {
            std::cerr << "Input file not found: " << input_file << std::endl;
            return 1;
        }

        if (process_step2(input_file, output_file, private_key, shuffle)) {
            std::cout << "Values processed and saved in " << output_file << std::endl;
        }

    } else if (action == "compare") {
        std::string file1 = config.get("Files", "our_step2_output");
        std::string file2 = config.get("Files", "partner_step2_output");
        std::string src_values_file = config.get("Files", "step1_input_file");
        std::string intersection_file = config.get("Files", "intersection_file");

        if (!file_exists(file1)) {
            std::cerr << "Input file not found: " << file1 << std::endl;
            return 1;
        }
        if (!file_exists(file2)) {
            std::cerr << "Input file not found: " << file2 << std::endl;
            return 1;
        }
        if (!shuffle && !file_exists(src_values_file)) {
            std::cerr << "Input file not found: " << src_values_file << std::endl;
            return 1;
        }

        // Use temp file for positions (streaming approach - O(1) memory)
        std::string positions_file = intersection_file + ".positions.tmp";
        size_t count = find_intersection_to_file(file1, file2, positions_file);

        if (shuffle) {
            write_intersection_count(count, intersection_file);
        } else {
            derive_src_values_streaming(positions_file, src_values_file, intersection_file);
        }

        // Cleanup temp file
        unlink(positions_file.c_str());

        std::cout << "Intersection result saved in " << intersection_file << std::endl;

    } else {
        std::cerr << "Unknown action: " << action << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

// Build: g++ -O3 -o psi psi.cpp -lssl -lcrypto
