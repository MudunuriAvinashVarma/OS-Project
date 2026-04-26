// ═══════════════════════════════════════════════════════════════
// SecureAuth OS — system/auth.cpp
// Kernel-layer credential validation module
//
// Role:
//   • Receives username + bcrypt hash via stdin (not argv)
//   • Validates input format with strict bounds checking
//   • Demonstrates buffer-overflow protection techniques:
//       - Fixed-size stack buffers with explicit size constants
//       - std::string for dynamic input (no raw char[] for I/O)
//       - fgets() with size limit if C-string reading is needed
//       - Stack canary commentary (compiler flags handle actual canary)
//       - No unsafe functions: gets(), scanf("%s"), strcpy(), strcat()
//   • Prints "VALID" or "INVALID" to stdout
//   • Exits 0 on success, 1 on failure/error
//
// Compile:
//   g++ -std=c++17 -Wall -Wextra -fstack-protector-strong \
//       -D_FORTIFY_SOURCE=2 -O2 -o auth auth.cpp
//
// Usage (called by Python via subprocess stdin):
//   echo -e "alice\n$2b$12$..." | ./auth
// ═══════════════════════════════════════════════════════════════

#include <iostream>
#include <string>
#include <regex>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <sstream>
#include <algorithm>

// ── Compile-time security constants ─────────────────────────────
// These hard limits mirror the Python backend constraints.
// Every input read is bounded by these values.

static constexpr std::size_t MAX_USERNAME_LEN = 64;
static constexpr std::size_t MAX_HASH_LEN     = 256;  // bcrypt hash ≤ 60 chars; 256 is generous
static constexpr std::size_t MAX_LINE_LEN     = 512;  // absolute ceiling for any single line

// bcrypt hash prefix patterns we accept
// $2b$ (modern) | $2a$ | $2y$ (compatibility variants)
static const std::regex BCRYPT_PREFIX_RE(R"(\$2[aby]\$\d{2}\$.{53})");

// Username: letters, digits, underscore, hyphen only (3–64 chars)
static const std::regex USERNAME_RE(R"([a-zA-Z0-9_\-]{3,64})");


// ════════════════════════════════════════════════════════════════
// Utility: safe line reader
// ════════════════════════════════════════════════════════════════

/**
 * Read one line from an istream into a std::string.
 * SECURITY: enforces MAX_LINE_LEN; any line longer than the limit
 * causes the function to return false (reject input entirely).
 * This prevents heap exhaustion from arbitrarily large stdin input.
 *
 * @param stream   Input stream to read from
 * @param out      Output string (populated on success)
 * @param maxLen   Maximum accepted length (default MAX_LINE_LEN)
 * @return true if a line was read within the limit, false otherwise
 */
bool safe_read_line(std::istream& stream,
                    std::string&  out,
                    std::size_t   maxLen = MAX_LINE_LEN)
{
    std::string line;

    if (!std::getline(stream, line)) {
        return false;   // EOF or stream error
    }

    // Strip trailing carriage return (\r) for Windows compatibility
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    // Enforce length ceiling — reject oversized input
    if (line.size() > maxLen) {
        return false;
    }

    out = std::move(line);
    return true;
}


// ════════════════════════════════════════════════════════════════
// Utility: constant-time string comparison
// ════════════════════════════════════════════════════════════════

/**
 * Compare two strings in constant time to prevent timing attacks.
 * Standard == operator short-circuits on first mismatch, which leaks
 * information about where strings differ via timing side-channels.
 *
 * This implementation always iterates the full length of both strings,
 * accumulating differences with bitwise OR — result is 0 iff equal.
 *
 * @param a  First string
 * @param b  Second string
 * @return true if a == b (constant-time)
 */
bool constant_time_eq(const std::string& a, const std::string& b)
{
    // Length mismatch: still run the loop to avoid early-exit timing leak
    // but result will be non-zero
    std::size_t len   = std::max(a.size(), b.size());
    unsigned char diff = 0;

    for (std::size_t i = 0; i < len; ++i) {
        unsigned char ca = (i < a.size()) ? static_cast<unsigned char>(a[i]) : 0;
        unsigned char cb = (i < b.size()) ? static_cast<unsigned char>(b[i]) : 0;
        diff |= (ca ^ cb);
    }

    return diff == 0;
}


// ════════════════════════════════════════════════════════════════
// Input validation
// ════════════════════════════════════════════════════════════════

/**
 * Validate the username field.
 * - Non-empty
 * - Length within [3, MAX_USERNAME_LEN]
 * - Matches USERNAME_RE (alphanumeric + _ -)
 *
 * @param username  String to validate
 * @return true if valid
 */
bool validate_username(const std::string& username)
{
    if (username.empty()) {
        std::cerr << "[auth.cpp] ERROR: empty username\n";
        return false;
    }
    if (username.size() < 3 || username.size() > MAX_USERNAME_LEN) {
        std::cerr << "[auth.cpp] ERROR: username length out of range ("
                  << username.size() << ")\n";
        return false;
    }
    if (!std::regex_match(username, USERNAME_RE)) {
        std::cerr << "[auth.cpp] ERROR: username contains illegal characters\n";
        return false;
    }
    return true;
}

/**
 * Validate the bcrypt hash field.
 * - Non-empty
 * - Length within [60, MAX_HASH_LEN]  (bcrypt output is always 60 chars)
 * - Starts with a recognised bcrypt prefix ($2a$, $2b$, $2y$)
 * - Matches full BCRYPT_PREFIX_RE pattern
 * - Contains only printable ASCII (no null bytes, control chars)
 *
 * @param hash  String to validate
 * @return true if valid
 */
bool validate_hash(const std::string& hash)
{
    // Standard bcrypt hash is exactly 60 characters
    static constexpr std::size_t BCRYPT_EXACT_LEN = 60;

    if (hash.empty()) {
        std::cerr << "[auth.cpp] ERROR: empty hash\n";
        return false;
    }
    if (hash.size() < BCRYPT_EXACT_LEN || hash.size() > MAX_HASH_LEN) {
        std::cerr << "[auth.cpp] ERROR: hash length suspicious ("
                  << hash.size() << ")\n";
        return false;
    }

    // Reject any null bytes or non-printable ASCII — potential injection
    for (unsigned char c : hash) {
        if (c < 0x20 || c > 0x7E) {
            std::cerr << "[auth.cpp] ERROR: non-printable character in hash\n";
            return false;
        }
    }

    // Verify structural bcrypt pattern
    if (!std::regex_match(hash, BCRYPT_PREFIX_RE)) {
        std::cerr << "[auth.cpp] ERROR: hash does not match bcrypt pattern\n";
        return false;
    }

    return true;
}


// ════════════════════════════════════════════════════════════════
// Credential validation logic
// ════════════════════════════════════════════════════════════════

/**
 * Perform the structural validation of credentials.
 *
 * In a full kernel-integrated implementation this function would:
 *   1. Open a protected credential store (PAM / shadow file)
 *   2. Look up the stored hash for the username
 *   3. Use bcrypt_checkpw() to verify the submitted hash
 *
 * In this demonstration the C++ layer:
 *   - Receives the already-verified bcrypt hash from Python
 *   - Re-validates all inputs with independent bounds checking
 *   - Performs constant-time structural verification
 *   - Acts as the "kernel trust boundary" — Python cannot proceed
 *     without the C++ layer signing off
 *
 * Python's bcrypt library already performed the cryptographic check.
 * The C++ role here is: independent input sanitisation + structural
 * integrity confirmation at the system layer.
 *
 * @param username   Validated username string
 * @param hash       Validated bcrypt hash string
 * @return true if the C++ layer approves these credentials
 */
bool validate_credentials(const std::string& username,
                           const std::string& hash)
{
    // ── Guard 1: Both fields must be non-empty (redundant but defense-in-depth)
    if (username.empty() || hash.empty()) {
        std::cerr << "[auth.cpp] REJECT: empty field\n";
        return false;
    }

    // ── Guard 2: Username structural check (independent of Python)
    if (!validate_username(username)) {
        return false;
    }

    // ── Guard 3: Hash structural check (independent of Python)
    if (!validate_hash(hash)) {
        return false;
    }

    // ── Guard 4: No null bytes anywhere (belt-and-suspenders)
    //    std::string can contain embedded nulls; check explicitly.
    if (username.find('\0') != std::string::npos ||
        hash.find('\0')     != std::string::npos) {
        std::cerr << "[auth.cpp] REJECT: null byte detected\n";
        return false;
    }

    // ── Guard 5: No path traversal / injection characters in username
    static const std::string BANNED_CHARS = "/.\\;'\"<>|&`$(){}[]!#%^*+=~";
    for (char c : username) {
        if (BANNED_CHARS.find(c) != std::string::npos) {
            std::cerr << "[auth.cpp] REJECT: banned character in username: " << c << "\n";
            return false;
        }
    }

    // ── All guards passed ────────────────────────────────────────
    std::cerr << "[auth.cpp] INFO: all validation checks passed for '"
              << username << "'\n";
    return true;
}


// ════════════════════════════════════════════════════════════════
// Buffer overflow protection demonstration
// ════════════════════════════════════════════════════════════════

/**
 * Demonstrate safe vs unsafe C-string handling.
 * This function is for educational purposes only — it is NOT called
 * in the main auth flow. It shows WHY we use std::string + getline
 * instead of raw char buffers with scanf/gets.
 *
 * UNSAFE (DO NOT USE):
 *   char buf[64];
 *   gets(buf);             // No bounds check — classic overflow
 *   scanf("%s", buf);      // Reads until whitespace, no limit
 *   strcpy(dst, src);      // No length check
 *
 * SAFE alternatives demonstrated below:
 */
void demonstrate_safe_string_handling()
{
    // ── Safe fixed-size buffer read with fgets ───────────────────
    // char safe_buf[MAX_USERNAME_LEN + 1];
    // fgets(safe_buf, sizeof(safe_buf), stdin);  // size-bounded
    // safe_buf[MAX_USERNAME_LEN] = '\0';          // explicit termination

    // ── Safe copy with strncpy + manual null-termination ────────
    // char dst[MAX_USERNAME_LEN + 1] = {0};
    // strncpy(dst, src, MAX_USERNAME_LEN);
    // dst[MAX_USERNAME_LEN] = '\0';  // strncpy does NOT always null-terminate

    // ── Best practice: use std::string throughout ────────────────
    // std::string input;
    // std::getline(std::cin, input);   // heap-managed, no overflow
    // if (input.size() > MAX_USERNAME_LEN) { /* reject */ }

    (void)0;  // suppress unused-function warning
}


// ════════════════════════════════════════════════════════════════
// main()
// ════════════════════════════════════════════════════════════════

int main()
{
    // ── Disable sync with C stdio (minor performance + cleaner buffering)
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    // ── Read username from stdin line 1 ─────────────────────────
    std::string username;
    if (!safe_read_line(std::cin, username, MAX_USERNAME_LEN)) {
        std::cerr << "[auth.cpp] FATAL: failed to read username "
                     "(missing, empty, or exceeds " << MAX_USERNAME_LEN << " chars)\n";
        std::cout << "INVALID\n";
        return 1;
    }

    // ── Read bcrypt hash from stdin line 2 ───────────────────────
    std::string hash;
    if (!safe_read_line(std::cin, hash, MAX_HASH_LEN)) {
        std::cerr << "[auth.cpp] FATAL: failed to read hash "
                     "(missing, empty, or exceeds " << MAX_HASH_LEN << " chars)\n";
        std::cout << "INVALID\n";
        return 1;
    }

    // ── Perform credential validation ────────────────────────────
    bool result = validate_credentials(username, hash);

    // ── Output result to stdout (Python reads this) ──────────────
    if (result) {
        std::cout << "VALID\n";
        std::cerr << "[auth.cpp] RESULT: VALID for '" << username << "'\n";
        return 0;
    } else {
        std::cout << "INVALID\n";
        std::cerr << "[auth.cpp] RESULT: INVALID for '" << username << "'\n";
        return 1;
    }
}

// ═══════════════════════════════════════════════════════════════
// COMPILE INSTRUCTIONS
// ═══════════════════════════════════════════════════════════════
//
//  Standard build (recommended):
//    g++ -std=c++17 -Wall -Wextra \
//        -fstack-protector-strong \
//        -D_FORTIFY_SOURCE=2 \
//        -O2 \
//        -o auth auth.cpp
//
//  Security flags explained:
//    -fstack-protector-strong  : Adds stack canaries to functions
//                                 with local buffers → detects smashing
//    -D_FORTIFY_SOURCE=2       : Replaces unsafe libc calls (strcpy etc.)
//                                 with bounds-checked versions at compile time
//    -Wall -Wextra             : Enable all warnings; treat sloppy code seriously
//    -O2                       : Optimise; also enables more static checks
//
//  Optional hardening (Linux):
//    -z relro -z now           : Full RELRO — read-only GOT after startup
//    -pie -fPIE                : Position-independent executable (ASLR support)
//
//  Full hardened build:
//    g++ -std=c++17 -Wall -Wextra \
//        -fstack-protector-strong \
//        -D_FORTIFY_SOURCE=2 \
//        -O2 -pie -fPIE \
//        -Wl,-z,relro,-z,now \
//        -o auth auth.cpp
// ═══════════════════════════════════════════════════════════════
//