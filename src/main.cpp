// C++ Text Intelligence Starter - Backend Server
//
// Simple REST API server providing text intelligence analysis
// powered by Deepgram's Text Intelligence service.
//
// Key Features:
//   - Contract-compliant API endpoint: POST /api/text-intelligence
//   - Accepts text or URL in JSON body
//   - Supports multiple intelligence features: summarization, topics, sentiment, intents
//   - CORS-enabled for frontend communication
//   - JWT session auth with rate limiting (production only)

#include <crow.h>
#include <crow/middlewares/cors.h>
#include <nlohmann/json.hpp>
#include <toml++/toml.hpp>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Server configuration, overridable via environment variables.
struct Config {
    std::string port;
    std::string host;
};

/// Loads server configuration from environment variables with defaults.
Config load_config() {
    Config cfg;
    const char* port = std::getenv("PORT");
    cfg.port = port ? port : "8081";
    const char* host = std::getenv("HOST");
    cfg.host = host ? host : "0.0.0.0";
    return cfg;
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/// Session secret used to sign JWTs. Generated at startup if not set in env.
static std::vector<unsigned char> session_secret;

/// JWT token lifetime in seconds (1 hour).
static const int JWT_EXPIRY_SECS = 3600;

/// Performs unpadded base64url encoding.
std::string base64url_encode(const unsigned char* data, size_t len) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(4 * ((len + 2) / 3));

    for (size_t i = 0; i < len; i += 3) {
        unsigned int n = static_cast<unsigned int>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<unsigned int>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<unsigned int>(data[i + 2]);

        result += table[(n >> 18) & 0x3F];
        result += table[(n >> 12) & 0x3F];
        if (i + 1 < len) result += table[(n >> 6) & 0x3F];
        if (i + 2 < len) result += table[n & 0x3F];
    }

    // Convert to URL-safe: replace + with -, / with _
    for (auto& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    return result;
}

/// Convenience overload for std::string input.
std::string base64url_encode(const std::string& data) {
    return base64url_encode(
        reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

/// Performs unpadded base64url decoding.
std::vector<unsigned char> base64url_decode(const std::string& input) {
    // Convert URL-safe back to standard base64
    std::string s = input;
    for (auto& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Add padding if needed
    while (s.size() % 4 != 0) s += '=';

    static const int lookup[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };

    std::vector<unsigned char> result;
    result.reserve(s.size() * 3 / 4);

    for (size_t i = 0; i < s.size(); i += 4) {
        int n = 0;
        int pad = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned char c = static_cast<unsigned char>(s[i + j]);
            if (c == '=') {
                pad++;
                n <<= 6;
            } else if (c < 128 && lookup[c] >= 0) {
                n = (n << 6) | lookup[c];
            } else {
                return {};
            }
        }
        result.push_back(static_cast<unsigned char>((n >> 16) & 0xFF));
        if (pad < 2) result.push_back(static_cast<unsigned char>((n >> 8) & 0xFF));
        if (pad < 1) result.push_back(static_cast<unsigned char>(n & 0xFF));
    }
    return result;
}

/// Initializes the session secret from environment or generates a random one.
void init_session_secret() {
    const char* secret = std::getenv("SESSION_SECRET");
    if (secret && std::strlen(secret) > 0) {
        session_secret.assign(secret, secret + std::strlen(secret));
        return;
    }
    // Generate a random 32-byte secret for local development
    session_secret.resize(32);
    RAND_bytes(session_secret.data(), 32);
}

/// Computes HMAC-SHA256 signature.
std::vector<unsigned char> hmac_sha256(
    const std::vector<unsigned char>& key, const std::string& data) {
    unsigned int len = 0;
    unsigned char result[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), result, &len);
    return std::vector<unsigned char>(result, result + len);
}

/// Creates a signed HS256 JWT with the configured expiry duration.
std::string create_jwt() {
    std::string header_json = R"({"alg":"HS256","typ":"JWT"})";
    std::string encoded_header = base64url_encode(header_json);

    auto now = std::time(nullptr);
    auto exp = now + JWT_EXPIRY_SECS;

    json payload;
    payload["iat"] = now;
    payload["exp"] = exp;
    std::string encoded_payload = base64url_encode(payload.dump());

    std::string signing_input = encoded_header + "." + encoded_payload;
    auto sig = hmac_sha256(session_secret, signing_input);
    std::string encoded_sig = base64url_encode(sig.data(), sig.size());

    return signing_input + "." + encoded_sig;
}

/// Validates a JWT signature and expiry. Returns empty string on success,
/// error message on failure.
std::string verify_jwt(const std::string& token) {
    // Split token into 3 parts
    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) return "invalid token format";
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return "invalid token format";
    if (token.find('.', dot2 + 1) != std::string::npos) return "invalid token format";

    std::string signing_input = token.substr(0, dot2);
    std::string provided_sig = token.substr(dot2 + 1);

    // Verify signature
    auto expected_sig_bytes = hmac_sha256(session_secret, signing_input);
    std::string expected_sig = base64url_encode(
        expected_sig_bytes.data(), expected_sig_bytes.size());

    if (provided_sig != expected_sig) {
        return "invalid signature";
    }

    // Decode and check expiry
    std::string payload_part = token.substr(dot1 + 1, dot2 - dot1 - 1);
    auto payload_bytes = base64url_decode(payload_part);
    if (payload_bytes.empty()) return "invalid payload encoding";

    std::string payload_str(payload_bytes.begin(), payload_bytes.end());
    try {
        auto claims = json::parse(payload_str);
        auto now = std::time(nullptr);
        if (claims.contains("exp") && now > claims["exp"].get<int64_t>()) {
            return "token expired";
        }
    } catch (...) {
        return "invalid payload";
    }

    return "";
}

/// Validates the Authorization header and returns a JSON error response
/// if invalid. Returns std::nullopt on success.
std::optional<json> require_session(const crow::request& req) {
    std::string auth_header = req.get_header_value("Authorization");

    if (auth_header.empty() || auth_header.substr(0, 7) != "Bearer ") {
        return json{
            {"error", {
                {"type", "AuthenticationError"},
                {"code", "MISSING_TOKEN"},
                {"message", "Authorization header with Bearer token is required"}
            }}
        };
    }

    std::string token = auth_header.substr(7);
    std::string err = verify_jwt(token);
    if (!err.empty()) {
        std::string message = (err.find("expired") != std::string::npos)
            ? "Session expired, please refresh the page"
            : "Invalid session token";
        return json{
            {"error", {
                {"type", "AuthenticationError"},
                {"code", "INVALID_TOKEN"},
                {"message", message}
            }}
        };
    }

    return std::nullopt;
}

// ============================================================================
// API KEY LOADING
// ============================================================================

/// Reads the Deepgram API key from the environment. Exits if not set.
std::string load_api_key() {
    const char* key = std::getenv("DEEPGRAM_API_KEY");
    if (!key || std::strlen(key) == 0) {
        std::cerr << "\nERROR: Deepgram API key not found!\n" << std::endl;
        std::cerr << "Please set your API key in .env file:" << std::endl;
        std::cerr << "   DEEPGRAM_API_KEY=your_api_key_here\n" << std::endl;
        std::cerr << "Get your API key at: https://console.deepgram.com\n" << std::endl;
        std::exit(1);
    }
    return std::string(key);
}

// ============================================================================
// ENVIRONMENT FILE LOADING
// ============================================================================

/// Loads environment variables from a .env file (ignores errors).
void load_dotenv() {
    std::ifstream file(".env");
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        // Trim whitespace
        while (!key.empty() && std::isspace(key.back())) key.pop_back();
        while (!key.empty() && std::isspace(key.front())) key.erase(key.begin());
        while (!value.empty() && std::isspace(value.back())) value.pop_back();
        while (!value.empty() && std::isspace(value.front())) value.erase(value.begin());

        // Remove surrounding quotes if present
        if (value.size() >= 2 &&
            ((value.front() == '"' && value.back() == '"') ||
             (value.front() == '\'' && value.back() == '\''))) {
            value = value.substr(1, value.size() - 2);
        }

        // Only set if not already set in environment
        if (!std::getenv(key.c_str())) {
            setenv(key.c_str(), value.c_str(), 0);
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Builds a structured error JSON response.
json error_response(const std::string& err_type, const std::string& code,
                    const std::string& message) {
    return json{
        {"error", {
            {"type", err_type},
            {"code", code},
            {"message", message},
            {"details", json::object()}
        }}
    };
}

/// URL-encodes a string for use in query parameters.
std::string url_encode(const std::string& str) {
    char* encoded = curl_easy_escape(nullptr, str.c_str(),
                                     static_cast<int>(str.size()));
    std::string result(encoded);
    curl_free(encoded);
    return result;
}

/// libcurl write callback for capturing response body.
static size_t write_callback(void* contents, size_t size, size_t nmemb,
                              std::string* output) {
    size_t total = size * nmemb;
    output->append(static_cast<char*>(contents), total);
    return total;
}

/// Performs an HTTP GET request and returns the response body.
/// Sets status_code to the HTTP status code.
std::string http_get(const std::string& url, long& status_code) {
    std::string response;
    CURL* curl = curl_easy_init();
    if (!curl) {
        status_code = 0;
        return "";
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        status_code = 0;
        return "";
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    curl_easy_cleanup(curl);
    return response;
}

/// Performs an HTTP POST request with JSON body and auth header.
/// Sets status_code to the HTTP status code.
std::string http_post_json(const std::string& url, const std::string& body,
                            const std::string& auth_token, long& status_code) {
    std::string response;
    CURL* curl = curl_easy_init();
    if (!curl) {
        status_code = 0;
        return "";
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string auth_header = "Authorization: Token " + auth_token;
    headers = curl_slist_append(headers, auth_header.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        std::cerr << "Deepgram API Error: " << curl_easy_strerror(res)
                  << std::endl;
        curl_easy_cleanup(curl);
        status_code = 0;
        return "";
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    curl_easy_cleanup(curl);
    return response;
}

/// Validates that a string looks like a URL (starts with http:// or https://).
bool is_valid_url(const std::string& url) {
    return url.substr(0, 7) == "http://" || url.substr(0, 8) == "https://";
}

// ============================================================================
// TOML METADATA
// ============================================================================

/// Converts a toml::node to nlohmann::json.
json toml_to_json(const toml::node& node) {
    if (auto* str = node.as_string()) {
        return json(str->get());
    } else if (auto* integer = node.as_integer()) {
        return json(integer->get());
    } else if (auto* floating = node.as_floating_point()) {
        return json(floating->get());
    } else if (auto* boolean = node.as_boolean()) {
        return json(boolean->get());
    } else if (auto* arr = node.as_array()) {
        json j = json::array();
        for (const auto& elem : *arr) {
            j.push_back(toml_to_json(elem));
        }
        return j;
    } else if (auto* tbl = node.as_table()) {
        json j = json::object();
        for (const auto& [k, v] : *tbl) {
            j[std::string(k)] = toml_to_json(v);
        }
        return j;
    }
    return json(nullptr);
}

// ============================================================================
// SERVER START
// ============================================================================

int main() {
    // Load .env file (ignore error if not present)
    load_dotenv();

    // Load configuration
    Config cfg = load_config();

    // Initialize session secret
    init_session_secret();

    // Load Deepgram API key
    std::string api_key = load_api_key();

    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Set up Crow application with CORS
    crow::App<crow::CORSHandler> app;

    auto& cors = app.get_middleware<crow::CORSHandler>();
    cors.global()
        .origin("*")
        .methods("GET"_method, "POST"_method, "OPTIONS"_method)
        .headers("Content-Type", "Authorization");

    // ========================================================================
    // ROUTE HANDLERS
    // ========================================================================

    /// Issues a signed JWT session token.
    /// GET /api/session
    CROW_ROUTE(app, "/api/session").methods(crow::HTTPMethod::Get)(
        [](const crow::request&) {
            std::string token = create_jwt();
            json resp;
            resp["token"] = token;
            auto response = crow::response(200, resp.dump());
            response.set_header("Content-Type", "application/json");
            return response;
        });

    /// Processes text analysis requests via Deepgram Read API.
    /// POST /api/text-intelligence
    CROW_ROUTE(app, "/api/text-intelligence").methods(crow::HTTPMethod::Post)(
        [&api_key](const crow::request& req) {
            // Auth check
            auto auth_err = require_session(req);
            if (auth_err.has_value()) {
                auto response = crow::response(401, auth_err->dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }

            // Parse JSON body
            json body;
            try {
                body = json::parse(req.body);
            } catch (...) {
                auto err = error_response("validation_error", "INVALID_TEXT",
                                          "Invalid JSON body");
                auto response = crow::response(400, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }

            std::string text = body.value("text", "");
            std::string url = body.value("url", "");

            // Validate: exactly one of text or url
            if (text.empty() && url.empty()) {
                auto err = error_response("validation_error", "INVALID_TEXT",
                    "Request must contain either 'text' or 'url' field");
                auto response = crow::response(400, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }
            if (!text.empty() && !url.empty()) {
                auto err = error_response("validation_error", "INVALID_TEXT",
                    "Request must contain either 'text' or 'url', not both");
                auto response = crow::response(400, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }

            // If URL provided, fetch the text content from it
            std::string text_content = text;
            if (!url.empty()) {
                // Validate URL format
                if (!is_valid_url(url)) {
                    auto err = error_response("validation_error",
                        "INVALID_URL", "Invalid URL format");
                    auto response = crow::response(400, err.dump());
                    response.set_header("Content-Type", "application/json");
                    return response;
                }

                long status_code = 0;
                std::string fetched = http_get(url, status_code);
                if (status_code == 0) {
                    auto err = error_response("validation_error",
                        "INVALID_URL", "Failed to fetch URL");
                    auto response = crow::response(400, err.dump());
                    response.set_header("Content-Type", "application/json");
                    return response;
                }
                if (status_code < 200 || status_code >= 300) {
                    auto err = error_response("validation_error",
                        "INVALID_URL",
                        "Failed to fetch URL: HTTP " + std::to_string(status_code));
                    auto response = crow::response(400, err.dump());
                    response.set_header("Content-Type", "application/json");
                    return response;
                }
                text_content = fetched;
            }

            // Check for empty text
            auto trimmed = text_content;
            trimmed.erase(0, trimmed.find_first_not_of(" \t\n\r"));
            trimmed.erase(trimmed.find_last_not_of(" \t\n\r") + 1);
            if (trimmed.empty()) {
                auto err = error_response("validation_error", "EMPTY_TEXT",
                    "Text content cannot be empty");
                auto response = crow::response(400, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }

            // Extract query parameters for intelligence features
            const auto& params = req.url_params;
            std::string language = params.get("language")
                ? params.get("language") : "en";
            std::string summarize = params.get("summarize")
                ? params.get("summarize") : "";
            std::string topics = params.get("topics")
                ? params.get("topics") : "";
            std::string sentiment = params.get("sentiment")
                ? params.get("sentiment") : "";
            std::string intents = params.get("intents")
                ? params.get("intents") : "";

            // Handle summarize v1 rejection
            if (summarize == "v1") {
                auto err = error_response("validation_error", "INVALID_TEXT",
                    "Summarization v1 is no longer supported. Please use v2 or true.");
                auto response = crow::response(400, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }

            // Build Deepgram API URL with query parameters
            std::string dg_url = "https://api.deepgram.com/v1/read?language="
                + url_encode(language);

            if (summarize == "true" || summarize == "v2") {
                dg_url += "&summarize=v2";
            }
            if (topics == "true") {
                dg_url += "&topics=true";
            }
            if (sentiment == "true") {
                dg_url += "&sentiment=true";
            }
            if (intents == "true") {
                dg_url += "&intents=true";
            }

            // Build request body for Deepgram
            json dg_body;
            dg_body["text"] = text_content;

            // Call Deepgram Read API
            long dg_status = 0;
            std::string dg_response = http_post_json(
                dg_url, dg_body.dump(), api_key, dg_status);

            if (dg_status == 0) {
                auto err = error_response("processing_error", "INVALID_TEXT",
                    "Failed to process text");
                auto response = crow::response(400, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }

            // Handle non-2xx from Deepgram
            if (dg_status < 200 || dg_status >= 300) {
                std::cerr << "Deepgram API Error (status " << dg_status
                          << "): " << dg_response << std::endl;
                auto err = error_response("processing_error", "INVALID_TEXT",
                    "Failed to process text");
                auto response = crow::response(400, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }

            // Parse Deepgram response to extract results
            json dg_result;
            try {
                dg_result = json::parse(dg_response);
            } catch (...) {
                std::cerr << "Deepgram Response Parse Error" << std::endl;
                auto err = error_response("processing_error", "INVALID_TEXT",
                    "Failed to parse Deepgram response");
                auto response = crow::response(500, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }

            // Return results (the Deepgram response includes a "results" key)
            json results = dg_result.contains("results")
                ? dg_result["results"] : json::object();

            json resp;
            resp["results"] = results;
            auto response = crow::response(200, resp.dump());
            response.set_header("Content-Type", "application/json");
            return response;
        });

    /// Returns metadata from deepgram.toml.
    /// GET /api/metadata
    CROW_ROUTE(app, "/api/metadata").methods(crow::HTTPMethod::Get)(
        [](const crow::request&) {
            try {
                auto tbl = toml::parse_file("deepgram.toml");
                auto meta = tbl["meta"];
                if (!meta) {
                    json err;
                    err["error"] = "INTERNAL_SERVER_ERROR";
                    err["message"] = "Missing [meta] section in deepgram.toml";
                    auto response = crow::response(500, err.dump());
                    response.set_header("Content-Type", "application/json");
                    return response;
                }
                json result = toml_to_json(*meta.node());
                auto response = crow::response(200, result.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            } catch (const std::exception& e) {
                std::cerr << "Error reading deepgram.toml: " << e.what()
                          << std::endl;
                json err;
                err["error"] = "INTERNAL_SERVER_ERROR";
                err["message"] = "Failed to read metadata from deepgram.toml";
                auto response = crow::response(500, err.dump());
                response.set_header("Content-Type", "application/json");
                return response;
            }
        });

    /// Returns a simple health check response.
    /// GET /health
    CROW_ROUTE(app, "/health").methods(crow::HTTPMethod::Get)(
        [](const crow::request&) {
            json resp;
            resp["status"] = "ok";
            resp["service"] = "text-intelligence";
            auto response = crow::response(200, resp.dump());
            response.set_header("Content-Type", "application/json");
            return response;
        });

    // Print startup banner
    std::cout << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Backend API running at http://localhost:" << cfg.port
              << std::endl;
    std::cout << std::endl;
    std::cout << "GET  /api/session" << std::endl;
    std::cout << "POST /api/text-intelligence (auth required)" << std::endl;
    std::cout << "GET  /api/metadata" << std::endl;
    std::cout << "GET  /health" << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << std::endl;

    // Start server
    int port = std::stoi(cfg.port);
    app.bindaddr(cfg.host).port(port).multithreaded().run();

    curl_global_cleanup();
    return 0;
}
