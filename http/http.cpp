#include <http.h>
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <regex>
#include <memory>
#include <cstdint>  
#include <locale>
#include <codecvt>


#define ANSI_BLACK         "\x1b[30m"
#define ANSI_RED           "\x1b[31m"
#define ANSI_GREEN         "\x1b[32m"
#define ANSI_YELLOW        "\x1b[33m"
#define ANSI_BLUE          "\x1b[34m"
#define ANSI_MAGENTA       "\x1b[35m"
#define ANSI_CYAN          "\x1b[36m"
#define ANSI_WHITE         "\x1b[37m"
#define ANSI_RESET         "\x1b[0m"

#define ANSI_BOLD_BLACK    "\x1b[1;30m"
#define ANSI_BOLD_RED      "\x1b[1;31m"
#define ANSI_BOLD_GREEN    "\x1b[1;32m"
#define ANSI_BOLD_YELLOW   "\x1b[1;33m"
#define ANSI_BOLD_BLUE     "\x1b[1;34m"
#define ANSI_BOLD_MAGENTA  "\x1b[1;35m"
#define ANSI_BOLD_CYAN     "\x1b[1;36m"
#define ANSI_BOLD_WHITE    "\x1b[1;37m"
#define ANSI_BOLD          "\x1b[1m"

std::wstring ConvertStringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

std::wstring StringToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr);
    return strTo;
}

std::wstring NormalStringToWideString(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
    return conv.from_bytes(str);
}

std::vector<uint8_t> ToUtf8Bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

void CmdHttpPut(const std::string& args) {
    std::vector<std::string> tokens;
    {
        std::istringstream iss(args);
        std::string token;
        while (std::getline(iss, token, '|')) {
            size_t start = token.find_first_not_of(" \t");
            size_t end = token.find_last_not_of(" \t");
            if (start != std::string::npos && end != std::string::npos)
                tokens.push_back(token.substr(start, end - start + 1));
        }
    }

    if (tokens.empty()) {
        std::cerr << "Usage: put <URL> [header1|header2|...] [|payload]\n";
        return;
    }

    std::string url = tokens[0];
    std::vector<std::string> headers;
    std::string payload;

    if (tokens.size() > 1) {
        if (tokens.size() > 2) {
            for (size_t i = 1; i < tokens.size() - 1; ++i)
                headers.push_back(tokens[i]);
            payload = tokens.back();
        } else {
            if (tokens[1].find(':') != std::string::npos)
                headers.push_back(tokens[1]);
            else
                payload = tokens[1];
        }
    }

    std::wstring wurl = ConvertStringToWString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};

    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = (DWORD)_countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = (DWORD)_countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    if (urlComp.nScheme != INTERNET_SCHEME_HTTP && urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
        std::cerr << "Unsupported URL scheme. Only HTTP and HTTPS are supported.\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0);
    if (!hSession) {
        std::cerr << "Failed to open WinHTTP session. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession,
                                       host,
                                       urlComp.nPort,
                                       0);
    if (!hConnect) {
        std::cerr << "Failed to connect to host. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD dwFlags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                           L"PUT",
                                           path,
                                           nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           dwFlags);
    if (!hRequest) {
        std::cerr << "Failed to open HTTP request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy))) {
        std::cerr << "Failed to set redirect policy. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring headers_w;
    for (const auto& hdr : headers) {
        headers_w += ConvertStringToWString(hdr) + L"\r\n";
    }
    const wchar_t* additionalHeaders = headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str();
    DWORD headersLength = (DWORD)headers_w.length();

    const char* payloadData = nullptr;
    DWORD payloadSize = 0;
    std::vector<char> payloadBuffer;
    if (!payload.empty()) {
        payloadBuffer.assign(payload.begin(), payload.end());
        payloadData = payloadBuffer.data();
        payloadSize = (DWORD)payloadBuffer.size();
    }

    if (!WinHttpSendRequest(hRequest,
                           additionalHeaders,
                           headersLength,
                           (void*)payloadData,
                           payloadSize,
                           payloadSize,
                           0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             nullptr, &statusCode, &size, nullptr)) {
        std::cerr << "Failed to query status code. Error: " << GetLastError() << "\n";
    } else {
        std::cout << "HTTP Status Code: " << statusCode << "\n\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            std::cerr << "Error querying data availability: " << GetLastError() << "\n";
            break;
        }
        if (dwSize == 0)
            break;

        std::vector<char> buffer(dwSize + 1);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
            std::cerr << "Error reading data: " << GetLastError() << "\n";
            break;
        }
        buffer[dwDownloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

struct WinHttpHandle {
    HINTERNET handle = nullptr;

    // Default constructor
    WinHttpHandle() = default;

    // Constructor from raw handle
    explicit WinHttpHandle(HINTERNET h) : handle(h) {}

    // Destructor
    ~WinHttpHandle() {
        if (handle) WinHttpCloseHandle(handle);
    }

    // No copy
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    // Move constructor
    WinHttpHandle(WinHttpHandle&& other) noexcept : handle(other.handle) {
        other.handle = nullptr;
    }

    // Move assignment
    WinHttpHandle& operator=(WinHttpHandle&& other) noexcept {
        static_assert(std::is_same_v<decltype(other), WinHttpHandle&&>, "other is not WinHttpHandle&&");
        if (this != std::addressof(other)) {
            if (handle) WinHttpCloseHandle(handle);
            handle = other.handle;
            other.handle = nullptr;
        }
        return *this;
    }

    explicit operator bool() const { return handle != nullptr; }
    HINTERNET* operator&() { return &handle; }
    HINTERNET get() const { return handle; }
};



std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return {};
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

static bool ParseArgs(const std::string& args, std::string& outUrl, std::vector<std::string>& outHeaders) {
    std::istringstream iss(args);
    if (!(iss >> outUrl)) return false; 

    std::string header;
    while (std::getline(iss, header, '|')) {
        size_t start = header.find_first_not_of(" \t");
        size_t end = header.find_last_not_of(" \t");
        if (start != std::string::npos && end != std::string::npos)
            outHeaders.push_back(header.substr(start, end - start + 1));
    }
    return true;
}

void CmdHttpGet(const std::string& args) {
    std::string url;
    std::vector<std::string> headers;

    if (!ParseArgs(args, url, headers)) {
        std::cerr << "Usage: get <URL> [header1|header2|...]\n";
        return;
    }

    WinHttpHandle hSession;
    hSession.handle = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cerr << "Failed to open WinHTTP session. Error: " << GetLastError() << "\n";
        return;
    }

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    std::wstring wurl = StringToWString(url);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    if (urlComp.nScheme != INTERNET_SCHEME_HTTP && urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
        std::cerr << "Unsupported URL scheme. Only HTTP and HTTPS are supported.\n";
        return;
    }

    WinHttpHandle hConnect;
    hConnect.handle = WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cerr << "Failed to connect to host. Error: " << GetLastError() << "\n";
        return;
    }

    DWORD dwFlags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

    WinHttpHandle hRequest;
    hRequest.handle = WinHttpOpenRequest(hConnect.get(), L"GET", urlComp.lpszUrlPath,
                                        nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
    if (!hRequest) {
        std::cerr << "Failed to open HTTP request. Error: " << GetLastError() << "\n";
        return;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    if (!WinHttpSetOption(hRequest.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy))) {
        std::cerr << "Failed to set redirect policy. Error: " << GetLastError() << "\n";
        return;
    } 

    std::wstring headers_w;
    for (const auto& hdr : headers) {
        headers_w += StringToWString(hdr) + L"\r\n";
    }

    if (!WinHttpSendRequest(hRequest.get(),
                           headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                           (DWORD)headers_w.length(),
                           nullptr, 0, 0, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        return;
    }

    if (!WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        return;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             nullptr, &statusCode, &size, nullptr)) {
        std::cerr << "Failed to query status code. Error: " << GetLastError() << "\n";
    } else {
        std::cout << "HTTP Status Code: " << statusCode << "\n\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest.get(), &dwSize)) {
            std::cerr << "Error querying data availability: " << GetLastError() << "\n";
            break;
        }
        if (dwSize == 0) break;

        std::vector<char> buffer(dwSize + 1);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest.get(), buffer.data(), dwSize, &dwDownloaded)) {
            std::cerr << "Error reading data: " << GetLastError() << "\n";
            break;
        }
        buffer[dwDownloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;
}

std::wstring ToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), NULL, 0);
    if (size_needed <= 0) return std::wstring();
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

std::string Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    size_t end = s.find_last_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

void CmdHttpPost(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);  
        }
        tokens.push_back(token);
    }

    std::string url, body;
    std::vector<std::wstring> headers;
    std::wstring contentTypeOverride;

    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        if (token == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (token == "-T" && i + 1 < tokens.size()) {
            contentTypeOverride = ToWString(tokens[++i]);
        } else if (token == "-d" && i + 1 < tokens.size()) {
            body = tokens[++i];
        } else if (token.rfind("-", 0) != 0 && url.empty()) {
            url = Trim(token);
        }
    }

    if (url.empty() || body.empty()) {
        std::cout << "Error:\nError: Usage: post [-H \"Header\"] [-T content-type] -d <body> <url>\n";
        return;
    }

    std::wstring finalContentType;
    if (!contentTypeOverride.empty()) {
        finalContentType = L"Content-Type: " + contentTypeOverride + L"\r\n";
    } else if (!body.empty() && (body[0] == '{' || body[0] == '[')) {
        finalContentType = L"Content-Type: application/json\r\n";
    } else {
        finalContentType = L"Content-Type: application/x-www-form-urlencoded\r\n";
    }
    headers.insert(headers.begin(), finalContentType);

    std::wstring wurl = ToWString(url);
    std::wcout << L"Debug: URL = " << wurl << L"\n";

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.c_str(), (DWORD)allHeaders.length(),
                                       (LPVOID)body.data(), (DWORD)body.size(),
                                       (DWORD)body.size(), 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cout << "Success:\nResponse:\n";

        DWORD dwSize = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                std::cout << "Error: Failed to query data available.\n";
                break;
            }
            if (dwSize == 0) {
                break; 
            }

            std::vector<char> buffer(dwSize + 1, 0);
            DWORD dwDownloaded = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                std::cout << "Error: Failed to read data.\n";
                break;
            }

            std::cout << std::string(buffer.data(), dwDownloaded);
        } while (dwSize > 0);

        std::cout << std::endl;

    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nError: HTTP POST failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpHeader(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (tokens[i].rfind("-", 0) != 0 && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nError: Usage: head [-H \"Header\"] <url>\n";
        return;
    }

    std::wstring wurl = ToWString(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)allHeaders.length(),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   WINHTTP_HEADER_NAME_BY_INDEX, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Success:\nResponse headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nError: Failed to read response headers\n";
            }
        } else {
            std::cout << "Error:\nError: Failed to query response headers size\n";
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nError: HTTP HEAD failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpDelete(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (tokens[i].rfind("-", 0) != 0 && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nError: Usage: delete [-H \"Header\"] <url>\n";
        return;
    }

    std::wstring wurl = ToWString(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"DELETE", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)allHeaders.length(),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                nullptr, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
            std::cout << "Success:\nHTTP DELETE status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP DELETE request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   WINHTTP_HEADER_NAME_BY_INDEX, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP DELETE failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpPatch(const std::string& args) {
    // Tokenize args respecting quoted strings
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;
    std::string body;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (tokens[i] == "-d" && i + 1 < tokens.size()) {
            body = tokens[++i];
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nError: Usage: patch [-H \"Header\"] [-d \"body\"] <url>\n";
        return;
    }

    std::wstring wurl = ToWString(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"PATCH", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Concatenate headers with CRLF
    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    // Convert body to UTF-8 bytes (raw bytes, not wchar_t)
    std::vector<uint8_t> bodyBytes = ToUtf8Bytes(body);

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)(allHeaders.size() * sizeof(wchar_t)),
                                       bodyBytes.empty() ? nullptr : bodyBytes.data(),
                                       (DWORD)bodyBytes.size(),
                                       (DWORD)bodyBytes.size(),
                                       0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
            std::cout << "Success:\nHTTP PATCH status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP PATCH request sent, but failed to get status code\n";
        }

        // Get size of raw headers
        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP PATCH failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpOptions(const std::string& args) {
    // Parse args: split by spaces but keep quoted strings intact
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nError: Usage: options [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = ToWString(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"OPTIONS", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Combine headers into one string with CRLF
    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)(allHeaders.size()),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP OPTIONS status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP OPTIONS request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        // First call to get the buffer size needed
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP OPTIONS failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

bool ParseUrl(const std::wstring& url, URL_COMPONENTS& urlComp) {
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    static wchar_t host[256];
    static wchar_t path[1024];
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    return WinHttpCrackUrl(url.c_str(), (DWORD)-1, 0, &urlComp) != FALSE;
}

void CmdHttpLink(const std::string& args) {
    // Parse args same way as OPTIONS
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: link [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = StringToWide(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nFailed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nConnection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    // For custom verbs like LINK, use WINHTTP_FLAG_BYPASS_PROXY_CACHE flag to avoid Error 87
    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE) : WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"LINK", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           flags);
    if (!hRequest) {
        std::cout << "Error:\nFailed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Combine headers into one string with CRLF
    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)(allHeaders.size()),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP LINK status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP LINK request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP LINK failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpUnlink(const std::string& args) {
    // Parse args: split by spaces but keep quoted strings intact
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: unlink [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = StringToWide(url);

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        return;
    }

    WinHttpHandle hSession(WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) {
        std::cout << "Error:\nFailed to open WinHTTP session\n";
        return;
    }

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));
    if (!hConnect) {
        std::cout << "Error:\nConnection failed\n";
        return;
    }

    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"UNLINK", urlComp.lpszUrlPath,
                                             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) {
        std::cout << "Error:\nFailed to open request\n";
        return;
    }

    // Combine headers into one string with CRLF
    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest.get(),
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)allHeaders.size(),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP UNLINK status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP UNLINK request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP UNLINK failed (code " << error << ")\n";
    }
}

void CmdHttpTrace(const std::string& args) {
    // Parse args: split by spaces but keep quoted strings intact
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: trace [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = StringToWide(url);

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        return;
    }

    WinHttpHandle hSession(WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) {
        std::cout << "Error:\nFailed to open WinHTTP session\n";
        return;
    }

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));
    if (!hConnect) {
        std::cout << "Error:\nConnection failed\n";
        return;
    }

    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"TRACE", urlComp.lpszUrlPath,
                                             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) {
        std::cout << "Error:\nFailed to open request\n";
        return;
    }

    // Add headers one by one using WinHttpAddRequestHeaders
    for (const auto& h : headers) {
        if (!WinHttpAddRequestHeaders(hRequest.get(), h.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD)) {
            std::cout << "Error:\nFailed to add header: " << WideToUtf8(h) << "\n";
            return;
        }
    }

    // Send request with nullptr headers param
    BOOL bResults = WinHttpSendRequest(
        hRequest.get(),
        nullptr,
        0,
        nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP TRACE status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP TRACE request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP TRACE failed (code " << error << ")\n";
    }
}

std::vector<std::wstring> ParseHeaders(const std::vector<std::string>& headerArgs) {
    std::vector<std::wstring> headers;
    for (const auto& h : headerArgs) {
        headers.push_back(NormalStringToWideString(h));
    }
    return headers;
}

// Print last WinHTTP error with context
void PrintWinHttpError(const std::string& context) {
    DWORD err = GetLastError();
    std::cerr << context << " failed with error: " << err << std::endl;
}

void CmdHttpConnect(const std::string& args) {
    std::istringstream iss(args);
    std::string proxy, target;

    iss >> proxy >> target;
    if (proxy.empty() || target.empty()) {
        std::cout << "Usage: connect <proxyHost:port> <targetHost:port> [-H \"Header: value\" ...]\n";
        return;
    }

    // Collect headers
    std::vector<std::string> headersArgs;
    while (iss >> std::ws) {
        if (iss.peek() == '-') {
            std::string flag;
            iss >> flag;
            if (flag == "-H") {
                std::string headerVal;
                if (!(iss >> std::quoted(headerVal))) {
                    std::cout << "Invalid header format. Use -H \"Header: value\"\n";
                    return;
                }
                headersArgs.push_back(headerVal);
            } else {
                std::cout << "Unknown flag " << flag << "\n";
                return;
            }
        } else {
            break;
        }
    }

    // Parse target
    size_t colonPos = target.find(':');
    if (colonPos == std::string::npos) {
        std::cout << "Invalid target format, must be host:port\n";
        return;
    }

    std::string targetHost = target.substr(0, colonPos);
    std::string targetPortStr = target.substr(colonPos + 1);
    int targetPort = std::stoi(targetPortStr);
    if (targetPort <= 0 || targetPort > 65535) {
        std::cout << "Invalid target port\n";
        return;
    }

    // Proxy string must be in the format "http=host:port" for WinHttp
    std::wstring wProxy = NormalStringToWideString("http=" + proxy);
    std::wstring wTargetHost = NormalStringToWideString(targetHost);

    // Open session with proxy
    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
        WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        wProxy.c_str(),
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        PrintWinHttpError("WinHttpOpen");
        return;
    }

    // Connect to target host
    HINTERNET hConnect = WinHttpConnect(hSession, wTargetHost.c_str(), targetPort, 0);
    if (!hConnect) {
        PrintWinHttpError("WinHttpConnect");
        WinHttpCloseHandle(hSession);
        return;
    }

    // Open CONNECT request
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"CONNECT", nullptr,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        PrintWinHttpError("WinHttpOpenRequest");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Prepare headers
    std::wstring headersCombined;
    if (!headersArgs.empty()) {
        auto headers = ParseHeaders(headersArgs);
        for (const auto& hdr : headers) {
            headersCombined += hdr + L"\r\n";
        }
    }

    // Send request
    BOOL bSend = WinHttpSendRequest(hRequest,
        headersCombined.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headersCombined.c_str(),
        headersCombined.empty() ? 0 : static_cast<DWORD>(headersCombined.length()),
        nullptr, 0, 0, 0);
    if (!bSend) {
        PrintWinHttpError("WinHttpSendRequest");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        PrintWinHttpError("WinHttpReceiveResponse");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Check status code
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        nullptr, &statusCode, &size, nullptr)) {
        PrintWinHttpError("WinHttpQueryHeaders");
    }

    std::cout << "HTTP CONNECT status code: " << statusCode << std::endl;
    if (statusCode == 200) {
        std::cout << "Tunnel successfully established to " << target << " through proxy " << proxy << std::endl;
    } else {
        std::cout << "Failed to establish tunnel, status code: " << statusCode << std::endl;
    }

    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpPropFind(const std::string& args) {
    // Parse args: split by spaces but keep quoted strings intact
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: propfind [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = StringToWide(url);

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        return;
    }

    WinHttpHandle hSession(WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) {
        std::cout << "Error:\nFailed to open WinHTTP session\n";
        return;
    }

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));
    if (!hConnect) {
        std::cout << "Error:\nConnection failed\n";
        return;
    }

    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"PROPFIND", urlComp.lpszUrlPath,
                                             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) {
        std::cout << "Error:\nFailed to open request\n";
        return;
    }

    // Check if user supplied Content-Type header; if not, add default
    bool hasContentType = false;
    for (const auto& h : headers) {
        if (_wcsnicmp(h.c_str(), L"Content-Type:", 13) == 0) {
            hasContentType = true;
            break;
        }
    }
    if (!hasContentType) {
        headers.push_back(L"Content-Type: application/xml");
    }

    // Add headers one by one using WinHttpAddRequestHeaders
    for (const auto& h : headers) {
        if (!WinHttpAddRequestHeaders(hRequest.get(), h.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD)) {
            std::cout << "Error:\nFailed to add header: " << WideToUtf8(h) << "\n";
            return;
        }
    }

    // Typical minimal PROPFIND XML body
    const char* propfindXml =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<propfind xmlns=\"DAV:\">"
        "<allprop/>"
        "</propfind>";
    DWORD bodySize = (DWORD)strlen(propfindXml);

    BOOL bResults = WinHttpSendRequest(
        hRequest.get(),
        nullptr, 0,
        (LPVOID)propfindXml, bodySize,
        bodySize, 0);

    if (bResults && WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP PROPFIND status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP PROPFIND request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }

        // Read and print response body (optional)
        std::vector<char> buffer(4096);
        DWORD bytesRead = 0;
        std::cout << "Response body:\n";
        while (WinHttpReadData(hRequest.get(), buffer.data(), (DWORD)buffer.size(), &bytesRead) && bytesRead > 0) {
            std::cout.write(buffer.data(), bytesRead);
        }
        std::cout << "\n";
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP PROPFIND failed (code " << error << ")\n";
    }
}

void CmdHttpHelp(const std::string& args) {
    (void)args;
    std::cout << ANSI_BOLD_CYAN "======== HTTP Commands Help ========\n" << ANSI_RESET;
    std::cout << "Available commands:\n";
    std::cout << " - http put <url> <headers|body>            : Send an HTTP PUT request.\n";
    std::cout << " - http get <url>                           : Send an HTTP GET request.\n";
    std::cout << " - http head [-H \"Header\"] <url>          : Send an HTTP HEAD request.\n";
    std::cout << " - http post <url> <headers|body>           : Send an HTTP POST request.\n";
    std::cout << " - http delete [-H \"Header\"] <url>        : Send an HTTP DELETE request.\n";
    std::cout << " - http options [-H \"Header\"] <url>       : Send an HTTP OPTIONS request.\n";
    std::cout << " - http link [-H \"Header: value\"] <url>   : Send an HTTP LINK request.\n";
    std::cout << " - http unlink [-H \"Header: value\"] <url> : Send an HTTP UNLINK request.\n";
    std::cout << " - http trace [-H \"Header: value\"] <url>  : Send an HTTP TRACE request.\n";
    std::cout << " - http propfind [-H \"Header: value\"] <url>: Send an HTTP PROPFIND request.\n";
    std::cout << " - http connect <proxyHost:port> <targetHost:port> [-H \"Header: value\"]  : Establish an HTTP CONNECT tunnel through the proxy.\n";
    std::cout << " - http patch [-H \"Header\"] [-d \"body\"] <url> : Send an HTTP PATCH request.\n";
    std::cout << " - http help                               : Show this help message.\n";
    std::cout << ANSI_BOLD_YELLOW "---------------------------------\n" << ANSI_RESET;
}