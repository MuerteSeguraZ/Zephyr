#define _WIN32_WINNT 0x0600 

#include "inspect.h"
#include <winsock2.h>       
#include <ws2tcpip.h>
#include <windows.h>
#include <winevt.h>
#include <iphlpapi.h>
#include <netioapi.h>      
#include <vector>          
#include <algorithm>
#include <chrono>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <sddl.h>
#include <lm.h>
#include <wincrypt.h>
#include <Aclapi.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wevtapi.lib")

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


namespace fs = std::filesystem;

std::string HashFile(const std::string& path, ALG_ID algId) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[4096];
    std::ifstream file(path, std::ios::binary);
    std::ostringstream hashStream;

    if (!file.is_open()) return "Failed to open file";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "Crypt context error";

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "Crypt hash error";
    }

    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || file.gcount() > 0) {
        if (!CryptHashData(hHash, buffer, static_cast<DWORD>(file.gcount()), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "Hashing error";
        }
    }

    BYTE hash[64];
    DWORD hashLen = sizeof(hash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        for (DWORD i = 0; i < hashLen; i++)
            hashStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    } else {
        hashStream << "Failed to get hash";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return hashStream.str();
}

std::string HumanSize(uintmax_t size) {
    const char* suffixes[] = { "B", "KB", "MB", "GB", "TB" };
    double s = static_cast<double>(size);
    int i = 0;
    while (s >= 1024 && i < 4) {
        s /= 1024;
        ++i;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << s << " " << suffixes[i];
    return oss.str();
}

void ShowFileAttributes(DWORD attrs) {
    if (attrs & FILE_ATTRIBUTE_READONLY) std::cout << "Readonly ";
    if (attrs & FILE_ATTRIBUTE_HIDDEN) std::cout << "Hidden ";
    if (attrs & FILE_ATTRIBUTE_SYSTEM) std::cout << "System ";
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) std::cout << "Directory ";
    if (attrs & FILE_ATTRIBUTE_ARCHIVE) std::cout << "Archive ";
    if (attrs & FILE_ATTRIBUTE_TEMPORARY) std::cout << "Temporary ";
    if (attrs & FILE_ATTRIBUTE_COMPRESSED) std::cout << "Compressed ";
    if (attrs & FILE_ATTRIBUTE_ENCRYPTED) std::cout << "Encrypted ";
    std::cout << "\n";
}

void ShowFileTimestamps(const fs::path& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file for timestamp.\n";
        return;
    }

    FILETIME ftCreate, ftAccess, ftWrite;
    if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
        SYSTEMTIME stUTC, stLocal;
        char buffer[100];

        auto printFileTime = [&](const FILETIME& ft, const char* label) {
            FileTimeToSystemTime(&ft, &stUTC);
            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
            sprintf_s(buffer, "%02d/%02d/%04d %02d:%02d:%02d",
                      stLocal.wMonth, stLocal.wDay, stLocal.wYear,
                      stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
            std::cout << label << ": " << buffer << "\n";
        };

        printFileTime(ftCreate, "Created");
        printFileTime(ftWrite, "Modified");
        printFileTime(ftAccess, "Last Access");
    } else {
        std::cerr << "Failed to get file times.\n";
    }

    CloseHandle(hFile);
}

void CmdInspectFile(const std::string& args) {
    std::istringstream iss(args);
    std::string cmd;
    iss >> cmd;
    std::string path;
    std::getline(iss >> std::ws, path);

    if (cmd == "file" && !path.empty()) {
        fs::path fpath = fs::u8path(path);

        if (!fs::exists(fpath)) {
            std::cerr << "File does not exist.\n";
            return;
        }

        std::cout << "File:         " << fpath.string() << "\n";
        auto size = fs::file_size(fpath);
        std::cout << "Size:         " << size << " bytes (" << HumanSize(size) << ")\n";

        DWORD attrs = GetFileAttributesW(fpath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            std::cerr << "Failed to get file attributes.\n";
        } else {
            std::cout << "Attributes:   ";
            ShowFileAttributes(attrs);
        }

        ShowFileTimestamps(fpath);

        std::cout << "Hashes:\n";
        std::cout << " - MD5:    " << HashFile(fpath.string(), CALG_MD5) << "\n";
        std::cout << " - SHA1:   " << HashFile(fpath.string(), CALG_SHA1) << "\n";
        std::cout << " - SHA256: " << HashFile(fpath.string(), CALG_SHA_256) << "\n";
    } else {
        std::cerr << "Usage: inspect file <path>\n";
    }
}

ULONGLONG FileTimeToULL(const FILETIME& ft) {
    return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

void CmdInspectProc(const std::string& args) {
    std::istringstream iss(args);
    std::string cmd;
    DWORD pid = 0;
    iss >> cmd >> pid;

    if (cmd != "proc" || pid == 0) {
        std::cerr << "Usage: inspect proc <pid>\n";
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process with PID " << pid << ". Error: " << GetLastError() << "\n";
        return;
    }

    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameExW(hProcess, NULL, exePath, MAX_PATH)) {
        std::wcout << L"Executable Path: " << exePath << L"\n";
    } else {
        std::cerr << "Failed to get executable path.\n";
    }

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
        double kernelSec = FileTimeToULL(ftKernel) / 1e7;
        double userSec = FileTimeToULL(ftUser) / 1e7;

        std::cout << "CPU Time:\n";
        std::cout << " - Kernel Mode: " << kernelSec << " seconds\n";
        std::cout << " - User Mode:   " << userSec << " seconds\n";
    } else {
        std::cerr << "Failed to get process times.\n";
    }

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        std::cout << "Memory Usage:\n";
        std::cout << " - Working Set Size: " << HumanSize(pmc.WorkingSetSize) << "\n";
        std::cout << " - Peak Working Set Size: " << HumanSize(pmc.PeakWorkingSetSize) << "\n";
        std::cout << " - Pagefile Usage: " << HumanSize(pmc.PagefileUsage) << "\n";
    } else {
        std::cerr << "Failed to get process memory info.\n";
    }

    DWORD handleCount = 0;
    if (GetProcessHandleCount(hProcess, &handleCount)) {
        std::cout << "Handle Count: " << handleCount << "\n";
    }

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
        int threadCount = 0;
        if (Thread32First(hThreadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid)
                    threadCount++;
            } while (Thread32Next(hThreadSnap, &te32));
        }
        std::cout << "Thread Count: " << threadCount << "\n";
        CloseHandle(hThreadSnap);
    } else {
        std::cerr << "Failed to create thread snapshot.\n";
    }

    CloseHandle(hProcess);
}

void PrintSid(PSID sid) {
    LPWSTR sidString = nullptr;
    if (ConvertSidToStringSidW(sid, &sidString)) {
        std::wcout << L"SID: " << sidString << L"\n";
        LocalFree(sidString);
    } else {
        std::cerr << "Failed to convert SID to string.\n";
    }
}

void CmdInspectUser(const std::string& args) {
    std::istringstream iss(args);
    std::string cmd, username;
    iss >> cmd >> username;

    if (cmd != "user" || username.empty()) {
        std::cerr << "Usage: inspect user <username>\n";
        return;
    }

    std::wstring wUsername(username.begin(), username.end());

    USER_INFO_4* pUserInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, wUsername.c_str(), 4, (LPBYTE*)&pUserInfo);
    if (status != NERR_Success) {
        std::cerr << "Failed to get user info. Error code: " << status << "\n";
        return;
    }

    std::wcout << L"User:       " << pUserInfo->usri4_name << L"\n";
    std::wcout << L"Full Name:  " << pUserInfo->usri4_full_name << L"\n";
    std::wcout << L"Comment:    " << pUserInfo->usri4_comment << L"\n";

    auto GetRidFromSid = [](PSID sid) -> DWORD {
        if (!IsValidSid(sid)) return 0;
        UCHAR subAuthCount = *GetSidSubAuthorityCount(sid);
        return *GetSidSubAuthority(sid, subAuthCount - 1);
    };

    DWORD rid = GetRidFromSid(pUserInfo->usri4_user_sid);
    std::wcout << L"RID:        " << rid << L"\n";

    PrintSid(pUserInfo->usri4_user_sid);

    NetApiBufferFree(pUserInfo);
}

void CmdInspectMem(const std::string& args) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }
    if (!args.empty()) {
        std::cerr << "Usage: inspect mem\n";
        return;
    }

    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(memStatus);

    if (!GlobalMemoryStatusEx(&memStatus)) {
        std::cerr << "Failed to get memory status. Error: " << GetLastError() << "\n";
        return;
    }

    std::cout << "Memory Status:\n";
    std::cout << " - Total Physical Memory:    " << HumanSize(memStatus.ullTotalPhys) << "\n";
    std::cout << " - Available Physical Memory: " << HumanSize(memStatus.ullAvailPhys) << "\n";
    std::cout << " - Total Page File:           " << HumanSize(memStatus.ullTotalPageFile) << "\n";
    std::cout << " - Available Page File:       " << HumanSize(memStatus.ullAvailPageFile) << "\n";
    std::cout << " - Total Virtual Memory:      " << HumanSize(memStatus.ullTotalVirtual) << "\n";
    std::cout << " - Available Virtual Memory:  " << HumanSize(memStatus.ullAvailVirtual) << "\n";
    std::cout << " - Memory Load:               " << memStatus.dwMemoryLoad << "%\n";
}

void CmdInspectNet(const std::string& args) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    std::string ifaceFilter = args;

    ULONG outBufLen = 15000;
    std::vector<BYTE> buffer(outBufLen);

    IP_ADAPTER_ADDRESSES* pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    DWORD dwRetVal = GetAdaptersAddresses(
        AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(outBufLen);
        pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
    }

    if (dwRetVal != NO_ERROR) {
        std::cerr << "GetAdaptersAddresses failed with error: " << dwRetVal << "\n";
        WSACleanup();
        return;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = pAddresses; adapter != nullptr; adapter = adapter->Next) {
        std::wstring friendlyNameW = adapter->FriendlyName ? adapter->FriendlyName : L"";
        std::string friendlyName(friendlyNameW.begin(), friendlyNameW.end());

        if (!ifaceFilter.empty() && friendlyName.find(ifaceFilter) == std::string::npos)
            continue;

        std::cout << "Interface: " << friendlyName << "\n";
        std::cout << " - Type: " << adapter->IfType
                  << (adapter->IfType == IF_TYPE_ETHERNET_CSMACD ? " (Ethernet)" : "") << "\n";

        std::cout << " - MAC: ";
        if (adapter->PhysicalAddressLength == 0) {
            std::cout << "N/A";
        } else {
            for (UINT i = 0; i < adapter->PhysicalAddressLength; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)adapter->PhysicalAddress[i];
                if (i < adapter->PhysicalAddressLength - 1) std::cout << ":";
            }
        }
        std::cout << std::dec << "\n";

        std::cout << " - Status: " << (adapter->OperStatus == IfOperStatusUp ? "Up" : "Down") << "\n";

        std::cout << " - IP Addresses:\n";
        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
            char ipStr[INET6_ADDRSTRLEN] = {0};
            int result = getnameinfo(
                unicast->Address.lpSockaddr,
                unicast->Address.iSockaddrLength,
                ipStr, sizeof(ipStr),
                nullptr, 0,
                NI_NUMERICHOST);

            if (result == 0) {
                std::cout << "    - " << ipStr << "\n";
            } else {
                std::cout << "    - [Unresolved IP, error " << result << "]\n";
            }
        }

        MIB_IF_ROW2 ifRow{};
        ifRow.InterfaceIndex = adapter->IfIndex;
        if (GetIfEntry2(&ifRow) == NO_ERROR) {
            std::cout << " - Speed: " << (ifRow.ReceiveLinkSpeed / 1000000) << " Mbps\n";
            std::cout << " - Stats:\n";
            std::cout << "    - Bytes Sent:     " << ifRow.OutOctets << "\n";
            std::cout << "    - Bytes Received: " << ifRow.InOctets << "\n";
            std::cout << "    - Packets Sent:   " << ifRow.OutUcastPkts << "\n";
            std::cout << "    - Packets Received: " << ifRow.InUcastPkts << "\n";
            std::cout << "    - Errors In:      " << ifRow.InErrors << "\n";
            std::cout << "    - Errors Out:     " << ifRow.OutErrors << "\n";
        }

        std::cout << "-------------------------\n";
    }

    WSACleanup();
}

SYSTEMTIME FileTimeToSystemTimeLocal(const FILETIME& ft) {
    SYSTEMTIME stUTC, stLocal;
    if (!FileTimeToSystemTime(&ft, &stUTC)) {
        ZeroMemory(&stLocal, sizeof(stLocal));
        return stLocal;
    }
    if (!SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal)) {
        ZeroMemory(&stLocal, sizeof(stLocal));
        return stLocal;
    }
    return stLocal;
}

std::string FormatSystemTime(const SYSTEMTIME& st) {
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buffer);
}

std::string RunPowerShell(const std::string& cmd) {
    std::string fullCmd = "powershell -NoProfile -Command \"" + cmd + "\"";
    FILE* pipe = _popen(fullCmd.c_str(), "r");
    if (!pipe) return "";

    char buffer[256];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);
    return result;
}

void PrintWindowsVersionInfo() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) 
    {
        wchar_t productName[256] = {};
        wchar_t releaseId[256] = {};
        wchar_t currentBuild[256] = {};
        DWORD ubr = 0;
        wchar_t editionId[256] = {};
        DWORD installDate = 0;

        DWORD size = sizeof(productName);
        RegQueryValueExW(hKey, L"ProductName", nullptr, nullptr, (LPBYTE)productName, &size);

        size = sizeof(releaseId);
        RegQueryValueExW(hKey, L"ReleaseId", nullptr, nullptr, (LPBYTE)releaseId, &size);

        size = sizeof(currentBuild);
        RegQueryValueExW(hKey, L"CurrentBuild", nullptr, nullptr, (LPBYTE)currentBuild, &size);

        size = sizeof(DWORD);
        RegQueryValueExW(hKey, L"UBR", nullptr, nullptr, (LPBYTE)&ubr, &size);

        size = sizeof(editionId);
        RegQueryValueExW(hKey, L"EditionID", nullptr, nullptr, (LPBYTE)editionId, &size);

        size = sizeof(DWORD);
        RegQueryValueExW(hKey, L"InstallDate", nullptr, nullptr, (LPBYTE)&installDate, &size);

        RegCloseKey(hKey);

        time_t t = installDate;
        struct tm localTm;
        localtime_s(&localTm, &t);
        char dateBuf[64];
        strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d %H:%M:%S", &localTm);

        std::wcout << L"Windows Product Name: " << productName << L"\n";
        std::wcout << L"Release ID: " << releaseId << L"\n";
        std::wcout << L"Current Build: " << currentBuild << L"." << ubr << L"\n";
        std::wcout << L"Edition: " << editionId << L"\n";
        std::cout << "Install Date: " << dateBuf << "\n";
    }
    else {
        std::cerr << "Failed to read Windows version info from registry.\n";
    }
}

void PrintProductEditionInfo() {
    OSVERSIONINFOEXW osvi = { sizeof(osvi) };
    if (!GetVersionExW((LPOSVERSIONINFOW)&osvi)) {
        std::cerr << "Failed to get OS version info.\n";
        return;
    }

    DWORD dwType = 0;
    BOOL result = GetProductInfo(
        osvi.dwMajorVersion,
        osvi.dwMinorVersion,
        osvi.wServicePackMajor,
        osvi.wServicePackMinor,
        &dwType);

    if (!result) {
        std::cerr << "GetProductInfo failed.\n";
        return;
    }

    std::string editionName = "Unknown Edition";
    switch (dwType) {
    case PRODUCT_HOME_BASIC: editionName = "Home Basic"; break;
    case PRODUCT_HOME_PREMIUM: editionName = "Home Premium"; break;
    case PRODUCT_PROFESSIONAL: editionName = "Professional"; break;
    case PRODUCT_ENTERPRISE: editionName = "Enterprise"; break;
    case PRODUCT_ULTIMATE: editionName = "Ultimate"; break;
    case PRODUCT_HOME_BASIC_E: editionName = "Home Basic E"; break;
    case PRODUCT_HOME_PREMIUM_E: editionName = "Home Premium E"; break;
    case PRODUCT_HOME_BASIC_N: editionName = "Home Basic N"; break;
    case PRODUCT_HOME_PREMIUM_N: editionName = "Home Premium N"; break;
    case PRODUCT_PROFESSIONAL_N: editionName = "Professional N"; break;
    case PRODUCT_ENTERPRISE_N: editionName = "Enterprise N"; break;
    case PRODUCT_ULTIMATE_N: editionName = "Ultimate N"; break;
    case PRODUCT_STARTER: editionName = "Starter"; break;
    case PRODUCT_CLUSTER_SERVER: editionName = "Cluster Server"; break;
    case PRODUCT_DATACENTER_SERVER: editionName = "Datacenter Server"; break;
    case PRODUCT_DATACENTER_SERVER_CORE: editionName = "Datacenter Server Core"; break;
    case PRODUCT_ENTERPRISE_SERVER: editionName = "Enterprise Server"; break;
    case PRODUCT_ENTERPRISE_SERVER_CORE: editionName = "Enterprise Server Core"; break;
    case PRODUCT_ENTERPRISE_SERVER_IA64: editionName = "Enterprise Server IA64"; break;
    case PRODUCT_SMALLBUSINESS_SERVER: editionName = "Small Business Server"; break;
    case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM: editionName = "Small Business Server Premium"; break;
    case PRODUCT_STANDARD_SERVER: editionName = "Standard Server"; break;
    case PRODUCT_STANDARD_SERVER_CORE: editionName = "Standard Server Core"; break;
    case PRODUCT_WEB_SERVER: editionName = "Web Server"; break;
    case PRODUCT_WEB_SERVER_CORE: editionName = "Web Server Core"; break;
    default: editionName = "Other Edition"; break;
    }

    std::cout << "Product Edition Info: " << editionName << "\n";
}

void PrintActivationStatus() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
        0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) 
    {
        DWORD licenseStatus = 0;
        DWORD size = sizeof(licenseStatus);

        RegQueryValueExW(hKey, L"LicenseStatus", nullptr, nullptr, (LPBYTE)&licenseStatus, &size);

        RegCloseKey(hKey);

        std::string statusStr;
        switch (licenseStatus) {
        case 0: statusStr = "Unlicensed"; break;
        case 1: statusStr = "Licensed"; break;
        case 2: statusStr = "Initial Grace Period"; break;
        case 3: statusStr = "Additional Grace Period"; break;
        case 4: statusStr = "Notification"; break;
        case 5: statusStr = "Extended Grace Period"; break;
        default: statusStr = "Unknown"; break;
        }
        std::cout << "Activation Status: " << statusStr << "\n";
    }
    else {
        std::cerr << "Failed to read activation status from registry.\n";
    }
}

void PrintSystemUptimeReadable() {
    ULONGLONG ms = GetTickCount64();
    ULONGLONG seconds = ms / 1000;
    ULONGLONG minutes = seconds / 60;
    ULONGLONG hours = minutes / 60;
    ULONGLONG days = hours / 24;

    hours %= 24;
    minutes %= 60;
    seconds %= 60;

    std::cout << "System Uptime: " << days << "d " << hours << "h " << minutes << "m " << seconds << "s\n";
}

void PrintRegisteredOwner() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) 
    {
        wchar_t owner[256] = {};
        DWORD size = sizeof(owner);
        RegQueryValueExW(hKey, L"RegisteredOwner", nullptr, nullptr, (LPBYTE)owner, &size);
        RegCloseKey(hKey);

        std::wcout << L"Registered Owner: " << owner << L"\n";
    }
    else {
        std::cerr << "Failed to read Registered Owner from registry.\n";
    }
}

void PrintWindowsFeatures() {
    std::cout << "Windows Optional Features (partial list):\n";

    std::string psCmd =
        "Get-WindowsOptionalFeature -Online | "
        "Where-Object {$_.FeatureName -match 'NetFx|Hyper-V|MicrosoftWindowsSubsystemForLinux'} | "
        "Select-Object FeatureName, State | Format-Table -AutoSize";

    std::string output = RunPowerShell(psCmd);
    std::cout << output << "\n";
}

void CmdInspectWin(const std::string& args) {
    (void)args; 

    std::cout << ANSI_BOLD_CYAN "=== Windows Version and Build Information ===\n" << ANSI_RESET;
    PrintWindowsVersionInfo();

    std::cout << ANSI_BOLD_CYAN "\n=== Product Edition Info ===\n" << ANSI_RESET;
    PrintProductEditionInfo();

    std::cout << ANSI_BOLD_CYAN "\n=== Activation Status ===\n" << ANSI_RESET;
    PrintActivationStatus();

    std::cout << ANSI_BOLD_CYAN "\n=== System Info ===\n" << ANSI_RESET;
    PrintRegisteredOwner();
    PrintSystemUptimeReadable();

    std::cout << ANSI_BOLD_CYAN "\n=== Windows Feature States ===\n" << ANSI_RESET;
    PrintWindowsFeatures();

    std::cout << ANSI_BOLD_YELLOW "--------------------------------------------\n" << ANSI_RESET;
}

bool ContainsCaseInsensitive(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char ch1, char ch2) {
            return std::toupper(ch1) == std::toupper(ch2);
        });
    return (it != haystack.end());
}

void CmdInspectEnv(const std::string& args) {
    std::string filter = args;
    filter.erase(0, filter.find_first_not_of(" \t")); 
    filter.erase(filter.find_last_not_of(" \t") + 1); 

    std::cout << ANSI_BOLD_CYAN "=== Environment Variables ===\n" << ANSI_RESET;

    LPWCH envStrings = GetEnvironmentStringsW();
    if (!envStrings) {
        std::cerr << ANSI_BOLD_RED "Failed to get environment strings.\n" << ANSI_RESET;
        return;
    }

    wchar_t* current = envStrings;
    while (*current) {
        std::wstring wvar(current);
        current += wvar.size() + 1;

        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wvar.c_str(), -1, NULL, 0, NULL, NULL);
        std::string varStr(sizeNeeded, 0);
        WideCharToMultiByte(CP_UTF8, 0, wvar.c_str(), -1, &varStr[0], sizeNeeded, NULL, NULL);

        if (!varStr.empty() && varStr.back() == '\0')
            varStr.pop_back();

        if (filter.empty() || ContainsCaseInsensitive(varStr, filter)) {
            std::cout << varStr << "\n";
        }
    }

    FreeEnvironmentStringsW(envStrings);
    std::cout << ANSI_BOLD_YELLOW "----------------------------\n" << ANSI_RESET;
}

void PrintBootTime() {
    ULONGLONG ms = GetTickCount64();
    time_t now = time(nullptr);
    time_t bootTime = now - (ms / 1000);
    struct tm localTm;
    localtime_s(&localTm, &bootTime);
    char dateBuf[64];
    strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d %H:%M:%S", &localTm);
    std::cout << "Boot Time: " << dateBuf << "\n";
}

void PrintSystemUptime() {
    ULONGLONG ms = GetTickCount64();
    ULONGLONG seconds = ms / 1000;
    ULONGLONG minutes = seconds / 60;
    ULONGLONG hours = minutes / 60;
    ULONGLONG days = hours / 24;

    hours %= 24;
    minutes %= 60;
    seconds %= 60;

    std::cout << "System Uptime: " << days << "d " << hours << "h "
              << minutes << "m " << seconds << "s\n";
}

std::string WideToUtf8(LPCWSTR wideStr) {
    int size = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &str[0], size, nullptr, nullptr);
    return str;
}

void PrintLastShutdownReason() {
    std::cout << "Last Shutdown Reason: ";

    LPCWSTR query =
        L"<QueryList>"
        L"  <Query Id='0' Path='System'>"
        L"    <Select Path='System'>"
        L"      *[System[(EventID=1074 or EventID=6006 or EventID=6008)]]"
        L"    </Select>"
        L"  </Query>"
        L"</QueryList>";

    EVT_HANDLE hResults = EvtQuery(nullptr, L"System", query, EvtQueryReverseDirection | EvtQueryTolerateQueryErrors);
    if (!hResults) {
        std::cout << ANSI_BOLD_RED "(Error querying Event Log)\n" << ANSI_RESET;
        return;
    }

    EVT_HANDLE events[1];
    DWORD returned = 0;
    if (EvtNext(hResults, 1, events, INFINITE, 0, &returned)) {
        DWORD bufferSize = 0;
        DWORD propertyCount = 0;

        EvtRender(nullptr, events[0], EvtRenderEventXml, 0, nullptr, &bufferSize, &propertyCount);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring xml(bufferSize / sizeof(wchar_t), L'\0');
            if (EvtRender(nullptr, events[0], EvtRenderEventXml, bufferSize, &xml[0], &bufferSize, &propertyCount)) {
                std::string xmlUtf8 = WideToUtf8(xml.c_str());

                size_t idStart = xmlUtf8.find("<EventID");
                if (idStart != std::string::npos) {
                    idStart = xmlUtf8.find(">", idStart) + 1;
                    size_t idEnd = xmlUtf8.find("</EventID>", idStart);
                    int eventID = std::stoi(xmlUtf8.substr(idStart, idEnd - idStart));

                    switch (eventID) {
                        case 1074: {
                            size_t reasonStart = xmlUtf8.find("<Data Name=\"param4\">");
                            if (reasonStart != std::string::npos) {
                                reasonStart += strlen("<Data Name=\"param4\">");
                                size_t reasonEnd = xmlUtf8.find("</Data>", reasonStart);
                                std::string reason = xmlUtf8.substr(reasonStart, reasonEnd - reasonStart);
                                std::cout << "Planned shutdown — " << reason << "\n";
                            } else {
                                std::string user = "(unknown user)";
                                std::string process = "(unknown process)";
                                size_t uStart = xmlUtf8.find("<Data Name=\"param1\">");
                                if (uStart != std::string::npos) {
                                    uStart += strlen("<Data Name=\"param1\">");
                                    size_t uEnd = xmlUtf8.find("</Data>", uStart);
                                    user = xmlUtf8.substr(uStart, uEnd - uStart);
                                }
                                size_t pStart = xmlUtf8.find("<Data Name=\"param2\">");
                                if (pStart != std::string::npos) {
                                    pStart += strlen("<Data Name=\"param2\">");
                                    size_t pEnd = xmlUtf8.find("</Data>", pStart);
                                    process = xmlUtf8.substr(pStart, pEnd - pStart);
                                }
                                std::cout << "Planned shutdown (initiated by " << user << " using " << process << ")\n";
                            }
                            break;
                        }
                        case 6006:
                            std::cout << "Clean shutdown (Event Log service stopped)\n";
                            break;
                        case 6008:
                            std::cout << "Unexpected shutdown (dirty boot)\n";
                            break;
                        default:
                            std::cout << "(Unknown shutdown reason — Event ID " << eventID << ")\n";
                            break;
                    }
                } else {
                    std::cout << ANSI_BOLD_RED "(Event ID not found in XML)\n" << ANSI_RESET;
                }
            } else {
                std::cout << ANSI_BOLD_RED "(Failed to render event XML)\n" << ANSI_RESET;
            }
        }
        EvtClose(events[0]);
    } else {
        std::cout << ANSI_BOLD_RED "(No shutdown events found)\n" << ANSI_RESET;
    }

    EvtClose(hResults);
}



void CmdInspectBoot(const std::string& args) {
    (void)args;

    std::cout << ANSI_BOLD_CYAN "=== Boot & Uptime Information ===\n" << ANSI_RESET;
    PrintBootTime();
    PrintSystemUptime();
    PrintLastShutdownReason();
    std::cout << ANSI_BOLD_YELLOW "----------------------------------\n" << ANSI_RESET;
}

void CmdInspectHelp(const std::string& args) {
    (void)args; 
    std::cout << ANSI_BOLD_CYAN "=== Inspect Commands Help ===\n" << ANSI_RESET;
    std::cout << "Available commands:\n";
    std::cout << " - inspect file <path>       : Inspect file attributes, size, timestamps, and hashes.\n";
    std::cout << " - inspect proc <pid>        : Inspect process by PID (executable path, CPU time, memory usage).\n";
    std::cout << " - inspect user <username>   : Inspect user account information by username.\n";
    std::cout << " - inspect mem               : Show system memory status.\n";
    std::cout << " - inspect net [filter]      : Show network interfaces and stats (optional filter).\n";
    std::cout << " - inspect win               : Show Windows version, product edition, activation status.\n";
    std::cout << " - inspect env [filter]      : Show environment variables (optional filter).\n";
    std::cout << " - inspect boot              : Show boot time, system uptime, last shutdown reason.\n";
    std::cout << ANSI_BOLD_YELLOW "----------------------------\n" << ANSI_RESET;
}