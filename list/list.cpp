#define UNICODE
#define _UNICODE

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <Shlwapi.h>
#include <setupapi.h>
#include <initguid.h>
#include <wincred.h>
#include <devguid.h>
#include <usbiodef.h>
#include <algorithm>  
#include <cwctype>   
#include <ctime>
#include <windows.h>
#include <fileapi.h>
#include <winbase.h>
#include <tchar.h>
#include <winioctl.h>
#include <lm.h>
#include <Wtsapi32.h>
#include <Sddl.h>
#include <Userenv.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <Psapi.h> 

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Setupapi.lib")

// Ya always need to have a WideToString helper
std::string WideToString(const wchar_t* wstr) {
    if (!wstr) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return {};
    std::string strTo(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], size_needed, nullptr, nullptr);
    return strTo;
}

// Annoying LPUSER_INFO_0 helper
void PrintUserName(LPUSER_INFO_0 pUserInfo) {
    if (pUserInfo && pUserInfo->usri0_name)
        std::wcout << L" - " << pUserInfo->usri0_name << L"\n";
}

std::wstring FormatUnixTime(DWORD timestamp) {
    if (timestamp == 0) return L"(never logged in)";

    time_t rawTime = static_cast<time_t>(timestamp);
    struct tm timeInfo;
    localtime_s(&timeInfo, &rawTime);

    wchar_t buffer[100];
    wcsftime(buffer, sizeof(buffer) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &timeInfo);
    return std::wstring(buffer);
}

void CmdListUsers(const std::string& args) {
    (void)args;
    std::wcout << L"[listusers] Listing all users on the system:\n";

    LPUSER_INFO_0 pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0;
    DWORD resumeHandle = 0; // <-- fix
    NET_API_STATUS status;

    do {
        status = NetUserEnum(nullptr, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
                             &entriesRead, &totalEntries, &resumeHandle);
        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            LPUSER_INFO_0 pTmp = pBuf;
            for (DWORD i = 0; i < entriesRead; i++) {
                PrintUserName(pTmp);
                pTmp++;
            }
            if (pBuf) {
                NetApiBufferFree(pBuf);
                pBuf = nullptr;
            }
        }
    } while (status == ERROR_MORE_DATA);

    if (status != NERR_Success) {
        std::wcout << L"Failed to enumerate users, error code: " << status << L"\n";
    }
}


void CmdListGroups(const std::string& args) {
    (void)args; 
    std::wcout << L"[listgroups] Listing all local groups on the system:\n";

    LPLOCALGROUP_INFO_0 pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0;
    DWORD_PTR resumeHandle = 0;
    NET_API_STATUS status;

    do {
        status = NetLocalGroupEnum(nullptr, 0, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
                                   &entriesRead, &totalEntries, &resumeHandle);
        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            LPLOCALGROUP_INFO_0 pTmp = pBuf;
            for (DWORD i = 0; i < entriesRead; i++) {
                if (pTmp && pTmp->lgrpi0_name)
                    std::wcout << L" - " << pTmp->lgrpi0_name << L"\n";
                pTmp++;
            }
            if (pBuf) {
                NetApiBufferFree(pBuf);
                pBuf = nullptr;
            }
        }
    } while (status == ERROR_MORE_DATA);

    if (status != NERR_Success) {
        std::wcout << L"Failed to enumerate groups, error code: " << status << L"\n";
    }
}

void CmdListLoggedIn(const std::string& args) {
    (void)args; 
    std::wcout << L"[listloggedin] Currently logged in users / active sessions:\n";

    PWTS_SESSION_INFO pSessionInfo = nullptr;
    DWORD sessionCount = 0;
    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
        for (DWORD i = 0; i < sessionCount; i++) {
            WTS_SESSION_INFO si = pSessionInfo[i];
            LPWSTR pUserName = nullptr;
            DWORD userNameLen = 0;
            if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, si.SessionId, WTSUserName, &pUserName, &userNameLen)) {
                if (pUserName && wcslen(pUserName) > 0) {
                    std::wcout << L" - SessionId: " << si.SessionId << L", User: " << pUserName << L", State: " << si.State << L"\n";
                }
                WTSFreeMemory(pUserName);
            }
        }
        WTSFreeMemory(pSessionInfo);
    } else {
        std::wcout << L"Failed to enumerate sessions.\n";
    }
}

void CmdListAdmins(const std::string& args) {
    std::string cleanArgs = args;
    if (!cleanArgs.empty() && cleanArgs.front() == '"' && cleanArgs.back() == '"') {
        cleanArgs = cleanArgs.substr(1, cleanArgs.length() - 2);
    }

    std::wstring groupName(cleanArgs.empty() ? L"Administrators" : std::wstring(cleanArgs.begin(), cleanArgs.end()));

    std::wcout << L"[listadmins] Listing members of the group: " << groupName << L"\n";

    LOCALGROUP_MEMBERS_INFO_0* pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0;
    DWORD_PTR resumeHandle = 0;
    NET_API_STATUS status;

    do {
        status = NetLocalGroupGetMembers(
            nullptr,
            groupName.c_str(),
            0,
            (LPBYTE*)&pBuf,
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle
        );

        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < entriesRead; i++) {
                if (pBuf[i].lgrmi0_sid) {
                    DWORD cchName = 0, cchDomain = 0;
                    SID_NAME_USE sidType;

                    LookupAccountSid(nullptr, pBuf[i].lgrmi0_sid, nullptr, &cchName, nullptr, &cchDomain, &sidType);
                    std::vector<wchar_t> nameBuf(cchName);
                    std::vector<wchar_t> domainBuf(cchDomain);

                    if (LookupAccountSid(nullptr, pBuf[i].lgrmi0_sid, nameBuf.data(), &cchName, domainBuf.data(), &cchDomain, &sidType)) {
                        std::wcout << L" - " << domainBuf.data() << L"\\" << nameBuf.data() << L"\n";
                    }
                }
            }
            NetApiBufferFree(pBuf);
            pBuf = nullptr;
        } else {
            std::wcout << L"Failed to retrieve group members, error: " << status << L"\n";
        }
    } while (status == ERROR_MORE_DATA);
}


void CmdListProfiles(const std::string& args) {
    (void)args; 
    std::wcout << L"[listprofiles] Listing user profiles on the machine:\n";

    WIN32_FIND_DATA ffd;
    HANDLE hFind = FindFirstFile(L"C:\\Users\\*", &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0) {
                std::wcout << L" - " << ffd.cFileName << L"\n";
            }
        } while (FindNextFile(hFind, &ffd));
        FindClose(hFind);
    } else {
        std::wcout << L"Failed to enumerate C:\\Users directory.\n";
    }
}

void CmdListDomains(const std::string& args) {
    (void)args; 
    std::wcout << L"[listdomains] Listing domain names computer is joined to:\n";

    PWSTR pName = nullptr;
    NETSETUP_JOIN_STATUS status;
    NET_API_STATUS result = NetGetJoinInformation(nullptr, &pName, &status);
    if (result == NERR_Success) {
        if (status == NetSetupDomainName) {
            std::wcout << L"Domain: " << pName << L"\n";
        } else if (status == NetSetupWorkgroupName) {
            std::wcout << L"Workgroup: " << pName << L"\n";
        } else {
            std::wcout << L"Computer is not joined to a domain or workgroup.\n";
        }
    } else {
        std::wcout << L"Failed to get join information, error: " << result << L"\n";
    }
    if (pName) {
        NetApiBufferFree(pName);
    }
}

void CmdListProcessUsers(const std::string& args) {
    (void)args; 
    std::wcout << L"[listprocessusers] Showing users associated with running processes:\n";

    DWORD processes[1024], needed = 0;
    if (!EnumProcesses(processes, sizeof(processes), &needed)) {
        std::wcout << L"Failed to enumerate processes.\n";
        return;
    }
    DWORD count = needed / sizeof(DWORD);

    for (DWORD i = 0; i < count; i++) {
        DWORD pid = processes[i];
        if (pid == 0) continue; 

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            HANDLE hToken = nullptr;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                DWORD size = 0;
                GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    std::vector<BYTE> buffer(size);
                    if (GetTokenInformation(hToken, TokenUser, buffer.data(), size, &size)) {
                        TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
                        WCHAR name[256], domain[256];
                        DWORD nameLen = 256, domainLen = 256;
                        SID_NAME_USE sidType;
                        if (LookupAccountSid(nullptr, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
                            std::wcout << L"PID: " << pid << L", User: " << domain << L"\\" << name << L"\n";
                        }
                    }
                }
                CloseHandle(hToken);
            }
            CloseHandle(hProcess);
        }
    }
}

void CmdListPrivileges(const std::string& args) {
    (void)args;
    std::wcout << L"[listprivileges] Listing all privileges on the current process token:\n";

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::wcout << L"Failed to open process token.\n";
        return;
    }

    DWORD size = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::wcout << L"Failed to get token privilege size.\n";
        CloseHandle(hToken);
        return;
    }

    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(hToken, TokenPrivileges, buffer.data(), size, &size)) {
        std::wcout << L"Failed to get token privileges.\n";
        CloseHandle(hToken);
        return;
    }

    TOKEN_PRIVILEGES* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());

    for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
        LUID_AND_ATTRIBUTES& la = privileges->Privileges[i];
        WCHAR name[256];
        DWORD nameLen = _countof(name);
        if (LookupPrivilegeName(nullptr, &la.Luid, name, &nameLen)) {
            std::wcout << L" - " << name << L"\n";
        } else {
            std::wcout << L" - (unknown privilege)\n";
        }
    }

    CloseHandle(hToken);
}

void CmdListUserDetails(const std::string& args) {
    std::wstring username(args.begin(), args.end());
    std::wcout << L"[listuserdetails] Details for user: " << username << L"\n";

    USER_INFO_2* pUserInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, username.c_str(), 2, (LPBYTE*)&pUserInfo);
    if (status != NERR_Success) {
        std::wcout << L"Failed to get user info, error: " << status << L"\n";
        return;
    }

    if (pUserInfo) {
        std::wcout << L"Full name: " << (pUserInfo->usri2_full_name ? pUserInfo->usri2_full_name : L"(none)") << L"\n";
        std::wcout << L"User comment: " << (pUserInfo->usri2_comment ? pUserInfo->usri2_comment : L"(none)") << L"\n";
        std::wcout << L"Flags: " << pUserInfo->usri2_flags << L"\n";
        std::wcout << L"Last logon: " << pUserInfo->usri2_last_logon << L"\n";
        std::wcout << L"Password age (seconds): " << pUserInfo->usri2_password_age << L"\n";
        std::wcout << L"User privilege level: " << pUserInfo->usri2_priv << L"\n";

        NetApiBufferFree(pUserInfo);
    }
}

void CmdListNetworkUsers(const std::string& args) {
    std::wstring username(args.begin(), args.end());
    std::wcout << L"[listnetworkusers] Listing users connected over network sessions\n";

    LPSESSION_INFO_10 pSessionInfo = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS status;

    do {
        status = NetSessionEnum(
            nullptr,        // local server
            nullptr,        // client name (nullptr = all)
            nullptr,        // user name (nullptr = all)
            10,             // level (SESSION_INFO_10)
            (LPBYTE*)&pSessionInfo,
            MAX_PREFERRED_LENGTH,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle
        );

        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            if (dwEntriesRead == 0) {
                std::wcout << L"No network sessions found.\n";
                break;
            }

            for (DWORD i = 0; i < dwEntriesRead; i++) {
                std::wstring username = pSessionInfo[i].sesi10_username ? pSessionInfo[i].sesi10_username : L"(none)";
                std::wstring clientname = pSessionInfo[i].sesi10_cname ? pSessionInfo[i].sesi10_cname : L"(none)";

                std::wcout << L"User: " << username
                           << L", Client: " << clientname
                           << L", Time (sec): " << pSessionInfo[i].sesi10_time
                           << L", Idle Time (sec): " << pSessionInfo[i].sesi10_idle_time
                           << L"\n";
            }
            NetApiBufferFree(pSessionInfo);
            pSessionInfo = nullptr;
        }
        else {
            std::wcout << L"Failed to enumerate sessions, error: " << status << L"\n";
            break;
        }
    } while (status == ERROR_MORE_DATA);
}

void CmdListLocalUsers(const std::string& args) {
    std::wcout << L"[listlocalusers] Listing all local user accounts\n";

    USER_INFO_0* pUserInfo = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS status;

    do {
        status = NetUserEnum(
            nullptr,            // local server
            0,                  // only username
            FILTER_NORMAL_ACCOUNT, // filter normal user accounts
            (LPBYTE*)&pUserInfo,
            MAX_PREFERRED_LENGTH,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle
        );

        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                std::wstring username = pUserInfo[i].usri0_name ? pUserInfo[i].usri0_name : L"(none)";
                std::wcout << L"User: " << username << L"\n";
            }

            NetApiBufferFree(pUserInfo);
            pUserInfo = nullptr;
        }
        else {
            std::wcout << L"Failed to enumerate local users, error: " << status << L"\n";
            break;
        }
    } while (status == ERROR_MORE_DATA);
}

void CmdListLocalGroups(const std::string& args) {
    std::wcout << L"[listlocalgroups] Listing all local groups\n";

    LOCALGROUP_INFO_0* pGroupInfo = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD_PTR dwResumeHandle = 0;
    NET_API_STATUS status;

    do {
        status = NetLocalGroupEnum(
            nullptr,                // local server
            0,                      // only group name
            (LPBYTE*)&pGroupInfo,
            MAX_PREFERRED_LENGTH,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle
        );

        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                std::wstring groupname = pGroupInfo[i].lgrpi0_name ? pGroupInfo[i].lgrpi0_name : L"(none)";
                std::wcout << L"Group: " << groupname << L"\n";
            }

            NetApiBufferFree(pGroupInfo);
            pGroupInfo = nullptr;
        }
        else {
            std::wcout << L"Failed to enumerate local groups, error: " << status << L"\n";
            break;
        }
    } while (status == ERROR_MORE_DATA);
}

void CmdListGroupMembers(const std::string& args) {
    std::string cleanArgs = args;

    if (!cleanArgs.empty() && cleanArgs.front() == '"' && cleanArgs.back() == '"') {
        cleanArgs = cleanArgs.substr(1, cleanArgs.length() - 2);
    }

    if (cleanArgs == "-all") {
        std::wcout << L"[listgroupmembers] Listing all members of all local groups:\n";

        LPLOCALGROUP_INFO_0 pGroupInfo = nullptr;
        DWORD entriesRead = 0, totalEntries = 0;
        DWORD_PTR resumeHandle = 0;  // fix again

        NET_API_STATUS status = NetLocalGroupEnum(
            nullptr, 0, (LPBYTE*)&pGroupInfo, MAX_PREFERRED_LENGTH,
            &entriesRead, &totalEntries, &resumeHandle
        );

        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < entriesRead; ++i) {
                std::wstring groupName = pGroupInfo[i].lgrpi0_name;
                std::wcout << L"\nGroup: " << groupName << L"\n";

                LOCALGROUP_MEMBERS_INFO_0* pBuf = nullptr;
                DWORD eRead = 0, tEntries = 0;
                DWORD_PTR rHandle = 0;  // Fix again again

                status = NetLocalGroupGetMembers(
                    nullptr, groupName.c_str(), 0,
                    (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
                    &eRead, &tEntries, &rHandle
                );

                if (status == NERR_Success || status == ERROR_MORE_DATA) {
                    for (DWORD j = 0; j < eRead; ++j) {
                        if (pBuf[j].lgrmi0_sid) {
                            DWORD cchName = 0, cchDomain = 0;
                            SID_NAME_USE sidType;

                            LookupAccountSid(nullptr, pBuf[j].lgrmi0_sid, nullptr, &cchName, nullptr, &cchDomain, &sidType);

                            std::vector<wchar_t> nameBuf(cchName);
                            std::vector<wchar_t> domainBuf(cchDomain);

                            if (LookupAccountSid(nullptr, pBuf[j].lgrmi0_sid, nameBuf.data(), &cchName, domainBuf.data(), &cchDomain, &sidType)) {
                                std::wcout << L" - " << domainBuf.data() << L"\\" << nameBuf.data() << L"\n";
                            }
                        }
                    }
                    if (pBuf) NetApiBufferFree(pBuf);
                } else {
                    std::wcout << L"Failed to get members of " << groupName << L", error: " << status << L"\n";
                }
            }

            if (pGroupInfo) NetApiBufferFree(pGroupInfo);
        } else {
            std::wcout << L"Failed to enumerate local groups, error: " << status << L"\n";
        }

        return;
    }

    std::wstring groupName(cleanArgs.begin(), cleanArgs.end());
    std::wcout << L"[listgroupmembers] Listing members of group: \"" << groupName << L"\"\n";

    LOCALGROUP_MEMBERS_INFO_0* pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0;
    DWORD_PTR resumeHandle = 0;  // Fix again again again

    NET_API_STATUS status = NetLocalGroupGetMembers(
        nullptr, groupName.c_str(), 0,
        (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
        &entriesRead, &totalEntries, &resumeHandle
    );

    if (status == NERR_Success || status == ERROR_MORE_DATA) {
        for (DWORD i = 0; i < entriesRead; ++i) {
            if (pBuf[i].lgrmi0_sid) {
                DWORD cchName = 0, cchDomain = 0;
                SID_NAME_USE sidType;

                LookupAccountSid(nullptr, pBuf[i].lgrmi0_sid, nullptr, &cchName, nullptr, &cchDomain, &sidType);

                std::vector<wchar_t> nameBuf(cchName);
                std::vector<wchar_t> domainBuf(cchDomain);

                if (LookupAccountSid(nullptr, pBuf[i].lgrmi0_sid, nameBuf.data(), &cchName, domainBuf.data(), &cchDomain, &sidType)) {
                    std::wcout << L" - " << domainBuf.data() << L"\\" << nameBuf.data() << L"\n";
                }
            }
        }
        if (pBuf) NetApiBufferFree(pBuf);
    } else {
        std::wcout << L"Failed to retrieve group members, error: " << status << L"\n";
    }
}

void CmdListRemoteSessions(const std::string& args) {
    bool showAll = false;
    bool showActive = false;
    bool showDisconnected = false;
    std::string filterUser;
    int filterProtocol = -1; // -1 means no filter :(

    std::vector<std::string> tokens;
    size_t pos = 0, prev = 0;
    while ((pos = args.find(' ', prev)) != std::string::npos) {
        tokens.push_back(args.substr(prev, pos - prev));
        prev = pos + 1;
    }
    if (prev < args.size())
        tokens.push_back(args.substr(prev));

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-all") {
            showAll = true;
        } else if (tokens[i] == "-active") {
            showActive = true;
        } else if (tokens[i] == "-disconnected") {
            showDisconnected = true;
        } else if (tokens[i] == "-user" && i + 1 < tokens.size()) {
            filterUser = tokens[i + 1];
            ++i;
        } else if (tokens[i] == "-protocol" && i + 1 < tokens.size()) {
            filterProtocol = std::stoi(tokens[i + 1]);
            ++i;
        }
    }

    std::wstring filterUserW;
    if (!filterUser.empty()) {
        filterUserW.assign(filterUser.begin(), filterUser.end());
        std::transform(filterUserW.begin(), filterUserW.end(), filterUserW.begin(), ::towlower);
    }

    PWTS_SESSION_INFO pSessionInfo = nullptr;
    DWORD sessionCount = 0;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
        std::cerr << "Failed to enumerate sessions.\n";
        return;
    }

    std::wcout << L"Remote sessions:\n";

    for (DWORD i = 0; i < sessionCount; ++i) {
        DWORD sessionId = pSessionInfo[i].SessionId;
        WTS_CONNECTSTATE_CLASS sessionState = pSessionInfo[i].State;

        if (!showAll) {
            if (showActive && sessionState != WTSActive) continue;
            if (showDisconnected && sessionState != WTSDisconnected) continue;
            if (!showActive && !showDisconnected && sessionState != WTSActive) continue;
        }

        LPWSTR pUserName = nullptr;
        DWORD userNameLen = 0;
        if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &pUserName, &userNameLen)) {
            continue;
        }

        if (pUserName == nullptr || userNameLen == 0) {
            if (pUserName) WTSFreeMemory(pUserName);
            continue;
        }

        std::wstring userNameW(pUserName);
        WTSFreeMemory(pUserName);

        if (!filterUserW.empty()) {
            std::wstring userNameLower = userNameW;
            std::transform(userNameLower.begin(), userNameLower.end(), userNameLower.begin(), ::towlower);
            if (userNameLower.find(filterUserW) == std::wstring::npos) {
                continue;
            }
        }

        LPWSTR pClientProtocol = nullptr;  
        DWORD protocolLen = 0;
        ULONG clientProtocol = 0;

        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSClientProtocolType, &pClientProtocol, &protocolLen)) {
            if (pClientProtocol && protocolLen == sizeof(ULONG)) {
                clientProtocol = *(ULONG*)pClientProtocol; 
            }
            WTSFreeMemory(pClientProtocol);
        }

        if (filterProtocol >= 0 && clientProtocol != (ULONG)filterProtocol) {
            continue;
        }

        std::wcout << L"SessionID: " << sessionId
                   << L", User: " << userNameW
                   << L", State: ";

        switch (sessionState) {
            case WTSActive: std::wcout << L"Active"; break;
            case WTSConnected: std::wcout << L"Connected"; break;
            case WTSConnectQuery: std::wcout << L"ConnectQuery"; break;
            case WTSShadow: std::wcout << L"Shadow"; break;
            case WTSDisconnected: std::wcout << L"Disconnected"; break;
            case WTSIdle: std::wcout << L"Idle"; break;
            case WTSListen: std::wcout << L"Listen"; break;
            case WTSReset: std::wcout << L"Reset"; break;
            case WTSDown: std::wcout << L"Down"; break;
            case WTSInit: std::wcout << L"Init"; break;
            default: std::wcout << L"Unknown"; break;
        }

        std::wcout << L", Protocol: ";
        switch (clientProtocol) {
            case 0: std::wcout << L"RDP"; break;
            case 1: std::wcout << L"ICA"; break;
            default: std::wcout << L"Other (" << clientProtocol << L")"; break;
        }
        std::wcout << L"\n";
    }

    WTSFreeMemory(pSessionInfo);
}

void CmdListDisabledUsers(const std::string& args) {
    std::wcout << L"[LIST] Disabled user accounts:\n";

    LPUSER_INFO_1 pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS nStatus;

    do {
        nStatus = NetUserEnum(
            nullptr, // local computer
            1,       // level 1: USER_INFO_1
            FILTER_NORMAL_ACCOUNT, // global users
            (LPBYTE*)&pBuf,
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle
        );

        if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pBuf != nullptr) {
            for (DWORD i = 0; i < entriesRead; ++i) {
                USER_INFO_1& user = pBuf[i];
                if (user.usri1_flags & UF_ACCOUNTDISABLE) {
                    std::wcout << L"  " << user.usri1_name << L"\n";
                }
            }
            NetApiBufferFree(pBuf);
            pBuf = nullptr;
        } else {
            std::cerr << "[LIST] Failed to enumerate users. Error code: " << nStatus << "\n";
            break;
        }
    } while (nStatus == ERROR_MORE_DATA);
}

void CmdListLockedUsers(const std::string& args) {
    (void)args;
    std::wcout << L"[LIST] Locked user accounts:\n";

    LPUSER_INFO_1 pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS nStatus;

    do {
        nStatus = NetUserEnum(
            nullptr,
            1,
            FILTER_NORMAL_ACCOUNT,
            (LPBYTE*)&pBuf,
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle
        );

        if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pBuf != nullptr) {
            for (DWORD i = 0; i < entriesRead; ++i) {
                USER_INFO_1& user = pBuf[i];
                if (user.usri1_flags & UF_LOCKOUT) {
                    std::wcout << L"  " << user.usri1_name << L"\n";
                }
            }
            NetApiBufferFree(pBuf);
            pBuf = nullptr;
        } else {
            std::cerr << "[LIST] Failed to enumerate users. Error code: " << nStatus << "\n";
            break;
        }
    } while (nStatus == ERROR_MORE_DATA);
}

void CmdListLastLogons(const std::string& args) {
    (void)args;
    std::wcout << L"[LIST] Last logon times for local users:\n";

    LPUSER_INFO_0 pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS nStatus;

    do {
        nStatus = NetUserEnum(
            nullptr,
            0, // USER_INFO_0 gives the username
            FILTER_NORMAL_ACCOUNT,
            (LPBYTE*)&pBuf,
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle
        );

        if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pBuf != nullptr) {
            for (DWORD i = 0; i < entriesRead; ++i) {
                USER_INFO_0& user0 = pBuf[i];
                LPUSER_INFO_2 pUser2 = nullptr;

                if (NetUserGetInfo(nullptr, user0.usri0_name, 2, (LPBYTE*)&pUser2) == NERR_Success) {
                    std::wcout << L" " << std::left << std::setw(20)
                        << user0.usri0_name << L" - Last logon: "
                        << FormatUnixTime(pUser2->usri2_last_logon) << L"\n";

                    NetApiBufferFree(pUser2);
                } else {
                    std::wcout << L" " << user0.usri0_name << L" - (error retrieving logon info)\n";
                }
            }

            NetApiBufferFree(pBuf);
            pBuf = nullptr;
        } else {
            std::cerr << "[LIST] Failed to enumerate users. Error code: " << nStatus << "\n";
            break;
        }
    } while (nStatus == ERROR_MORE_DATA);
}

std::string DriveTypeToString(UINT type) {
    switch (type) {
        case DRIVE_REMOVABLE: return "Removable";
        case DRIVE_FIXED:     return "Fixed";
        case DRIVE_REMOTE:    return "Network";
        case DRIVE_CDROM:     return "CD-ROM";
        case DRIVE_RAMDISK:   return "RAM Disk";
        case DRIVE_NO_ROOT_DIR:
        case DRIVE_UNKNOWN:
        default:              return "Unknown";
    }
}

bool IsUSBDrive(const std::string& driveLetter) {
    std::string devicePath = "\\\\.\\" + driveLetter.substr(0, 2);
    HANDLE hDrive = CreateFileA(devicePath.c_str(), 0,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);

    if (hDrive == INVALID_HANDLE_VALUE)
        return false;

    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    BYTE buffer[1024];
    DWORD bytesReturned;
    bool isUSB = false;

    if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                        &query, sizeof(query),
                        &buffer, sizeof(buffer),
                        &bytesReturned, nullptr)) {
        STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)buffer;
        if (desc->BusType == BusTypeUsb)
            isUSB = true;
    }

    CloseHandle(hDrive);
    return isUSB;
}

void CmdListDrives(const std::string& args) {
    std::string mode = args;
    for (auto& c : mode) c = tolower(c);
    if (mode.empty()) mode = "all";

    DWORD drives = GetLogicalDrives();
    if (drives == 0) {
        std::cerr << "[LIST] Failed to get logical drives.\n";
        return;
    }

    std::cout << "[LIST] Drive Information:\n\n";
    std::cout << std::left << std::setw(8) << "Drive"
              << std::setw(12) << "Type"
              << std::setw(15) << "Filesystem"
              << std::setw(12) << "Label"
              << std::setw(16) << "Free / Total"
              << "Status\n";

    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        std::string root = std::string(1, letter) + ":\\";
        if (!(drives & (1 << (letter - 'A')))) continue;

        UINT type = GetDriveTypeA(root.c_str());
        std::string typeStr = DriveTypeToString(type);

        // Filter logic
        if (mode == "usb" && (!IsUSBDrive(root))) continue;
        if (mode == "fixed" && type != DRIVE_FIXED) continue;
        if (mode == "all" || mode == "removable") {} // allow all

        char fsName[MAX_PATH] = { 0 };
        char volumeName[MAX_PATH] = { 0 };
        DWORD serialNumber = 0, maxCompLen = 0, fsFlags = 0;

        bool ready = GetVolumeInformationA(
            root.c_str(), volumeName, MAX_PATH, &serialNumber,
            &maxCompLen, &fsFlags, fsName, MAX_PATH
        );

        ULARGE_INTEGER freeBytes, totalBytes;
        std::string statusStr;
        std::string spaceStr = "-";

        if (GetDiskFreeSpaceExA(root.c_str(), &freeBytes, &totalBytes, nullptr)) {
            spaceStr = std::to_string(freeBytes.QuadPart / (1024 * 1024 * 1024)) + "GB / " +
                       std::to_string(totalBytes.QuadPart / (1024 * 1024 * 1024)) + "GB";
        }

        statusStr = ready ? "Ready" : "Not Ready";

        std::cout << std::left << std::setw(8) << root
                  << std::setw(12) << typeStr
                  << std::setw(15) << (ready ? fsName : "-")
                  << std::setw(12) << (ready ? volumeName : "-")
                  << std::setw(16) << spaceStr
                  << statusStr << "\n";
    }
}

struct VolumeInfo {
    std::wstring guidPath;
    std::vector<std::wstring> mountPoints;
    std::wstring label;
    std::wstring fs;
    std::wstring type;
    std::wstring bitlocker;
    ULONGLONG freeBytes = 0;
    ULONGLONG totalBytes = 0;
};

std::wstring GetVolumeType(const std::wstring& rootPath) {
    UINT type = GetDriveTypeW(rootPath.c_str());
    switch (type) {
        case DRIVE_FIXED: return L"Fixed";
        case DRIVE_REMOVABLE: return L"Removable";
        case DRIVE_CDROM: return L"CDROM";
        case DRIVE_REMOTE: return L"Network";
        case DRIVE_RAMDISK: return L"RAM";
        default: return L"Unknown";
    }
}

#ifndef _MSC_VER
std::wstring GetBitlockerStatus(const std::wstring&) {
    return L"N/A";
}
#endif

void CmdListVolumes(const std::string& args) {
    bool showAll = args.find("-all") != std::string::npos;
    bool showJson = args.find("-json") != std::string::npos;
    bool showBitlocker = args.find("-bitlocker") != std::string::npos;
    bool showGuid = args.find("-guid") != std::string::npos;
    bool showMounts = args.find("-mounts") != std::string::npos;
    bool showRaw = args.find("-raw") != std::string::npos;
    bool skipHidden = args.find("-nohidden") != std::string::npos;
    bool labelsOnly = args.find("-labels") != std::string::npos;

    wchar_t volumeName[MAX_PATH] = {0};
    HANDLE hVol = FindFirstVolumeW(volumeName, ARRAYSIZE(volumeName));
    if (hVol == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[LIST] Failed to enumerate volumes.\n";
        return;
    }

    std::vector<VolumeInfo> volumes;
    do {
        VolumeInfo vi;
        vi.guidPath = volumeName;

        DWORD charCount = MAX_PATH;
        wchar_t names[MAX_PATH] = {0};
        GetVolumePathNamesForVolumeNameW(volumeName, names, MAX_PATH, &charCount);

        wchar_t* p = names;
        while (*p) {
            vi.mountPoints.push_back(p);
            p += wcslen(p) + 1;
        }

        if (skipHidden && vi.mountPoints.empty()) continue;

        if (!vi.mountPoints.empty()) {
            const std::wstring& root = vi.mountPoints[0];
            wchar_t fsName[MAX_PATH] = {0}, label[MAX_PATH] = {0};
            GetVolumeInformationW(root.c_str(), label, MAX_PATH, NULL, NULL, NULL, fsName, MAX_PATH);
            vi.label = label;
            vi.fs = fsName;
            vi.type = GetVolumeType(root);

            ULARGE_INTEGER freeBytes, totalBytes;
            if (GetDiskFreeSpaceExW(root.c_str(), &freeBytes, &totalBytes, NULL)) {
                vi.freeBytes = freeBytes.QuadPart;
                vi.totalBytes = totalBytes.QuadPart;
            }
        }

        if (labelsOnly && vi.label.empty()) continue;

        if (showBitlocker) {
            vi.bitlocker = GetBitlockerStatus(volumeName);
        }

        volumes.push_back(vi);
    } while (FindNextVolumeW(hVol, volumeName, ARRAYSIZE(volumeName)));
    FindVolumeClose(hVol);

    if (showJson) {
        std::wcout << L"[LIST] JSON volume output:\n[\n";
        for (size_t i = 0; i < volumes.size(); ++i) {
            const auto& v = volumes[i];
            std::wcout << L"  {\n";
            std::wcout << L"    \"guid\": \"" << v.guidPath << L"\",\n";
            std::wcout << L"    \"mounts\": [";
            for (size_t j = 0; j < v.mountPoints.size(); ++j) {
                std::wcout << L"\"" << v.mountPoints[j] << L"\"";
                if (j + 1 < v.mountPoints.size()) std::wcout << L", ";
            }
            std::wcout << L"],\n";
            std::wcout << L"    \"label\": \"" << v.label << L"\",\n";
            std::wcout << L"    \"fs\": \"" << v.fs << L"\",\n";
            std::wcout << L"    \"type\": \"" << v.type << L"\",\n";
            if (showBitlocker)
                std::wcout << L"    \"bitlocker\": \"" << v.bitlocker << L"\",\n";
            std::wcout << L"    \"free\": " << v.freeBytes << L",\n";
            std::wcout << L"    \"total\": " << v.totalBytes << L"\n  }";
            if (i + 1 < volumes.size()) std::wcout << L",";
            std::wcout << L"\n";
        }
        std::wcout << L"]\n";
    } else {
        std::wcout << L"[LIST] Volume Information:\n\n";
        std::wcout << std::left << std::setw(12) << L"Mount" << std::setw(10) << L"Label" << std::setw(8) << L"FS" << std::setw(10) << L"Type";
        if (showGuid) std::wcout << std::setw(40) << L"GUID";
        if (showBitlocker) std::wcout << std::setw(10) << L"BitLocker";
        std::wcout << L"Size (Free / Total)\n";

        for (const auto& v : volumes) {
            std::wstring mount = v.mountPoints.empty() ? L"(none)" : v.mountPoints[0];
            std::wcout << std::left << std::setw(12) << mount.substr(0,12);
            std::wcout << std::setw(10) << v.label.substr(0,10);
            std::wcout << std::setw(8) << v.fs.substr(0,8);
            std::wcout << std::setw(10) << v.type.substr(0,10);
            if (showGuid) std::wcout << std::setw(40) << v.guidPath;
            if (showBitlocker) std::wcout << std::setw(10) << v.bitlocker;

            std::wstringstream ss;
            ss << (v.freeBytes / (1024 * 1024 * 1024)) << L"GB / " << (v.totalBytes / (1024 * 1024 * 1024)) << L"GB";
            std::wcout << ss.str() << L"\n";

            if (showMounts && v.mountPoints.size() > 1) {
                for (size_t i = 1; i < v.mountPoints.size(); ++i)
                    std::wcout << L"              (mnt): " << v.mountPoints[i] << L"\n";
            }
        }
    }
}

void CmdListHelp(const std::string& args) {
    (void)args; 
    std::cout << "Available commands:\n";
    std::cout << "  listusers           - List all user accounts\n";
    std::cout << "  listdisabledusers   - List all disabled accounts\n";
    std::cout << "  listlockedusers     - List accounts that are currently locked out\n";
    std::cout << "  listgroups (alias: listlocalgroups) - List all local groups\n";
    std::cout << "  listloggedin        - List currently logged-in users/sessions\n";
    std::cout << "  listlastlogons      - List local users and their last logon timestamp\n";
    std::cout << "  listadmins          - List members of Administrators group\n";
    std::cout << "  listprofiles        - List user profiles on the machine\n";
    std::cout << "  listgroupmembers [groupname] - List members of a specific group. Can see all via [-all] flag.\n";
    std::cout << "  listdomains         - Show domain/workgroup info\n";
    std::cout << "  listprocessusers    - Show users associated with running processes\n";
    std::cout << "  listprivileges      - Show current user's privileges\n";
    std::cout << "  listnetworkusers    - Show users connected over network sessions\n";
    std::cout << "  listuserdetails [username] - Show detailed info for a user\n";
    std::cout << "  listlocalusers      - List all local user accounts\n";
    std::cout << "  listdrives [usb|fixed|all] - Show detailed drive information, filterable by type\n";
    std::cout << "  listremotesessions [flags] - List remote sessions with optional filters:\n";
    std::cout << "    -all              - Show all remote sessions\n";
    std::cout << "    -active           - Show only active remote sessions\n";
    std::cout << "    -disconnected     - Show only disconnected remote sessions\n";
    std::cout << "    -user <username>  - Filter by username (case-insensitive)\n";
    std::cout << "    -protocol <num>   - Filter by protocol type (0 = Console, 2 = RDP, etc.)\n";
    std::cout << "  listvolumes [flags] - Show detailed info on all volumes. Flags:\n";
    std::cout << "    -all        : Show all volumes, including hidden/system\n";
    std::cout << "    -json       : Output results as JSON\n";
    std::cout << "    -guid       : Show Volume GUID paths\n";
    std::cout << "    -bitlocker  : Show BitLocker status via WMI\n";
    std::cout << "    -mounts     : Show all mount points (e.g., mounted folders)\n";
    std::cout << "    -raw        : Show raw device paths (e.g., \\\\.\\Volume{...})\n";
    std::cout << "    -labels     : Include volume label even if empty\n";
    std::cout << "    -nohidden   : Hide volumes with no mount points or labels\n";
    std::cout << "  help                - Show this help\n";
    std::cout << "  exit                - Exit the program\n";
}