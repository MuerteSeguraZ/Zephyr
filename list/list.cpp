#define UNICODE
#define _UNICODE

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>  
#include <cwctype>   
#include <windows.h>
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

void CmdListHelp(const std::string& args) {
    (void)args; 
    std::cout << "Available commands:\n";
    std::cout << "  listusers           - List all user accounts\n";
    std::cout << "  listgroups (alias: listlocalgroups) - List all local groups\n";
    std::cout << "  listloggedin        - List currently logged-in users/sessions\n";
    std::cout << "  listadmins          - List members of Administrators group\n";
    std::cout << "  listprofiles        - List user profiles on the machine\n";
    std::cout << "  listgroupmembers [groupname] - List members of a specific group. Can see all via [-all] flag.\n";
    std::cout << "  listdomains         - Show domain/workgroup info\n";
    std::cout << "  listprocessusers    - Show users associated with running processes\n";
    std::cout << "  listprivileges      - Show current user's privileges\n";
    std::cout << "  listnetworkusers    - Show users connected over network sessions\n";
    std::cout << "  listuserdetails [username] - Show detailed info for a user\n";
    std::cout << "  listlocalusers      - List all local user accounts\n";
    std::cout << "  listremotesessions [flags] - List remote sessions with optional filters:\n";
    std::cout << "    -all              - Show all remote sessions\n";
    std::cout << "    -active           - Show only active remote sessions\n";
    std::cout << "    -disconnected     - Show only disconnected remote sessions\n";
    std::cout << "    -user <username>  - Filter by username (case-insensitive)\n";
    std::cout << "    -protocol <num>   - Filter by protocol type (0 = Console, 2 = RDP, etc.)\n";
    std::cout << "  help                - Show this help\n";
    std::cout << "  exit                - Exit the program\n";
}