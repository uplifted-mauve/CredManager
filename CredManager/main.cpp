#include "pch.h"

using namespace std::literals;

bool verbose = false;

inline void PrintLastError()
{
    wil::unique_cotaskmem_string str;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)str.put(),
        0, NULL);
    std::wcout << str.get() << std::endl;
}

struct CredManagerEntry
{
    std::wstring name;
    size_t size;
    FILETIME lastWritten;
    DWORD type;
};

std::vector<CredManagerEntry> EnumerateCreds(PCWSTR filter)
{
    PCREDENTIAL* credentialBlock = nullptr;
    auto cleanup = wil::scope_exit([&]
        {
            if (credentialBlock)
            {
                CredFree(credentialBlock);
            }
        });

    DWORD count;
    unsigned long long totalBlob = 0;
    unsigned long long payloadSize = 0;
    std::vector<CredManagerEntry> credentials;

    if (CredEnumerate(filter, 0, &count, &credentialBlock))
    {
        std::wcout << L"Found " << count << L" creds" << std::endl;
        for (auto i = 0U; i < count; i++)
        {
            PCREDENTIAL credential = credentialBlock[i];
            // Guestimate the total data size stored in Credential Manager
            payloadSize += sizeof(wchar_t) * wcslen(credential->TargetName);
            if (credential->Comment)
            {
                payloadSize += sizeof(wchar_t) * wcslen(credential->Comment);
            }
            if (credential->TargetAlias)
            {
                payloadSize += sizeof(wchar_t) * wcslen(credential->TargetAlias);
            }
            if (credential->UserName)
            {
                payloadSize += sizeof(wchar_t) * wcslen(credential->UserName);
            }
            if (credential->Attributes)
            {
                for (auto j = 0U; j < credential->AttributeCount; j++)
                {
                    if (credential->Attributes[j].Keyword)
                    {
                        payloadSize += sizeof(wchar_t) * wcslen(credential->Attributes[j].Keyword);
                    }
                    payloadSize += credential->Attributes[j].ValueSize;

                    payloadSize += sizeof(CREDENTIAL_ATTRIBUTE);
                }
            }
            payloadSize += credential->CredentialBlobSize;

            payloadSize += sizeof(CREDENTIAL);

            if (verbose)
            {
                std::wcout << L"TargetName: " << credential->TargetName << std::endl;
                std::wcout << L"Persist: " << credential->Persist << std::endl;
                std::wcout << L"Type: " << credential->Type << std::endl;
                std::wcout << L"Flags: " << credential->Flags << std::endl;
                std::wcout << L"BlobSize: " << credential->CredentialBlobSize << std::endl;
                std::wcout << L"Blob: " << credential->CredentialBlob << std::endl;
            }
            totalBlob += credential->CredentialBlobSize;

            credentials.push_back({ { credential->TargetName }, credential->CredentialBlobSize, credential->LastWritten, credential->Type });
        }
    }
    else
    {
        std::wcout << L" Error enumerating cred store " << GetLastError() << std::endl;
        PrintLastError();
    }

    std::wcout << L"Total blob size: " << std::setprecision(5) << (double)totalBlob / 1024.0 << L"KiB" << std::endl;
    std::wcout << L"Estimated total size: " << std::setprecision(5) << (double)payloadSize / 1024.0 << L"KiB" << std::endl;


    return credentials;
}

void PrintCredentialBlob(const CredManagerEntry& cred)
{
    PCREDENTIAL selectedCred = nullptr;
    auto selectedCredCleanup = wil::scope_exit([&]
        {
            if (selectedCred)
            {
                CredFree(selectedCred);
            }
        });

    if (CredRead(cred.name.c_str(), cred.type, 0, &selectedCred))
    {
        void* blob = selectedCred->CredentialBlob;

        std::string_view sv(reinterpret_cast<char*>(selectedCred->CredentialBlob), selectedCred->CredentialBlobSize);
        std::cout << "Value:" << std::endl << sv << std::endl;
    }
}

void ProcessCredentialsInteractive(std::vector<CredManagerEntry>&& credentials, unsigned days)
{
    std::ranges::sort(credentials, [](CredManagerEntry& a, CredManagerEntry& b) { return a.size > b.size; });
    
    // how log ago we want to keep
    auto minAgeInDays = std::chrono::hours(24h * days);
    if (minAgeInDays.count() < 0)
    {
        std::wcout << L"Error - Number of days entered is too large" << std::endl;
        return;
    }

    if (std::chrono::time_point<std::chrono::system_clock>(minAgeInDays) > std::chrono::system_clock::now())
    {
        std::wcout << L"Error - Number of days entered greater than the time between now and 1 January 1970" << std::endl;
        return;
    }

    const std::chrono::time_point<std::chrono::system_clock> ago = std::chrono::time_point<std::chrono::system_clock>(std::chrono::system_clock::now() - minAgeInDays);

    // Microseconds between 1601-01-01 00:00:00 UTC and 1970-01-01 00:00:00 UTC
    static const uint64_t EPOCH_DIFFERENCE_MICROS = 11644473600000000ull;

    auto filteredView = credentials | std::views::filter([&ago](CredManagerEntry& e) {
        uint64_t total_us = ((static_cast<uint64_t>(e.lastWritten.dwHighDateTime) << 32) | static_cast<uint64_t>(e.lastWritten.dwLowDateTime)) / 10;
        total_us -= EPOCH_DIFFERENCE_MICROS;
        const auto time = std::chrono::time_point<std::chrono::system_clock>(std::chrono::microseconds(total_us));
        return time < ago;
        }) | std::ranges::to<std::vector>(); /*| std::views::take(10)*/
    
    std::wcout << L"Filtered down to " << filteredView.size() << L" creds in time range" << std::endl;
    bool all = false;

    int i = 1;
    for (auto& cred : filteredView)
    {
        std::wcout << std::endl << L"[" << i++ << L"/" << filteredView.size() << L"]" << std::endl;
        uint64_t total_us = ((static_cast<uint64_t>(cred.lastWritten.dwHighDateTime) << 32) | static_cast<uint64_t>(cred.lastWritten.dwLowDateTime)) / 10;
        total_us -= EPOCH_DIFFERENCE_MICROS;

        std::wcout << std::chrono::time_point<std::chrono::system_clock>(std::chrono::microseconds(total_us)) << L" " << cred.name << L" : " << std::setprecision(2) << (double)cred.size / 1024.0 << L" KiB" << std::endl;

        bool shouldDelete = all;

        while (!all)
        {
            std::wcout << L"Delete entry? (Y)es (N)o (A)ll (Q)uit: ";
            std::string action;
            std::cin >> action;

            if (action.size() != 1)
            {
                continue;
            }

            if (action[0] == 'y' || action[0] == 'Y')
            {
                shouldDelete = true;
                break;
            }

            if (action[0] == 'n' || action[0] == 'N')
            {
                break;
            }

            if (action[0] == 'a' || action[0] == 'A')
            {
                shouldDelete = true;
                all = true;
                break;
            }

            if (action[0] == 'q' || action[0] == 'Q')
            {
                std::wcout << L"Terminating..." << std::endl;
                ExitProcess(10);
                break;
            }

            if (action[0] == 'v' || action[0] == 'V')
            {
                PrintCredentialBlob(cred);
                return;
            }
        }

        if (shouldDelete)
        {
            std::wcout << L"Deleting" << std::endl;
            if (!CredDelete(cred.name.c_str(), CRED_TYPE_GENERIC, 0))
            {
                std::wcout << L"Error deleting " << cred.name << L" : " << GetLastError() << std::endl;
                PrintLastError();
            }
            else
            {
                std::wcout << L"Deleted " << cred.name << std::endl;
            }
        }
    }
}

void ParseFilter(std::wstring* filter, char* argv[])
{
    FAIL_FAST_IF_NULL(filter);
    size_t inLength = strnlen_s(argv[1], 255);
    if (inLength == 255)
    {
        std::wcout << L"Warning - the provided filter is too long and may be truncated" << std::endl;
    }

    // First get the size needed by passing a null buffer
    int convertResult = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[1], static_cast<int>(inLength), nullptr, 0);
    if (convertResult > 0)
    {
        filter->resize(convertResult);
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[1], static_cast<int>(inLength), &(*filter)[0], static_cast<int>(filter->size()));
    }
    else
    {
        std::wcout << L"Failure to convert argv to UTF16 " << GetLastError() << std::endl;
        PrintLastError();
        ExitProcess(1);
    }
}

unsigned ParseDays(char* arg)
{
    char* end = arg + strnlen_s(arg, 50);
    auto days = strtoul(arg, &end, 10);
    return days;
}

int main(int argc, char *argv[])
{
    std::wstring filter;
    unsigned days = 180;
        
    if (argc <= 1)
    {
        filter = L"Adobe*";
    }
    else if (argc >= 2 && argc <= 3)
    {
        ParseFilter(&filter, argv);

        if (argc == 3)
        {
            days = ParseDays(argv[2]);
        }
    }
    else
    {
        std::wcout << L"Usage: CredManager [filter] [age]" << std::endl 
            << L" filter - string including wildcard to select which credentials to query (max 255 char). Defaults to Adobe*" << std::endl 
            << L" age - delete credentials older than x number of days" << std::endl;
        return 2;
    }
    
    auto creds = EnumerateCreds(filter.c_str());
    ProcessCredentialsInteractive(std::move(creds), days);
    return 0;
}