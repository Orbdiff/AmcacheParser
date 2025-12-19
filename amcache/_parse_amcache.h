#include <windows.h>
#include <urlmon.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <future>
#include <ctime>
#include <algorithm>

#include "../signature/_signature_parser.h"
#include "../yara/_yara_scan.hpp"
#include "../time/_time_utils.h"

inline bool   g_only_instance = false;
inline bool   g_only_unsigned_cheat = false;
inline time_t g_logon_time = 0;

HANDLE g_console = GetStdHandle(STD_OUTPUT_HANDLE);

enum ConsoleColor
{
    C_DEFAULT = 7,
    C_GRAY = 8,
    C_GREEN = 10,
    C_RED = 12,
    C_YELLOW = 14,
    C_CYAN = 11,
    C_WHITE = 15
};

void SetColor(WORD c)
{
    SetConsoleTextAttribute(g_console, c);
}

WORD ColorForSignature(SignatureStatus s)
{
    switch (s)
    {
    case SignatureStatus::Signed:   return C_GREEN;
    case SignatureStatus::Unsigned: return C_YELLOW;
    case SignatureStatus::Cheat:    return C_RED;
    case SignatureStatus::NotFound: return C_GRAY;
    default:                        return C_DEFAULT;
    }
}

struct amcache_entry
{
    std::wstring base_dir;
    std::wstring work_dir;
    std::wstring dotnet_installer;
};

struct ScanResult
{
    std::wstring date;
    std::wstring path;
    SignatureStatus sig = SignatureStatus::NotFound;
    bool yara = false;
    time_t exec_time = 0;
};

std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string r(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), r.data(), size, nullptr, nullptr);
    return r;
}

time_t ParseAmcacheTime(const std::wstring& d)
{
    std::tm tm{};
    swscanf_s(
        d.c_str(),
        L"%d-%d-%d %d:%d:%d",
        &tm.tm_year,
        &tm.tm_mon,
        &tm.tm_mday,
        &tm.tm_hour,
        &tm.tm_min,
        &tm.tm_sec
    );

    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;

    return _mkgmtime(&tm);
}

std::wstring TimeToLocalString(time_t utc)
{
    std::tm local{};
    localtime_s(&local, &utc);

    wchar_t buf[64]{};
    wcsftime(buf, 64, L"%Y-%m-%d %H:%M:%S", &local);
    return buf;
}

bool download_file(const std::wstring& url, const std::wstring& output)
{
    return SUCCEEDED(URLDownloadToFileW(nullptr, url.c_str(), output.c_str(), 0, nullptr));
}

bool run_command(const std::wstring& cmd, const std::wstring& wd)
{
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::wstring c = cmd;

    if (!CreateProcessW(nullptr, c.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, wd.c_str(), &si, &pi))
        return false;

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

void cleanup_csv_directory(const std::wstring& dir)
{
    WIN32_FIND_DATAW ffd{};
    HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    FILETIME newest{};
    std::wstring keep;
    std::vector<std::wstring> all;

    do
    {
        if (!wcscmp(ffd.cFileName, L".") || !wcscmp(ffd.cFileName, L".."))
            continue;

        std::wstring full = dir + L"\\" + ffd.cFileName;
        all.push_back(full);

        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            std::wstring name = ffd.cFileName;
            if (name.ends_with(L".csv") &&
                name.find(L"Amcache_UnassociatedFileEntries") != std::wstring::npos)
            {
                if (keep.empty() || CompareFileTime(&ffd.ftLastWriteTime, &newest) > 0)
                {
                    newest = ffd.ftLastWriteTime;
                    keep = full;
                }
            }
        }
    } while (FindNextFileW(hFind, &ffd));

    FindClose(hFind);

    for (auto& f : all)
    {
        if (!_wcsicmp(f.c_str(), keep.c_str())) continue;
        DWORD attr = GetFileAttributesW(f.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) continue;
        (attr & FILE_ATTRIBUTE_DIRECTORY) ? RemoveDirectoryW(f.c_str()) : DeleteFileW(f.c_str());
    }
}

const wchar_t* SignatureStatusToString(SignatureStatus s)
{
    switch (s)
    {
    case SignatureStatus::Signed:   return L"Signed";
    case SignatureStatus::Unsigned: return L"Unsigned";
    case SignatureStatus::Cheat:    return L"Cheat";
    case SignatureStatus::NotFound: return L"NotFound";
    default:                        return L"Unknown";
    }
}

bool ScanWithYara(const std::wstring& path)
{
    if (!std::filesystem::exists(path)) return false;
    std::vector<std::string> matches;
    return FastScanFile(WideToUtf8(path), matches);
}

ScanResult ProcessEntry(const std::wstring& date, const std::wstring& path)
{
    ScanResult r{};
    r.date = date;
    r.path = path;
    r.exec_time = ParseAmcacheTime(date);

    if (g_only_instance && g_logon_time && r.exec_time <= g_logon_time)
        return r;

    r.sig = GetSignatureStatus(path);

    if (g_only_unsigned_cheat &&
        r.sig != SignatureStatus::Unsigned &&
        r.sig != SignatureStatus::Cheat)
    {
        r.sig = SignatureStatus::NotFound;
        return r;
    }

    r.yara = ScanWithYara(path);
    return r;
}

void parse_final_csv(const std::wstring& dir)
{
    WIN32_FIND_DATAW ffd{};
    HANDLE hFind = FindFirstFileW((dir + L"\\*.csv").c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    std::wstring csv = dir + L"\\" + ffd.cFileName;
    FindClose(hFind);

    std::wifstream file(csv);
    if (!file) return;

    constexpr size_t MAX_THREADS = 4;
    std::vector<std::future<ScanResult>> futures;
    std::vector<ScanResult> results;

    std::wstring line;
    while (std::getline(file, line))
    {
        size_t c1 = line.find(L','), c2 = line.find(L',', c1 + 1), c3 = line.find(L',', c2 + 1);
        if (c1 == std::wstring::npos || c2 == std::wstring::npos || c3 == std::wstring::npos)
            continue;

        std::wstring date = line.substr(c2 + 1, c3 - c2 - 1);
        size_t drive = line.find(L":\\");
        if (drive == std::wstring::npos || drive == 0) continue;

        size_t ps = drive - 1;
        size_t pe = line.find(L',', ps);
        if (pe == std::wstring::npos) continue;

        std::wstring path = line.substr(ps, pe - ps);

        if (futures.size() >= MAX_THREADS)
        {
            results.push_back(futures.front().get());
            futures.erase(futures.begin());
        }

        futures.emplace_back(std::async(std::launch::async, ProcessEntry, date, path));
    }

    for (auto& f : futures)
        results.push_back(f.get());

    results.erase(
        std::remove_if(results.begin(), results.end(),
            [](const ScanResult& r)
            {
                return (r.sig == SignatureStatus::NotFound &&
                    (g_only_instance || g_only_unsigned_cheat));
            }),
        results.end()
    );

    if (results.empty())
    {
        SetColor(C_YELLOW);
        std::cout << "\n[!] No entries matched the selected filters.\n";
        SetColor(C_GRAY);
        std::cout << "    Tip: Run again with both filters set to 'n'.\n\n";
        SetColor(C_DEFAULT);
        return;
    }

    std::sort(results.begin(), results.end(),
        [](const ScanResult& a, const ScanResult& b)
        {
            return a.exec_time > b.exec_time;
        });

    SetColor(C_CYAN);
    std::wcout << L"=============================================================\n";
    std::wcout << L"                  AMCACHEPARSER MADE BY DIFF               \n";
    std::wcout << L"=============================================================\n\n";
    SetColor(C_DEFAULT);

    for (const auto& r : results)
    {
        SetColor(C_WHITE);
        std::wcout << L"[+] Executed Time : ";
        SetColor(C_CYAN);
        std::wcout << TimeToLocalString(r.exec_time) << L"\n";

        SetColor(C_WHITE);
        std::wcout << L"    Path          : ";
        SetColor(C_DEFAULT);
        std::wcout << r.path << L"\n";

        SetColor(C_WHITE);
        std::wcout << L"    Signature     : ";
        SetColor(ColorForSignature(r.sig));
        std::wcout << SignatureStatusToString(r.sig) << L"\n";

        SetColor(C_WHITE);
        std::wcout << L"    YARA Match    : ";
        SetColor(r.yara ? C_RED : C_GREEN);
        std::wcout << (r.yara ? L"YES" : L"NO") << L"\n";

        SetColor(C_GRAY);
        std::wcout << L"-------------------------------------------------------------\n\n";
        SetColor(C_DEFAULT);
    }
}

void amcache_parser()
{
    wchar_t exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);

    amcache_entry ctx{};
    ctx.base_dir = exe;
    ctx.base_dir = ctx.base_dir.substr(0, ctx.base_dir.find_last_of(L"\\/"));
    ctx.work_dir = ctx.base_dir + L"\\AmCache";
    ctx.dotnet_installer = ctx.work_dir + L"\\windowsdesktop-runtime-9.0.11-win-x64.exe";

    CreateDirectoryW(ctx.work_dir.c_str(), nullptr);

    InitGenericRules();
    InitYara();

    download_file(
        L"https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/9.0.11/windowsdesktop-runtime-9.0.11-win-x64.exe",
        ctx.dotnet_installer
    );

    run_command(
        L"cmd.exe /c windowsdesktop-runtime-9.0.11-win-x64.exe /passive /norestart",
        ctx.work_dir
    );

    struct { std::wstring u, n; } deps[] =
    {
        { L"https://github.com/Orbdiff/AmcacheParser/releases/download/dependency/AmcacheParser.exe", L"AmcacheParser.exe" },
        { L"https://github.com/Orbdiff/AmcacheParser/releases/download/dependency/AmcacheParser.dll", L"AmcacheParser.dll" },
        { L"https://github.com/Orbdiff/AmcacheParser/releases/download/dependency/AmcacheParser.runtimeconfig.json", L"AmcacheParser.runtimeconfig.json" }
    };

    for (auto& d : deps)
        download_file(d.u, ctx.work_dir + L"\\" + d.n);

    run_command(
        L"cmd.exe /c AmcacheParser.exe -f \"C:\\Windows\\appcompat\\Programs\\Amcache.hve\" --csv .",
        ctx.work_dir
    );

    cleanup_csv_directory(ctx.work_dir);

    wchar_t opt{};
    std::wcout << L"[?] Show only Instance entries (y/n): ";
    std::wcin >> opt;
    g_only_instance = (opt == L'y' || opt == L'Y');

    std::wcout << L"[?] Show only Unsigned/Cheat (y/n): ";
    std::wcin >> opt;
    g_only_unsigned_cheat = (opt == L'y' || opt == L'Y');

    g_logon_time = GetCurrentUserLogonTime();

    if (g_logon_time)
    {
        SetColor(C_CYAN);
        std::cout << "\n[#] User Logon Time : ";
        SetColor(C_WHITE);
        std::cout << FormatTime(g_logon_time) << "\n\n";
        SetColor(C_DEFAULT);
    }

    parse_final_csv(ctx.work_dir);
    FinalizeYara();
}