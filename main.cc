// next update improvements: GUI :)

#include <windows.h>
#include <iostream>
#include <limits>

#include "amcache/_parse_amcache.h"

int wmain()
{
    amcache_parser();

    std::wcout << L"\nPress Enter to Exit...";
    std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');
    std::wcin.get();

    return 0;
}