//
// Created by lemur on 13/01/2024.
//
#include <iostream>
#include <fstream>
#include <vector>
#include <locale>
#include <codecvt>
#include <stdio.h>
#include <cstring>


#define FNV_OFFSET_BASIS	(const unsigned int) 2166136261
#define FNV_PRIME		(const unsigned int) 16777619


int main(int argc, char** argv) {

    std::vector<std::string> lines;
    std::vector<std::string>::iterator it;

    std::ifstream infile;
    std::string line;
    std::string k;

    infile.open(argv[1], std::ios::in);
    if (infile.is_open()) {

        while (std::getline(infile, line)) {
            lines.push_back(line);
        }
        infile.close();
    }

    int i = 0;
    int c = 0;
    auto hash = FNV_OFFSET_BASIS;

    for (it = lines.begin(); it != lines.end(); it++, i++) {
        k = lines[i];

        printf("#define ");
        std::string suffix = k.substr(k.length()-4, 4);

        if (strncmp(suffix.data(), ".DLL", 4) == 0 ||
            strncmp(suffix.data(), ".dll", 4) == 0)
        {
            std::wstring conv = std::wstring_convert<std::codecvt_utf8<wchar_t>>()
                    .from_bytes(k.data());

            for (auto j = 0; j < conv.length(); j++) {
               c = conv.data()[j];

               hash ^= c;
               hash *= FNV_PRIME;

               if (j <= conv.length() - 4) {
                   putchar(toupper(c));
               }
            }

            printf(" 0x%x\n", hash);
            conv.clear();
            continue;
        }


        for (auto j = 0; j < k.length(); j++) {
            c = k.data()[j];

            hash ^= c;
            hash *= FNV_PRIME;

            putchar(toupper(c));
        }
        printf(" 0x%x\n", hash);
    }
    return 0;
}
