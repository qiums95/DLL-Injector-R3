#include "injector.h"
#include <iostream>
#include <string>
#include <vector>

int main() {
    DWORD PID = 0;
    std::vector<UNLOAD_DATA> injectedList;

    std::wcout << L"=========================================" << std::endl;
    std::wcout << L"           Manual Map Injector           " << std::endl;
    std::wcout << L"=========================================\n" << std::endl;
    std::wcout << L"[DLLinject] Please enter the target Process ID (PID):" << std::endl;
    std::wcout << L"> ";
    std::wcin >> PID;
    std::wcin.ignore();

    if (std::wcin.fail() || PID == 0) {
        std::wcout << L"[DLLinject] Error: Invalid PID entered!" << std::endl;
        system("pause");
        return -1;
    }

    while (true) {
        system("cls");

        std::wcout << L"=========================================" << std::endl;
        std::wcout << L"  Target PID: " << PID << L"  |  Injected: " << injectedList.size() << std::endl;
        std::wcout << L"=========================================" << std::endl;
        std::wcout << L"  1. Inject DLL" << std::endl;
        std::wcout << L"  2. Unload DLL" << std::endl;
        std::wcout << L"  3. Change PID" << std::endl;
        std::wcout << L"  4. Exit" << std::endl;
        std::wcout << L"-----------------------------------------" << std::endl;
        std::wcout << L"> ";

        int choice = 0;
        std::wcin >> choice;
        std::wcin.ignore();

        if (std::wcin.fail()) {
            std::wcin.clear();
            std::wcin.ignore(10000, L'\n');
            continue;
        }

        // ©¤©¤ 1. ×¢Èë ©¤©¤
        if (choice == 1) {
            std::wstring dllPath;
            std::wcout << L"\n[DLLinject] DLL path (drag & drop supported):" << std::endl;
            std::wcout << L"> ";
            std::getline(std::wcin, dllPath);

            if (!dllPath.empty() && dllPath.front() == L'\"' && dllPath.back() == L'\"') {
                dllPath = dllPath.substr(1, dllPath.length() - 2);
            }

            if (dllPath.empty()) {
                std::wcout << L"[DLLinject] Error: Path cannot be empty!" << std::endl;
                std::wcout << L"\nPress Enter to continue...";
                std::wcin.get();
                continue;
            }

            UNLOAD_DATA ud = {};
            if (!InjectFromFile(PID, dllPath.c_str(), &ud)) {
                std::wcout << L"[DLLinject] X Injection failed." << std::endl;
            }
            else {
                injectedList.push_back(ud);
                std::wcout << L"[DLLinject] >>> OK! Base: 0x"
                    << std::hex << (uintptr_t)ud.pBase << std::dec
                    << L", Size: " << ud.dwSizeOfImage << std::endl;
            }
            std::wcout << L"\nPress Enter to continue...";
            std::wcin.get();
        }
        // ©¤©¤ 2. Ð¶ÔØ ©¤©¤
        else if (choice == 2) {
            if (injectedList.empty()) {
                std::wcout << L"[DLLinject] No DLLs to unload." << std::endl;
                std::wcout << L"\nPress Enter to continue...";
                std::wcin.get();
                continue;
            }

            std::wcout << L"\n[DLLinject] Select DLL to unload:" << std::endl;
            for (size_t i = 0; i < injectedList.size(); ++i) {
                std::wcout << L"  " << (i + 1) << L". Base: 0x"
                    << std::hex << (uintptr_t)injectedList[i].pBase << std::dec
                    << L"  Size: " << injectedList[i].dwSizeOfImage << std::endl;
            }
            std::wcout << L"  0. Cancel" << std::endl;
            std::wcout << L"> ";

            size_t idx = 0;
            std::wcin >> idx;
            std::wcin.ignore();

            if (std::wcin.fail() || idx == 0) {
                std::wcin.clear();
                std::wcin.ignore(10000, L'\n');
                continue;
            }

            if (idx > injectedList.size()) {
                std::wcout << L"[DLLinject] Invalid index." << std::endl;
                std::wcout << L"\nPress Enter to continue...";
                std::wcin.get();
                continue;
            }

            const UNLOAD_DATA& ud = injectedList[idx - 1];
            std::wcout << L"[DLLinject] Unloading base 0x"
                << std::hex << (uintptr_t)ud.pBase << std::dec << L" ..." << std::endl;

            if (!UnloadDll(PID, ud)) {
                std::wcout << L"[DLLinject] X Unload failed." << std::endl;
            }
            else {
                injectedList.erase(injectedList.begin() + (idx - 1));
                std::wcout << L"[DLLinject] >>> Unloaded successfully." << std::endl;
            }
            std::wcout << L"\nPress Enter to continue...";
            std::wcin.get();
        }
        // ©¤©¤ 3. ÇÐ»» PID ©¤©¤
        else if (choice == 3) {
            if (!injectedList.empty()) {
                std::wcout << L"\n[!] Switching PID will clear " << injectedList.size()
                    << L" injection record(s). Continue? (y/n): ";
                wchar_t c = 0;
                std::wcin >> c;
                std::wcin.ignore();
                if (c != L'y' && c != L'Y') {
                    continue;
                }
            }

            injectedList.clear();

            std::wcout << L"\n[DLLinject] Enter new PID:" << std::endl;
            std::wcout << L"> ";
            std::wcin >> PID;
            std::wcin.ignore();

            if (std::wcin.fail() || PID == 0) {
                std::wcin.clear();
                std::wcin.ignore(10000, L'\n');
                std::wcout << L"[DLLinject] Invalid PID, keeping old." << std::endl;
                std::wcout << L"\nPress Enter to continue...";
                std::wcin.get();
            }
            else {
                std::wcout << L"[DLLinject] PID changed to " << PID << L"." << std::endl;
                std::wcout << L"\nPress Enter to continue...";
                std::wcin.get();
            }
        }
        // ©¤©¤ 4. ÍË³ö ©¤©¤
        else if (choice == 4) {
            std::wcout << L"[DLLinject] Bye." << std::endl;
            break;
        }
    }

    return 0;
}