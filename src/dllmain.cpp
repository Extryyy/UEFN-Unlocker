#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <cwchar>
#include <vector>
#include <memcury.h>

#define WIN32_LEAN_AND_MEAN

const char* logo =
R"( _____  _____  ________  ________  ____  _____
|_   _||_   _||_   __  ||_   __  ||_   \|_   _|
  | |    | |    | |_ \_|  | |_ \_|  |   \ | |
  | '    ' |    |  _| _   |  _|     | |\ \| |
   \ \__/ /    _| |__/ | _| |_     _| |_\   |_
    `.__.'    |_________|_____|   |_____|_____|
 ____________         __                 __
|_   _||_   _|       [  |               [  |  _
  | |    | | _ .--.   | |  .--.   .---.  | | / ] .---.  _ .--.
  | '    ' |[ `.-. |  | |/ .'`\ \/ /'`\] | '' < / /__\\[ `/'`\]
   \ \__/ /  | | | |  | || \__. || \__.  | |`\ \| \__., | |
    `.__.'  [___||__][___]'.__.' '.___.'[__|  \_]'.__.'[___]

)";

static auto currentProcess = GetCurrentProcess();

inline void writeMemory(const uintptr_t address, const std::vector<BYTE>& toWrite) {
    WriteProcessMemory(currentProcess, (LPVOID)address, toWrite.data(), toWrite.size(), NULL);
}

struct SectionView {
    uintptr_t base;
    size_t size;
};

static bool GetSectionView(HMODULE module, const char* sectionName, SectionView& outSection) {
    if (!module) return false;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        char name[9] = {};
        memcpy(name, section->Name, 8);
        if (strcmp(name, sectionName) == 0) {
            outSection.base = reinterpret_cast<uintptr_t>(module) + section->VirtualAddress;
            outSection.size = section->Misc.VirtualSize;
            return true;
        }
    }

    return false;
}

static uintptr_t FindWideStringInModule(HMODULE module, const wchar_t* value) {
    if (!module || !value) return 0;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto moduleBase = reinterpret_cast<uintptr_t>(module);
    const auto moduleSize = static_cast<size_t>(nt->OptionalHeader.SizeOfImage);

    const auto patternBytes = reinterpret_cast<const BYTE*>(value);
    const size_t patternSize = (wcslen(value) + 1) * sizeof(wchar_t);
    if (patternSize == 0 || moduleSize < patternSize) return 0;

    const auto* scan = reinterpret_cast<const BYTE*>(moduleBase);
    for (size_t i = 0; i <= moduleSize - patternSize; ++i) {
        if (memcmp(scan + i, patternBytes, patternSize) == 0) {
            return moduleBase + i;
        }
    }

    return 0;
}

static uintptr_t FindRipLeaReference(uintptr_t textBase, size_t textSize, uintptr_t targetAddress) {
    if (!textBase || textSize < 7) return 0;

    auto* bytes = reinterpret_cast<const BYTE*>(textBase);
    for (size_t i = 0; i <= textSize - 7; ++i) {
        // 48 8D /r with modrm indicating [rip+disp32]
        if (bytes[i] != 0x48 || bytes[i + 1] != 0x8D || (bytes[i + 2] & 0xC7) != 0x05) {
            continue;
        }

        const int32_t displacement = *reinterpret_cast<const int32_t*>(bytes + i + 3);
        const auto instruction = textBase + i;
        const auto resolved = instruction + 7 + displacement;
        if (resolved == targetAddress) {
            return instruction;
        }
    }

    return 0;
}

static uintptr_t FindNearbyPattern(uintptr_t center, uintptr_t searchMin, uintptr_t searchMax, const std::vector<BYTE>& pattern) {
    if (!center || pattern.empty()) return 0;

    const auto begin = (center > searchMin) ? center : searchMin;
    const auto end = searchMax;
    if (begin >= end || end - begin < pattern.size()) return 0;

    auto* bytes = reinterpret_cast<const BYTE*>(begin);
    const auto scanSize = static_cast<size_t>(end - begin);

    for (size_t i = 0; i <= scanSize - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (bytes[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            return begin + i;
        }
    }

    return 0;
}

static uintptr_t FindCannotModifyCookedAssetsPatchAddress(HMODULE module, const wchar_t* markerString) {
    const auto markerAddress = FindWideStringInModule(module, markerString);
    if (!markerAddress) return 0;

    SectionView textSection {};
    if (!GetSectionView(module, ".text", textSection)) return 0;

    const auto leaRef = FindRipLeaReference(textSection.base, textSection.size, markerAddress);
    if (!leaRef) return 0;

    const auto searchStart = leaRef;
    const auto searchEnd = min(textSection.base + textSection.size, leaRef + 0x800);

    uintptr_t xorPatchAddress = FindNearbyPattern(searchStart, searchStart, searchEnd, { 0x32, 0xC0 }); // xor al, al
    if (!xorPatchAddress) {
        xorPatchAddress = FindNearbyPattern(searchStart, searchStart, searchEnd, { 0x31, 0xC0 }); // xor eax, eax
    }

    return xorPatchAddress;
}

void Main(const HMODULE hModule) {
    AllocConsole();
    SetConsoleTitleA("UEFN Unlocker by gamerbross v1.3");
    FILE* pFile;
    freopen_s(&pFile, ("CONOUT$"), "w", stdout);

    std::cout << logo << "Made by @gamerbross_ on X/Twitter!\n";

    // rel16/32
    static const std::vector<BYTE> jeBytes  = { 0x0F, 0x84 };
    static const std::vector<BYTE> jneBytes = { 0x0F, 0x85 };
    static const std::vector<BYTE> jlBytes  = { 0x0F, 0x8C };

    static const std::vector<BYTE> jnoBytes = { 0x0F, 0x81 }; // using jump if not overflow cus easier and should always work
    static const std::vector<BYTE> nopBytes = { 0x90, 0x90 };

    // rel8
    static const std::vector<BYTE> xorByte  = { 0x32 };
    static const std::vector<BYTE> je8Byte  = { 0x74 };
    static const std::vector<BYTE> jb8Byte  = { 0x72 };
    static const std::vector<BYTE> jmp8Byte = { 0x71 };

    const wchar_t* cookedAssetErrorString = L"Error_CannotModifyCookedAssets";
    HMODULE targetModule = GetModuleHandleA("Valkyrie.dll");
    bool usingValkyrieModule = false;

    if (targetModule && !FindWideStringInModule(targetModule, cookedAssetErrorString)) {
        targetModule = nullptr;
    }
    else if (targetModule) {
        usingValkyrieModule = true;
    }

    if (!targetModule) {
        targetModule = GetModuleHandleA(nullptr);
    }

    std::cout << "[+] Cooked asset check module: " << (usingValkyrieModule ? "Valkyrie.dll" : "Main module") << "\n";

    auto cookedAssetPatchAddress = FindCannotModifyCookedAssetsPatchAddress(targetModule, cookedAssetErrorString);
    MemcuryAssertM(cookedAssetPatchAddress, "AOB scan failed for Error_CannotModifyCookedAssets patch!");

    writeMemory(cookedAssetPatchAddress, { 0xB0, 0x01 }); // mov al, 1

    auto AssetCantBeEdited = Memcury::Scanner::FindStringRef(L"AssetCantBeEdited", false);
    if (!AssetCantBeEdited.Get()) AssetCantBeEdited = Memcury::Scanner::FindStringRef(L"NotifyBlockedByCookedAsset", false);

    MemcuryAssertM(AssetCantBeEdited.Get(), "Unable to Edit Cooked asset could not be found!");

    writeMemory(AssetCantBeEdited
        .ScanFor(xorByte).Get(),
        { 0xB3, 0x01 } // mov bl, 1
    );

    writeMemory(
        Memcury::Scanner::FindStringRef(L"Folder '{0}' is read only and its contents cannot be edited")
        .ScanFor(jneBytes, false).Get(),
        jnoBytes
    );
    writeMemory(
        Memcury::Scanner::FindStringRef(L"Alias asset '{0}' is in a read only folder. Unable to edit read only assets.")
        .ScanFor(jeBytes, false).Get(),
        jnoBytes
    );

    writeMemory(
        Memcury::Scanner::FindStringRef(L"CannotDuplicateCooked").FindFunctionBoundary().ScanFor(jlBytes).Get(),
        jnoBytes
    );

    writeMemory(
        Memcury::Scanner::FindStringRef(L"Package is cooked or missing editor data\n").ScanFor(je8Byte, false).Get(),
        jmp8Byte
    );

    std::cout << "Done!\n";
    std::cout << "Press F6 to close this window.\n";

    while (!GetAsyncKeyState(VK_F6)) Sleep(100);

    fclose(stdout);
    if (pFile) fclose(pFile);
    FreeConsole();

    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(const HMODULE hModule, const DWORD dwReason, const LPVOID lpReserved)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (auto thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Main, hModule, 0, NULL))
            CloseHandle(thread);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }


    return TRUE;
}
