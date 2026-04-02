#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cwchar>
#include <vector>
#include <psapi.h>
#include <memcury.h>

#pragma comment(lib, "psapi.lib")

#define WIN32_LEAN_AND_MEAN

const char* logo =
R"(UEFN Unlocker By Extry

)";

static auto currentProcess = GetCurrentProcess();

inline void writeMemory(const uintptr_t address, const std::vector<BYTE>& toWrite) {
    if (address == 0) return;

    DWORD oldProtect = 0;
    if (VirtualProtect(reinterpret_cast<LPVOID>(address), toWrite.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        WriteProcessMemory(currentProcess, reinterpret_cast<LPVOID>(address), toWrite.data(), toWrite.size(), nullptr);
        VirtualProtect(reinterpret_cast<LPVOID>(address), toWrite.size(), oldProtect, &oldProtect);
    }
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

static uintptr_t FindWideStringProcessWide(const wchar_t* value, HMODULE& outModule) {
    outModule = nullptr;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(currentProcess, hMods, sizeof(hMods), &cbNeeded)) return 0;

    const int count = cbNeeded / sizeof(HMODULE);
    for (int i = 0; i < count; ++i) {
        HMODULE hMod = hMods[i];
        uintptr_t addr = FindWideStringInModule(hMod, value);
        if (addr) {
            outModule = hMod;
            return addr;
        }
    }
    return 0;
}

// ===================================================================
// AGGRESSIVE RIP-RELATIVE REFERENCE FINDER
// ===================================================================
static uintptr_t FindRipLeaReference(uintptr_t textBase, size_t textSize, uintptr_t targetAddress) {
    if (!textBase || textSize < 6) return 0;

    auto* bytes = reinterpret_cast<const BYTE*>(textBase);
    for (size_t i = 0; i <= textSize - 7; ++i) {
        // REX + LEA [rip+disp32]
        if ((bytes[i] & 0xF0) == 0x40 && bytes[i + 1] == 0x8D && (bytes[i + 2] & 0xC7) == 0x05) {
            const int32_t disp = *reinterpret_cast<const int32_t*>(bytes + i + 3);
            if (textBase + i + 7 + disp == targetAddress) return textBase + i;
        }
        // LEA [rip+disp32] no REX
        if (bytes[i] == 0x8D && (bytes[i + 1] & 0xC7) == 0x05) {
            const int32_t disp = *reinterpret_cast<const int32_t*>(bytes + i + 2);
            if (textBase + i + 6 + disp == targetAddress) return textBase + i;
        }
        // REX + MOV reg, [rip+disp32]
        if ((bytes[i] & 0xF0) == 0x40 && bytes[i + 1] == 0x8B && (bytes[i + 2] & 0xC7) == 0x05) {
            const int32_t disp = *reinterpret_cast<const int32_t*>(bytes + i + 3);
            if (textBase + i + 7 + disp == targetAddress) return textBase + i;
        }
    }
    return 0;
}

// ===================================================================
// NEW: AGGRESSIVE STRING REFERENCE FINDER (used for AssetCantBeEdited)
//     Tries Memcury first, then falls back to process-wide raw string + reference scan
// ===================================================================
static Memcury::Scanner FindStringRefAggressive(const wchar_t* str) {
    // Try normal Memcury first (fast path for strings in main module)
    auto scanner = Memcury::Scanner::FindStringRef(str, false);
    if (scanner.Get()) return scanner;

    // Fallback: process-wide raw string search + reference finder
    HMODULE mod = nullptr;
    const auto strAddr = FindWideStringProcessWide(str, mod);
    if (!strAddr || !mod) return Memcury::Scanner(0);

    SectionView text{};
    if (!GetSectionView(mod, ".text", text)) return Memcury::Scanner(0);

    const auto ref = FindRipLeaReference(text.base, text.size, strAddr);
    if (!ref) return Memcury::Scanner(0);

    return Memcury::Scanner(ref);
}

// ===================================================================
// BRUTE-FORCE PATCH FOR Error_CannotModifyCookedAssets (already working)
// ===================================================================
static uintptr_t FindCannotModifyCookedAssetsPatchAddress() {
    std::cout << "[+] Searching for Error_CannotModifyCookedAssets (PROCESS-WIDE ultra-aggressive mode)...\n";

    HMODULE stringModule = nullptr;
    const auto markerAddress = FindWideStringProcessWide(L"Error_CannotModifyCookedAssets", stringModule);

    if (!markerAddress) {
        std::cout << "[-] String NOT found in ANY module → falling back to Memcury...\n";
        auto refScanner = Memcury::Scanner::FindStringRef(L"Error_CannotModifyCookedAssets", false);
        if (!refScanner.Get()) {
            std::cout << "[-] Memcury FindStringRef also failed.\n";
            return 0;
        }
        auto funcBoundary = refScanner.FindFunctionBoundary();
        return funcBoundary.Get();
    }

    std::cout << "[+] String found at 0x" << std::hex << markerAddress 
              << std::dec << " (module: 0x" << std::hex << reinterpret_cast<uintptr_t>(stringModule) << std::dec << ")\n";

    SectionView textSection {};
    if (!GetSectionView(stringModule, ".text", textSection)) return 0;

    const auto leaRef = FindRipLeaReference(textSection.base, textSection.size, markerAddress);
    if (!leaRef) return 0;

    std::cout << "[+] Reference (LEA/MOV) found at 0x" << std::hex << leaRef << std::dec << "\n";

    Memcury::Scanner refScanner(leaRef);
    auto funcBoundary = refScanner.FindFunctionBoundary();
    return funcBoundary.Get();
}

void Main(const HMODULE hModule) {
    AllocConsole();
    SetConsoleTitleA("UEFN Unlocker By Extry");
    FILE* pFile;
    freopen_s(&pFile, ("CONOUT$"), "w", stdout);

    std::cout << logo << "Made by Extry to save the fishes\n";

    static const std::vector<BYTE> jeBytes  = { 0x0F, 0x84 };
    static const std::vector<BYTE> jneBytes = { 0x0F, 0x85 };
    static const std::vector<BYTE> jlBytes  = { 0x0F, 0x8C };
    static const std::vector<BYTE> jnoBytes = { 0x0F, 0x81 };
    static const std::vector<BYTE> nopBytes = { 0x90, 0x90 };
    static const std::vector<BYTE> xorByte  = { 0x32 };
    static const std::vector<BYTE> je8Byte  = { 0x74 };
    static const std::vector<BYTE> jb8Byte  = { 0x72 };
    static const std::vector<BYTE> jmp8Byte = { 0x71 };

    HMODULE targetModule = GetModuleHandleA("Valkyrie.dll");
    bool usingValkyrieModule = false;

    if (targetModule && !FindWideStringInModule(targetModule, L"Error_CannotModifyCookedAssets")) {
        targetModule = nullptr;
    } else if (targetModule) {
        usingValkyrieModule = true;
    }

    if (!targetModule) targetModule = GetModuleHandleA(nullptr);

    std::cout << "[+] Cooked asset check module: " << (usingValkyrieModule ? "Valkyrie.dll" : "Main module") << "\n";

    // ==================== Error_CannotModifyCookedAssets (already succeeded) ====================
    auto cookedAssetPatchAddress = FindCannotModifyCookedAssetsPatchAddress();
    MemcuryAssertM(cookedAssetPatchAddress, "AOB scan failed for Error_CannotModifyCookedAssets patch!");

    writeMemory(cookedAssetPatchAddress, { 0xB0, 0x01, 0xC3 }); // mov al, 1; ret
    std::cout << "[+] Brute-force return-true patch applied to Error_CannotModifyCookedAssets!\n";

    // ==================== FIXED: AssetCantBeEdited (now uses the same aggressive method) ====================
    std::cout << "[+] Searching for AssetCantBeEdited / NotifyBlockedByCookedAsset (aggressive mode)...\n";

    auto AssetCantBeEdited = FindStringRefAggressive(L"AssetCantBeEdited");
    if (!AssetCantBeEdited.Get()) {
        AssetCantBeEdited = FindStringRefAggressive(L"NotifyBlockedByCookedAsset");
    }

    MemcuryAssertM(AssetCantBeEdited.Get(), "Unable to Edit Cooked asset could not be found!");

    writeMemory(AssetCantBeEdited.ScanFor(xorByte).Get(), { 0xB3, 0x01 });
    std::cout << "[+] mov bl, 1 patch applied to AssetCantBeEdited / NotifyBlockedByCookedAsset!\n";

    // ==================== Remaining patches (unchanged) ====================
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