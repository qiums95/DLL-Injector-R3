#include "injector.h"

#ifndef _DEBUG
#define LOG(text, ...) 
#else
#define LOG(text, ...) printf("[DLLinject] " text, ##__VA_ARGS__)
#endif

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		LOG("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

bool InjectFromMemory(DWORD PID, BYTE* pSrcData, SIZE_T FileSize) {
	if (!pSrcData || FileSize == 0) {
		LOG("Invalid memory data.\n");
		return false;
	}

	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		CloseHandle(hToken);
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc) {
		LOG("OpenProcess failed: 0x%X\n", GetLastError());
		return false;
	}

	if (!IsCorrectTargetArchitecture(hProc)) {
		LOG("Invalid Process Architecture.\n");
		CloseHandle(hProc);
		return false;
	}

	LOG("Mapping DLL from memory...\n");
	if (!ManualMapDll(hProc, PID, pSrcData, FileSize, true, true, true, true, DLL_PROCESS_ATTACH, 0)) {
		LOG("Error while mapping.\n");
		CloseHandle(hProc);
		return false;
	}

	CloseHandle(hProc);
	LOG("Injection successfully completed!\n");
	return true;
}

bool InjectFromFile(DWORD PID, const wchar_t* dllPath) {
	if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
		LOG("Dll file doesn't exist\n");
		return false;
	}

	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);
	if (File.fail()) {
		LOG("Opening the file failed: %X\n", (DWORD)File.rdstate());
		return false;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		LOG("Filesize invalid (Too small).\n");
		File.close();
		return false;
	}

	BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData) {
		LOG("Can't allocate memory for dll file.\n");
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	bool bSuccess = InjectFromMemory(PID, pSrcData, (SIZE_T)FileSize);
	delete[] pSrcData;

	return bSuccess;
}

bool ManualMapDll(HANDLE hProc, DWORD PID, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved) {
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
		LOG("Invalid file\n");
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != CURRENT_ARCH) {
		LOG("Invalid platform\n");
		return false;
	}

	LOG("File ok\n");

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {
		LOG("Target process memory allocation failed (ex) 0x%X\n", GetLastError());
		return false;
	}

	DWORD oldp = 0;
	VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
	SEHExceptionSupport = false;
#endif
	data.pbase = pTargetBase;
	data.fdwReasonParam = fdwReason;
	data.reservedParam = lpReserved;
	data.SEHSupport = SEHExceptionSupport;


	//File header
	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) { //only first 0x1000 bytes for the header
		LOG("Can't write file header 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				LOG("Can't map sections: 0x%x\n", GetLastError());
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	//Mapping params
	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		LOG("Target process mapping allocation failed (ex) 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		LOG("Can't write mapping 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	//Shell code
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		LOG("Memory shellcode allocation failed (ex) 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
		LOG("Can't write shellcode 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	LOG("Mapped DLL at %p\n", pTargetBase);
	LOG("Mapping info at %p\n", MappingDataAlloc);
	LOG("Shell code at %p\n", pShellcode);

	LOG("Data allocated\n");

#ifdef _DEBUG
	LOG("My shellcode pointer %p\n", Shellcode);
	LOG("Target point %p\n", pShellcode);
	system("pause");
#endif
	/*
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
	if (!hThread) {
		LOG("Thread creation failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);

	LOG("Thread created at: %p, waiting for return...\n", pShellcode);
	*/

	HANDLE hThread = NULL;
	DWORD dwTID = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);

		if (Thread32First(hSnap, &te)) {
			do {
				if (te.th32OwnerProcessID == PID && te.th32ThreadID != GetCurrentThreadId()) {

					hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
					if (hThread) {
						dwTID = te.th32ThreadID;
						break;
					}
				}
			} while (Thread32Next(hSnap, &te));
		}
		CloseHandle(hSnap);
	}

	if (!hThread) {
		LOG("Thread Hijacking Failed: No suitable thread found or access denied.\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	if (SuspendThread(hThread) == (DWORD)-1) {
		LOG("SuspendThread failed: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		CloseHandle(hThread);
		return false;
	}

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(hThread, &ctx)) {
		LOG("GetThreadContext failed: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		ResumeThread(hThread);
		CloseHandle(hThread);
		return false;
	}

	void* pStub = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pStub) {
		LOG("Stub allocation failed.\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		ResumeThread(hThread);
		CloseHandle(hThread);
		return false;
	}

#ifdef _WIN64
	BYTE Stub[] = {
		0x48, 0x83, 0xEC, 0x08,
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
		0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
		0x9C,
		0x55, 0x48, 0x8B, 0xEC,
		0x48, 0x83, 0xE4, 0xF0,
		0x48, 0x83, 0xEC, 0x20,
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xD0,
		0x48, 0x8B, 0xE5, 0x5D,
		0x9D,
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,
		0xC3
	};

	DWORD64 oldRip = ctx.Rip;
	DWORD loRip = (DWORD)(oldRip & 0xFFFFFFFF);
	DWORD hiRip = (DWORD)((oldRip >> 32) & 0xFFFFFFFF);

	memcpy(Stub + 7, &loRip, sizeof(DWORD));
	memcpy(Stub + 15, &hiRip, sizeof(DWORD));
	memcpy(Stub + 45, &MappingDataAlloc, sizeof(DWORD64));
	memcpy(Stub + 55, &pShellcode, sizeof(DWORD64));

	ctx.Rip = (DWORD64)pStub;
#else
	BYTE Stub[] = {
		0x83, 0xEC, 0x04,
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
		0x50, 0x51, 0x52,
		0x9C,
		0x68, 0x00, 0x00, 0x00, 0x00,
		0xB8, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xD0,
		0x9D,
		0x5A, 0x59, 0x58,
		0xC3
	};

	DWORD oldEip = ctx.Eip;
	memcpy(Stub + 6, &oldEip, sizeof(DWORD));
	memcpy(Stub + 15, &MappingDataAlloc, sizeof(DWORD));
	memcpy(Stub + 20, &pShellcode, sizeof(DWORD));

	ctx.Eip = (DWORD)pStub;
#endif

	WriteProcessMemory(hProc, pStub, Stub, sizeof(Stub), nullptr);
	SetThreadContext(hThread, &ctx);
	ResumeThread(hThread);

	LOG("Thread Hijacked successfully! Target TID: %d, Waiting for C++ payload execution...\n", dwTID);

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		DWORD exitcode = 0;
		GetExitCodeProcess(hProc, &exitcode);
		if (exitcode != STILL_ACTIVE) {
			LOG("Process crashed, exit code: %d\n", exitcode);
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pStub, 0, MEM_RELEASE);
			CloseHandle(hThread);
			return false;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) {
			LOG("Wrong mapping ptr\n");
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pStub, 0, MEM_RELEASE);
			CloseHandle(hThread);
			return false;
		}

		Sleep(10);
	}

	LOG("Payload finished! Waiting for thread to safely return...\n");

	CONTEXT checkCtx;
	checkCtx.ContextFlags = CONTEXT_CONTROL;
	while (true) {
		if (SuspendThread(hThread) == (DWORD)-1) {
			LOG("Target thread died during execution! Breaking loop.\n");
			break;
		}
		GetThreadContext(hThread, &checkCtx);
		ResumeThread(hThread);

#ifdef _WIN64
		if (checkCtx.Rip < (DWORD64)pStub || checkCtx.Rip >= ((DWORD64)pStub + 0x1000)) {
			break;
		}
#else
		if (checkCtx.Eip < (DWORD)pStub || checkCtx.Eip >= ((DWORD)pStub + 0x1000)) {
			break;
		}
#endif
		Sleep(1);
	}

	CloseHandle(hThread);

	LOG("Thread safely returned to original flow. Cleaning up...\n");

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
	if (emptyBuffer == nullptr) {
		LOG("Unable to allocate memory\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pStub, 0, MEM_RELEASE);
		return false;
	}
	memset(emptyBuffer, 0, 1024 * 1024 * 20);

	//CLEAR PE HEAD
	if (ClearHeader) {
		if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
			LOG("WARNING!: Can't clear HEADER\n");
		}
	}
	//END CLEAR PE HEAD


	if (ClearNonNeededSections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
					strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
					strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
					LOG("Processing %s removal\n", pSectionHeader->Name);
					if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
						LOG("Can't clear section %s: 0x%x\n", pSectionHeader->Name, GetLastError());
					}
				}
			}
		}
	}

	if (AdjustProtections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				DWORD old = 0;
				DWORD newP = PAGE_READONLY;

				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
					newP = PAGE_READWRITE;
				}
				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
					newP = PAGE_EXECUTE_READ;
				}
				if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
					LOG("section %s set as %lX\n", (char*)pSectionHeader->Name, newP);
				}
				else {
					LOG("FAIL: section %s not set as %lX\n", (char*)pSectionHeader->Name, newP);
				}
			}
		}
		DWORD old = 0;
		VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
	}

	if (!WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr)) {
		LOG("WARNING: Can't clear shellcode\n");
	}
	if (!WriteProcessMemory(hProc, pStub, emptyBuffer, 0x1000, nullptr)) {
		LOG("WARNING: Can't clear Stub\n");
	}
	if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
		LOG("WARNING: can't release shell code memory\n");
	}
	if (!VirtualFreeEx(hProc, pStub, 0, MEM_RELEASE)) {
		LOG("WARNING: can't release Stub memory\n");
	}
	if (!VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
		LOG("WARNING: can't release mapping data memory\n");
	}
	free(emptyBuffer);
	return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

#ifdef _WIN64

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

#endif

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
