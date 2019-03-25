#include <stdio.h>
#include <windows.h>

DWORD WINAPI ThreadProc(PVOID p)
{
    MessageBox(NULL, L"Message from injected code!", L"Message", MB_ICONINFORMATION);
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc != 2){
        printf("\n\tUsage: %s [PID]\n\n", argv[0]);
        return -1;
    }

    printf("\nOpening %s process\n", argv[1]);

    HANDLE targetProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE,
        strtoul(argv[1], NULL, 0)
    );

    if (!targetProcess) {
        printf("Unable to open process: (%u)\n", GetLastError());
        return -1;
    }

    PVOID imageBase = GetModuleHandle(NULL);
    printf("current image base is : %#x\n", imageBase);

    PIMAGE_DOS_HEADER curProcDosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS curProcNTHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + curProcDosHeader->e_lfanew);

    printf("allocating memory in the target process\n");
    PVOID mem = VirtualAllocEx(targetProcess, NULL, curProcNTHeaders->OptionalHeader.SizeOfImage, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("Unable to allocate memory in the target process: (%u)\n", GetLastError());
        CloseHandle(targetProcess);
        return 0;
    }
    printf("memory allocated at %#x\n", mem);

    PVOID buffer = VirtualAlloc(NULL, curProcNTHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(buffer, imageBase, curProcNTHeaders->OptionalHeader.SizeOfImage);

    printf("Relocating image\n");
    
    PIMAGE_BASE_RELOCATION curProcReloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)buffer +
        curProcNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    ULONG delta = (ULONG)mem - (ULONG)imageBase;
    printf("the delta is: %#x\n", delta);

    ULONG count, i, *p;
    while (curProcReloc->VirtualAddress) {
        if (curProcReloc->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
            count = (curProcReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            PUSHORT typeOffset = (PUSHORT)(curProcReloc + 1);

            for (i = 0; i < count; i++) {
                if (typeOffset[i]){
                    p = (PULONG)((PUCHAR)buffer + curProcReloc->VirtualAddress + (typeOffset[i] & 0xfff));
                    *p += delta;
                }
            }
        }
        curProcReloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)curProcReloc + curProcReloc->SizeOfBlock);
    }

    printf("writing the relocated image into the target process\n");
    if (!WriteProcessMemory(targetProcess, mem, buffer, curProcNTHeaders->OptionalHeader.SizeOfImage, NULL)) {
        printf("Error: unable to write process memory (%u)\n", GetLastError());
        VirtualFreeEx(targetProcess, mem, 0, MEM_RELEASE);
        CloseHandle(targetProcess);
        return -1;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    
    printf("Creating thread in target process\n");
    HANDLE newThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PUCHAR)ThreadProc + delta), NULL, 0, NULL);
    if (!newThread) {
        printf("Unable to create remote thread in target process: (%u)\n", GetLastError());
        VirtualFreeEx(targetProcess, mem, 0, MEM_RELEASE);
        CloseHandle(targetProcess);
        return -1;
    }

    printf("waiting for the thread to terminate...\n");
    WaitForSingleObject(newThread, INFINITE);

    printf("Thread terminated\n");

    VirtualFreeEx(targetProcess, mem, 0, MEM_RELEASE);
    CloseHandle(targetProcess);
    return 0;
}