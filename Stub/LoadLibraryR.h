
#ifndef _REFLECTIVEDLLINJECTION_LOADLIBRARYR_H
#define _REFLECTIVEDLLINJECTION_LOADLIBRARYR_H
#include "ReflectiveDLLInjection.h"

DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer );

HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength );

HANDLE WINAPI LoadRemoteLibraryR( HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter );

HMODULE GetKernel32BaseAddr1();
DWORD MyGetProcAddress1();
BOOL MyStrcmp1(char* src, const char*dst);

//必要的声明
typedef DWORD(WINAPI *fnGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName);

typedef HMODULE(WINAPI *fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);

typedef LPVOID(WINAPI *pfnVirtualAllocEx)(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);

typedef BOOL(WINAPI *pfnWriteProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
);

typedef BOOL(WINAPI *pfnVirtualProtect)(_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect);

typedef HANDLE(WINAPI *pfnCreateRemoteThread)(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
);
#endif
