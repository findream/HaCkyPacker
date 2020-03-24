#include "Stub.h"
//参考文章：https://bbs.pediy.com/thread-17624.htm

//************************************************************
//AntiDumpByImageSize:修改ImageSize来antidump
//typedef struct _LDR_MODULE 
//{
//	LIST_ENTRY InLoadOrderModuleList;
//	LIST_ENTRY InMemoryOrderModuleList;
//	LIST_ENTRY InInitializationOrderModuleList;
//	PVOID BaseAddress;
//	PVOID EntryPoint;
//	ULONG SizeOfImage;                   //ImageSize
//	UNICODE_STRING FullDllName;
//	UNICODE_STRING BaseDllName;
//	ULONG Flags;
//	SHORT LoadCount;
//	SHORT TlsIndex;
//	LIST_ENTRY HashTableEntry;
//	ULONG TimeDateStamp;
//} LDR_MODULE, *PLDR_MODULE;
//************************************************************
void AntiDumpByImageSize()
{
	_asm
	{
		mov eax, fs:[0x30]                //PEB
		mov eax, [eax + 0x0C]             //_PEB_LDR_DATA
		mov eax, [eax + 0x0C]             //_LDR_MODULE
		mov dword ptr[eax + 0x20], 1234
	}
}

void AntiDumpByHideProcess()
{

}

//************************************************************
//AntiDumpByMemory：将PE头设置为不可访问属性
//ChildFunc:GetKernel32BaseAddr
          //MyGetProcAddress
//************************************************************
void AntiDumpByMemory()
{
	HMODULE hKernel32 = GetKernel32BaseAddr();
	fnGetProcAddress g_pfnGetProcAddress =
		(fnGetProcAddress)MyGetProcAddress();
	fnGetModuleHandleA MyGetModuleHandle =
		(fnGetModuleHandleA)g_pfnGetProcAddress(hKernel32, "GetModuleHandleA");
	fnVirtualProtect MyVirtualProtect = 
		(fnVirtualProtect)g_pfnGetProcAddress(hKernel32, "VirtualProtect");

	LPBYTE lpBaseAddress = (LPBYTE)MyGetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pImageNtHeaders = 
		(PIMAGE_NT_HEADERS)((DWORD)lpBaseAddress + pImageDosHeader->e_lfanew);

	DWORD dwImageBase = pImageNtHeaders->OptionalHeader.ImageBase;
	//DWORD dwImageSize = pImageNtHeaders->OptionalHeader.SizeOfImage;

	//利用VirtualProtect设置不可读取的权限
	DWORD dwOld = 0;
	MyVirtualProtect((LPBYTE)dwImageBase, 1000, PAGE_NOACCESS, &dwOld);
	
}

