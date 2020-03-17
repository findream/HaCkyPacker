#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#pragma warning(disable:4996)


//需要导出的SHELL_DATA结构体，里面包含着与PE相关的重要成员，用于与Pack部分的交换
typedef struct _SHELL_DATA
{
	
	DWORD					dwImageSize;		//镜像大小
	PIMAGE_DOS_HEADER		pDosHeader;		//Dos头
	PIMAGE_NT_HEADERS		pNtHeader;		//NT头
	PIMAGE_OPTIONAL_HEADER  pOptionalHeader;  //可选头
	PIMAGE_SECTION_HEADER	pSecHeader;		//第一个SECTION结构体指针
	DWORD					dwImageBase;    //镜像基址
	DWORD                   dwCodeBase;		//代码段起始地址
	DWORD					dwCodeSize;		//代码大小
	DWORD					dwOEP;			//OEP地址
	DWORD					dwSizeOfHeader;	//文件头大小
	DWORD					dwSectionNum;		//区段数量
	DWORD					dwFileAlign;		//文件对齐
	DWORD					dwMemAlign;		//内存对齐

	IMAGE_DATA_DIRECTORY	PERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	PEImportDir;	//导入表信息

	DWORD					IATSectionBase;	//IAT所在段基址
	DWORD					IATSectionSize;	//IAT所在段大小
	LPBYTE                  lpFinalBuf;     //最终的Buf
	DWORD                   IATNewSectionBase;   //lpFinalBuf的IAT
	DWORD                   IATNewSectionSize;

	DWORD                   dwXorKey;				//解密KEY

	DWORD dwDataDir[20][2];  //数据目录表的RVA和Size	
	DWORD dwNumOfDataDir;	//数据目录表的个数

	DWORD dwWeiZaoIATVirtualAddress;
	DWORD dwWeiZaoIATSize;

}SHELL_DATA, *PSHELL_DATA;

//在头文件中定义必要的Win32函数指针
typedef DWORD(WINAPI *fnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef HMODULE(WINAPI *fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef HMODULE(WINAPI *fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
typedef BOOL(WINAPI *fnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef LPVOID(WINAPI *fnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef void(WINAPI *fnExitProcess)(_In_ UINT uExitCode);
typedef int(WINAPI *fnMessageBox)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);
typedef HMODULE(WINAPI *fnGetMoudleHandleA)(_In_ LPCWSTR lpMoudleName);
typedef VOID(WINAPI *fnRtlMoveMemory)(_Out_  VOID UNALIGNED *Destination,_In_ const VOID UNALIGNED *Source,_In_ SIZE_T Length);
enum PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort = 7,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	MaxProcessInfoClass,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31,
	SystemKernelDebuggerInformation = 35
};
typedef NTSTATUS(WINAPI *NtQueryInformationProcessPtr)(
	HANDLE processHandle,
	PROCESSINFOCLASS processInformationClass,
	PVOID processInformation,
	ULONG processInformationLength,
	PULONG returnLength);

typedef HANDLE(WINAPI *pfnCreateToolhelp32Snapshot)(
	DWORD dwFlags,
	DWORD th32ProcessID);

typedef BOOL(WINAPI *pfnProcess32First)(
	HANDLE hSnapshot,
	LPPROCESSENTRY32 lppe);

typedef HANDLE(WINAPI *pfnGetCurrentProcess)();

typedef BOOL(WINAPI *pfnProcess32Next)(
	HANDLE hSnapshot,
	LPPROCESSENTRY32 lppe);

typedef BOOL(WINAPI *pfnCloseHandle)(
	_In_ _Post_ptr_invalid_ HANDLE hObject);

typedef HANDLE(WINAPI *pfnGetCurrentThread)();

typedef BOOL(WINAPI *pfnGetThreadContext)(
	_In_ HANDLE hThread,
	_Inout_ LPCONTEXT lpContext);



//非API函数
void RecReloc();
BOOL MyStrcmp(char* src, const char*dst);
void InitWin32FunAddr();
HMODULE GetKernel32BaseAddr();
DWORD MyGetProcAddress();
void DecryptCodeSeg(DWORD XorKey);
BOOL CheckDebugByNtQueryInformationProcess_ProcessDebugPort();
BOOL CheckDebugByDbgWindow();
BOOL Mystricmp(char str1[], const char str2[]);
void FixIAT();
void SetFileHeaderProtect(bool nWrite);
void  DecryptIAT();
//void RecordDataDir(DWORD IATNewSectionBase, DWORD IATNewSectionSize);
void RecoverDataDir();
PIMAGE_OPTIONAL_HEADER GetOptionHeader(LPBYTE lpBaseAddress);
PIMAGE_NT_HEADERS GetNtHeader(LPBYTE lpBaseAddress);