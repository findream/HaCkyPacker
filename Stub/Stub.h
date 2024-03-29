#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#pragma warning(disable:4996)

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4
#define ENCRYPT_BLOCK_SIZE 8


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

	char                   dwAESKey[8];				//解密KEY

	DWORD dwDataDir[20][2];  //数据目录表的RVA和Size	
	DWORD dwNumOfDataDir;	//数据目录表的个数

	DWORD dwWeiZaoIATVirtualAddress;
	DWORD dwWeiZaoIATSize;

	//兼容GUI
	DWORD                   WorkMode;

}SHELL_DATA, *PSHELL_DATA;

//在头文件中定义必要的Win32函数指针
typedef DWORD(WINAPI *fnGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName);

typedef HMODULE(WINAPI *fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);

typedef HMODULE(WINAPI *fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);

typedef BOOL(WINAPI *fnVirtualProtect)(_In_ LPVOID lpAddress, 
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect, 
	_Out_ PDWORD lpflOldProtect);
typedef LPVOID(WINAPI *fnVirtualAlloc)(_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize, 
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect);
typedef void(WINAPI *fnExitProcess)(_In_ UINT uExitCode);

typedef int(WINAPI *fnMessageBox)(HWND hWnd, 
	LPSTR lpText,
	LPSTR lpCaption, 
	UINT uType);

typedef HMODULE(WINAPI *fnGetMoudleHandleA)(_In_ LPCWSTR lpMoudleName);

typedef VOID(WINAPI *fnRtlMoveMemory)(_Out_  VOID UNALIGNED *Destination,
	_In_ const VOID UNALIGNED *Source,
	_In_ SIZE_T Length);

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

typedef BOOL(WINAPI *pfnCryptAcquireContextA)(
	_Out_       HCRYPTPROV  *phProv,
	_In_opt_    LPCSTR    szContainer,
	_In_opt_    LPCSTR    szProvider,
	_In_        DWORD       dwProvType,
	_In_        DWORD       dwFlags
);

typedef BOOL(WINAPI *pfnCryptCreateHash)(
	_In_    HCRYPTPROV  hProv,
	_In_    ALG_ID      Algid,
	_In_    HCRYPTKEY   hKey,
	_In_    DWORD       dwFlags,
	_Out_   HCRYPTHASH  *phHash
);

typedef BOOL(WINAPI *pfnCryptHashData)(
	_In_                    HCRYPTHASH  hHash,
	_In_reads_bytes_(dwDataLen)  CONST BYTE  *pbData,
	_In_                    DWORD   dwDataLen,
	_In_                    DWORD   dwFlags
);

typedef BOOL(WINAPI *pfnCryptDeriveKey)(
	_In_    HCRYPTPROV  hProv,
	_In_    ALG_ID      Algid,
	_In_    HCRYPTHASH  hBaseData,
	_In_    DWORD       dwFlags,
	_Out_   HCRYPTKEY   *phKey
);

typedef BOOL(WINAPI *pfnCryptDestroyHash)(
	_In_    HCRYPTHASH  hHash
);

typedef HANDLE(WINAPI *pfnHeapCreate)(
	_In_ DWORD flOptions,
	_In_ SIZE_T dwInitialSize,
	_In_ SIZE_T dwMaximumSize
);

typedef LPVOID(WINAPI *pfnHeapAlloc)(
	_In_ HANDLE hHeap,
	_In_ DWORD dwFlags,
	_In_ SIZE_T dwBytes
);

typedef BOOL(WINAPI *pfnCryptDecrypt)(
	_In_                                            HCRYPTKEY   hKey,
	_In_                                            HCRYPTHASH  hHash,
	_In_                                            BOOL        Final,
	_In_                                            DWORD       dwFlags,
	_Inout_updates_bytes_to_(*pdwDataLen, *pdwDataLen)   BYTE        *pbData,
	_Inout_                                         DWORD       *pdwDataLen
);


typedef BOOL(WINAPI *pfnHeapFree)(
	_Inout_ HANDLE hHeap,
	_In_ DWORD dwFlags,
	__drv_freesMem(Mem) _Frees_ptr_opt_ LPVOID lpMem
);

typedef BOOL(WINAPI *pfnCryptDestroyKey)(
	_In_    HCRYPTKEY   hKey
);

typedef BOOL(WINAPI *pfnCryptReleaseContext)(
	_In_    HCRYPTPROV  hProv,
	_In_    DWORD       dwFlags
);

typedef HANDLE(WINAPI *pfnCreateFileA)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
);

typedef DWORD(WINAPI *pfnGetFileSize)(
	_In_ HANDLE hFile,
	_Out_opt_ LPDWORD lpFileSizeHigh
);

typedef BOOL (WINAPI *pfnReadFile)(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

typedef BOOL(WINAPI *pfnOpenProcessToken)(
	_In_ HANDLE ProcessHandle,
	_In_ DWORD DesiredAccess,
	_Outptr_ PHANDLE TokenHandle
);


typedef BOOL(WINAPI *pfnLookupPrivilegeValueA)(
	_In_opt_ LPCSTR lpSystemName,
	_In_     LPCSTR lpName,
	_Out_    PLUID   lpLuid
);

typedef BOOL(WINAPI *pfnAdjustTokenPrivileges)(
	_In_ HANDLE TokenHandle,
	_In_ BOOL DisableAllPrivileges,
	_In_opt_ PTOKEN_PRIVILEGES NewState,
	_In_ DWORD BufferLength,
	_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
	_Out_opt_ PDWORD ReturnLength
);


typedef HANDLE(WINAPI *pfnOpenProcess)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
);

typedef DWORD(WINAPI *pfnWaitForSingleObject)(
	_In_ HANDLE hHandle,
	_In_ DWORD dwMilliseconds
);

typedef HANDLE(WINAPI *pfnGetProcessHeap)(
	VOID
);

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

typedef DWORD (WINAPI *pfnGetCurrentProcessId)(
	VOID
);


//非API函数
void RecReloc();
BOOL MyStrcmp(char* src, const char*dst);
void InitWin32FunAddr();
HMODULE GetKernel32BaseAddr();
DWORD MyGetProcAddress();
void DecryptCodeSeg();
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
void DecryKey(char* src, char* str);
void Mystrcpy(char *s, char *t);
void AntiDumpByImageSize();
void AntiDumpByHideProcess();
void AntiDumpByMemory();
BOOL  FindString(LPBYTE lpBaseAddress, DWORD ImageSize);

//Anti
bool CheckDebugByBeingDebugged();
BOOL CheckDebugBy0xCC();
BOOL CheckDebugByHardBreakpoint();
BOOL CheckVMWareByIn();
BOOL CheckVMWareByCpuid();