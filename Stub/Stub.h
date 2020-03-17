#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#pragma warning(disable:4996)


//��Ҫ������SHELL_DATA�ṹ�壬�����������PE��ص���Ҫ��Ա��������Pack���ֵĽ���
typedef struct _SHELL_DATA
{
	
	DWORD					dwImageSize;		//�����С
	PIMAGE_DOS_HEADER		pDosHeader;		//Dosͷ
	PIMAGE_NT_HEADERS		pNtHeader;		//NTͷ
	PIMAGE_OPTIONAL_HEADER  pOptionalHeader;  //��ѡͷ
	PIMAGE_SECTION_HEADER	pSecHeader;		//��һ��SECTION�ṹ��ָ��
	DWORD					dwImageBase;    //�����ַ
	DWORD                   dwCodeBase;		//�������ʼ��ַ
	DWORD					dwCodeSize;		//�����С
	DWORD					dwOEP;			//OEP��ַ
	DWORD					dwSizeOfHeader;	//�ļ�ͷ��С
	DWORD					dwSectionNum;		//��������
	DWORD					dwFileAlign;		//�ļ�����
	DWORD					dwMemAlign;		//�ڴ����

	IMAGE_DATA_DIRECTORY	PERelocDir;		//�ض�λ����Ϣ
	IMAGE_DATA_DIRECTORY	PEImportDir;	//�������Ϣ

	DWORD					IATSectionBase;	//IAT���ڶλ�ַ
	DWORD					IATSectionSize;	//IAT���ڶδ�С
	LPBYTE                  lpFinalBuf;     //���յ�Buf
	DWORD                   IATNewSectionBase;   //lpFinalBuf��IAT
	DWORD                   IATNewSectionSize;

	DWORD                   dwXorKey;				//����KEY

	DWORD dwDataDir[20][2];  //����Ŀ¼���RVA��Size	
	DWORD dwNumOfDataDir;	//����Ŀ¼��ĸ���

	DWORD dwWeiZaoIATVirtualAddress;
	DWORD dwWeiZaoIATSize;

}SHELL_DATA, *PSHELL_DATA;

//��ͷ�ļ��ж����Ҫ��Win32����ָ��
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



//��API����
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