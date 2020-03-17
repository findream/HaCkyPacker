#include "Stub.h"


//************************************************************
//CheckDebugByNtQueryInformationProcess_ProcessDebugPort:利用NtQueryInformationProcess进行反调试
//ChildFunc:NULL
//原理：NtQueryInformationProcess是没有公开的Ntdll的函数，通过设置第二个参数的类型，然后得到第三个参数的值
//判断该值是否为0，如果为0，说明没有被调试
//************************************************************
BOOL CheckDebugByNtQueryInformationProcess_ProcessDebugPort()
{

	int debugPort = 0;
	HMODULE hKernel32 = GetKernel32BaseAddr();
	fnGetProcAddress g_pfnGetProcAddress = 
		(fnGetProcAddress)MyGetProcAddress();

	fnLoadLibraryA g_pfnLoadLibraryA = 
		(fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");

	HMODULE hModule = g_pfnLoadLibraryA("Ntdll.dll");
	NtQueryInformationProcessPtr MyNtQueryInformationProcess = 
		(NtQueryInformationProcessPtr)g_pfnGetProcAddress(hModule, "NtQueryInformationProcess");
	
	pfnGetCurrentProcess MyGetCurrentProcess =
		(pfnGetCurrentProcess)g_pfnGetProcAddress(hKernel32, "GetCurrentProcess");
	MyNtQueryInformationProcess(MyGetCurrentProcess(), 
		ProcessDebugPort, 
		&debugPort, 
		sizeof(debugPort),
		NULL);
	return debugPort != 0;
}

//************************************************************
//CheckDebugByNtQueryInformationProcess_ProcessDebugObjectHandle:利用NtQueryInformationProcess进行反调试
//ChildFunc:NULL
//原理：NtQueryInformationProcess是没有公开的Ntdll的函数，通过设置第二个参数的类型，然后得到第三个参数的值
//判断该值是否为0，如果为0，说明没有被调试
//************************************************************
BOOL CheckDebugByNtQueryInformationProcess_ProcessDebugObjectHandle()
{
	HANDLE hdebugObject = NULL;

	HMODULE hKernel32 = GetKernel32BaseAddr();
	fnGetProcAddress g_pfnGetProcAddress =
		(fnGetProcAddress)MyGetProcAddress();

	fnLoadLibraryA g_pfnLoadLibraryA =
		(fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");
	HMODULE hModule = g_pfnLoadLibraryA("Ntdll.dll");

	NtQueryInformationProcessPtr MyNtQueryInformationProcess =
		(NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");

	pfnGetCurrentProcess MyGetCurrentProcess =
		(pfnGetCurrentProcess)g_pfnGetProcAddress(hKernel32, "GetCurrentProcess");

	MyNtQueryInformationProcess(MyGetCurrentProcess(), ProcessDebugObjectHandle, &hdebugObject, sizeof(hdebugObject), NULL);
	return hdebugObject != NULL;
}

//************************************************************
// CheckDebugByBeingDebugged:通过BeingDebugged成员进行反调试，如果处于调试状态返回True
// ChildFunc：NULL
//************************************************************
bool CheckDebugByBeingDebugged()   //bool是一个字节，BOOL是四个字节
{
	bool BeingDugged = false;
	__asm
	{
		mov eax, DWORD ptr fs : [0x30];     //获取peb
		mov al, byte ptr ds : [eax + 0x02];   //获取peb.beingdugged
		mov BeingDugged, al;                //如果被调试返回非0
	}
	return BeingDugged;
}

//************************************************************
//CheckDebugByDbgWindow:检测windows标题进行反调试
//ChildFunc:Mystricmp
//************************************************************
BOOL CheckDebugByDbgWindow()
{
	DWORD ret = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	HMODULE hKernel32 = GetKernel32BaseAddr();
	fnGetProcAddress g_pfnGetProcAddress =
		(fnGetProcAddress)MyGetProcAddress();

	fnLoadLibraryA MyLoadLibraryA =
		(fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");

	HMODULE hModule = MyLoadLibraryA("kernel32.dll");

	pfnCreateToolhelp32Snapshot MyCreateToolhelp32Snapshot =
		(pfnCreateToolhelp32Snapshot)g_pfnGetProcAddress(hModule, "CreateToolhelp32Snapshot");

	pfnProcess32First  MyProcess32First =
		(pfnProcess32First)g_pfnGetProcAddress(hModule, "Process32First");

	pfnProcess32Next MyProcess32Next =
		(pfnProcess32Next)g_pfnGetProcAddress(hModule, "Process32Next");

	pfnCloseHandle MyCloseHandle = 
		(pfnCloseHandle)g_pfnGetProcAddress(hModule, "CloseHandle");

	HANDLE hProcessSnap = MyCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	BOOL bMore = MyProcess32First(hProcessSnap, &pe32);
	while (bMore)
	{
		if (Mystricmp(pe32.szExeFile, "OllyDBG.EXE") || Mystricmp(pe32.szExeFile, "OllyICE.exe") || Mystricmp(pe32.szExeFile, "x64_dbg.exe") || Mystricmp(pe32.szExeFile, "windbg.exe") || Mystricmp(pe32.szExeFile, "ImmunityDebugger.exe"))
		{
			return TRUE;
		}
		bMore = MyProcess32Next(hProcessSnap, &pe32);
	}
	MyCloseHandle(hProcessSnap);
	return FALSE;
}


BOOL Mystricmp(char str1[], const char str2[])
{
	unsigned char chr1, chr2;
	int i = 0;
	while (1)
	{
		chr1 = (str1[i] >= 'a' && str1[i] <= 'z') ? (str1[i] - 32) : str1[i];
		chr2 = (str2[i] >= 'a' && str2[i] <= 'z') ? (str2[i] - 32) : str2[i];
		i++;

		if (chr1 != chr2)
			break;
		if (chr1 == '\0' || chr2 == '\0')
			break;
	}
	if (chr1 > chr2)
		return FALSE;
	else if (chr1 == chr2)
		return TRUE;
	else if (chr1 < chr2)
		return FALSE;
}


//************************************************************
//CheckDebugBy0xCC()：通过全镜像搜索0xCC来判断是否下软件断点
//ChildFunc：NULL
//************************************************************
BOOL CheckDebugBy0xCC()
{

	DWORD dwBaseImage = (DWORD)GetModuleHandle(NULL);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwBaseImage;;
	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(pNtHeaders->Signature) + sizeof(IMAGE_FILE_HEADER) +
		(WORD)pNtHeaders->FileHeader.SizeOfOptionalHeader);

	DWORD dwAddr = pSectionHeader->VirtualAddress + dwBaseImage;
	DWORD dwCodeSize = pSectionHeader->SizeOfRawData;
	BOOL Found = FALSE;
	__asm
	{
		cld
		mov     edi, dwAddr
		mov     ecx, dwCodeSize
		mov     al, 0CCH
		repne   scasb      //扫描比较
		jnz     NotFound
		mov Found, 1
		NotFound:
	}
	return Found;
}


//************************************************************
//CheckDebugByHardBreakpoint()：检测线程环境上下文结构中的Dr0-Dr3四个寄存器
//ChildFunc:NULL
//************************************************************
BOOL CheckDebugByHardBreakpoint()
{
	HMODULE hKernel32 = GetKernel32BaseAddr();
	fnGetProcAddress g_pfnGetProcAddress =
		(fnGetProcAddress)MyGetProcAddress();

	fnLoadLibraryA MyLoadLibraryA =
		(fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");

	HMODULE hModule = MyLoadLibraryA("kernel32.dll");
	
	pfnGetCurrentThread MyGetCurrentThread =
		(pfnGetCurrentThread)g_pfnGetProcAddress(hModule, "GetCurrentThread");

	pfnGetThreadContext MyGetThreadContext =
		(pfnGetThreadContext)g_pfnGetProcAddress(hModule, "GetThreadContext");

	CONTEXT context;
	HANDLE hThread = GetCurrentThread();
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread, &context);
	if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
	{
		return TRUE;
	}
	return FALSE;
}

//************************************************************
//CheckVMWareByIn()：通过in特殊权限指令检测VM
//ChildFunc:NULL
//************************************************************
BOOL CheckVMWareByIn()
{
	bool bRes = true;

	__asm
	{
			push   edx
			push   ecx
			push   ebx
			mov    eax, 'VMXh'
			mov    ebx, 0
			mov    ecx, 10
			mov    edx, 'VX'
			in     eax, dx
			cmp    ebx, 'VMXh'
			setz[bRes]   //setz意思是将zf标志位的值传入bRes
			pop    ebx
			pop    ecx
			pop    edx
	}

	return bRes;
}

//************************************************************
//CheckVMWareByCpuid()：通过Cpuid特殊权限指令检测VM
//ChildFunc:NULL
//mov eax, 1
//cpuid
//执行完成后，处理器签名放在EAX中，功能位及其它的内容分别放在EBX、ECX和EDX中。
//将EAX置为1，运行CPUID指令后获取ECX中的值并判断。
//http://www.52bug.cn/cracktool/5843.html
//************************************************************
BOOL CheckVMWareByCpuid()
{
	DWORD dw_ecx;
	bool bFlag = true;
	_asm
	{
		pushad;
		pushfd;
		mov eax, 1;             //传入功能号
		cpuid;
		mov dw_ecx, ecx;        //功能位放置于ecx
		and dw_ecx, 0x80000000; //取最高位
		test ecx, ecx;
		setz[bFlag];
		popfd;
		popad;
	}
	if (bFlag)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}