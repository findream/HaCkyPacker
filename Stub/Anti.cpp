#include "Stub.h"


//************************************************************
//CheckDebugByNtQueryInformationProcess_ProcessDebugPort:����NtQueryInformationProcess���з�����
//ChildFunc:NULL
//ԭ��NtQueryInformationProcess��û�й�����Ntdll�ĺ�����ͨ�����õڶ������������ͣ�Ȼ��õ�������������ֵ
//�жϸ�ֵ�Ƿ�Ϊ0�����Ϊ0��˵��û�б�����
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
//CheckDebugByNtQueryInformationProcess_ProcessDebugObjectHandle:����NtQueryInformationProcess���з�����
//ChildFunc:NULL
//ԭ��NtQueryInformationProcess��û�й�����Ntdll�ĺ�����ͨ�����õڶ������������ͣ�Ȼ��õ�������������ֵ
//�жϸ�ֵ�Ƿ�Ϊ0�����Ϊ0��˵��û�б�����
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
// CheckDebugByBeingDebugged:ͨ��BeingDebugged��Ա���з����ԣ�������ڵ���״̬����True
// ChildFunc��NULL
//************************************************************
bool CheckDebugByBeingDebugged()   //bool��һ���ֽڣ�BOOL���ĸ��ֽ�
{
	bool BeingDugged = false;
	__asm
	{
		mov eax, DWORD ptr fs : [0x30];     //��ȡpeb
		mov al, byte ptr ds : [eax + 0x02];   //��ȡpeb.beingdugged
		mov BeingDugged, al;                //��������Է��ط�0
	}
	return BeingDugged;
}

//************************************************************
//CheckDebugByDbgWindow:���windows������з�����
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
//CheckDebugBy0xCC()��ͨ��ȫ��������0xCC���ж��Ƿ�������ϵ�
//ChildFunc��NULL
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
		repne   scasb      //ɨ��Ƚ�
		jnz     NotFound
		mov Found, 1
		NotFound:
	}
	return Found;
}


//************************************************************
//CheckDebugByHardBreakpoint()������̻߳��������Ľṹ�е�Dr0-Dr3�ĸ��Ĵ���
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
//CheckVMWareByIn()��ͨ��in����Ȩ��ָ����VM
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
			setz[bRes]   //setz��˼�ǽ�zf��־λ��ֵ����bRes
			pop    ebx
			pop    ecx
			pop    edx
	}

	return bRes;
}

//************************************************************
//CheckVMWareByCpuid()��ͨ��Cpuid����Ȩ��ָ����VM
//ChildFunc:NULL
//mov eax, 1
//cpuid
//ִ����ɺ󣬴�����ǩ������EAX�У�����λ�����������ݷֱ����EBX��ECX��EDX�С�
//��EAX��Ϊ1������CPUIDָ����ȡECX�е�ֵ���жϡ�
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
		mov eax, 1;             //���빦�ܺ�
		cpuid;
		mov dw_ecx, ecx;        //����λ������ecx
		and dw_ecx, 0x80000000; //ȡ���λ
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