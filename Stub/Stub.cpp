//此文件是Stub部分的主文件，本次不在使用基于Dll的入口函数，直接生成lib
#include "Stub.h"
#include "..//HaCkyPack/StubData.h"

//合并.data和.rdata段到.text段，并将.text段设置为读写执行。
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

//导出一个全局变量，并初始化
extern "C" __declspec(dllexport)SHELL_DATA g_ShellData = { 0 };

//初始化相关Win32函数
fnGetProcAddress	g_pfnGetProcAddress = NULL;
fnLoadLibraryA		g_pfnLoadLibraryA = NULL;
fnGetModuleHandleA	g_pfnGetModuleHandleA = NULL;
fnVirtualProtect	g_pfnVirtualProtect = NULL;
fnVirtualAlloc		g_pfnVirtualAlloc = NULL;
fnExitProcess		g_pfnExitProcess = NULL;
fnMessageBox		g_pfnMessageBoxA = NULL;

//一些全局变量
DWORD dwImageBase = 0;		//整个程序的镜像基址
DWORD dwNewOEP = 0;		    //PE文件的OEP


//************************************************************
//Start()：Stub.dll最开始执行的地方，反调试开始的地方
//ChildFunc：NULL
//************************************************************
extern "C" __declspec(dllexport) __declspec(naked)
void Start()
{
	//Step1:首先是获取所有Win32函数地址
	InitWin32FunAddr();


	//Step2:恢复IAT数据表
	RecoverDataDir();
	
	//Step3:填充IAT
	FixIAT();

	//Step2：解密IAT表
	//DecryptIAT();



	//Step2:解密代码段
	DecryptCodeSeg(g_ShellData.dwXorKey);

	//Step3:反调试
	//if (CheckDebugByDbgWindow())
	//{
	//	ExitProcess(0);
	//}
	//反调试
	//IAT加密等
	//跳转入程序入口点
	dwNewOEP = g_ShellData.dwOEP + g_ShellData.dwImageBase;
	_asm jmp dwNewOEP
}


//************************************************************
//InitWin32FunAddr()：初始化Win32函数
//ChildFunc：GetKernel32BaseAddr()
             //MyGetProcAddress
//************************************************************
void InitWin32FunAddr()
{
	//从Kenel32中获取函数
	HMODULE hKernel32 = GetKernel32BaseAddr();
	g_pfnGetProcAddress = (fnGetProcAddress)MyGetProcAddress();
	g_pfnLoadLibraryA = (fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");
	g_pfnGetModuleHandleA = (fnGetModuleHandleA)g_pfnGetProcAddress(hKernel32, "GetModuleHandleA");
	g_pfnVirtualProtect = (fnVirtualProtect)g_pfnGetProcAddress(hKernel32, "VirtualProtect");
	g_pfnExitProcess = (fnExitProcess)g_pfnGetProcAddress(hKernel32, "ExitProcess");
	g_pfnVirtualAlloc = (fnVirtualAlloc)g_pfnGetProcAddress(hKernel32, "VirtualAlloc");
	g_pfnMessageBoxA = (fnMessageBox)g_pfnGetProcAddress(hKernel32, "MessageBoxA");
}

/*-------------------------
=============WIN7============
0:001> !peb
PEB at 7ffda000
	InheritedAddressSpace:    No
	ReadImageFileExecOptions: No
	BeingDebugged:            Yes
	ImageBaseAddress:         00180000
	Ldr                       76fa7880
	Ldr.Initialized:          Yes
	Ldr.InInitializationOrderModuleList: 003c1898 . 003d88b8
	Ldr.InLoadOrderModuleList:           003c1808 . 003d88a8
	Ldr.InMemoryOrderModuleList:         003c1810 . 003d88b0

0:001> dt _PEB 7ffda000
uxtheme!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x8 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsLegacyProcess  : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 SpareBits        : 0y000
   +0x004 Mutant           : 0xffffffff
   +0x008 ImageBaseAddress : 0x00180000
   +0x00c Ldr              : 0x76fa7880 _PEB_LDR_DATA

0:001> dt  _PEB_LDR_DATA 0x76fa7880
uxtheme!_PEB_LDR_DATA
   +0x000 Length           : 0x30
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null)
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x3c1808 - 0x3d88a8 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x3c1810 - 0x3d88b0 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x3c1898 - 0x3d88b8 ]

0:001> dt _LIST_ENTRY 0x3c1808
uxtheme!_LIST_ENTRY
 [ 0x3c1888 - 0x76fa788c ]
   +0x000 Flink            : 0x003c1888 _LIST_ENTRY [ 0x3c1b80 - 0x3c1808 ]   <----
   +0x004 Blink            : 0x76fa788c _LIST_ENTRY [ 0x3c1808 - 0x3d88a8 ]
0:001> dd  0x3c1808
003c1808  003c1888 76fa788c 003c1890 76fa7894
003c1818  00000000 00000000 00180000 00183689
003c1828  00030000 0040003e 003c1698 00180016
003c1838  003c16c0 00004000 0000ffff 76faa5e8
003c1848  76faa5e8 4a5bc60f 00000000 00000000
003c1858  003c1858 003c1858 003c1860 003c1860
003c1868  003da520 003d6d98 76f2c1e4 00000000
003c1878  00000000 00000000 7c7323a1 080069a0
0:001> dd 003c1888
003c1888  003c1b80 003c1808 003c1b88 003c1810
003c1898  003c1c78 76fa789c 76ed0000 00000000
003c18a8  0013c000 003c003a 003c1788 00140012
003c18b8  76f3d4cc 00004004 0000ffff 76faa680
003c18c8  76faa680 4a5bdadb 00000000 00000000
003c18d8  003c18d8 003c18d8 003c18e0 003c18e0
003c18e8  003c18e8 003c18e8 00000000 77ec0000
003c18f8  00000000 00000000 297323f4 0c0069a0
0:001> dt _LDR_DATA_TABLE_ENTRY 3c1b80
uxtheme!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x3c1c68 - 0x3c1888 ]
   +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x3c1c70 - 0x3c1890 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x3c2498 - 0x3c1c78 ]
   +0x018 DllBase          : 0x75560000
   +0x01c EntryPoint       : 0x755b10c5
   +0x020 SizeOfImage      : 0xd4000
   +0x024 FullDllName      : _UNICODE_STRING "C:\Windows\system32\kernel32.dll"
   +0x02c BaseDllName      : _UNICODE_STRING "kernel32.dll"
=================WIN10===============
...
---------------------------*/
//************************************************************
//获取Kernel32的BaseAddress
//ChildFunc:NULL
//************************************************************
HMODULE GetKernel32BaseAddr()
{
	HMODULE hKernel = NULL;

	_asm
	{
		pushad
		mov eax, fs:[0x30]     //PEB
		mov eax, [eax + 0x0C]    //PEB_LDR_DATA
		mov eax, [eax + 0x0C]    //InLoadOrderModuleList1 
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x18]    //Kernel32 BaseAddr
		mov hKernel, eax
		popad
	}
	return hKernel;
}

//************************************************************
//获取GetProcAddress 函数地址
//ChildFunc:GetKernel32BaseAddr
            //MyStrcmp
//************************************************************
DWORD MyGetProcAddress()
{
	//Kernel32的基地址
	HMODULE hKernel32 = GetKernel32BaseAddr();

	//通过导出表获取GetProcAddress的地址
	//1.获取DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(PBYTE)hKernel32;
	//2.获取NT头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hKernel32 + pDosHeader->e_lfanew);
	//3.获取导出表的结构体指针
	PIMAGE_DATA_DIRECTORY pExportDir =
		&(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

	PIMAGE_EXPORT_DIRECTORY pExport =
		(PIMAGE_EXPORT_DIRECTORY)((PBYTE)hKernel32 + pExportDir->VirtualAddress);
	//EAT
	PDWORD pEAT = (PDWORD)((DWORD)hKernel32 + pExport->AddressOfFunctions);
	//ENT
	PDWORD pENT = (PDWORD)((DWORD)hKernel32 + pExport->AddressOfNames);
	//EIT
	PWORD pEIT = (PWORD)((DWORD)hKernel32 + pExport->AddressOfNameOrdinals);

	//4.遍历导出表，获取GetProcAddress()函数地址
	DWORD dwNumofFun = pExport->NumberOfFunctions;
	DWORD dwNumofName = pExport->NumberOfNames;
	for (DWORD i = 0; i < dwNumofFun; i++)
	{
		//如果为无效函数，跳过
		if (pEAT[i] == NULL)
			continue;
		//判断是以函数名导出还是以序号导出
		DWORD j = 0;
		for (; j < dwNumofName; j++)
		{
			if (i == pEIT[j])
			{
				break;
			}
		}
		if (j != dwNumofName)
		{
			char* ExpFunName = (CHAR*)((PBYTE)hKernel32 + pENT[j]);
			//进行对比,如果正确返回地址
			if (MyStrcmp(ExpFunName, "GetProcAddress"))
			{
				return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
			}
		}
	}
	return 0;
}


//************************************************************
//FixIAT():模拟PE加载器WinLoader填充IAT
//ChildFunc:SetFileHeaderProtect 修改内存保护属性
//************************************************************
void FixIAT()
{
	//设置文件属性为可写
	SetFileHeaderProtect(true);
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)g_pfnGetModuleHandleA(NULL);
	                         

	IMAGE_THUNK_DATA* pOrigalFirstThunk = NULL;
	IMAGE_THUNK_DATA* pFirstThunk = NULL;
	DWORD dwFunAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptionHeader((LPBYTE)ImageBase)->DataDirectory[1].VirtualAddress)
		return;

	//导入表=导入表偏移+加载基址
	IMAGE_IMPORT_DESCRIPTOR* pImportTable = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptionHeader((LPBYTE)ImageBase)->DataDirectory[1].VirtualAddress + ImageBase);


	while (pImportTable->Name)
	{
		//IAT=偏移加加载基址
		pFirstThunk = (IMAGE_THUNK_DATA*)(pImportTable->FirstThunk + ImageBase);
		if (pImportTable->OriginalFirstThunk == 0) // 如果不存在INT则使用IAT
		{
			pOrigalFirstThunk = pFirstThunk;
		}
		else
		{
			pOrigalFirstThunk = (IMAGE_THUNK_DATA*)(pImportTable->OriginalFirstThunk + ImageBase);
		}

		// 加载dll
		hImpModule = (HMODULE)g_pfnLoadLibraryA((char*)(pImportTable->Name + ImageBase));
		//导入函数地址
		while (pOrigalFirstThunk->u1.Function)
		{
			//判断导入的方式、序号还是名称
			if (!IMAGE_SNAP_BY_ORDINAL(pOrigalFirstThunk->u1.Ordinal))
			{
				pImpName = (IMAGE_IMPORT_BY_NAME*)(pOrigalFirstThunk->u1.Function + ImageBase);
				dwFunAddress = (DWORD)g_pfnGetProcAddress(hImpModule, (char*)pImpName->Name);
			}
			else
			{
				dwFunAddress = (DWORD)g_pfnGetProcAddress(hImpModule, (char*)(pOrigalFirstThunk->u1.Function & 0xFFFF));
			}

			g_pfnVirtualProtect(&pFirstThunk->u1.Function, sizeof(pFirstThunk->u1.Function), PAGE_READWRITE, &dwOldProtect);


			pFirstThunk->u1.Function = dwFunAddress;
			g_pfnVirtualProtect(&pFirstThunk->u1.Function, sizeof(pFirstThunk->u1.Function), dwOldProtect, &dwOldProtect);
			++pOrigalFirstThunk;
			++pFirstThunk;
		}
		++pImportTable;
	}
	SetFileHeaderProtect(false);
}


//************************************************************
// SetFileHeaderProtect:修改内存保护属性
// ChildFunc:NULL
//************************************************************
void SetFileHeaderProtect(bool nWrite)
{
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)g_pfnGetModuleHandleA(NULL);
	DWORD nOldProtect = 0;
	if (nWrite)
		g_pfnVirtualProtect((LPVOID)ImageBase, 0x400, PAGE_EXECUTE_READWRITE, &nOldProtect);
	else
		g_pfnVirtualProtect((LPVOID)ImageBase, 0x400, nOldProtect, &nOldProtect);
}


//************************************************************
//DecryptIAT:解密IAT
//ChilddFunc:NULL
//************************************************************
void  DecryptIAT()
{
	FILE *fp = fopen("HackyPackLog.log", "a");

	LPBYTE lpFinalBuf = (LPBYTE)g_pfnGetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFinalBuf;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpFinalBuf + pDosHeader->e_lfanew);
	DWORD Rav_Import_Table = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR ImportTable = PIMAGE_IMPORT_DESCRIPTOR((DWORD)lpFinalBuf + Rav_Import_Table);

	//遍历所有的IID
	//遍历IIDpFirsrThunk
	while (ImportTable->Name)
	{
		//DllName
		//获取RvaOfDllName
		PDWORD dwTmpDllName = &ImportTable->Name;
		fprintf(fp, "[*]Packer::EncryIAT--->dwOldRvaOfDllName：%x\n", *dwTmpDllName);


		char* pDllName = (char*)((DWORD)lpFinalBuf + ImportTable->Name);
		fprintf(fp, "[*]Packer::EncryIAT--->dwOldDllName：%s\n", pDllName);
		for (DWORD i = 0; i < strlen(pDllName); i++)
			pDllName[i] ^= 0x234;
		fprintf(fp, "[*]Packer::EncryIAT--->dwNewDllName：%s\n", pDllName);

		//避免提前修改RvaOfDllName值导致DllName获取不到
		*dwTmpDllName = *dwTmpDllName ^ 0x123;
		fprintf(fp, "[*]Packer::EncryIAT--->dwNewRvaOfDllName：%x\n", *dwTmpDllName);

		PIMAGE_THUNK_DATA pFirsrThunk = (PIMAGE_THUNK_DATA)((DWORD)lpFinalBuf + ImportTable->FirstThunk);
		//遍历每个IAT
		while (pFirsrThunk->u1.AddressOfData)
		{

			//如果是序号方式导入
			if (IMAGE_SNAP_BY_ORDINAL(pFirsrThunk->u1.AddressOfData))
			{
				PDWORD dwTmpOrd = &pFirsrThunk->u1.Ordinal;
				*dwTmpOrd = *dwTmpOrd ^ 0x234;
			}
			else
			{
				//此处获取的是函数地址
				PDWORD FuncAddr = &pFirsrThunk->u1.Function;
				fprintf(fp, "[*]Packer::EncryIAT--->u1.Function：%x\n", *FuncAddr);


				//此处还应该获取函数名称
				PIMAGE_IMPORT_BY_NAME pThunkName = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpFinalBuf + pFirsrThunk->u1.AddressOfData);

				PWORD Hint = &pThunkName->Hint;
				fprintf(fp, "[*]Packer::EncryIAT--->u1.OldFunction：%x\n", *Hint);

				char* FuncName = pThunkName->Name;
				fprintf(fp, "[*]Packer::EncryIAT--->OldFuncName：%s\n", FuncName);

				for (DWORD i = 0; i < strlen(FuncName); i++)
					FuncName[i] ^= 0x234;
				fprintf(fp, "[*]Packer::EncryIAT--->NewFuncName：%s\n", FuncName);

				*FuncAddr = *FuncAddr ^ 0x345;
				//*(PDWORD)((DWORD)lpBaseAddress + pFirsrThunk->u1.Function) = TmpFuncAddr;
				fprintf(fp, "[*]Packer::EncryIAT--->NewFuncAddr：%x\n", *FuncAddr);

				*Hint = *Hint ^ 0x456;
				fprintf(fp, "[*]Packer::EncryIAT--->NewHint ：%x\n", *Hint);
				//*(PWORD)((DWORD)lpBaseAddress + pThunkName->Hint) = TmpHint;
			}
			pFirsrThunk++;
		}
		ImportTable++;
	}
	fclose(fp);
}

PIMAGE_OPTIONAL_HEADER GetOptionHeader(LPBYTE lpBaseAddress)
{
	return &GetNtHeader(lpBaseAddress)->OptionalHeader;
}

PIMAGE_NT_HEADERS GetNtHeader(LPBYTE lpBaseAddress)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	return PIMAGE_NT_HEADERS((DWORD)lpBaseAddress + pImageDosHeader->e_lfanew);
}
//void RecordDataDir(DWORD IATNewSectionBase, DWORD IATNewSectionSize)
//{
//	DWORD dwOldProtect = 0;
//	LPBYTE lpBaseAddress = (LPBYTE)g_pfnGetModuleHandleA(NULL);
//	g_pfnVirtualProtect(&GetOptionHeader(lpBaseAddress)->DataDirectory[1], 0x8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
//	GetOptionHeader(lpBaseAddress)->DataDirectory[1].VirtualAddress = IATNewSectionBase;
//	GetOptionHeader(lpBaseAddress)->DataDirectory[1].Size = IATNewSectionSize;
//	g_pfnVirtualProtect(&GetOptionHeader(lpBaseAddress)->DataDirectory[1], 0x8, dwOldProtect, &dwOldProtect);
//}


//************************************************************
//RecoverDataDir:恢复数据目录
//ChildFunc:NULL
//************************************************************
void RecoverDataDir()
{
	//获取当前程序的加载基址
	char* dwBase = (char*)g_pfnGetModuleHandleA(NULL);
	//获取数据目录表的个数
	DWORD dwNumOfDataDir = g_ShellData.dwNumOfDataDir;

	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptionHeader((LPBYTE)dwBase)->DataDirectory);
	//遍历数据目录表
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}

		//修改属性为可读可写
		g_pfnVirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);

		//还原数据目录表项
		pDataDirectory->VirtualAddress = g_ShellData.dwDataDir[i][0];
		pDataDirectory->Size = g_ShellData.dwDataDir[i][1];

		//把属性修改回去
		g_pfnVirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);

		pDataDirectory++;
	}
}


//************************************************************
//MyStrcmp:比较两个字符串
//ChildFunc:NULL
//************************************************************
BOOL MyStrcmp(char* src, const char*dst)
{
	BOOL ret = TRUE;
	while (!(ret = *(unsigned char *)src - *(unsigned char *)dst) && *dst)
		++src, ++dst;
	if (ret < 0)
		ret = FALSE;
	else if (ret > 0)
		ret = FALSE;
	else if (ret == 0)
		ret = TRUE;
	return ret;
}


//************************************************************
//DecryptCodeSeg:解密被加密的代码段
//ChildFunc:NULL
//************************************************************
void DecryptCodeSeg(DWORD XorKey)
{
	DWORD i = 0;
	LPBYTE lpCodeBase = (LPBYTE)(g_ShellData.dwCodeBase + g_ShellData.dwImageBase);

	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect(lpCodeBase, g_ShellData.dwCodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	for (i = 0; i < g_ShellData.dwCodeSize; i++)
		lpCodeBase[i] ^= XorKey;
	g_pfnVirtualProtect(lpCodeBase, g_ShellData.dwCodeSize, dwOldProtect, &dwOldProtect);
}

//************************************************************
//CheckDebugByNtQueryInformationProcess_ProcessDebugPort:利用NtQueryInformationProcess进行反调试
//ChildFunc:NULL
//原理：NtQueryInformationProcess是没有公开的Ntdll的函数，通过设置第二个参数的类型，然后得到第三个参数的值
//判断该值是否为0，如果为0，说明没有被调试
//************************************************************
BOOL CheckDebugByNtQueryInformationProcess_ProcessDebugPort()
{

	int debugPort = 0;
	HMODULE hModule = LoadLibrary("Ntdll.dll");
	NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
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
	HMODULE hModule = LoadLibrary("Ntdll.dll");
	NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hdebugObject, sizeof(hdebugObject), NULL);
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
	HMODULE hModule = g_pfnLoadLibraryA("kernel32.dll");
	MyCreateToolhelp32Snapshot CreateToolhelp32Snapshot = (MyCreateToolhelp32Snapshot)g_pfnGetProcAddress(hModule, "CreateToolhelp32Snapshot");
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	MyProcess32First  Process32First = (MyProcess32First)g_pfnGetProcAddress(hModule, "Process32First");
	BOOL bMore = Process32First(hProcessSnap, &pe32);
	while (bMore)
	{
		if (Mystricmp(pe32.szExeFile, "OllyDBG.EXE") || Mystricmp(pe32.szExeFile, "OllyICE.exe") || Mystricmp(pe32.szExeFile, "x64_dbg.exe")  || Mystricmp(pe32.szExeFile, "windbg.exe") || Mystricmp(pe32.szExeFile, "ImmunityDebugger.exe") )
		{
			return TRUE;
		}
		bMore = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
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
	__try
	{
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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		bRes = false;
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

void RecReloc()
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;		//偏移值
		WORD Type : 4;			//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;

	//1.获取重定位表结构体指针
	PIMAGE_BASE_RELOCATION	pPEReloc =
		(PIMAGE_BASE_RELOCATION)(dwImageBase + g_ShellData.PERelocDir.VirtualAddress);

	//2.开始修复重定位
	while (pPEReloc->VirtualAddress)
	{
		//2.1修改内存属性为可写
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);

		//2.2修复重定位
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pPEReloc + 1);
		DWORD dwNumber = (pPEReloc->SizeOfBlock - 8) / 2;
		for (DWORD i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == NULL)
				break;
			//RVA
			DWORD dwRVA = pTypeOffset[i].offset + pPEReloc->VirtualAddress;
			//FAR地址
			DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)dwImageBase + dwRVA);
			*(PDWORD)((DWORD)dwImageBase + dwRVA) =
				AddrOfNeedReloc - g_ShellData.dwImageBase + dwImageBase;
		}

		//2.3恢复内存属性
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, dwOldProtect, &dwOldProtect);

		//2.4修复下一个区段
		pPEReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pPEReloc + pPEReloc->SizeOfBlock);
	}
}