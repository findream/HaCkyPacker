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
fnRtlMoveMemory     g_pfnRtlMoveMemory = NULL;

//一些全局变量
DWORD dwImageBase = 0;		//整个程序的镜像基址
DWORD dwNewOEP = 0;		    //PE文件的OEP
unsigned char data[94] = {
	0x47, 0x9B, 0xF7, 0x91, 0xFE, 0x1A, 0xD5, 0x57, 0xEE, 0x12, 0x12, 0x12, 0x12, 0x91, 0x6F, 0xEE,
	0x15, 0x65, 0x52, 0xD5, 0x57, 0xEA, 0x12, 0x12, 0x12, 0x12, 0x91, 0x6F, 0xEA, 0x2C, 0x65, 0x3E,
	0x99, 0x57, 0x1E, 0x11, 0x57, 0xEE, 0x1D, 0xAC, 0x02, 0x99, 0x57, 0x02, 0x11, 0x57, 0xEA, 0x1D,
	0xAC, 0x12, 0x2B, 0xD0, 0x67, 0x1D, 0x99, 0x57, 0x1A, 0x99, 0x47, 0xEE, 0x13, 0xD0, 0x99, 0x57,
	0xEA, 0x16, 0x22, 0x9A, 0x10, 0x9F, 0x57, 0xEA, 0xED, 0x12, 0xF9, 0xDC, 0x9F, 0x57, 0xEE, 0xED,
	0x12, 0xF9, 0xA8, 0x99, 0x57, 0x1A, 0x91, 0xD2, 0x15, 0xD4, 0x12, 0x12, 0xDB, 0xD1
};


//************************************************************
//Start()：Stub.dll最开始执行的地方，反调试开始的地方
//ChildFunc：NULL
//************************************************************
//extern "C" __declspec(dllexport) __declspec(naked)
extern "C" __declspec(dllexport) __declspec()
void Start()
{
	//Step1:首先是获取所有Win32函数地址
	InitWin32FunAddr();


	//Step3:解密加密的字符串
	LPBYTE lpBaseAddress = NULL;
	DWORD TmpImageSize = 0;
	LPBYTE TmplpBaseAddress = NULL;
	lpBaseAddress = (LPBYTE)g_pfnGetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

	PIMAGE_NT_HEADERS pImageNtHeaders =
		(PIMAGE_NT_HEADERS)((DWORD)lpBaseAddress + pImageDosHeader->e_lfanew);  //

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);

	while (pSectionHeader->Name)
	{
		char* SectionName = (char*)(pSectionHeader->Name);
		if (MyStrcmp(SectionName, ".rdata"))
		{
			TmplpBaseAddress = (LPBYTE)(pSectionHeader->VirtualAddress + (DWORD)lpBaseAddress);
			TmpImageSize = pSectionHeader->SizeOfRawData;
			break;
		}
		pSectionHeader++;
	}
	




	//Step2:恢复IAT数据表
	RecoverDataDir();
	
	//Step3:填充IAT
	FixIAT();

	//AntiDump
	AntiDumpByImageSize();
	//AntiDumpByMemory();   //注意在vs2017编写的程序中容易出现奔溃


	//Step2：加密IAT表
	//DecryptIAT();



	//Step2:解密代码段
	//需要解密KEY
	DecryptCodeSeg();

	FindString(TmplpBaseAddress, TmpImageSize);



	//Step3:反调试
	//if (CheckDebugByDbgWindow())
	//{
	//	ExitProcess(0);
	//}
	//反调试
	//IAT加密等
	//跳转入程序入口点

	//采用改变指令流来加花
	DWORD p = 0;
	__asm {
		call	l1;
	l1:
		pop		eax;
		mov		p, eax;			//确定当前程序段的位置
		call	f1;
		_EMIT	0xEA;			//花指令，此处永远不会执行到
		jmp		l2;				//call结束以后执行到这里
	f1:
		pop ebx;
		inc ebx;
		push ebx;
		mov eax, 0x1234567;
		ret;
	l2:
		call f2;				//用ret指令实现跳转
		mov ebx, 0x1234567;	    //这里永远不会执行到
		jmp e;
	f2:
		mov ebx, 0x1234567;
		pop ebx;				//弹出压栈的地址
		mov ebx, offset e;		
		push ebx;				
		ret;					//跳转
	e:
		mov ebx, 0x1234567;
	}
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

	HMODULE hNtdll = g_pfnLoadLibraryA("Ntdll.dll");
	g_pfnRtlMoveMemory = (fnRtlMoveMemory)g_pfnGetProcAddress(hNtdll, "RtlMoveMemory");
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
//DecryptIAT:加密IAT
//ChilddFunc:NULL
//https://www.jianshu.com/p/1ee8bf2ec131
//https://zhuanlan.zhihu.com/p/66096824
//************************************************************
void  DecryptIAT()
{
	//FILE *fp = fopen("HackyPackLog.log", "a");
	HMODULE hModule = (HMODULE)GetModuleHandle(NULL);
	DWORD dwRvaOfImportTable =
		GetOptionHeader((LPBYTE)hModule)->DataDirectory[1].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(dwRvaOfImportTable + (DWORD)hModule);

	//外层遍历模块
	while (pImportTable->Name)
	{
		//获取当前模块地址
		char* dllName = (char*)((DWORD)hModule + pImportTable->Name);
		HMODULE hDllModule = g_pfnLoadLibraryA(dllName);
		if (pImportTable->FirstThunk)
		{
			//IAT
			PDWORD FirstThunk = PDWORD(pImportTable->FirstThunk + (DWORD)hModule);
			DWORD ThunkRva = 0;
			if (pImportTable->OriginalFirstThunk == 0)
				ThunkRva = pImportTable->FirstThunk;
			else
				ThunkRva = pImportTable->OriginalFirstThunk;
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(ThunkRva + (DWORD)hModule);

			//函数的名字
			char*FunName = 0;
			//内层遍历模块中的函数
			while (pThunk->u1.Ordinal)
			{
				//序号导入
				if (pThunk->u1.Ordinal & 0x80000000)
				{
					FunName = (char*)(pThunk->u1.Ordinal & 0x7fffffff);
				}
				else
				{
				//名称导入
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)
						(pThunk->u1.Ordinal + (DWORD)hModule);
					FunName = pImportByName->Name;
				}

				DWORD dwFunAddr = (DWORD)g_pfnGetProcAddress(hDllModule, FunName);
				//加密函数地址
				dwFunAddr ^= 0x13973575;
				LPVOID AllocMem = (PDWORD)g_pfnVirtualAlloc(NULL, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				//大家好像都是用的这一套加密逻辑
				byte OpCode[] = { 0xe8, 0x01, 0x00, 0x00,
								  0x00, 0xe9, 0x58, 0xeb,
								  0x01, 0xe8, 0xb8, 0x8d,
								  0xe4, 0xd8, 0x62, 0xeb,
								  0x01, 0x15, 0x35, 0x75,
								  0x35, 0x97, 0x13, 0xeb,
								  0x01, 0xff, 0x50, 0xeb,
								  0x02, 0xff, 0x15, 0xc3 };
				//把dwFunAddr写入到解密的ShellCode中
				OpCode[11] = dwFunAddr;
				OpCode[12] = dwFunAddr >> 0x8;
				OpCode[13] = dwFunAddr >> 0x10;
				OpCode[14] = dwFunAddr >> 0x18;

				//拷贝数据到申请的内存
				g_pfnRtlMoveMemory(AllocMem, OpCode, 0x20);

				//修改保护属性
				DWORD dwProtect = 0;
				g_pfnVirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &dwProtect);
				//把获取到的加密函数地址填充在导入地址表里面
				*(FirstThunk) = (DWORD)AllocMem;
				g_pfnVirtualProtect(FirstThunk, 4, dwProtect, &dwProtect);

				++FirstThunk;
				++pThunk;
			}
		}
		++pImportTable;
	}
	//fclose(fp);
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

void Mystrcpy(char* s, char* t)
{
	for (int i = 0; i < 8; i++)
	{
		s[i] = t[i];
	}
	//do
	//{
	//	*s++ = *t++;
	//} while (*t != '\0');
}

//************************************************************
//DecryptCodeSeg:解密被加密的代码段
//ChildFunc:NULL
//************************************************************
void DecryptCodeSeg()
{
	char szPassword[8] = { 0 };
	//DecryKey(szPassword,g_ShellData.dwAESKey);//"0EpqKsg";
	char Table[] = "0123456789ABCDEFGEIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	int  Size = 94;
	DWORD Old = 0;
	VirtualProtect(data, Size, PAGE_EXECUTE_READWRITE, &Old);
	for (int i = 0; i < Size; i++)
	{
		data[i] ^= 0x12;
	}

	(*(void(*)(char*, char*,char*))&data)(szPassword, g_ShellData.dwAESKey, Table);
	VirtualProtect(data, Size, Old, &Old);
		
	//获取常见的CSP-API地址
	HMODULE hAdvapi32 = g_pfnLoadLibraryA("Advapi32.dll");
	HMODULE hNtdll = g_pfnLoadLibraryA("ntdll.dll");
	HMODULE hKerel32 = g_pfnLoadLibraryA("Kernel32.dll");
	pfnCryptAcquireContextA  MyCryptAcquireContextA =
		(pfnCryptAcquireContextA)g_pfnGetProcAddress(hAdvapi32,"CryptAcquireContextA");

	pfnCryptCreateHash MyCryptCreateHash = 
		(pfnCryptCreateHash)g_pfnGetProcAddress(hAdvapi32, "CryptCreateHash");

	pfnCryptHashData MyCryptHashData = 
		(pfnCryptHashData)g_pfnGetProcAddress(hAdvapi32, "CryptHashData");

	pfnCryptDeriveKey MyCryptDeriveKey = 
		(pfnCryptDeriveKey)g_pfnGetProcAddress(hAdvapi32, "CryptDeriveKey");

	pfnCryptDestroyHash MyCryptDestroyHash = 
		(pfnCryptDestroyHash)g_pfnGetProcAddress(hAdvapi32, "CryptDestroyHash");

	pfnCryptDecrypt MyCryptDecrypt = 
		(pfnCryptDecrypt)g_pfnGetProcAddress(hAdvapi32, "CryptDecrypt");

	pfnCryptDestroyKey MyCryptDestroyKey = 
		(pfnCryptDestroyKey)g_pfnGetProcAddress(hAdvapi32, "CryptDestroyKey");

	pfnCryptReleaseContext MyCryptReleaseContext = 
		(pfnCryptReleaseContext)g_pfnGetProcAddress(hAdvapi32, "CryptReleaseContext");

	pfnHeapCreate MyHeapCreate = 
		(pfnHeapCreate)g_pfnGetProcAddress(hKerel32, "HeapCreate");

	pfnHeapAlloc MyHeapAlloc = 
		(pfnHeapAlloc)g_pfnGetProcAddress(hKerel32, "HeapAlloc");

	fnRtlMoveMemory MyRtlMoveMemory =
		(fnRtlMoveMemory)g_pfnGetProcAddress(hNtdll, "RtlMoveMemory");

	pfnHeapFree MyHeapFree = 
		(pfnHeapFree)g_pfnGetProcAddress(hKerel32, "HeapFree");



	DWORD i = 0;
	LPBYTE lpCodeBase = (LPBYTE)(g_ShellData.dwCodeBase + g_ShellData.dwImageBase);
	//以下是解密算法
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	LPBYTE pbBuffer = NULL;
	DWORD dwBlockLen = 0;
	DWORD dwBufferLen = 0;
	DWORD dwCount = 0;
	if (MyCryptAcquireContextA(
		&hCryptProv,
		NULL,               //用户登陆名 NULL表示使用默认密钥容器，默认密钥容器名
		NULL,
		PROV_RSA_FULL,
		0))
	{
	//	printf("A cryptographic provider has been acquired. \n");
	}
	else
	{
		if (MyCryptAcquireContextA(
			&hCryptProv,
			NULL,
			NULL,
			PROV_RSA_AES,
			CRYPT_NEWKEYSET))//创建密钥容器
		{
			//创建密钥容器成功，并得到CSP句柄
		//	printf("A new key container has been created.\n");
		}
		else
		{
		//	printf("Could not create a new key container.\n");
		}
	}

	// 创建一个会话密钥
	if (MyCryptCreateHash(
		hCryptProv,
		CALG_MD5,
		0,
		0,
		&hHash))
	{
	//	printf("A hash object has been created. \n");
	}
	else
	{
	//	printf("Error during CryptCreateHash!\n");
	}
	// 用输入的密码产生一个散列
	if (MyCryptHashData(
		hHash,
		(BYTE *)szPassword,
		7,
		0))
	{
	//	printf("The password has been added to the hash. \n");
	}
	else
	{
		//printf("Error during CryptHashData. \n");
	}

	// 通过散列生成会话密钥
	if (MyCryptDeriveKey(
		hCryptProv,
		ENCRYPT_ALGORITHM,
		//CALG_AES_128,
		hHash,
		KEYLENGTH,
		&hKey))
	{
	//	printf("An encryption key is derived from the password hash. \n");
	}
	else
	{
	//	printf("Error during CryptDeriveKey!\n");
	}
	MyCryptDestroyHash(hHash);
	hHash = NULL;
	// 因为加密算法是按ENCRYPT_BLOCK_SIZE 大小的块加密的，所以被加密的
	// 数据长度必须是ENCRYPT_BLOCK_SIZE 的整数倍。下面计算一次加密的
	// 数据长度。
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	if (ENCRYPT_BLOCK_SIZE > 1)
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	else
		dwBufferLen = dwBlockLen;

	//开辟空间，准备加密代码段
	HANDLE hHeap = MyHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, dwBufferLen, 0);
	pbBuffer = (LPBYTE)MyHeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferLen);


	// 加密数据
	DWORD dwTmp1 = 0;
	DWORD dwTmpCodeSize1 = g_ShellData.dwCodeSize;
	BOOL bFinual1 = FALSE;

	DWORD dwProtect = 0;
	g_pfnVirtualProtect(lpCodeBase, dwTmpCodeSize1, PAGE_EXECUTE_READWRITE, &dwProtect);
	do
	{
		//判断是否是最后一块
		if (dwTmpCodeSize1 > dwBlockLen)
		{
			MyRtlMoveMemory(pbBuffer, (lpCodeBase + dwTmp1), dwBlockLen);
			dwCount = dwBlockLen;
			bFinual1 = FALSE;     //说明大于对齐大小，不是最后一块
		}
		else
		{
			MyRtlMoveMemory(pbBuffer, (lpCodeBase + dwTmp1), dwTmpCodeSize1);
			dwCount = dwTmpCodeSize1;
			bFinual1 = TRUE;      //说明小于等于对齐大小，是最后一块
		}

		if (!MyCryptDecrypt(
			hKey,           //密钥
			0,              //如果数据同时进行散列和加密，这里传入一个散列对象
			bFinual1,        //如果是最后一个被加密的块，输入TRUE.如果不是输入FALSE
			0,              //保留
			pbBuffer,       //输入被加密数据，输出加密后的数据
			&dwCount))       //输入被加密数据实际长度，输出加密后数据长度
		{
		//	printf("Error during CryptEncrypt. \n");
		}

		MyRtlMoveMemory(lpCodeBase + dwTmp1, pbBuffer, dwCount);
		dwTmp1 += dwCount;
		dwTmpCodeSize1 -= dwCount;
	} while (dwTmpCodeSize1 > 0);

	g_pfnVirtualProtect(lpCodeBase, dwTmpCodeSize1, dwProtect, &dwProtect);

	if (pbBuffer
		&&hKey
		&&hCryptProv)
	{
		MyHeapFree(hHeap, HEAP_NO_SERIALIZE, pbBuffer);
		MyCryptDestroyKey(hKey);
		//CryptDestroyHash(hHash);
		MyCryptReleaseContext(hCryptProv, 0);
	}


}
//************************************************************
//DecryKey：解密Key
//ChildFunc：NULL
//************************************************************
void DecryKey(char* src,char* str)
{
	char Table[] = "0123456789ABCDEFGEIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	//char input[8] = { 0 };
	for (DWORD i = 0; i < 8; i++)
	{
		for (DWORD j = 0; j < 63; j++)
		{
			if (str[i] == Table[j])
			{
				src[i] = j + 48;
			}
		}
	}
	src[7] = '\0';
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


//恢复加密的字符串
BOOL  FindString(LPBYTE lpBaseAddress, DWORD ImageSize)
{
	HMODULE hKerel32 = g_pfnLoadLibraryA("Kernel32.dll");
	pfnHeapCreate MyHeapCreate =
		(pfnHeapCreate)g_pfnGetProcAddress(hKerel32, "HeapCreate");

	pfnHeapAlloc MyHeapAlloc =
		(pfnHeapAlloc)g_pfnGetProcAddress(hKerel32, "HeapAlloc");

	pfnHeapFree MyHeapFree =
		(pfnHeapFree)g_pfnGetProcAddress(hKerel32, "HeapFree");

	DWORD dwOld = 0;
	g_pfnVirtualProtect(lpBaseAddress, ImageSize, PAGE_EXECUTE_READWRITE, &dwOld);
	DWORD i = 0;
	do
	{
		DWORD Tmp = 0;
		//char String[260] = { 0 };
		HANDLE hHeap = MyHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 260, 0);
		char* String = (char*)MyHeapAlloc(hHeap, HEAP_ZERO_MEMORY, 260);
		//如果连续四个字符都是可打印字符，则符合要求
		if ((lpBaseAddress[i] >= 0x20 && lpBaseAddress[i] <= 0x7E)
			&& (lpBaseAddress[i + 1] >= 0x20 && lpBaseAddress[i + 1] <= 0x7E)
			&& (lpBaseAddress[i + 2] >= 0x20 && lpBaseAddress[i + 2] <= 0x7E)
			&& (lpBaseAddress[i + 3] >= 0x20 && lpBaseAddress[i + 3] <= 0x7E))
		{
			//符合要求则记录一下出现的间隔，以便后期加上
			//此处应该循环一下
			while (lpBaseAddress[i + Tmp] >= 0x20 && lpBaseAddress[i + Tmp] <= 0x7E)
			{
				String[Tmp] = lpBaseAddress[i + Tmp] ^ 0x123;
				lpBaseAddress[i + Tmp] = String[Tmp];
				Tmp++;
			}
			String[Tmp + 1] = '\0';
			//	fprintf(fp, "[*]Packer::FindString--->NewString:%s\n", String);

		}
		MyHeapFree(hHeap, HEAP_NO_SERIALIZE, String);
		i += (Tmp + 1);
	} while (i < ImageSize);
	g_pfnVirtualProtect(lpBaseAddress, ImageSize, dwOld, &dwOld);
	return TRUE;
}