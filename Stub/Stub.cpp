//���ļ���Stub���ֵ����ļ������β���ʹ�û���Dll����ں�����ֱ������lib
#include "Stub.h"
#include "..//HaCkyPack/StubData.h"

//�ϲ�.data��.rdata�ε�.text�Σ�����.text������Ϊ��дִ�С�
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

//����һ��ȫ�ֱ���������ʼ��
extern "C" __declspec(dllexport)SHELL_DATA g_ShellData = { 0 };

//��ʼ�����Win32����
fnGetProcAddress	g_pfnGetProcAddress = NULL;
fnLoadLibraryA		g_pfnLoadLibraryA = NULL;
fnGetModuleHandleA	g_pfnGetModuleHandleA = NULL;
fnVirtualProtect	g_pfnVirtualProtect = NULL;
fnVirtualAlloc		g_pfnVirtualAlloc = NULL;
fnExitProcess		g_pfnExitProcess = NULL;
fnMessageBox		g_pfnMessageBoxA = NULL;
fnRtlMoveMemory     g_pfnRtlMoveMemory = NULL;

//һЩȫ�ֱ���
DWORD dwImageBase = 0;		//��������ľ����ַ
DWORD dwNewOEP = 0;		    //PE�ļ���OEP
unsigned char data[94] = {
	0x47, 0x9B, 0xF7, 0x91, 0xFE, 0x1A, 0xD5, 0x57, 0xEE, 0x12, 0x12, 0x12, 0x12, 0x91, 0x6F, 0xEE,
	0x15, 0x65, 0x52, 0xD5, 0x57, 0xEA, 0x12, 0x12, 0x12, 0x12, 0x91, 0x6F, 0xEA, 0x2C, 0x65, 0x3E,
	0x99, 0x57, 0x1E, 0x11, 0x57, 0xEE, 0x1D, 0xAC, 0x02, 0x99, 0x57, 0x02, 0x11, 0x57, 0xEA, 0x1D,
	0xAC, 0x12, 0x2B, 0xD0, 0x67, 0x1D, 0x99, 0x57, 0x1A, 0x99, 0x47, 0xEE, 0x13, 0xD0, 0x99, 0x57,
	0xEA, 0x16, 0x22, 0x9A, 0x10, 0x9F, 0x57, 0xEA, 0xED, 0x12, 0xF9, 0xDC, 0x9F, 0x57, 0xEE, 0xED,
	0x12, 0xF9, 0xA8, 0x99, 0x57, 0x1A, 0x91, 0xD2, 0x15, 0xD4, 0x12, 0x12, 0xDB, 0xD1
};


//************************************************************
//Start()��Stub.dll�ʼִ�еĵط��������Կ�ʼ�ĵط�
//ChildFunc��NULL
//************************************************************
//extern "C" __declspec(dllexport) __declspec(naked)
extern "C" __declspec(dllexport) __declspec()
void Start()
{
	//Step1:�����ǻ�ȡ����Win32������ַ
	InitWin32FunAddr();


	//Step3:���ܼ��ܵ��ַ���
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
	




	//Step2:�ָ�IAT���ݱ�
	RecoverDataDir();
	
	//Step3:���IAT
	FixIAT();

	//AntiDump
	AntiDumpByImageSize();
	//AntiDumpByMemory();   //ע����vs2017��д�ĳ��������׳��ֱ���


	//Step2������IAT��
	//DecryptIAT();



	//Step2:���ܴ����
	//��Ҫ����KEY
	DecryptCodeSeg();

	FindString(TmplpBaseAddress, TmpImageSize);



	//Step3:������
	//if (CheckDebugByDbgWindow())
	//{
	//	ExitProcess(0);
	//}
	//������
	//IAT���ܵ�
	//��ת�������ڵ�

	//���øı�ָ�������ӻ�
	DWORD p = 0;
	__asm {
		call	l1;
	l1:
		pop		eax;
		mov		p, eax;			//ȷ����ǰ����ε�λ��
		call	f1;
		_EMIT	0xEA;			//��ָ��˴���Զ����ִ�е�
		jmp		l2;				//call�����Ժ�ִ�е�����
	f1:
		pop ebx;
		inc ebx;
		push ebx;
		mov eax, 0x1234567;
		ret;
	l2:
		call f2;				//��retָ��ʵ����ת
		mov ebx, 0x1234567;	    //������Զ����ִ�е�
		jmp e;
	f2:
		mov ebx, 0x1234567;
		pop ebx;				//����ѹջ�ĵ�ַ
		mov ebx, offset e;		
		push ebx;				
		ret;					//��ת
	e:
		mov ebx, 0x1234567;
	}
	dwNewOEP = g_ShellData.dwOEP + g_ShellData.dwImageBase;
	_asm jmp dwNewOEP
}


//************************************************************
//InitWin32FunAddr()����ʼ��Win32����
//ChildFunc��GetKernel32BaseAddr()
             //MyGetProcAddress
//************************************************************
void InitWin32FunAddr()
{
	//��Kenel32�л�ȡ����
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
//��ȡKernel32��BaseAddress
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
//��ȡGetProcAddress ������ַ
//ChildFunc:GetKernel32BaseAddr
            //MyStrcmp
//************************************************************
DWORD MyGetProcAddress()
{
	//Kernel32�Ļ���ַ
	HMODULE hKernel32 = GetKernel32BaseAddr();

	//ͨ���������ȡGetProcAddress�ĵ�ַ
	//1.��ȡDOSͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(PBYTE)hKernel32;
	//2.��ȡNTͷ
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hKernel32 + pDosHeader->e_lfanew);
	//3.��ȡ������Ľṹ��ָ��
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

	//4.������������ȡGetProcAddress()������ַ
	DWORD dwNumofFun = pExport->NumberOfFunctions;
	DWORD dwNumofName = pExport->NumberOfNames;
	for (DWORD i = 0; i < dwNumofFun; i++)
	{
		//���Ϊ��Ч����������
		if (pEAT[i] == NULL)
			continue;
		//�ж����Ժ�����������������ŵ���
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
			//���жԱ�,�����ȷ���ص�ַ
			if (MyStrcmp(ExpFunName, "GetProcAddress"))
			{
				return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
			}
		}
	}
	return 0;
}


//************************************************************
//FixIAT():ģ��PE������WinLoader���IAT
//ChildFunc:SetFileHeaderProtect �޸��ڴ汣������
//************************************************************
void FixIAT()
{
	//�����ļ�����Ϊ��д
	SetFileHeaderProtect(true);
	//��ȡ��ǰ����ļ��ػ�ַ
	DWORD ImageBase = (DWORD)g_pfnGetModuleHandleA(NULL);
	                         

	IMAGE_THUNK_DATA* pOrigalFirstThunk = NULL;
	IMAGE_THUNK_DATA* pFirstThunk = NULL;
	DWORD dwFunAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptionHeader((LPBYTE)ImageBase)->DataDirectory[1].VirtualAddress)
		return;

	//�����=�����ƫ��+���ػ�ַ
	IMAGE_IMPORT_DESCRIPTOR* pImportTable = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptionHeader((LPBYTE)ImageBase)->DataDirectory[1].VirtualAddress + ImageBase);


	while (pImportTable->Name)
	{
		//IAT=ƫ�ƼӼ��ػ�ַ
		pFirstThunk = (IMAGE_THUNK_DATA*)(pImportTable->FirstThunk + ImageBase);
		if (pImportTable->OriginalFirstThunk == 0) // ���������INT��ʹ��IAT
		{
			pOrigalFirstThunk = pFirstThunk;
		}
		else
		{
			pOrigalFirstThunk = (IMAGE_THUNK_DATA*)(pImportTable->OriginalFirstThunk + ImageBase);
		}

		// ����dll
		hImpModule = (HMODULE)g_pfnLoadLibraryA((char*)(pImportTable->Name + ImageBase));
		//���뺯����ַ
		while (pOrigalFirstThunk->u1.Function)
		{
			//�жϵ���ķ�ʽ����Ż�������
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
// SetFileHeaderProtect:�޸��ڴ汣������
// ChildFunc:NULL
//************************************************************
void SetFileHeaderProtect(bool nWrite)
{
	//��ȡ��ǰ����ļ��ػ�ַ
	DWORD ImageBase = (DWORD)g_pfnGetModuleHandleA(NULL);
	DWORD nOldProtect = 0;
	if (nWrite)
		g_pfnVirtualProtect((LPVOID)ImageBase, 0x400, PAGE_EXECUTE_READWRITE, &nOldProtect);
	else
		g_pfnVirtualProtect((LPVOID)ImageBase, 0x400, nOldProtect, &nOldProtect);
}


//************************************************************
//DecryptIAT:����IAT
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

	//������ģ��
	while (pImportTable->Name)
	{
		//��ȡ��ǰģ���ַ
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

			//����������
			char*FunName = 0;
			//�ڲ����ģ���еĺ���
			while (pThunk->u1.Ordinal)
			{
				//��ŵ���
				if (pThunk->u1.Ordinal & 0x80000000)
				{
					FunName = (char*)(pThunk->u1.Ordinal & 0x7fffffff);
				}
				else
				{
				//���Ƶ���
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)
						(pThunk->u1.Ordinal + (DWORD)hModule);
					FunName = pImportByName->Name;
				}

				DWORD dwFunAddr = (DWORD)g_pfnGetProcAddress(hDllModule, FunName);
				//���ܺ�����ַ
				dwFunAddr ^= 0x13973575;
				LPVOID AllocMem = (PDWORD)g_pfnVirtualAlloc(NULL, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				//��Һ������õ���һ�׼����߼�
				byte OpCode[] = { 0xe8, 0x01, 0x00, 0x00,
								  0x00, 0xe9, 0x58, 0xeb,
								  0x01, 0xe8, 0xb8, 0x8d,
								  0xe4, 0xd8, 0x62, 0xeb,
								  0x01, 0x15, 0x35, 0x75,
								  0x35, 0x97, 0x13, 0xeb,
								  0x01, 0xff, 0x50, 0xeb,
								  0x02, 0xff, 0x15, 0xc3 };
				//��dwFunAddrд�뵽���ܵ�ShellCode��
				OpCode[11] = dwFunAddr;
				OpCode[12] = dwFunAddr >> 0x8;
				OpCode[13] = dwFunAddr >> 0x10;
				OpCode[14] = dwFunAddr >> 0x18;

				//�������ݵ�������ڴ�
				g_pfnRtlMoveMemory(AllocMem, OpCode, 0x20);

				//�޸ı�������
				DWORD dwProtect = 0;
				g_pfnVirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &dwProtect);
				//�ѻ�ȡ���ļ��ܺ�����ַ����ڵ����ַ������
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
//RecoverDataDir:�ָ�����Ŀ¼
//ChildFunc:NULL
//************************************************************
void RecoverDataDir()
{
	//��ȡ��ǰ����ļ��ػ�ַ
	char* dwBase = (char*)g_pfnGetModuleHandleA(NULL);
	//��ȡ����Ŀ¼��ĸ���
	DWORD dwNumOfDataDir = g_ShellData.dwNumOfDataDir;

	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptionHeader((LPBYTE)dwBase)->DataDirectory);
	//��������Ŀ¼��
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}

		//�޸�����Ϊ�ɶ���д
		g_pfnVirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);

		//��ԭ����Ŀ¼����
		pDataDirectory->VirtualAddress = g_ShellData.dwDataDir[i][0];
		pDataDirectory->Size = g_ShellData.dwDataDir[i][1];

		//�������޸Ļ�ȥ
		g_pfnVirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);

		pDataDirectory++;
	}
}


//************************************************************
//MyStrcmp:�Ƚ������ַ���
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
//DecryptCodeSeg:���ܱ����ܵĴ����
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
		
	//��ȡ������CSP-API��ַ
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
	//�����ǽ����㷨
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	LPBYTE pbBuffer = NULL;
	DWORD dwBlockLen = 0;
	DWORD dwBufferLen = 0;
	DWORD dwCount = 0;
	if (MyCryptAcquireContextA(
		&hCryptProv,
		NULL,               //�û���½�� NULL��ʾʹ��Ĭ����Կ������Ĭ����Կ������
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
			CRYPT_NEWKEYSET))//������Կ����
		{
			//������Կ�����ɹ������õ�CSP���
		//	printf("A new key container has been created.\n");
		}
		else
		{
		//	printf("Could not create a new key container.\n");
		}
	}

	// ����һ���Ự��Կ
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
	// ��������������һ��ɢ��
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

	// ͨ��ɢ�����ɻỰ��Կ
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
	// ��Ϊ�����㷨�ǰ�ENCRYPT_BLOCK_SIZE ��С�Ŀ���ܵģ����Ա����ܵ�
	// ���ݳ��ȱ�����ENCRYPT_BLOCK_SIZE �����������������һ�μ��ܵ�
	// ���ݳ��ȡ�
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	if (ENCRYPT_BLOCK_SIZE > 1)
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	else
		dwBufferLen = dwBlockLen;

	//���ٿռ䣬׼�����ܴ����
	HANDLE hHeap = MyHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, dwBufferLen, 0);
	pbBuffer = (LPBYTE)MyHeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferLen);


	// ��������
	DWORD dwTmp1 = 0;
	DWORD dwTmpCodeSize1 = g_ShellData.dwCodeSize;
	BOOL bFinual1 = FALSE;

	DWORD dwProtect = 0;
	g_pfnVirtualProtect(lpCodeBase, dwTmpCodeSize1, PAGE_EXECUTE_READWRITE, &dwProtect);
	do
	{
		//�ж��Ƿ������һ��
		if (dwTmpCodeSize1 > dwBlockLen)
		{
			MyRtlMoveMemory(pbBuffer, (lpCodeBase + dwTmp1), dwBlockLen);
			dwCount = dwBlockLen;
			bFinual1 = FALSE;     //˵�����ڶ����С���������һ��
		}
		else
		{
			MyRtlMoveMemory(pbBuffer, (lpCodeBase + dwTmp1), dwTmpCodeSize1);
			dwCount = dwTmpCodeSize1;
			bFinual1 = TRUE;      //˵��С�ڵ��ڶ����С�������һ��
		}

		if (!MyCryptDecrypt(
			hKey,           //��Կ
			0,              //�������ͬʱ����ɢ�кͼ��ܣ����ﴫ��һ��ɢ�ж���
			bFinual1,        //��������һ�������ܵĿ飬����TRUE.�����������FALSE
			0,              //����
			pbBuffer,       //���뱻�������ݣ�������ܺ������
			&dwCount))       //���뱻��������ʵ�ʳ��ȣ�������ܺ����ݳ���
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
//DecryKey������Key
//ChildFunc��NULL
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
		WORD offset : 12;		//ƫ��ֵ
		WORD Type : 4;			//�ض�λ����(��ʽ)
	}TYPEOFFSET, *PTYPEOFFSET;

	//1.��ȡ�ض�λ��ṹ��ָ��
	PIMAGE_BASE_RELOCATION	pPEReloc =
		(PIMAGE_BASE_RELOCATION)(dwImageBase + g_ShellData.PERelocDir.VirtualAddress);

	//2.��ʼ�޸��ض�λ
	while (pPEReloc->VirtualAddress)
	{
		//2.1�޸��ڴ�����Ϊ��д
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);

		//2.2�޸��ض�λ
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pPEReloc + 1);
		DWORD dwNumber = (pPEReloc->SizeOfBlock - 8) / 2;
		for (DWORD i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == NULL)
				break;
			//RVA
			DWORD dwRVA = pTypeOffset[i].offset + pPEReloc->VirtualAddress;
			//FAR��ַ
			DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)dwImageBase + dwRVA);
			*(PDWORD)((DWORD)dwImageBase + dwRVA) =
				AddrOfNeedReloc - g_ShellData.dwImageBase + dwImageBase;
		}

		//2.3�ָ��ڴ�����
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, dwOldProtect, &dwOldProtect);

		//2.4�޸���һ������
		pPEReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pPEReloc + pPEReloc->SizeOfBlock);
	}
}


//�ָ����ܵ��ַ���
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
		//��������ĸ��ַ����ǿɴ�ӡ�ַ��������Ҫ��
		if ((lpBaseAddress[i] >= 0x20 && lpBaseAddress[i] <= 0x7E)
			&& (lpBaseAddress[i + 1] >= 0x20 && lpBaseAddress[i + 1] <= 0x7E)
			&& (lpBaseAddress[i + 2] >= 0x20 && lpBaseAddress[i + 2] <= 0x7E)
			&& (lpBaseAddress[i + 3] >= 0x20 && lpBaseAddress[i + 3] <= 0x7E))
		{
			//����Ҫ�����¼һ�³��ֵļ�����Ա���ڼ���
			//�˴�Ӧ��ѭ��һ��
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