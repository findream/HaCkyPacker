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

//һЩȫ�ֱ���
DWORD dwImageBase = 0;		//��������ľ����ַ
DWORD dwNewOEP = 0;		    //PE�ļ���OEP


//************************************************************
//Start()��Stub.dll�ʼִ�еĵط��������Կ�ʼ�ĵط�
//ChildFunc��NULL
//************************************************************
extern "C" __declspec(dllexport) __declspec(naked)
void Start()
{
	//Step1:�����ǻ�ȡ����Win32������ַ
	InitWin32FunAddr();


	//Step2:�ָ�IAT���ݱ�
	RecoverDataDir();
	
	//Step3:���IAT
	FixIAT();

	//Step2������IAT��
	//DecryptIAT();



	//Step2:���ܴ����
	DecryptCodeSeg(g_ShellData.dwXorKey);

	//Step3:������
	//if (CheckDebugByDbgWindow())
	//{
	//	ExitProcess(0);
	//}
	//������
	//IAT���ܵ�
	//��ת�������ڵ�
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
//************************************************************
void  DecryptIAT()
{
	FILE *fp = fopen("HackyPackLog.log", "a");

	LPBYTE lpFinalBuf = (LPBYTE)g_pfnGetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFinalBuf;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpFinalBuf + pDosHeader->e_lfanew);
	DWORD Rav_Import_Table = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR ImportTable = PIMAGE_IMPORT_DESCRIPTOR((DWORD)lpFinalBuf + Rav_Import_Table);

	//�������е�IID
	//����IIDpFirsrThunk
	while (ImportTable->Name)
	{
		//DllName
		//��ȡRvaOfDllName
		PDWORD dwTmpDllName = &ImportTable->Name;
		fprintf(fp, "[*]Packer::EncryIAT--->dwOldRvaOfDllName��%x\n", *dwTmpDllName);


		char* pDllName = (char*)((DWORD)lpFinalBuf + ImportTable->Name);
		fprintf(fp, "[*]Packer::EncryIAT--->dwOldDllName��%s\n", pDllName);
		for (DWORD i = 0; i < strlen(pDllName); i++)
			pDllName[i] ^= 0x234;
		fprintf(fp, "[*]Packer::EncryIAT--->dwNewDllName��%s\n", pDllName);

		//������ǰ�޸�RvaOfDllNameֵ����DllName��ȡ����
		*dwTmpDllName = *dwTmpDllName ^ 0x123;
		fprintf(fp, "[*]Packer::EncryIAT--->dwNewRvaOfDllName��%x\n", *dwTmpDllName);

		PIMAGE_THUNK_DATA pFirsrThunk = (PIMAGE_THUNK_DATA)((DWORD)lpFinalBuf + ImportTable->FirstThunk);
		//����ÿ��IAT
		while (pFirsrThunk->u1.AddressOfData)
		{

			//�������ŷ�ʽ����
			if (IMAGE_SNAP_BY_ORDINAL(pFirsrThunk->u1.AddressOfData))
			{
				PDWORD dwTmpOrd = &pFirsrThunk->u1.Ordinal;
				*dwTmpOrd = *dwTmpOrd ^ 0x234;
			}
			else
			{
				//�˴���ȡ���Ǻ�����ַ
				PDWORD FuncAddr = &pFirsrThunk->u1.Function;
				fprintf(fp, "[*]Packer::EncryIAT--->u1.Function��%x\n", *FuncAddr);


				//�˴���Ӧ�û�ȡ��������
				PIMAGE_IMPORT_BY_NAME pThunkName = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpFinalBuf + pFirsrThunk->u1.AddressOfData);

				PWORD Hint = &pThunkName->Hint;
				fprintf(fp, "[*]Packer::EncryIAT--->u1.OldFunction��%x\n", *Hint);

				char* FuncName = pThunkName->Name;
				fprintf(fp, "[*]Packer::EncryIAT--->OldFuncName��%s\n", FuncName);

				for (DWORD i = 0; i < strlen(FuncName); i++)
					FuncName[i] ^= 0x234;
				fprintf(fp, "[*]Packer::EncryIAT--->NewFuncName��%s\n", FuncName);

				*FuncAddr = *FuncAddr ^ 0x345;
				//*(PDWORD)((DWORD)lpBaseAddress + pFirsrThunk->u1.Function) = TmpFuncAddr;
				fprintf(fp, "[*]Packer::EncryIAT--->NewFuncAddr��%x\n", *FuncAddr);

				*Hint = *Hint ^ 0x456;
				fprintf(fp, "[*]Packer::EncryIAT--->NewHint ��%x\n", *Hint);
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


//************************************************************
//DecryptCodeSeg:���ܱ����ܵĴ����
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
//CheckDebugByNtQueryInformationProcess_ProcessDebugPort:����NtQueryInformationProcess���з�����
//ChildFunc:NULL
//ԭ��NtQueryInformationProcess��û�й�����Ntdll�ĺ�����ͨ�����õڶ������������ͣ�Ȼ��õ�������������ֵ
//�жϸ�ֵ�Ƿ�Ϊ0�����Ϊ0��˵��û�б�����
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
//CheckDebugByNtQueryInformationProcess_ProcessDebugObjectHandle:����NtQueryInformationProcess���з�����
//ChildFunc:NULL
//ԭ��NtQueryInformationProcess��û�й�����Ntdll�ĺ�����ͨ�����õڶ������������ͣ�Ȼ��õ�������������ֵ
//�жϸ�ֵ�Ƿ�Ϊ0�����Ϊ0��˵��û�б�����
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
			setz[bRes]   //setz��˼�ǽ�zf��־λ��ֵ����bRes
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