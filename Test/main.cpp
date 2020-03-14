# include <windows.h>
# include <stdio.h>
# include <string.h>
# include <tlhelp32.h>
#pragma warning(disable:4996)



BOOL Mystricmp(char str1[],const char str2[])
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


BOOL CheckVMWare()
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

PIMAGE_NT_HEADERS GetNtHeader(LPBYTE lpBaseAddress)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	return PIMAGE_NT_HEADERS((DWORD)lpBaseAddress + pImageDosHeader->e_lfanew);
}

PIMAGE_OPTIONAL_HEADER GetOptionHeader(LPBYTE lpBaseAddress)
{
	return &GetNtHeader(lpBaseAddress)->OptionalHeader;
}



void SetFileHeaderProtect(bool nWrite)
{
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)GetModuleHandleA(NULL);
	DWORD nOldProtect = 0;
	if (nWrite)
		VirtualProtect((LPVOID)ImageBase, 0x400, PAGE_EXECUTE_READWRITE, &nOldProtect);
	else
		VirtualProtect((LPVOID)ImageBase, 0x400, nOldProtect, &nOldProtect);
}

void FixIAT()
{
	SetFileHeaderProtect(true);
	LPBYTE lpBaseAddress = (LPBYTE)GetModuleHandleA(NULL);
	DWORD Rav_Import_Table =
		GetOptionHeader(lpBaseAddress)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR ImportTable =
		PIMAGE_IMPORT_DESCRIPTOR((DWORD)lpBaseAddress + Rav_Import_Table);

	PIMAGE_THUNK_DATA pOrigalFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME pImpName = NULL;
	DWORD dwFuncAddress = 0;

	while (ImportTable->Name)
	{
		//加载Dll
		char* pDllName = (char*)((DWORD)lpBaseAddress + ImportTable->Name);
		HMODULE hModule = (HMODULE)LoadLibraryA(pDllName);

		//填充IMAGE_THUNK_DATA结构体
		PIMAGE_THUNK_DATA pFirstThunk =
			(PIMAGE_THUNK_DATA)((DWORD)lpBaseAddress + ImportTable->FirstThunk);
		if (ImportTable->OriginalFirstThunk == 0)
		{
			pOrigalFirstThunk = pFirstThunk;
		}
		else
		{
			pOrigalFirstThunk =
				(PIMAGE_THUNK_DATA)((DWORD)lpBaseAddress + ImportTable->OriginalFirstThunk);
		}

		while (pOrigalFirstThunk->u1.AddressOfData)
		{
			//判断导入方式
			if (IMAGE_SNAP_BY_ORDINAL(pOrigalFirstThunk->u1.AddressOfData))
			{
				//按照序号导入
				dwFuncAddress = (DWORD)GetProcAddress(hModule, (char*)(pOrigalFirstThunk->u1.Ordinal & 0x7FFFFFFF));

			}
			else
			{
				//按照函数名称导入
				pImpName =
					(PIMAGE_IMPORT_BY_NAME)
					((DWORD)lpBaseAddress + pOrigalFirstThunk->u1.Function);

				//获取函数的地址
				dwFuncAddress = (DWORD)GetProcAddress(hModule, pImpName->Name);
			}

			//开始填充IAT
			DWORD dwOldProtect = 0;
			VirtualProtect(&pFirstThunk->u1.Function,
				sizeof(pFirstThunk->u1.Function), PAGE_READWRITE, &dwOldProtect);
			pFirstThunk->u1.Function = dwFuncAddress;
			VirtualProtect(&pFirstThunk->u1.Function,
				sizeof(pFirstThunk->u1.Function), dwOldProtect, &dwOldProtect);
			++pFirstThunk;
			++pOrigalFirstThunk;
		}
		++ImportTable;
	}
	SetFileHeaderProtect(false);
}
int main(void)
{

	MessageBox(NULL, "aaa", "aaa", MB_OK);
	MessageBox(NULL, "aaa", "aaa", MB_OK);
	MessageBox(NULL, "aaa", "aaa", MB_OK);
	MessageBox(NULL, "aaa", "aaa", MB_OK);
	if(1)
		MessageBox(NULL, "aaa", "aaa", MB_OK);
}



