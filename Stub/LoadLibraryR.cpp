#include <stdio.h>
#include "LoadLibraryR.h"


char* mystrstr1(char* dest,const char* src) 
{
	char* tdest = dest;
	const char* tsrc = src;
	int i = 0;//tdest ������Ԫ���±�λ�ã����±�0��ʼ�ң�����ͨ�������������ã��������±꿪ʼ�ң�
	int j = 0;//tsrc �Ӵ���Ԫ���±�λ��
	while (i <= strlen(tdest) - 1 && j <= strlen(tsrc) - 1)
	{
		if (tdest[i] == tsrc[j])//�ַ���ȣ������ƥ����һ���ַ�
		{
			i++;
			j++;
		}
		else//��ƥ������з�����һ���ַ����Ӵ��еĲ��ȣ����ϻ��˵� ��һ��Ҫƥ���λ��
		{
			i = i - j + 1;
			j = 0;
		}
	}
	//ѭ�����˺�j��ֵ����strlen(tsrc) �Ӵ��е��ַ��Ѿ��������ж�����ƥ�䵽��
	if (j == strlen(tsrc))
	{
		return tdest + i - strlen(tsrc);
	}
	return NULL;
}




DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders         = NULL;
	
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
	UINT_PTR uiBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0;
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;

	//�ж��Ƿ���X64
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	// Win32
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// NTͷ
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	//�ж���X64����X32,���ڻ���
	if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B ) // PE32
	{
		if( dwCompiledArch != 1 )
			return 0;
	}
	else if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B ) // PE64
	{
		if( dwCompiledArch != 2 )
			return 0;
	}
	else
	{
		return 0;
	}

	// ������
	uiNameArray = 
		(UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// ������VA
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

	// ����������VA
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

	// ������ַ����VA
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

	// �����������VA
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );	

	// ���ָ���
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// Ѱ�ҵ�������ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

		if( mystrstr1( cpExportedFunctionName, "ReflectiveLoader" ))  //<-------
		{
			// ��ȡ������ַ����
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );	
	
			// ������ż�����Ӧ�ĵ�ַ
			uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

			//�����ļ�ƫ��
			return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
		}
		//��һ��
		uiNameArray += sizeof(DWORD);
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// ����DLL
HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength )
{

	//��ʼ��������ַ
	HMODULE hKernel32 = GetKernel32BaseAddr1();
	fnGetProcAddress g_pfnGetProcAddress =
		(fnGetProcAddress)MyGetProcAddress1();
	fnLoadLibraryA g_pfnLoadLibraryA =
		(fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");
	pfnVirtualProtect MyVirtualProtect = 
		(pfnVirtualProtect)g_pfnGetProcAddress(hKernel32, "VirtualProtect");

	//===============================================================================

	HMODULE hResult                    = NULL;
	DWORD dwReflectiveLoaderOffset     = 0;
	DWORD dwOldProtect1                = 0;
	DWORD dwOldProtect2                = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain                   = NULL;

	if( lpBuffer == NULL || dwLength == 0 )
		return NULL;

	__try
	{
		//��ȡ��������ReflectLoader��ƫ�Ƶ�ַ
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
		if( dwReflectiveLoaderOffset != 0 )
		{
			//��ȡVA��ַ
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			//д��
			if( MyVirtualProtect( lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1 ) )
			{
				// ��ֵ
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if( pDllMain != NULL )
				{
					// ����DllMain
					if( !pDllMain( NULL, DLL_QUERY_HMODULE, &hResult ) )	
						hResult = NULL;
				}
				//�ָ�
				MyVirtualProtect( lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2 );
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hResult = NULL;
	}

	return hResult;
}


//Զ�̵���ReflectiveLoader
HANDLE WINAPI LoadRemoteLibraryR( HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter )
{

	//��ʼ��������ַ
	HMODULE hKernel32 = GetKernel32BaseAddr1();
	fnGetProcAddress g_pfnGetProcAddress =
		(fnGetProcAddress)MyGetProcAddress1();
	fnLoadLibraryA g_pfnLoadLibraryA =
		(fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");

	pfnVirtualAllocEx MyVirtualAllocEx = 
		(pfnVirtualAllocEx)g_pfnGetProcAddress(hKernel32, "VirtualAllocEx");
	
	pfnWriteProcessMemory MyWriteProcessMemory =
		(pfnWriteProcessMemory)g_pfnGetProcAddress(hKernel32, "WriteProcessMemory");

	pfnCreateRemoteThread MyCreateRemoteThread =
		(pfnCreateRemoteThread)g_pfnGetProcAddress(hKernel32, "CreateRemoteThread");
	
	//===========================================================================
	BOOL bSuccess                             = FALSE;
	LPVOID lpRemoteLibraryBuffer              = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread                            = NULL;
	DWORD dwReflectiveLoaderOffset            = 0;
	DWORD dwThreadId                          = 0;

	__try
	{
		do
		{

			//�ж��Ƿ�Ϊ��
			if( !hProcess  || !lpBuffer || !dwLength )
				break;

			// ��ȡflectiveLoader
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
			if( !dwReflectiveLoaderOffset )
				break;

			//���ٿռ�
			lpRemoteLibraryBuffer = MyVirtualAllocEx( hProcess,
				NULL, 
				dwLength,
				MEM_RESERVE|MEM_COMMIT,
				PAGE_EXECUTE_READWRITE ); 
			if( !lpRemoteLibraryBuffer )
				break;

			// д��
			if( !MyWriteProcessMemory( hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL ) )
				break;
			
			//���VA
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset );

			// Զ���̵߳���
			hThread = MyCreateRemoteThread( hProcess, 
				NULL, 
				1024*1024,
				lpReflectiveLoader,
				lpParameter, 
				(DWORD)NULL,
				&dwThreadId );

		} while( 0 );

	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hThread = NULL;
	}

	return hThread;
}
//===============================================================================================//

HMODULE GetKernel32BaseAddr1()
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


DWORD MyGetProcAddress1()
{
	//Kernel32�Ļ���ַ
	HMODULE hKernel32 = GetKernel32BaseAddr1();

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
			if (MyStrcmp1(ExpFunName, "GetProcAddress"))
			{
				return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
			}
		}
	}
	return 0;
}

BOOL MyStrcmp1(char* src, const char*dst)
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