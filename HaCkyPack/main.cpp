#include "Packer.h"
#pragma warning(disable:4996)

int main(int argc, char **argv)
{
	Packer packer;

	//兼容GUI--参数过滤
	if (argc != 3)
	{
		packer.fp = fopen("HackyPackLog.log", "w");
		fprintf(packer.fp, "[!]Packer::Main--->Argc Number Error\n");
		fclose(packer.fp);
		return 1;
	}
	
	//兼容GUI--初始化工作模式
	char FilePath[MAX_PATH] = {0};
	strcpy(FilePath, argv[1]);
	packer.WorkMode = ((DWORD)argv[2][0]-0x30);
	if (packer.WorkMode != 0 &&
		packer.WorkMode != 1 &&
		packer.WorkMode != 2)
	{
		packer.fp = fopen("HackyPackLog.log", "w");
		fprintf(packer.fp, "[!]Packer::Main--->WorkMode Error\n");
		fclose(packer.fp);
		return 1;
	}

	//char FilePath[MAX_PATH] = "C:\\Test.exe";
	//Step1：获取待加壳程序的基本PE信息
	BOOL bFlag_GetInfo= packer.GetPEInfo(FilePath);
	if (bFlag_GetInfo == FALSE)
	{
		return 1;
	}


	//Step2：载入Stub部分
	StubInfo stubinfo = { 0 };
	BOOL bFlag_LoadStub = packer.LoadStub(&stubinfo);
	if (bFlag_LoadStub == FALSE)
	{
		return 1;
	}




	//Step3:复制Stub数据,避免突发性的权限访问错误
	DWORD dwStubImageSize = packer.GetStubImageSize(stubinfo.StubBase);
	LPBYTE lpNewStubBaseAddr = new BYTE[dwStubImageSize];
	memset(lpNewStubBaseAddr, 0, dwStubImageSize);
	memcpy_s(lpNewStubBaseAddr, dwStubImageSize, stubinfo.StubBase, dwStubImageSize);
	packer.fp = fopen("HackyPackLog.log", "a");
	fprintf(packer.fp, "[*]Packer::Main--->MemcpyStub Success,BaseAddr:%0X\n", lpNewStubBaseAddr);
	fclose(packer.fp);


	//Step4:获取Stub的数据并填充原始PE的PE数据
	BOOL bFlag_GetStubInfo = FALSE;
	bFlag_GetStubInfo = packer.GetStubInfo(lpNewStubBaseAddr, &stubinfo);
	if (bFlag_GetStubInfo == FALSE)
	{
		return 1;
	}



	//代码混淆
	if (packer.WorkMode == 2)
	{
		DWORD dwVACodeBase = (DWORD)packer.lpMemBuf + packer.dwCodeBase;
		DWORD dwVACodeSize = packer.dwCodeSize;
		BOOL ggg = packer.UDisam(dwVACodeBase, dwVACodeSize);
	}



	//Step3: 加密代码段
	char szPassword[8] = "0AcdDfZ";;
	//strcpy(szPassword, packer.EncryKey(stubinfo.pStubConf->dwAESKey));
	BOOL bFlag_EncryCodeSeg = FALSE;
	bFlag_EncryCodeSeg = packer.EncryCodeSeg(szPassword);
	if (bFlag_EncryCodeSeg == FALSE)
	{
		return 1;
	}

	//Step4：修复重定位
	BOOL bFlag_FixStubReloc = FALSE;
	bFlag_FixStubReloc = packer.FixStubReloc(lpNewStubBaseAddr);
	if (bFlag_FixStubReloc == FALSE)
	{
		return 1;
	}

	//Step5：设置OEP
	DWORD dwStubOep = stubinfo.pfnStart - (DWORD)lpNewStubBaseAddr;
	BOOL bFlag_SetOep = FALSE;
	bFlag_SetOep = packer.SetOepOfPEFile(dwStubOep);
	if (bFlag_SetOep == FALSE)
	{
		return 1;
	}



	//Step6：合并stub
	const char NewSectionName[MAX_PATH] = ".Hacky";
	LPBYTE lpFinalBuf = NULL;
	DWORD dwFinalBufSize = 0;
	DWORD dwNewSectionSize = packer.AddNewSection(packer.lpMemBuf, 
		packer.dwImageSize, 
		NewSectionName, 
		lpNewStubBaseAddr, 
		dwStubImageSize,
		lpFinalBuf,
		dwFinalBufSize);

	//加密lpFinalBufSize中的.rdata表
	//获取rdata段的地址和大小
	LPBYTE TmplpBaseAddress = NULL;
	DWORD TmpImageSize = 0;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)lpFinalBuf;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)lpFinalBuf + dos->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(nt);
	while (pSectionHeader->Name)
	{
		char* SectionName = (char*)(pSectionHeader->Name);
		if (strcmp(SectionName, "") == 0)
			break;
		if ((strcmp(SectionName, ".rdata") == 0) || (strcmp(SectionName, "const") == 0))
		{
			TmplpBaseAddress = (LPBYTE)(pSectionHeader->VirtualAddress + (DWORD)lpFinalBuf);
			TmpImageSize = pSectionHeader->SizeOfRawData;
			break;
		}
		pSectionHeader++;
	}


	//加密字符串
	BOOL bFlag_EncodeString = FALSE;
	bFlag_EncodeString = packer.FindString(TmplpBaseAddress, TmpImageSize);
	if (bFlag_EncodeString == FALSE)
	{
		return 1;
	}


	//清空IAT表数据
	BOOL bFlag_ClearDataDir = FALSE;
	bFlag_ClearDataDir = packer.ClearDataDir(lpFinalBuf, &stubinfo);
	if (bFlag_ClearDataDir == FALSE)
	{
		return 1;
	}
	//************************************************************
	//后知后觉：
	//关于在ClearDataDir函数中，无法传递原始PE数据给Stub的g_ShellData的bug
	//首先：当我们之前使用stubinfo结构体进行数据交换的时候，stubinfo结构体
	//对应的stub的指针指向的是原先Load之后复制的堆内存，但是在ClearDataDir函
	//数继续使用stubinfo结构体进行数据交换的话，仍然使用还是之前的堆内存，但
	//是stub的内存数据，此时和原始PE的数据发生了合并，保存的新的堆内存。所以‘
	//无法传递
	//项目太大了，要严格把握每一步的结构。
	//************************************************************


	//关闭ADSL
	packer.GetOptionHeader(lpFinalBuf)->DllCharacteristics &= (~0x40);

	//Step9:保存文件
	char* NewFilePath = packer.GetNewFilePath(FilePath);
	BOOL bFlag_SaveFinalFile = FALSE;
	bFlag_SaveFinalFile = packer.SaveFinalFile(lpFinalBuf, dwFinalBufSize, NewFilePath);
	if (bFlag_SaveFinalFile == FALSE)
	{
		return 1;
	}

	//Step3：只有在模式2中读取ReflectDll_Dll.dll
	DWORD dwSizeOfReflectDll = 0;
	LPBYTE lpReflectDllBuf = NULL;
	if (packer.WorkMode == 2)
	{
		packer.fp = fopen("HackyPackLog.log", "a");

		//读取ReflectDll_Dll.dll
		HANDLE hFile_ReflectDll = CreateFile("ReflectDll_Dll.dll",
			GENERIC_READ | GENERIC_WRITE, 0, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile_ReflectDll == NULL)
		{
			fprintf(packer.fp, "[!]Packer::Main--->OpenReflectDll Error:%d\n", GetLastError());
			fclose(packer.fp);
			CloseHandle(hFile_ReflectDll);
			return 1;
		}


		dwSizeOfReflectDll = GetFileSize(hFile_ReflectDll, 0);
		lpReflectDllBuf = new BYTE[dwSizeOfReflectDll];
		DWORD dwTmpSizeOfReflectDll = 0;
		if (FALSE == ReadFile(hFile_ReflectDll,
			lpReflectDllBuf,
			dwSizeOfReflectDll,
			&dwTmpSizeOfReflectDll,
			NULL))
		{
			fprintf(packer.fp, "[!]Packer::Main--->ReadReflectDll Error:%d\n", GetLastError());
			fclose(packer.fp);
			CloseHandle(hFile_ReflectDll);
			return 1;
		}

		//附加数据
		HANDLE hNewFile = CreateFile(NewFilePath,
			FILE_APPEND_DATA, 0, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hNewFile == NULL)
		{
			fprintf(packer.fp, "[!]Packer::Main--->OpenNewFile Error:%d\n", GetLastError());
			fclose(packer.fp);
			CloseHandle(hFile_ReflectDll);
			return 1;
		}


		//写入数据
		DWORD WriteSize = 0;
		BOOL bResult = FALSE;
		bResult = WriteFile(hNewFile, lpReflectDllBuf, dwSizeOfReflectDll, &WriteSize, NULL);
		if (bResult == FALSE)
		{
			fprintf(packer.fp, "[!]Packer::Main--->WriteFile Error:%d\n", GetLastError());
			fclose(packer.fp);
			CloseHandle(hFile_ReflectDll);
			return 1;
		}

		fclose(packer.fp);
		CloseHandle(hNewFile);
		CloseHandle(hFile_ReflectDll);
	}

	delete[] packer.lpMemBuf;
	if (lpReflectDllBuf != NULL)
		delete[] lpReflectDllBuf;
	return 0;
}