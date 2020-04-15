#include "Packer.h"
#pragma warning(disable:4996)

int main(int argc, char **argv)
{
	Packer packer;

	//����GUI--��������
	if (argc != 3)
	{
		packer.fp = fopen("HackyPackLog.log", "w");
		fprintf(packer.fp, "[!]Packer::Main--->Argc Number Error\n");
		fclose(packer.fp);
		return 1;
	}
	
	//����GUI--��ʼ������ģʽ
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
	//Step1����ȡ���ӿǳ���Ļ���PE��Ϣ
	BOOL bFlag_GetInfo= packer.GetPEInfo(FilePath);
	if (bFlag_GetInfo == FALSE)
	{
		return 1;
	}


	//Step2������Stub����
	StubInfo stubinfo = { 0 };
	BOOL bFlag_LoadStub = packer.LoadStub(&stubinfo);
	if (bFlag_LoadStub == FALSE)
	{
		return 1;
	}




	//Step3:����Stub����,����ͻ���Ե�Ȩ�޷��ʴ���
	DWORD dwStubImageSize = packer.GetStubImageSize(stubinfo.StubBase);
	LPBYTE lpNewStubBaseAddr = new BYTE[dwStubImageSize];
	memset(lpNewStubBaseAddr, 0, dwStubImageSize);
	memcpy_s(lpNewStubBaseAddr, dwStubImageSize, stubinfo.StubBase, dwStubImageSize);
	packer.fp = fopen("HackyPackLog.log", "a");
	fprintf(packer.fp, "[*]Packer::Main--->MemcpyStub Success,BaseAddr:%0X\n", lpNewStubBaseAddr);
	fclose(packer.fp);


	//Step4:��ȡStub�����ݲ����ԭʼPE��PE����
	BOOL bFlag_GetStubInfo = FALSE;
	bFlag_GetStubInfo = packer.GetStubInfo(lpNewStubBaseAddr, &stubinfo);
	if (bFlag_GetStubInfo == FALSE)
	{
		return 1;
	}



	//�������
	if (packer.WorkMode == 2)
	{
		DWORD dwVACodeBase = (DWORD)packer.lpMemBuf + packer.dwCodeBase;
		DWORD dwVACodeSize = packer.dwCodeSize;
		BOOL ggg = packer.UDisam(dwVACodeBase, dwVACodeSize);
	}



	//Step3: ���ܴ����
	char szPassword[8] = "0AcdDfZ";;
	//strcpy(szPassword, packer.EncryKey(stubinfo.pStubConf->dwAESKey));
	BOOL bFlag_EncryCodeSeg = FALSE;
	bFlag_EncryCodeSeg = packer.EncryCodeSeg(szPassword);
	if (bFlag_EncryCodeSeg == FALSE)
	{
		return 1;
	}

	//Step4���޸��ض�λ
	BOOL bFlag_FixStubReloc = FALSE;
	bFlag_FixStubReloc = packer.FixStubReloc(lpNewStubBaseAddr);
	if (bFlag_FixStubReloc == FALSE)
	{
		return 1;
	}

	//Step5������OEP
	DWORD dwStubOep = stubinfo.pfnStart - (DWORD)lpNewStubBaseAddr;
	BOOL bFlag_SetOep = FALSE;
	bFlag_SetOep = packer.SetOepOfPEFile(dwStubOep);
	if (bFlag_SetOep == FALSE)
	{
		return 1;
	}



	//Step6���ϲ�stub
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

	//����lpFinalBufSize�е�.rdata��
	//��ȡrdata�εĵ�ַ�ʹ�С
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


	//�����ַ���
	BOOL bFlag_EncodeString = FALSE;
	bFlag_EncodeString = packer.FindString(TmplpBaseAddress, TmpImageSize);
	if (bFlag_EncodeString == FALSE)
	{
		return 1;
	}


	//���IAT������
	BOOL bFlag_ClearDataDir = FALSE;
	bFlag_ClearDataDir = packer.ClearDataDir(lpFinalBuf, &stubinfo);
	if (bFlag_ClearDataDir == FALSE)
	{
		return 1;
	}
	//************************************************************
	//��֪�����
	//������ClearDataDir�����У��޷�����ԭʼPE���ݸ�Stub��g_ShellData��bug
	//���ȣ�������֮ǰʹ��stubinfo�ṹ��������ݽ�����ʱ��stubinfo�ṹ��
	//��Ӧ��stub��ָ��ָ�����ԭ��Load֮���ƵĶ��ڴ棬������ClearDataDir��
	//������ʹ��stubinfo�ṹ��������ݽ����Ļ�����Ȼʹ�û���֮ǰ�Ķ��ڴ棬��
	//��stub���ڴ����ݣ���ʱ��ԭʼPE�����ݷ����˺ϲ���������µĶ��ڴ档���ԡ�
	//�޷�����
	//��Ŀ̫���ˣ�Ҫ�ϸ����ÿһ���Ľṹ��
	//************************************************************


	//�ر�ADSL
	packer.GetOptionHeader(lpFinalBuf)->DllCharacteristics &= (~0x40);

	//Step9:�����ļ�
	char* NewFilePath = packer.GetNewFilePath(FilePath);
	BOOL bFlag_SaveFinalFile = FALSE;
	bFlag_SaveFinalFile = packer.SaveFinalFile(lpFinalBuf, dwFinalBufSize, NewFilePath);
	if (bFlag_SaveFinalFile == FALSE)
	{
		return 1;
	}

	//Step3��ֻ����ģʽ2�ж�ȡReflectDll_Dll.dll
	DWORD dwSizeOfReflectDll = 0;
	LPBYTE lpReflectDllBuf = NULL;
	if (packer.WorkMode == 2)
	{
		packer.fp = fopen("HackyPackLog.log", "a");

		//��ȡReflectDll_Dll.dll
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

		//��������
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


		//д������
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