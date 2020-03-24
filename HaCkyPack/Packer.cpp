#include "Packer.h"
#pragma warning(disable:4996)

//c++�๹�����������
Packer::Packer()
{
	//�ڹ��캯����������Ա���г�ʼ��
	InitClassNumber();
}
Packer::~Packer()
{

}

//************************************************************
//InitClassNumber:��ʼ�����Ա
//ChildFunc:NULL
//fp:ΪLog�ľ������Pack����ͷţ��������ͷ�
//************************************************************
void Packer::InitClassNumber()
{
	fp = NULL;
	hFile = NULL;

	pFileBuf = NULL;
	lpMemBuf = NULL;
	pDosHeader = NULL;
	pNtHeader = NULL;
	pSecHeader = NULL;
	dwFileSize = 0;

	dwSizeOfHeader = 0;
	dwSectionNum = 0;
	dwImageSize = 0;
	dwImageBase = 0;
	dwCodeBase = 0;
	dwCodeSize = 0;
	dwOEP = 0;
	dwShellOEP = 0;

	dwFileAlign = 0;
	dwMemAlign = 0;

	PERelocDir = { 0 };
	PEImportDir = { 0 };
	IATSectionBase = 0;
	IATSectionSize = 0;

	//�����Ǹ�BUG���Ҿ�Ȼ���Ĳ��ˣ�������
	dwNumOfDataDir = 0;
	for (DWORD i = 0; i < 20; i++)
	{
		dwDataDir[i][0] = 0;
		dwDataDir[i][1] = 0;
	}
}

//************************************************************
//GetPEInfo:��ȡ�ļ�������PE��ؽṹ��Ϣ
//ChildFunc:
	//OpenFile()--->�ж��ļ��Ƿ����
	//
//************************************************************
BOOL Packer::GetPEInfo(char* FilePath)
{
	//�ж��ļ��Ƿ����
	if (FALSE == OpenFile(FilePath,&dwFileSize))
		return FALSE;

	//��ȡ��Packer���ļ����ڴ�
	pFileBuf = new BYTE[dwFileSize];
	DWORD ReadSize = 0;
	if (FALSE == ReadFile(hFile, pFileBuf, dwFileSize, &ReadSize, NULL))
	{
		fp = fopen("HackyPackLog.log", "a");
		fprintf(fp, "[!]Packer::GetPEInfo--->ReadFile Error:%d...\n", GetLastError());
		fclose(fp);
		CloseHandle(hFile);
		return FALSE;
	}
	CloseHandle(hFile);

	//�ж�PE�ļ��Ƿ�Ϸ�
	if (FALSE == IsLegalPE())
		return FALSE;

	//��ȡһЩ��Ҫ��PE�ļ���Ϣ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;    //Dosͷ
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuf + pDosHeader->e_lfanew);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);

	dwImageSize = pNtHeader->OptionalHeader.SizeOfImage;
	dwMemAlign = pNtHeader->OptionalHeader.SectionAlignment;
	
	//(size) % (alignment) == 0 ? (size) : ((size) / (alignment)+ 1)*(alignment);
	//�˴������ڴ����ķ�ʽ��PE�ļ������ڴ棬�����ں��ڴ�������оͲ���Ҫ���¶�����
	if (dwImageSize % dwMemAlign)
		dwImageSize = (dwImageSize / dwMemAlign + 1) * dwMemAlign;
	else
		dwImageSize = dwImageSize;

	//�����µĿռ����ڱ����ڴ�����PE�ļ�����
	//�ڴ����ķ�ʽ������߼����£�
	/*-----------------------------------------------------
	      ���ȸ���PE�ļ���DOSͷ���ļ�ͷ����ѡͷ����Ϊ�����������ļ���
	�����ڴ�����һ���ģ������ڶ�������⣬Ȼ��ֱ���û�н��������ݣ�
	�����������ǰ����ļ�����ķ�ʽ�������ڴ��еģ�������ӳ�����ڴ��ʱ��
	��Ҫת�����ڴ���룬�����õ�����ɾ�������ڴ�
	------------------------------------------------------*/
	dwSizeOfHeader = pNtHeader->OptionalHeader.SizeOfHeaders;
	LPBYTE lpMemPEBuf = new BYTE[dwImageSize];
	memset(lpMemPEBuf, 0, dwImageSize);
	memcpy_s(lpMemPEBuf, dwSizeOfHeader, pFileBuf, dwSizeOfHeader);


	dwSectionNum = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (DWORD i = 0; i < dwSectionNum; i++, pSectionHeader++)
	{
		memcpy_s(lpMemPEBuf + pSectionHeader->VirtualAddress,     //�ڴ����
			pSectionHeader->SizeOfRawData,
			pFileBuf + pSectionHeader->PointerToRawData,          //�ļ�����
			pSectionHeader->SizeOfRawData);
	}
	//��ʱPE�ļ��Ѿ����ڴ����ķ�ʽ�������ڴ�����
	memset(pFileBuf, 0, dwFileSize);
	delete[] pFileBuf;   //�ͷ�
	pFileBuf = NULL;

	lpMemBuf = lpMemPEBuf;
	lpMemPEBuf = NULL;
	//dwFileSize = dwFileSize;
	//dwImageSize = dwImageSize;
	pDosHeader = (PIMAGE_DOS_HEADER)lpMemBuf;
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)lpMemBuf + pDosHeader->e_lfanew);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
	pSecHeader = pSectionHeader;
	dwImageBase = pNtHeader->OptionalHeader.ImageBase;
	

	//��ȡCodeSize
	//dwCodeBase = pNtHeader->OptionalHeader.BaseOfCode;
	//dwCodeSize = pNtHeader->OptionalHeader.SizeOfCode;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader((LPBYTE)lpMemBuf);
	PIMAGE_SECTION_HEADER pSectionHeader1 = IMAGE_FIRST_SECTION(pNtHeader);
	while (pSectionHeader1->Name)
	{
		char* SectionName = (char*)(pSectionHeader1->Name);
		if (strcmp(SectionName, ".text") == 0)
		{
			dwCodeBase = pSectionHeader1->VirtualAddress;
			dwCodeSize = pSectionHeader1->SizeOfRawData;
			break;
		}
		pSectionHeader1++;
	}
	
	dwOEP = pNtHeader->OptionalHeader.AddressOfEntryPoint;
	dwSizeOfHeader = pNtHeader->OptionalHeader.SizeOfHeaders;
	dwSectionNum = pNtHeader->FileHeader.NumberOfSections;
	dwFileAlign = pNtHeader->OptionalHeader.FileAlignment;
	dwMemAlign = pNtHeader->OptionalHeader.SectionAlignment;
	PERelocDir = 
		IMAGE_DATA_DIRECTORY(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PEImportDir = 
		IMAGE_DATA_DIRECTORY(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	IATSectionBase = PEImportDir.VirtualAddress;
	IATSectionSize = PEImportDir.Size;

	//���±����޸�����Ŀ¼����Ҫ�Ķ�������TM�Ǹ�BUG
	dwNumOfDataDir = pNtHeader->OptionalHeader.NumberOfRvaAndSizes;
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		dwDataDir[i][0] = pNtHeader->OptionalHeader.DataDirectory[i].VirtualAddress;
		dwDataDir[i][1] = pNtHeader->OptionalHeader.DataDirectory[i].Size;
	}

	//PIMAGE_SECTION_HEADER pTmpSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	//for (DWORD i = 0; i < dwSectionNum; i++, pSectionHeader++)
	//{
	//	if (PEImportDir.VirtualAddress >= pTmpSectionHeader->VirtualAddress&&
	//		PEImportDir.VirtualAddress <= pTmpSectionHeader[1].VirtualAddress)
	//	{
	//		//��������ε���ʼ��ַ�ʹ�С
	//		IATSectionBase = pTmpSectionHeader->VirtualAddress;
	//		IATSectionSize = pTmpSectionHeader[1].VirtualAddress - pTmpSectionHeader->VirtualAddress;
	//		break;
	//	}
	//}
	if (lpMemBuf != NULL &&
		dwFileSize != NULL &&
		dwImageSize != NULL &&
		pDosHeader != NULL &&
		pNtHeader != NULL &&
		pOptionalHeader != NULL &&
		pSecHeader != NULL &&
		dwImageBase != NULL &&
		dwCodeBase != NULL &&
		dwCodeSize != NULL &&
		dwOEP != NULL &&
		dwSizeOfHeader != NULL &&
		dwSectionNum != NULL &&
		dwFileAlign != NULL &&
		dwMemAlign != NULL &&
		IATSectionBase != NULL &&
		IATSectionSize != NULL)
	{
		fp = fopen("HackyPackLog.log", "a");
		fprintf(fp, "[*]Packer::GetPEInfo--->GetPEInfo...ok\n");
		fprintf(fp, "\t\t[*]Packer::GetPEInfo--->IATSectionBase:%d\n", IATSectionBase);
		fprintf(fp, "\t\t[*]Packer::GetPEInfo--->IATSectionSize:%d\n", IATSectionSize);
		fclose(fp);
		return TRUE;
	}
	else
	{
		fp = fopen("HackyPackLog.log", "a");
		fprintf(fp, "[!]Packer::GetPEInfo--->GetPEInfo...failed\n");
		fclose(fp);
		return FALSE;
	}
		
}

//************************************************************
//Packer::OpenFile ���ļ�������ȡ�ļ���Сͨ�����ε���ʽ����
//ChildFunc:NULL
//************************************************************
BOOL Packer::OpenFile(char* FilePath,DWORD *dwFileSize)
{
	hFile = CreateFile(FilePath,
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		fp = fopen("HackyPackLog.log", "w");
		fprintf(fp, "[!]Packer::OpenFile--->CreateFile Error:%d...\n",GetLastError());
		fclose(fp);
		hFile = NULL;
		return FALSE;
	}
	*dwFileSize = GetFileSize(hFile,NULL);
	if (*dwFileSize != NULL)
	{
		fp = fopen("HackyPackLog.log", "w");
		fprintf(fp, "[*]Packer::OpenFile--->GetFileSize %d...\n", *dwFileSize);
		fclose(fp);
	}
	return TRUE;
}



//************************************************************
//IsLegalPE:�����ж�PE�ļ��Ƿ����PE�ļ���ʽ�淶
//ChildFunc��NUll
//************************************************************
BOOL Packer::IsLegalPE()
{
	//�ж��Ƿ�ΪPE�ļ�
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		fp = fopen("HackyPackLog.log", "a");
		fprintf(fp, "[!]Packer::IsLegalPE--->MZ Signal Error...\n");
		fclose(fp);
		delete[] pFileBuf;
		return FALSE;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		fp = fopen("HackyPackLog.log", "a");
		fprintf(fp, "[!]Packer::IsLegalPE--->PE Signal Error...\n");
		fclose(fp);
		delete[] pFileBuf;
		return FALSE;
	}
	fp = fopen("HackyPackLog.log", "a");
	fprintf(fp, "[*]Packer::IsLegalPE--->LegalPE,FileSize:%d...\n",dwFileSize);
	fclose(fp);
	return TRUE;
}


//************************************************************
//LoadStub:����stub.dll
//ChildFunc:NUll
//************************************************************
BOOL Packer::LoadStub(StubInfo *stubinfo)
{
	fp = fopen("HackyPackLog.log", "a");
	stubinfo->StubBase =(LPBYTE)LoadLibrary("Stub.dll");
	 if (stubinfo->StubBase == NULL)
	 {
		 fprintf(fp, "[!]Packer::LoadStub--->LoadStub failed\n");
		 fclose(fp);
		 return FALSE;
	 }
	 fprintf(fp, "[*]Packer::LoadStub--->LoadStub Success,BaseAddr:%0x\n", stubinfo->StubBase);
	 fclose(fp);
	 return TRUE;
}

//************************************************************
//EncryCodeSeg�����ܴ���Σ��ڴ���ʽ����
//ChildFunc��NULL
//************************************************************
BOOL Packer::EncryCodeSeg(char* szPassword)
{
	//fp = fopen("HackyPackLog.log", "a");
	//LPBYTE pVAOfCodeBaseAddr = (LPBYTE)(lpMemBuf + dwCodeBase);
	//for (DWORD i = 0; i < dwCodeSize; i++)
	//	pVAOfCodeBaseAddr[i] ^= XorCode;
	//fprintf(fp, "[*]Packer::EncryCodeSeg--->EncryCodeSeg Ok...\n");
	//fclose(fp);
	//return TRUE;

	//���ܵĵ�ַ

	fp = fopen("HackyPackLog.log", "a");
	LPBYTE pVAOfCodeBaseAddr = (LPBYTE)(lpMemBuf + dwCodeBase);

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	LPBYTE pbBuffer = NULL;
	DWORD dwBlockLen = 0;
	DWORD dwBufferLen = 0;
	DWORD dwCount = 0;


	if (CryptAcquireContext(
		&hCryptProv,
		NULL,               //�û���½�� NULL��ʾʹ��Ĭ����Կ������Ĭ����Կ������
		NULL,
		PROV_RSA_FULL,
		0))
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptAcquireContext...success\n");
	}
	else
	{
		if (CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_RSA_AES,
			CRYPT_NEWKEYSET))//������Կ����
		{
			//������Կ�����ɹ������õ�CSP���
			fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptAcquireContext...success\n");
		}
		else
		{
			fprintf(fp, "[!]Packer:::EncryCodeSeg--->CryptAcquireContext...failed:%d\n",GetLastError());
		}
	}

	// ����һ���Ự��Կ
	if (CryptCreateHash(
		hCryptProv,
		CALG_MD5,
		0,
		0,
		&hHash))
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptCreateHash...success\n");
	}
	else
	{
		fprintf(fp, "[!]Packer:::EncryCodeSeg--->CryptCreateHash...failed:%d\n",GetLastError());
	}
	// ��������������һ��ɢ��
	if (CryptHashData(
		hHash,
		(BYTE *)szPassword,
		strlen(szPassword),
		0))
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptHashData...success\n");
	}
	else
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptHashData...failed:%d\n",GetLastError());
	}

	// ͨ��ɢ�����ɻỰ��Կ
	if (CryptDeriveKey(
		hCryptProv,
		ENCRYPT_ALGORITHM,
		//CALG_AES_128,
		hHash,
		KEYLENGTH,
		&hKey))
		
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptDeriveKey...success\n");
	}
	else
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptDeriveKey...failed:%d\n",GetLastError());
	}



	CryptDestroyHash(hHash);
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
	if (pbBuffer = (BYTE *)malloc(dwBufferLen))
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->malloc...success\n");
	}
	else
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->malloc...failed:%d\n",GetLastError());
	}
	memset(pbBuffer, 0, dwBufferLen);
	// ��������
	DWORD dwTmp = 0;
	DWORD dwTmpCodeSize = dwCodeSize;
	BOOL bFinual = FALSE;
	do 
	{
		//�ж��Ƿ������һ��
		if (dwTmpCodeSize > dwBlockLen)
		{
			memcpy(pbBuffer, (pVAOfCodeBaseAddr + dwTmp), dwBlockLen);
			dwCount = dwBlockLen;
			bFinual = FALSE;     //˵�����ڶ����С���������һ��
		}
		else
		{
			memcpy(pbBuffer, (pVAOfCodeBaseAddr + dwTmp), dwTmpCodeSize);
			dwCount = dwTmpCodeSize;
			bFinual = TRUE;      //˵��С�ڵ��ڶ����С�������һ��
		}
			

		if (!CryptEncrypt(
			hKey,           //��Կ
			0,              //�������ͬʱ����ɢ�кͼ��ܣ����ﴫ��һ��ɢ�ж���
			bFinual,        //��������һ�������ܵĿ飬����TRUE.�����������FALSE
			0,              //����
			pbBuffer,       //���뱻�������ݣ�������ܺ������
			&dwCount,       //���뱻��������ʵ�ʳ��ȣ�������ܺ����ݳ���
			dwBufferLen))   //pbBuffer�Ĵ�С��
		{
			fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptEncrypt...failed:%d\n", GetLastError());
		}
		memcpy(pVAOfCodeBaseAddr +dwTmp, pbBuffer, dwCount);
		dwTmp += dwCount;
		dwTmpCodeSize -= dwCount;
	} while (dwTmpCodeSize>0);


	if (pbBuffer
		&&hKey
		&&hCryptProv)
	{
		free(pbBuffer);
		CryptDestroyKey(hKey);
		//CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
	}
	
	fclose(fp);
	return TRUE;


}


//************************************************************
//AddNewSection:���һ������
//ChildFunc��GetLastSection
//typedef struct _IMAGE_SECTION_HEADER {
//	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
//	union {
//		DWORD PhysicalAddress;
//		DWORD VirtualSize;
//	} Misc;
//	DWORD VirtualAddress;
//	DWORD SizeOfRawData;
//	DWORD PointerToRawData;
//	DWORD PointerToRelocations;
//	DWORD PointerToLinenumbers;
//	WORD  NumberOfRelocations;
//	WORD  NumberOfLinenumbers;
//	DWORD Characteristics;
//} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
//************************************************************
DWORD Packer::AddNewSection(LPBYTE lpOldPEMemBuf,
	DWORD dwOldPEImageSize,
	const char* szNewSectionName,
	LPBYTE lpNewSection,DWORD NewSectionSize,
	LPBYTE& pFinalBuf,DWORD& dwSizeOfFinalBuf)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpOldPEMemBuf;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)lpOldPEMemBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	//��ȡ���һ������
	PIMAGE_SECTION_HEADER pLastSection = GetLastSection(lpOldPEMemBuf);

	//���θ���+1
	pNtHeader->FileHeader.NumberOfSections += 1;
	
	//�޸���������
	PIMAGE_SECTION_HEADER AddSectionHeader = &pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];	
	memcpy(AddSectionHeader->Name, szNewSectionName, 7);

	//�ڴ����0x1000
	//�����ε��ڴ�ƫ�� = ���һ�����ε��ڴ�ƫ��+���һ�����ε��ڴ��С
	DWORD dwTemp = (pLastSection->Misc.VirtualSize / dwMemAlign) * dwMemAlign;
	//���VirtualSize�����ڴ�����ȵ���������˵��Ҫ��������1���ڴ�����ȴ�С���ڴ�
	if (pLastSection->Misc.VirtualSize % dwMemAlign)
		dwTemp += 0x1000;
	AddSectionHeader->VirtualAddress = pLastSection->VirtualAddress + dwTemp;

	//���ڴ��еĴ�С��Ҳ����ӳ���С
	AddSectionHeader->Misc.VirtualSize = NewSectionSize;

	//�½�����PointerToRawDataӦ��λ�ھ�ӳ���С֮��
	AddSectionHeader->PointerToRawData = dwOldPEImageSize;

	//�ļ���С��ͬʱ��Ҫ�����ļ������Ҫ��
	 dwTemp = (NewSectionSize / dwFileAlign) * dwFileAlign;
	if (NewSectionSize % dwFileAlign)
	{
		dwTemp += dwFileAlign;
	}
	AddSectionHeader->SizeOfRawData = dwTemp;


	//�޸Ľ���ͷ��־
	AddSectionHeader->Characteristics = 0XE0000040;
	
	dwTemp = (NewSectionSize / dwMemAlign) * dwMemAlign;
	if (NewSectionSize % dwMemAlign)
	{
		dwTemp += dwMemAlign;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwTemp;

	//4.����ϲ�����Ҫ�Ŀռ�
	dwSizeOfFinalBuf = dwOldPEImageSize + dwTemp;
	pFinalBuf = new BYTE[dwSizeOfFinalBuf];
	memset(pFinalBuf, 0, dwSizeOfFinalBuf);

	memcpy_s(pFinalBuf, dwOldPEImageSize, lpOldPEMemBuf, dwOldPEImageSize);
	memcpy_s(pFinalBuf + dwOldPEImageSize, dwTemp, lpNewSection, dwTemp);
	return dwTemp;
}


//************************************************************
//GetLastSection����ȡ���һ������
//ChildFunc��NULL
//************************************************************
PIMAGE_SECTION_HEADER Packer::GetLastSection(LPBYTE lpMemBuf)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpMemBuf;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(lpMemBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pLastSection =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];

	return pLastSection;
}

//************************************************************
//FixStubReloc������Stub���ض�λ����Ϊ��LoadStub��ʱ��ϵͳ�Ѿ���stub.dll����������
//ChildFunc:GetOptionHeader
//typedef struct _IMAGE_BASE_RELOCATION {
//	DWORD   VirtualAddress;//RVA
//	DWORD   SizeOfBlock;   //�ض�λ���ݴ�С
//	WORD    TypeOffset;    // �ض�λ������
//} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
//************************************************************
BOOL Packer::FixStubReloc(LPBYTE StubBaseAddr)
{
	//��λStub.dll���ض�λ��
	PIMAGE_DATA_DIRECTORY	pStubRelocDir =
		&(GetOptionHeader(StubBaseAddr)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	DWORD dwRVAOfStubReloc = pStubRelocDir->VirtualAddress;
	PIMAGE_BASE_RELOCATION pRelocOfStub = PIMAGE_BASE_RELOCATION((DWORD)StubBaseAddr + dwRVAOfStubReloc);
	fp = fopen("HackyPackLog.log", "a");
	while (pRelocOfStub->SizeOfBlock)
	{
		typedef struct _TYPEOFFSET
		{
			WORD offset : 12;			//ƫ��ֵ
			WORD Type : 4;			    //�ض�λ����(��ʽ)
		}TYPEOFFSET, *PTYPEOFFSET;
		PTYPEOFFSET pTypeOffset = PTYPEOFFSET(pRelocOfStub + 1);

		//10H-->(10H-8H)/2=4,һ�����ĸ��ض�λ���飬
		//8Hָ����VirtualAddress��sizeofBlock��ռ���ֽ���Ϊ8������2H����ʾһ��TypeOffsetΪ2���ֽڡ�
		DWORD dwNumOfBlock = (pRelocOfStub->SizeOfBlock - 8) / 2;

		for (DWORD i = 0; i < dwNumOfBlock; i++)
		{
			if (*(PWORD)&pTypeOffset[i] == NULL)
				break;

			DWORD dwRVAOfRelocBlock = pRelocOfStub->VirtualAddress + pTypeOffset[i].offset;

			//��Ҫ�ض�λ�ĵ�ַ
			DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)StubBaseAddr + dwRVAOfRelocBlock);
			DWORD dwOld = 0;
			fprintf(fp, "[*]Packer::FixStubReloc--->Old Reloc:%d\n", *(PDWORD)((DWORD)StubBaseAddr + dwRVAOfRelocBlock));
			VirtualProtect(&AddrOfNeedReloc, 4, PAGE_READWRITE, &dwOld);
			
			//���㹫ʽ����Ҫ�ض�λ��RVA-��ǰ�Ļ���ַ(StubImageBase)+Ŀ�ĳ���Ļ���ַ(OldPeBaseAddr+SizeOfOldImage)
			DWORD dwTmpImageBase = GetOptionHeader(StubBaseAddr)->ImageBase;
			*(PDWORD)((DWORD)StubBaseAddr + dwRVAOfRelocBlock)=AddrOfNeedReloc - dwTmpImageBase + dwImageBase + dwImageSize;
			
			VirtualProtect(&AddrOfNeedReloc, 4, dwOld, &dwOld);

			fprintf(fp, "[*]Packer::FixStubReloc--->New Reloc:%d\n", *(PDWORD)((DWORD)StubBaseAddr + dwRVAOfRelocBlock));
		}
		pRelocOfStub = (PIMAGE_BASE_RELOCATION)
			((DWORD)pRelocOfStub + pRelocOfStub->SizeOfBlock);
	}
	pRelocOfStub->VirtualAddress += dwImageSize;
	//ԭʼPE�ļ����ض�λĿ¼��ָ����Ϣ
	PIMAGE_DATA_DIRECTORY pOldPERelocDir =
		&(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	pOldPERelocDir->Size = pStubRelocDir->Size;
	pOldPERelocDir->VirtualAddress = pStubRelocDir->Size + dwImageSize;
	fprintf(fp, "[*]Packer::FixStubReloc--->PERelocDir Update:%d\n", pOldPERelocDir->VirtualAddress);
	fclose(fp);
	return TRUE;
}



//************************************************************
//SetOepOfPEFile:�����µ�OEP��Start-StubBaseAddr+PEImageSize
//ChildFunc��NULL
//************************************************************
BOOL Packer::SetOepOfPEFile(DWORD dwStubOep)
{
	fp = fopen("HackyPackLog.log", "a");
	DWORD Tmp = pNtHeader->OptionalHeader.AddressOfEntryPoint;
	pNtHeader->OptionalHeader.AddressOfEntryPoint = dwStubOep + dwImageSize;
	if (pNtHeader->OptionalHeader.AddressOfEntryPoint == Tmp)
	{
		fprintf(fp, "[!]Packer::SetOepOfPEFile--->NewOep Failed\n");
		fclose(fp);
		return FALSE;
	}
	fprintf(fp, "[*]Packer::SetOepOfPEFile--->NewOep :%x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
	fclose(fp);
	return TRUE;
}


//************************************************************
//GetNewFilePath���������ļ���·��
//ChildFunc:NULL
//************************************************************
char* GetNewFilePath(char* FilePath)
{
	//char NewFilePath[MAX_PATH] = { 0 };
	PathRemoveExtension(FilePath);  
	strcat(FilePath, "_HaCky.exe");
	//PathRemoveFileSpec(FilePath);
	//strcat(FilePath, FileName);
	//strcpy(NewFilePath, FilePath);
	return FilePath;
}

//************************************************************
//SaveFinalFile�������ļ�
//ChildFunc::
//************************************************************
BOOL Packer::SaveFinalFile(LPBYTE lpFinalBuf, DWORD dwFinalBufSize,char* FilePath)
{
	fp = fopen("HackyPackLog.log", "a");
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFinalBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpFinalBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		pSectionHeader->PointerToRawData = pSectionHeader->VirtualAddress;
	}

	//�������ļ�·��
	char* NewFilePath = GetNewFilePath(FilePath);


	HANDLE hFile = CreateFileA(
		NewFilePath,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		fprintf(fp, "[!]Packer::SaveFinalFile--->CreateFile :%d\n", GetLastError());
		fclose(fp);
		return FALSE;
	}

	DWORD WriteSize = 0;
	BOOL bResult = WriteFile(hFile, lpFinalBuf, dwFinalBufSize, &WriteSize, NULL);
	if (bResult==FALSE)
	{
		fprintf(fp, "[!]Packer::SaveFinalFile--->WriteFile :%d\n", GetLastError());
		fclose(fp);
		CloseHandle(hFile);
		return FALSE;
	}
	CloseHandle(hFile);
	//�ж��ļ��Ƿ����
	if (INVALID_HANDLE_VALUE != CreateFile(NewFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))
	{
		fprintf(fp, "[*]Packer::SaveFinalFile--->NewFile :%s\n", NewFilePath);
		fclose(fp);
		return TRUE;
	}
	return TRUE;
}

//************************************************************
//GetStubImageSize����ȡStub��ӳ���С
//ChildFunc:NULL
//************************************************************
DWORD  Packer::GetStubImageSize(LPBYTE lpStubBaseAddr)
{
	PIMAGE_DOS_HEADER pDosHeader_Stub = (PIMAGE_DOS_HEADER)lpStubBaseAddr;
	PIMAGE_NT_HEADERS pNtHeaders_Stub = (PIMAGE_NT_HEADERS)(lpStubBaseAddr + pDosHeader_Stub->e_lfanew);
	return pNtHeaders_Stub->OptionalHeader.SizeOfImage;
}



char* Packer::EncryKey(char* str)
{
	char Table[] = "0123456789ABCDEFGEIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	char Ret[MAX_PATH] = { 0 };
	for (DWORD i = 0; i < strlen(str); i++)
	{
		Ret[i] = Table[str[i] - 48];
	}
	return Ret;

}
//************************************************************
//GetStubInfo:��֮ǰ������public��ԭʼPE���ݴ��ݸ�Stub��g_ShellData֮��
//ChildFunc:NULL
//************************************************************
BOOL Packer::GetStubInfo(LPBYTE	lpNewStubBaseAddr, StubInfo *stubinfo)
{
	fp = fopen("HackyPackLog.log", "a");
	LPBYTE a = stubinfo->StubBase ;
		//= lpNewStubBaseAddr;
	stubinfo->pfnStart = (DWORD)MyGetProcAddress((HMODULE)lpNewStubBaseAddr, "Start");
	stubinfo->pStubConf = (StubConf*)MyGetProcAddress((HMODULE)lpNewStubBaseAddr, "g_ShellData");

	//����ȡ����PE�����Ϣ�����Stub.dll��StubConf�ṹ��
	stubinfo->pStubConf->dwImageSize = dwImageSize;
	stubinfo->pStubConf->pDosHeader = pDosHeader;
	stubinfo->pStubConf->pNtHeader = pNtHeader;
	stubinfo->pStubConf->pOptionalHeader = pOptionalHeader;
	stubinfo->pStubConf->pSecHeader = pSecHeader;
	stubinfo->pStubConf->dwImageBase = dwImageBase;
	stubinfo->pStubConf->dwCodeBase = dwCodeBase;
	stubinfo->pStubConf->dwCodeSize = dwCodeSize;
	stubinfo->pStubConf->dwOEP = dwOEP;
	stubinfo->pStubConf->dwSizeOfHeader = dwSizeOfHeader;
	stubinfo->pStubConf->dwSectionNum = dwSectionNum;
	stubinfo->pStubConf->dwFileAlign = dwFileAlign;
	stubinfo->pStubConf->dwMemAlign = dwMemAlign;
	stubinfo->pStubConf->PERelocDir = PERelocDir;
	stubinfo->pStubConf->PEImportDir = PEImportDir;
	stubinfo->pStubConf->IATSectionBase = IATSectionBase;
	stubinfo->pStubConf->IATSectionSize = IATSectionSize;
	char str[8] = "0AcdDfZ";  //   EncryKey(str)
	strcpy(stubinfo->pStubConf->dwAESKey, EncryKey(str));


	//�����Ǹ�Bug���Ҿ�Ȼ���Ĳ��ˣ�������
	stubinfo->pStubConf->dwNumOfDataDir = dwNumOfDataDir;
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		stubinfo->pStubConf->dwDataDir[i][0] = 
			pOptionalHeader->DataDirectory[i].VirtualAddress;

		stubinfo->pStubConf->dwDataDir[i][1] =
			pOptionalHeader->DataDirectory[i].Size;
	}


	if (stubinfo->pfnStart != 0 &&
		stubinfo->StubBase != 0 &&
		stubinfo->pStubConf != NULL)
	{
		fprintf(fp, "[!]Packer::LoadStub--->LoadStub ok\n");
		fclose(fp);
		return TRUE;
	}
	else
	{
		fprintf(fp, "[!]Packer::LoadStub--->LoadStub failed\n");
		fclose(fp);
		return FALSE;
	}
}

BOOL MyStrcmp(char* src,const char* dst);

//************************************************************
//MyGetProcAddress:ͨ���������������õ�API������ַ
//ChildFunc:MyStrcmp
//************************************************************
DWORD Packer::MyGetProcAddress(HMODULE hKernel32,const char* FuncName)
{

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
			if (MyStrcmp(ExpFunName, FuncName))
			{
				return pEAT[i] + (DWORD)hKernel32;
			}
		}
	}
	return 0;
}

BOOL MyStrcmp(char* src,const char* dst)
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
//EncryIAT:����IAT������
//ChildFunc:NULL

//typedef struct _IMAGE_IMPORT_DESCRIPTOR {
//	union {
//		DWORD   Characteristics;            // 0 for terminating null import descriptor
//		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
//	} DUMMYUNIONNAME;
//	DWORD   TimeDateStamp;                  // 0 if not bound,
//											// -1 if bound, and real date\time stamp
//											//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
//											// O.W. date/time stamp of DLL bound to (Old BIND)
//
//	DWORD   ForwarderChain;                 // -1 if no forwarders
//	DWORD   Name;
//	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
//} IMAGE_IMPORT_DESCRIPTOR;
//typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

//typedef struct _IMAGE_THUNK_DATA32 {
//	union {
//		DWORD ForwarderString;      // PBYTE 
//		DWORD Function;             // PDWORD
//		DWORD Ordinal;
//		DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
//	} u1;
//} IMAGE_THUNK_DATA32;
//typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

//typedef struct _IMAGE_IMPORT_BY_NAME {
//	WORD    Hint;
//	CHAR   Name[1]
//		;
//} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
//https://bbs.pediy.com/thread-247611.htm
//************************************************************
BOOL Packer::EncryIAT(LPBYTE lpBaseAddress)
{

	fp = fopen("HackyPackLog.log", "a");

	PIMAGE_DOS_HEADER pDosHeader = 
		(PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = 
		(PIMAGE_NT_HEADERS)((DWORD)lpBaseAddress + pDosHeader->e_lfanew);
	DWORD Rav_Import_Table = 
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR ImportTable = 
		PIMAGE_IMPORT_DESCRIPTOR((DWORD)lpBaseAddress + Rav_Import_Table);

	//���ÿ�д����
	ImportTable->Characteristics |= 0x80000000;
	
	//�������е�IID
	//����IIDpFirsrThunk
	while (ImportTable->Name)
	{
		//DllName
		
		//��ȡRvaOfDllName
		PDWORD dwTmpDllName = &ImportTable->Name;
		fprintf(fp, "[*]Packer::EncryIAT--->dwOldRvaOfDllName��%x\n", *dwTmpDllName);


		char* pDllName = (char*)((DWORD)lpBaseAddress + ImportTable->Name);
		fprintf(fp, "[*]Packer::EncryIAT--->dwOldDllName��%s\n", pDllName);
		for (DWORD i = 0; i < strlen(pDllName); i++)
			pDllName[i] ^= 0x234;
		fprintf(fp, "[*]Packer::EncryIAT--->dwNewDllName��%s\n", pDllName);
		
		//������ǰ�޸�RvaOfDllNameֵ����DllName��ȡ����
		*dwTmpDllName = *dwTmpDllName ^ 0x123;
		fprintf(fp, "[*]Packer::EncryIAT--->dwNewRvaOfDllName��%x\n", *dwTmpDllName);

		PIMAGE_THUNK_DATA pFirsrThunk = (PIMAGE_THUNK_DATA)((DWORD)lpBaseAddress + ImportTable->FirstThunk);
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
				PIMAGE_IMPORT_BY_NAME pThunkName = 
					(PIMAGE_IMPORT_BY_NAME)((DWORD)lpBaseAddress + pFirsrThunk->u1.AddressOfData);
				
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
				fprintf(fp, "[*]Packer::EncryIAT--->NewHint ��%x\n", Hint);
				*(PWORD)((DWORD)lpBaseAddress + pThunkName->Hint) = *Hint;
			}
			pFirsrThunk++;
		}
		ImportTable++;
	}
	fclose(fp);
	return TRUE;
}

BOOL Packer::GetStubBaseAddr(LPBYTE lpBaseAddress,DWORD *dwStubBaseAddress)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(lpBaseAddress);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	while (pSectionHeader->Name)
	{
		char* SectionName = (char*)pSectionHeader->Name;
		if (strcmp(SectionName, ".Hacky") == 0)
		{
			*dwStubBaseAddress = (DWORD)lpBaseAddress+pSectionHeader->VirtualAddress;
			return TRUE;
		}
		pSectionHeader++;
	}
	return FALSE;
}

BOOL Packer::GetStubIATInfo(DWORD dwStubBaseAddress,
	DWORD *dwStubiDateVirtualSize,
	DWORD *dwStubiDateVirtualAddress,
	DWORD *dwStubiDateSizeOfRawData,
	DWORD *dwStubiDatePointerToRawData)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)dwStubBaseAddress;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	//DWORD dwNumOfRvaAndSize = GetOptionHeader((LPBYTE)dwStubBaseAddress)->NumberOfRvaAndSizes;
	//*dwStubIATVirtualAddress = 
		//GetOptionHeader((LPBYTE)dwStubBaseAddress)->DataDirectory[1].VirtualAddress;
	
	//*dwStubIATSize =
		//GetOptionHeader((LPBYTE)dwStubBaseAddress)->DataDirectory[1].Size;

	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader((LPBYTE)dwStubBaseAddress);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	while (pSectionHeader->Name)
	{
		char* SectionName = (char*)(pSectionHeader->Name);
		if (strcmp(SectionName, ".idata") == 0)
		{
			*dwStubiDateVirtualSize =  pSectionHeader->Misc.VirtualSize;
			*dwStubiDateVirtualAddress = pSectionHeader->VirtualAddress;
			*dwStubiDateSizeOfRawData = pSectionHeader->SizeOfRawData;
			*dwStubiDatePointerToRawData = pSectionHeader->PointerToRawData;
			return TRUE;
		}
		pSectionHeader++;
	}
	return FALSE;
}

BOOL Packer::CpyStubIAT(LPBYTE lpFinalBuf, 
	DWORD dwFinalBufSize,
	DWORD dwStubBaseAddress,
	DWORD dwStubIATVirtualAddress, 
	DWORD dwStubIATSize,
	DWORD *WeiZaoStubIATVirtualAddress)
{




	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(lpFinalBuf);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	while (pSectionHeader->Name)
	{
		char* SectionName = (char*)pSectionHeader->Name;
		if (strcmp(SectionName, ".idata") == 0)
		{
			pSectionHeader->Misc.VirtualSize = dwStubIATSize;
			pSectionHeader->VirtualAddress = (DWORD)(lpFinalBuf + dwFinalBufSize);
			pSectionHeader->SizeOfRawData = dwStubIATSize;
			pSectionHeader->PointerToRawData = (DWORD)(lpFinalBuf + dwFinalBufSize);
			return TRUE;
		}
		pSectionHeader++;
	}

	//����α���IAT��ַ
	StubInfo stubinfo = { 0 };
	//�˴�ʹ��ԭ����GetProcAddress�����ᷢ��17?�Ĵ���
	//���������Լ�ͨ��������ģ��GetProcAddress
	stubinfo.pStubConf = 
		(StubConf*)MyGetProcAddress((HMODULE)dwStubBaseAddress, "g_ShellData");

	stubinfo.pStubConf->dwWeiZaoIATVirtualAddress = 
		*WeiZaoStubIATVirtualAddress;
	stubinfo.pStubConf->dwWeiZaoIATSize = dwStubIATSize;
	return TRUE;
	
}

BOOL Packer::CatWeiIAT(LPBYTE lpFinalBuf, DWORD dwWeiZaoStubIATVirtualAddress, DWORD dwStubIATSize)
{
	//GetOptionHeader(lpFinalBuf)->DataDirectory[1].VirtualAddress = 
		//dwWeiZaoStubIATVirtualAddress;

	//GetOptionHeader(lpFinalBuf)->DataDirectory[1].Size = dwStubIATSize;

	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(lpFinalBuf);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	while (pSectionHeader->Name)
	{
		char* SectionName = (char*)pSectionHeader->Name;
		if (strcmp(SectionName, ".idata") == 0)
		{
			pSectionHeader->Misc.VirtualSize = dwStubIATSize;
			pSectionHeader->VirtualAddress = dwWeiZaoStubIATVirtualAddress;
			pSectionHeader->SizeOfRawData = dwStubIATSize;
			pSectionHeader->PointerToRawData = dwWeiZaoStubIATVirtualAddress;
			return TRUE;
		}
		pSectionHeader++;
	}

	return FALSE;
}

//************************************************************
//ClearDataDir��������е�DataDirectory
//ChildFunc:NULL
//************************************************************
BOOL Packer::ClearDataDir(LPBYTE lpBaseAddress, StubInfo *stubinfo)
{
	//��������Ŀ¼��
	for (DWORD i = 0; i < stubinfo->pStubConf->dwNumOfDataDir; i++)
	{
		if (i == 2)
		{
			continue;
		}
		//�������Ŀ¼����
		GetOptionHeader((LPBYTE)lpBaseAddress)->DataDirectory[i].VirtualAddress = 0;
		GetOptionHeader((LPBYTE)lpBaseAddress)->DataDirectory[i].Size = 0;
	}
	return TRUE;
}

PIMAGE_OPTIONAL_HEADER Packer::GetOptionHeader(LPBYTE lpBaseAddress)
{
	return &GetNtHeader(lpBaseAddress)->OptionalHeader;
}

PIMAGE_NT_HEADERS Packer::GetNtHeader(LPBYTE lpBaseAddress)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	return PIMAGE_NT_HEADERS((DWORD)lpBaseAddress + pImageDosHeader->e_lfanew);
}


//************************************************************
//FindString������.rdata���ַ���
//************************************************************
BOOL  Packer::FindString(LPBYTE lpBaseAddress,DWORD ImageSize)
{
	fp = fopen("HackyPackLog.log", "a");
	DWORD i = 0;
	do
	{
		DWORD Tmp = 0;
		char String[MAX_PATH] = { 0 };
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
				String[Tmp] = lpBaseAddress[i + Tmp]^0x123;
				lpBaseAddress[i + Tmp] = String[Tmp];
				Tmp++;
			}
			String[Tmp + 1] = '\0';
			fprintf(fp, "[*]Packer::FindString--->NewString:%s\n", String);
			
		}

		i += (Tmp + 1);
	} while (i < ImageSize);
	return TRUE;
	fclose(fp);
}