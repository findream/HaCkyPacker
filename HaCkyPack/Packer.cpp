#include "Packer.h"
#pragma warning(disable:4996)

//c++类构造和析构函数
Packer::Packer()
{
	//在构造函数里面对类成员进行初始化
	InitClassNumber();
}
Packer::~Packer()
{

}

//************************************************************
//InitClassNumber:初始化类成员
//ChildFunc:NULL
//fp:为Log的句柄，在Pack最后被释放，否则不让释放
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

	//以下是个BUG，我居然还改不了，嘤嘤嘤
	dwNumOfDataDir = 0;
	for (DWORD i = 0; i < 20; i++)
	{
		dwDataDir[i][0] = 0;
		dwDataDir[i][1] = 0;
	}
}

//************************************************************
//GetPEInfo:读取文件，保存PE相关结构信息
//ChildFunc:
	//OpenFile()--->判断文件是否存在
	//
//************************************************************
BOOL Packer::GetPEInfo(char* FilePath)
{
	//判断文件是否存在
	if (FALSE == OpenFile(FilePath,&dwFileSize))
		return FALSE;

	//读取待Packer的文件到内存
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

	//判断PE文件是否合法
	if (FALSE == IsLegalPE())
		return FALSE;

	//获取一些必要的PE文件信息
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;    //Dos头
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuf + pDosHeader->e_lfanew);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);

	dwImageSize = pNtHeader->OptionalHeader.SizeOfImage;
	dwMemAlign = pNtHeader->OptionalHeader.SectionAlignment;
	
	//(size) % (alignment) == 0 ? (size) : ((size) / (alignment)+ 1)*(alignment);
	//此处采用内存对齐的方式将PE文件载入内存，这样在后期处理过程中就不需要重新对齐了
	if (dwImageSize % dwMemAlign)
		dwImageSize = (dwImageSize / dwMemAlign + 1) * dwMemAlign;
	else
		dwImageSize = dwImageSize;

	//开辟新的空间用于保存内存对齐的PE文件数据
	//内存对齐的方式保存的逻辑如下：
	/*-----------------------------------------------------
	      首先复制PE文件的DOS头，文件头，可选头，因为这三部分在文件中
	和在内存中是一样的，不存在对齐的问题，然后分别复制没有节区的数据，
	节区的数据是按照文件对齐的方式保存在内存中的，所以在映射如内存的时候
	需要转换成内存对齐，将无用的数据删掉载入内存
	------------------------------------------------------*/
	dwSizeOfHeader = pNtHeader->OptionalHeader.SizeOfHeaders;
	LPBYTE lpMemPEBuf = new BYTE[dwImageSize];
	memset(lpMemPEBuf, 0, dwImageSize);
	memcpy_s(lpMemPEBuf, dwSizeOfHeader, pFileBuf, dwSizeOfHeader);


	dwSectionNum = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (DWORD i = 0; i < dwSectionNum; i++, pSectionHeader++)
	{
		memcpy_s(lpMemPEBuf + pSectionHeader->VirtualAddress,     //内存对齐
			pSectionHeader->SizeOfRawData,
			pFileBuf + pSectionHeader->PointerToRawData,          //文件对齐
			pSectionHeader->SizeOfRawData);
	}
	//此时PE文件已经以内存对齐的方式保存在内存中了
	memset(pFileBuf, 0, dwFileSize);
	delete[] pFileBuf;   //释放
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
	

	//获取CodeSize
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

	//以下保存修复数据目录所需要的东西，这TM是个BUG
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
	//		//保存该区段的起始地址和大小
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
//Packer::OpenFile 打开文件，并获取文件大小通过传参的形式传出
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
//IsLegalPE:用于判断PE文件是否符合PE文件格式规范
//ChildFunc：NUll
//************************************************************
BOOL Packer::IsLegalPE()
{
	//判断是否为PE文件
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
//LoadStub:加载stub.dll
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
//EncryCodeSeg：加密代码段，内存形式对齐
//ChildFunc：NULL
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

	//加密的地址

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
		NULL,               //用户登陆名 NULL表示使用默认密钥容器，默认密钥容器名
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
			CRYPT_NEWKEYSET))//创建密钥容器
		{
			//创建密钥容器成功，并得到CSP句柄
			fprintf(fp, "[*]Packer:::EncryCodeSeg--->CryptAcquireContext...success\n");
		}
		else
		{
			fprintf(fp, "[!]Packer:::EncryCodeSeg--->CryptAcquireContext...failed:%d\n",GetLastError());
		}
	}

	// 创建一个会话密钥
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
	// 用输入的密码产生一个散列
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

	// 通过散列生成会话密钥
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

	// 因为加密算法是按ENCRYPT_BLOCK_SIZE 大小的块加密的，所以被加密的
	// 数据长度必须是ENCRYPT_BLOCK_SIZE 的整数倍。下面计算一次加密的
	// 数据长度。
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	if (ENCRYPT_BLOCK_SIZE > 1)
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	else
		dwBufferLen = dwBlockLen;

	//开辟空间，准备加密代码段
	if (pbBuffer = (BYTE *)malloc(dwBufferLen))
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->malloc...success\n");
	}
	else
	{
		fprintf(fp, "[*]Packer:::EncryCodeSeg--->malloc...failed:%d\n",GetLastError());
	}
	memset(pbBuffer, 0, dwBufferLen);
	// 加密数据
	DWORD dwTmp = 0;
	DWORD dwTmpCodeSize = dwCodeSize;
	BOOL bFinual = FALSE;
	do 
	{
		//判断是否是最后一块
		if (dwTmpCodeSize > dwBlockLen)
		{
			memcpy(pbBuffer, (pVAOfCodeBaseAddr + dwTmp), dwBlockLen);
			dwCount = dwBlockLen;
			bFinual = FALSE;     //说明大于对齐大小，不是最后一块
		}
		else
		{
			memcpy(pbBuffer, (pVAOfCodeBaseAddr + dwTmp), dwTmpCodeSize);
			dwCount = dwTmpCodeSize;
			bFinual = TRUE;      //说明小于等于对齐大小，是最后一块
		}
			

		if (!CryptEncrypt(
			hKey,           //密钥
			0,              //如果数据同时进行散列和加密，这里传入一个散列对象
			bFinual,        //如果是最后一个被加密的块，输入TRUE.如果不是输入FALSE
			0,              //保留
			pbBuffer,       //输入被加密数据，输出加密后的数据
			&dwCount,       //输入被加密数据实际长度，输出加密后数据长度
			dwBufferLen))   //pbBuffer的大小。
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
//AddNewSection:添加一个区段
//ChildFunc：GetLastSection
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

	//获取最后一个区段
	PIMAGE_SECTION_HEADER pLastSection = GetLastSection(lpOldPEMemBuf);

	//区段个数+1
	pNtHeader->FileHeader.NumberOfSections += 1;
	
	//修改区段名字
	PIMAGE_SECTION_HEADER AddSectionHeader = &pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];	
	memcpy(AddSectionHeader->Name, szNewSectionName, 7);

	//内存对齐0x1000
	//新区段的内存偏移 = 最后一个区段的内存偏移+最后一个区段的内存大小
	DWORD dwTemp = (pLastSection->Misc.VirtualSize / dwMemAlign) * dwMemAlign;
	//如果VirtualSize不是内存颗粒度的整数倍，说明要额外申请1个内存颗粒度大小的内存
	if (pLastSection->Misc.VirtualSize % dwMemAlign)
		dwTemp += 0x1000;
	AddSectionHeader->VirtualAddress = pLastSection->VirtualAddress + dwTemp;

	//在内存中的大小，也就是映像大小
	AddSectionHeader->Misc.VirtualSize = NewSectionSize;

	//新节区的PointerToRawData应该位于就映像大小之后
	AddSectionHeader->PointerToRawData = dwOldPEImageSize;

	//文件大小，同时需要满足文件对齐的要求
	 dwTemp = (NewSectionSize / dwFileAlign) * dwFileAlign;
	if (NewSectionSize % dwFileAlign)
	{
		dwTemp += dwFileAlign;
	}
	AddSectionHeader->SizeOfRawData = dwTemp;


	//修改节区头标志
	AddSectionHeader->Characteristics = 0XE0000040;
	
	dwTemp = (NewSectionSize / dwMemAlign) * dwMemAlign;
	if (NewSectionSize % dwMemAlign)
	{
		dwTemp += dwMemAlign;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwTemp;

	//4.申请合并所需要的空间
	dwSizeOfFinalBuf = dwOldPEImageSize + dwTemp;
	pFinalBuf = new BYTE[dwSizeOfFinalBuf];
	memset(pFinalBuf, 0, dwSizeOfFinalBuf);

	memcpy_s(pFinalBuf, dwOldPEImageSize, lpOldPEMemBuf, dwOldPEImageSize);
	memcpy_s(pFinalBuf + dwOldPEImageSize, dwTemp, lpNewSection, dwTemp);
	return dwTemp;
}


//************************************************************
//GetLastSection：获取最后一个区段
//ChildFunc：NULL
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
//FixStubReloc：修正Stub的重定位表，因为在LoadStub的时候系统已经将stub.dll进行了修正
//ChildFunc:GetOptionHeader
//typedef struct _IMAGE_BASE_RELOCATION {
//	DWORD   VirtualAddress;//RVA
//	DWORD   SizeOfBlock;   //重定位数据大小
//	WORD    TypeOffset;    // 重定位项数组
//} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
//************************************************************
BOOL Packer::FixStubReloc(LPBYTE StubBaseAddr)
{
	//定位Stub.dll的重定位表
	PIMAGE_DATA_DIRECTORY	pStubRelocDir =
		&(GetOptionHeader(StubBaseAddr)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	DWORD dwRVAOfStubReloc = pStubRelocDir->VirtualAddress;
	PIMAGE_BASE_RELOCATION pRelocOfStub = PIMAGE_BASE_RELOCATION((DWORD)StubBaseAddr + dwRVAOfStubReloc);
	fp = fopen("HackyPackLog.log", "a");
	while (pRelocOfStub->SizeOfBlock)
	{
		typedef struct _TYPEOFFSET
		{
			WORD offset : 12;			//偏移值
			WORD Type : 4;			    //重定位属性(方式)
		}TYPEOFFSET, *PTYPEOFFSET;
		PTYPEOFFSET pTypeOffset = PTYPEOFFSET(pRelocOfStub + 1);

		//10H-->(10H-8H)/2=4,一共有四个重定位数组，
		//8H指的是VirtualAddress和sizeofBlock所占的字节数为8，除以2H，表示一个TypeOffset为2个字节。
		DWORD dwNumOfBlock = (pRelocOfStub->SizeOfBlock - 8) / 2;

		for (DWORD i = 0; i < dwNumOfBlock; i++)
		{
			if (*(PWORD)&pTypeOffset[i] == NULL)
				break;

			DWORD dwRVAOfRelocBlock = pRelocOfStub->VirtualAddress + pTypeOffset[i].offset;

			//需要重定位的地址
			DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)StubBaseAddr + dwRVAOfRelocBlock);
			DWORD dwOld = 0;
			fprintf(fp, "[*]Packer::FixStubReloc--->Old Reloc:%d\n", *(PDWORD)((DWORD)StubBaseAddr + dwRVAOfRelocBlock));
			VirtualProtect(&AddrOfNeedReloc, 4, PAGE_READWRITE, &dwOld);
			
			//计算公式：需要重定位的RVA-当前的基地址(StubImageBase)+目的程序的基地址(OldPeBaseAddr+SizeOfOldImage)
			DWORD dwTmpImageBase = GetOptionHeader(StubBaseAddr)->ImageBase;
			*(PDWORD)((DWORD)StubBaseAddr + dwRVAOfRelocBlock)=AddrOfNeedReloc - dwTmpImageBase + dwImageBase + dwImageSize;
			
			VirtualProtect(&AddrOfNeedReloc, 4, dwOld, &dwOld);

			fprintf(fp, "[*]Packer::FixStubReloc--->New Reloc:%d\n", *(PDWORD)((DWORD)StubBaseAddr + dwRVAOfRelocBlock));
		}
		pRelocOfStub = (PIMAGE_BASE_RELOCATION)
			((DWORD)pRelocOfStub + pRelocOfStub->SizeOfBlock);
	}
	pRelocOfStub->VirtualAddress += dwImageSize;
	//原始PE文件的重定位目录表指针信息
	PIMAGE_DATA_DIRECTORY pOldPERelocDir =
		&(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	pOldPERelocDir->Size = pStubRelocDir->Size;
	pOldPERelocDir->VirtualAddress = pStubRelocDir->Size + dwImageSize;
	fprintf(fp, "[*]Packer::FixStubReloc--->PERelocDir Update:%d\n", pOldPERelocDir->VirtualAddress);
	fclose(fp);
	return TRUE;
}



//************************************************************
//SetOepOfPEFile:设置新的OEP，Start-StubBaseAddr+PEImageSize
//ChildFunc：NULL
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
//GetNewFilePath：构造新文件的路径
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
//SaveFinalFile：保存文件
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

	//构造新文件路径
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
	//判断文件是否存在
	if (INVALID_HANDLE_VALUE != CreateFile(NewFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))
	{
		fprintf(fp, "[*]Packer::SaveFinalFile--->NewFile :%s\n", NewFilePath);
		fclose(fp);
		return TRUE;
	}
	return TRUE;
}

//************************************************************
//GetStubImageSize：获取Stub的映像大小
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
//GetStubInfo:将之前保存在public的原始PE数据传递给Stub的g_ShellData之中
//ChildFunc:NULL
//************************************************************
BOOL Packer::GetStubInfo(LPBYTE	lpNewStubBaseAddr, StubInfo *stubinfo)
{
	fp = fopen("HackyPackLog.log", "a");
	LPBYTE a = stubinfo->StubBase ;
		//= lpNewStubBaseAddr;
	stubinfo->pfnStart = (DWORD)MyGetProcAddress((HMODULE)lpNewStubBaseAddr, "Start");
	stubinfo->pStubConf = (StubConf*)MyGetProcAddress((HMODULE)lpNewStubBaseAddr, "g_ShellData");

	//将获取到的PE相关信息共享给Stub.dll的StubConf结构体
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


	//以下是个Bug，我居然还改不了，嘤嘤嘤
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
//MyGetProcAddress:通过遍历导出表，来得到API函数地址
//ChildFunc:MyStrcmp
//************************************************************
DWORD Packer::MyGetProcAddress(HMODULE hKernel32,const char* FuncName)
{

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
//EncryIAT:加密IAT的数据
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

	//设置可写属性
	ImportTable->Characteristics |= 0x80000000;
	
	//遍历所有的IID
	//遍历IIDpFirsrThunk
	while (ImportTable->Name)
	{
		//DllName
		
		//获取RvaOfDllName
		PDWORD dwTmpDllName = &ImportTable->Name;
		fprintf(fp, "[*]Packer::EncryIAT--->dwOldRvaOfDllName：%x\n", *dwTmpDllName);


		char* pDllName = (char*)((DWORD)lpBaseAddress + ImportTable->Name);
		fprintf(fp, "[*]Packer::EncryIAT--->dwOldDllName：%s\n", pDllName);
		for (DWORD i = 0; i < strlen(pDllName); i++)
			pDllName[i] ^= 0x234;
		fprintf(fp, "[*]Packer::EncryIAT--->dwNewDllName：%s\n", pDllName);
		
		//避免提前修改RvaOfDllName值导致DllName获取不到
		*dwTmpDllName = *dwTmpDllName ^ 0x123;
		fprintf(fp, "[*]Packer::EncryIAT--->dwNewRvaOfDllName：%x\n", *dwTmpDllName);

		PIMAGE_THUNK_DATA pFirsrThunk = (PIMAGE_THUNK_DATA)((DWORD)lpBaseAddress + ImportTable->FirstThunk);
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
				PIMAGE_IMPORT_BY_NAME pThunkName = 
					(PIMAGE_IMPORT_BY_NAME)((DWORD)lpBaseAddress + pFirsrThunk->u1.AddressOfData);
				
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
				fprintf(fp, "[*]Packer::EncryIAT--->NewHint ：%x\n", Hint);
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

	//导出伪造的IAT地址
	StubInfo stubinfo = { 0 };
	//此处使用原生的GetProcAddress函数会发生17?的错误
	//所以我们自己通过导出表模拟GetProcAddress
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
//ClearDataDir：清空所有的DataDirectory
//ChildFunc:NULL
//************************************************************
BOOL Packer::ClearDataDir(LPBYTE lpBaseAddress, StubInfo *stubinfo)
{
	//遍历数据目录表
	for (DWORD i = 0; i < stubinfo->pStubConf->dwNumOfDataDir; i++)
	{
		if (i == 2)
		{
			continue;
		}
		//清除数据目录表项
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
//FindString：检索.rdata的字符串
//************************************************************
BOOL  Packer::FindString(LPBYTE lpBaseAddress,DWORD ImageSize)
{
	fp = fopen("HackyPackLog.log", "a");
	DWORD i = 0;
	do
	{
		DWORD Tmp = 0;
		char String[MAX_PATH] = { 0 };
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