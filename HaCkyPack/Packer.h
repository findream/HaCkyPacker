#pragma once
#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <stdlib.h>
#include "StubData.h"
#include <Dbghelp.h> 
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shlwapi")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4
#define ENCRYPT_BLOCK_SIZE 8

class Packer
{
public:
	Packer();
	~Packer();

public:
	FILE                    *fp;            //log文件
	HANDLE					hFile;			//PE文件句柄
	LPBYTE					pFileBuf;	    //PE文件缓冲区(文件对齐)
	LPBYTE					lpMemBuf;       //内存对齐
	DWORD					dwFileSize;		//文件大小

	DWORD					dwImageSize;		//镜像大小
	PIMAGE_DOS_HEADER		pDosHeader;		//Dos头
	PIMAGE_NT_HEADERS		pNtHeader;		//NT头
	PIMAGE_OPTIONAL_HEADER  pOptionalHeader;  //可选头
	PIMAGE_SECTION_HEADER	pSecHeader;		//第一个SECTION结构体指针
	DWORD					dwImageBase;    //镜像基址
	DWORD					dwCodeBase;		//代码基址
	DWORD					dwCodeSize;		//代码大小
	DWORD					dwOEP;			//OEP地址
	DWORD					dwShellOEP;		//新OEP地址
	DWORD					dwSizeOfHeader;	//文件头大小
	DWORD					dwSectionNum;		//区段数量
	DWORD					dwFileAlign;		//文件对齐
	DWORD					dwMemAlign;		//内存对齐

	IMAGE_DATA_DIRECTORY	PERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	PEImportDir;		//导入表信息

	DWORD					IATSectionBase;	//IAT所在段基址
	DWORD					IATSectionSize;	//IAT所在段大小

	//以下保存修复数据目录所需要的东西，这TM是个BUG
	DWORD                   dwNumOfDataDir;
	DWORD                   dwDataDir[20][2];  //数据目录表的RVA和Size


public:
	void InitClassNumber();
	BOOL IsLegalPE();
	BOOL GetPEInfo(char* FilePath);
	BOOL OpenFile(char* FilePath,DWORD *dwFileSize);
	BOOL EncryCodeSeg(char* szPassword);
	BOOL LoadStub(StubInfo *stubinfo);
	DWORD AddNewSection(LPBYTE lpOldPEMemBuf, DWORD dwOldPEImageSize,const char* szNewSectionName,LPBYTE lpNewSection, DWORD NewSectionSize, LPBYTE& FinalBuf, DWORD& dwSizeOfFinalBuf);
	PIMAGE_SECTION_HEADER GetLastSection(LPBYTE lpMemBuf);
	BOOL FixStubReloc(LPBYTE StubBaseAddr);
	PIMAGE_OPTIONAL_HEADER GetOptionHeader(LPBYTE lpBaseAddress);
	BOOL SetOepOfPEFile(DWORD dwStubOep);
	BOOL SaveFinalFile(LPBYTE lpFinalBuf,DWORD dwFinalBufSize,char* FilePath);
	DWORD GetStubImageSize(LPBYTE lpStubBaseAddr);
	
	DWORD MyGetProcAddress(HMODULE hKernel32, const char* FuncName);

	BOOL EncryIAT(LPBYTE lpNewStubBaseAddr);
	BOOL GetStubBaseAddr(LPBYTE lpBaseAddress,
		DWORD *dwStubBaseAddress);
	BOOL GetStubIATInfo(DWORD dwStubBaseAddress, 
		DWORD *dwStubiDateVirtualSize,
		DWORD *dwStubiDateVirtualAddress,
		DWORD *dwStubiDateSizeOfRawData,
		DWORD *dwStubiDatePointerToRawData);
	BOOL CpyStubIAT(LPBYTE lpFinalBuf,DWORD dwFinalBufSize, DWORD dwStubBaseAddress, DWORD dwStubIATVirtualAddress, DWORD dwStubIATSize, DWORD *WeiZaoStubIATVirtualAddress);
	BOOL CatWeiIAT(LPBYTE lpFinalBuf,DWORD dwWeiZaoStubIATVirtualAddress,DWORD dwStubIATSize);

	BOOL ClearDataDir(LPBYTE pFileData, StubInfo *stubinfo);
	BOOL GetStubInfo(LPBYTE	lpNewStubBaseAddr, StubInfo *stubinfo);
	PIMAGE_NT_HEADERS GetNtHeader(LPBYTE lpBaseAddress);
	char* EncryKey(char* str);
	BOOL  FindString(LPBYTE lpFinalBuf, DWORD Size);
	
};