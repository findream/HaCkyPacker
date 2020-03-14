#pragma once
#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <stdlib.h>
#include "StubData.h"
#include <Dbghelp.h> 
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shlwapi")

class Packer
{
public:
	Packer();
	~Packer();

public:
	FILE                    *fp;            //log�ļ�
	HANDLE					hFile;			//PE�ļ����
	LPBYTE					pFileBuf;	    //PE�ļ�������(�ļ�����)
	LPBYTE					lpMemBuf;       //�ڴ����
	DWORD					dwFileSize;		//�ļ���С

	DWORD					dwImageSize;		//�����С
	PIMAGE_DOS_HEADER		pDosHeader;		//Dosͷ
	PIMAGE_NT_HEADERS		pNtHeader;		//NTͷ
	PIMAGE_OPTIONAL_HEADER  pOptionalHeader;  //��ѡͷ
	PIMAGE_SECTION_HEADER	pSecHeader;		//��һ��SECTION�ṹ��ָ��
	DWORD					dwImageBase;    //�����ַ
	DWORD					dwCodeBase;		//�����ַ
	DWORD					dwCodeSize;		//�����С
	DWORD					dwOEP;			//OEP��ַ
	DWORD					dwShellOEP;		//��OEP��ַ
	DWORD					dwSizeOfHeader;	//�ļ�ͷ��С
	DWORD					dwSectionNum;		//��������
	DWORD					dwFileAlign;		//�ļ�����
	DWORD					dwMemAlign;		//�ڴ����

	IMAGE_DATA_DIRECTORY	PERelocDir;		//�ض�λ����Ϣ
	IMAGE_DATA_DIRECTORY	PEImportDir;		//�������Ϣ

	DWORD					IATSectionBase;	//IAT���ڶλ�ַ
	DWORD					IATSectionSize;	//IAT���ڶδ�С

	//���±����޸�����Ŀ¼����Ҫ�Ķ�������TM�Ǹ�BUG
	DWORD                   dwNumOfDataDir;
	DWORD                   dwDataDir[20][2];  //����Ŀ¼����RVA��Size


public:
	void InitClassNumber();
	BOOL IsLegalPE();
	BOOL GetPEInfo(char* FilePath);
	BOOL OpenFile(char* FilePath,DWORD *dwFileSize);
	BOOL EncryCodeSeg(DWORD XorCode);
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
	//BOOL ClearDataDir(LPBYTE lpFinalBuf, StubInfo *stubinfo);
	BOOL ClearDataDir(LPBYTE pFileData, StubInfo *stubinfo);
	BOOL GetStubInfo(LPBYTE	lpNewStubBaseAddr, StubInfo *stubinfo);
	PIMAGE_NT_HEADERS GetNtHeader(LPBYTE lpBaseAddress);
	
};