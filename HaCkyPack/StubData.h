#pragma once
#include <windows.h>

typedef struct _StubConf
{
	
	DWORD					dwImageSize;		//�����С
	PIMAGE_DOS_HEADER		pDosHeader;		    //Dosͷ
	PIMAGE_NT_HEADERS		pNtHeader;		    //NTͷ
	PIMAGE_OPTIONAL_HEADER  pOptionalHeader;    //��ѡͷ
	PIMAGE_SECTION_HEADER	pSecHeader;		    //��һ��SECTION�ṹ��ָ��
	DWORD					dwImageBase;    //�����ַ
	DWORD                   dwCodeBase;		//�������ʼ��ַ
	DWORD					dwCodeSize;		//�����С
	DWORD					dwOEP;			//OEP��ַ
	DWORD					dwSizeOfHeader;	//�ļ�ͷ��С
	DWORD					dwSectionNum;		//��������
	DWORD					dwFileAlign;		//�ļ�����
	DWORD					dwMemAlign;		//�ڴ����

	IMAGE_DATA_DIRECTORY	PERelocDir;		//�ض�λ����Ϣ
	IMAGE_DATA_DIRECTORY	PEImportDir;		//�������Ϣ

	DWORD					IATSectionBase;	//IAT���ڶλ�ַ
	DWORD					IATSectionSize;	//IAT���ڶδ�С
	LPBYTE                  lpFinalBuf;     //���յ�Buf
	DWORD                   IATNewSectionBase;   //lpFinalBuf��IAT
	DWORD                   IATNewSectionSize;

	DWORD                   dwXorKey;			//����KEY

	DWORD dwDataDir[20][2];  //����Ŀ¼���RVA��Size	
	DWORD dwNumOfDataDir;	//����Ŀ¼��ĸ���
}StubConf;

struct StubInfo
{
	LPBYTE StubBase;		//stub.dll�ļ��ػ�ַ
	DWORD pfnStart;			//stub.dll(start)���������ĵ�ַ
	StubConf* pStubConf;	//stub.dll(g_conf)����ȫ�ֱ����ĵ�ַ
};