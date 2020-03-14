#pragma once
#include <windows.h>

typedef struct _StubConf
{
	
	DWORD					dwImageSize;		//镜像大小
	PIMAGE_DOS_HEADER		pDosHeader;		    //Dos头
	PIMAGE_NT_HEADERS		pNtHeader;		    //NT头
	PIMAGE_OPTIONAL_HEADER  pOptionalHeader;    //可选头
	PIMAGE_SECTION_HEADER	pSecHeader;		    //第一个SECTION结构体指针
	DWORD					dwImageBase;    //镜像基址
	DWORD                   dwCodeBase;		//代码段起始地址
	DWORD					dwCodeSize;		//代码大小
	DWORD					dwOEP;			//OEP地址
	DWORD					dwSizeOfHeader;	//文件头大小
	DWORD					dwSectionNum;		//区段数量
	DWORD					dwFileAlign;		//文件对齐
	DWORD					dwMemAlign;		//内存对齐

	IMAGE_DATA_DIRECTORY	PERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	PEImportDir;		//导入表信息

	DWORD					IATSectionBase;	//IAT所在段基址
	DWORD					IATSectionSize;	//IAT所在段大小
	LPBYTE                  lpFinalBuf;     //最终的Buf
	DWORD                   IATNewSectionBase;   //lpFinalBuf的IAT
	DWORD                   IATNewSectionSize;

	DWORD                   dwXorKey;			//解密KEY

	DWORD dwDataDir[20][2];  //数据目录表的RVA和Size	
	DWORD dwNumOfDataDir;	//数据目录表的个数
}StubConf;

struct StubInfo
{
	LPBYTE StubBase;		//stub.dll的加载基址
	DWORD pfnStart;			//stub.dll(start)导出函数的地址
	StubConf* pStubConf;	//stub.dll(g_conf)导出全局变量的地址
};