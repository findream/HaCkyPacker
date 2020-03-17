#include "Packer.h"
#pragma warning(disable:4996)

int main()
{
	Packer packer;
	char FilePath[MAX_PATH] = "D:\\Test.exe";

	//Step1：获取待加壳程序的基本PE信息
	BOOL a = packer.GetPEInfo(FilePath);


	//Step2：载入Stub部分
	StubInfo stubinfo = { 0 };
	BOOL b = packer.LoadStub(&stubinfo);



	//Step3:复制Stub数据,避免突发性的权限访问错误
	DWORD dwStubImageSize = packer.GetStubImageSize(stubinfo.StubBase);
	LPBYTE lpNewStubBaseAddr = new BYTE[dwStubImageSize];
	memset(lpNewStubBaseAddr, 0, dwStubImageSize);
	memcpy_s(lpNewStubBaseAddr, dwStubImageSize, stubinfo.StubBase, dwStubImageSize);
	packer.fp = fopen("HackyPackLog.log", "a");
	fprintf(packer.fp, "[*]Packer::Main--->MemcpyStub Success,BaseAddr:%0X\n", lpNewStubBaseAddr);
	fclose(packer.fp);





	//Step4:获取Stub的数据并填充原始PE的PE数据
	BOOL e = packer.GetStubInfo(lpNewStubBaseAddr, &stubinfo);



	//Step3: 加密代码段
	BOOL c = packer.EncryCodeSeg(stubinfo.pStubConf->dwXorKey);

	
	//Step4：修复重定位
	BOOL f = packer.FixStubReloc(lpNewStubBaseAddr);

	//Step5：设置OEP
	DWORD dwStubOep = stubinfo.pfnStart - (DWORD)lpNewStubBaseAddr;
	BOOL g = packer.SetOepOfPEFile(dwStubOep);




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


	
	//Step6:加密IAT表
	//现在需要解决的问题是这样的，
	//1. 需要定位到合并之后的Stub.dll内存起始地址，通过.HaCky节区VirtualAddress来获取
	//2. 获取了Stub.dll内存起始地址，定位到导入表，获取VirtualAddress和Size
	//3. 整个复制一遍，伪造这样一个导入表，记住VirtualAddress和Size需要导出
	//4. 在恢复的时候先链接到伪造的导入表，这样IDA显示的就是伪造的dll的导入表
	//5. 在解密的时候，一定需要将原来的导入表的VirtualAddress和Size写回(这个通过交互函数解决)


	//1. 需要定位到合并之后的Stub.dll内存起始地址
	//DWORD dwStubBaseAddress = 0;
	//BOOL aa = packer.GetStubBaseAddr(lpFinalBuf, &dwStubBaseAddress);
	//4. 加密整个原始PE文件IAT表
	//BOOL i = packer.EncryIAT(lpFinalBuf);





	//清空IAT表数据
	BOOL j = packer.ClearDataDir(lpFinalBuf, &stubinfo);
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
	BOOL h = packer.SaveFinalFile(lpFinalBuf, dwFinalBufSize,FilePath);

	delete[] packer.lpMemBuf;
	return 0;
}