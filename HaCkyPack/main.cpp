#include "Packer.h"
#pragma warning(disable:4996)

int main()
{
	Packer packer;
	char FilePath[MAX_PATH] = "D:\\Test.exe";

	//Step1����ȡ���ӿǳ���Ļ���PE��Ϣ
	BOOL a = packer.GetPEInfo(FilePath);


	//Step2������Stub����
	StubInfo stubinfo = { 0 };
	BOOL b = packer.LoadStub(&stubinfo);



	//Step3:����Stub����,����ͻ���Ե�Ȩ�޷��ʴ���
	DWORD dwStubImageSize = packer.GetStubImageSize(stubinfo.StubBase);
	LPBYTE lpNewStubBaseAddr = new BYTE[dwStubImageSize];
	memset(lpNewStubBaseAddr, 0, dwStubImageSize);
	memcpy_s(lpNewStubBaseAddr, dwStubImageSize, stubinfo.StubBase, dwStubImageSize);
	packer.fp = fopen("HackyPackLog.log", "a");
	fprintf(packer.fp, "[*]Packer::Main--->MemcpyStub Success,BaseAddr:%0X\n", lpNewStubBaseAddr);
	fclose(packer.fp);





	//Step4:��ȡStub�����ݲ����ԭʼPE��PE����
	BOOL e = packer.GetStubInfo(lpNewStubBaseAddr, &stubinfo);



	//Step3: ���ܴ����
	BOOL c = packer.EncryCodeSeg(stubinfo.pStubConf->dwXorKey);

	
	//Step4���޸��ض�λ
	BOOL f = packer.FixStubReloc(lpNewStubBaseAddr);

	//Step5������OEP
	DWORD dwStubOep = stubinfo.pfnStart - (DWORD)lpNewStubBaseAddr;
	BOOL g = packer.SetOepOfPEFile(dwStubOep);




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


	
	//Step6:����IAT��
	//������Ҫ����������������ģ�
	//1. ��Ҫ��λ���ϲ�֮���Stub.dll�ڴ���ʼ��ַ��ͨ��.HaCky����VirtualAddress����ȡ
	//2. ��ȡ��Stub.dll�ڴ���ʼ��ַ����λ���������ȡVirtualAddress��Size
	//3. ��������һ�飬α������һ���������סVirtualAddress��Size��Ҫ����
	//4. �ڻָ���ʱ�������ӵ�α��ĵ��������IDA��ʾ�ľ���α���dll�ĵ����
	//5. �ڽ��ܵ�ʱ��һ����Ҫ��ԭ���ĵ�����VirtualAddress��Sizeд��(���ͨ�������������)


	//1. ��Ҫ��λ���ϲ�֮���Stub.dll�ڴ���ʼ��ַ
	//DWORD dwStubBaseAddress = 0;
	//BOOL aa = packer.GetStubBaseAddr(lpFinalBuf, &dwStubBaseAddress);
	//4. ��������ԭʼPE�ļ�IAT��
	//BOOL i = packer.EncryIAT(lpFinalBuf);





	//���IAT������
	BOOL j = packer.ClearDataDir(lpFinalBuf, &stubinfo);
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
	BOOL h = packer.SaveFinalFile(lpFinalBuf, dwFinalBufSize,FilePath);

	delete[] packer.lpMemBuf;
	return 0;
}