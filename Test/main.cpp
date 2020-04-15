# include <windows.h>
# include <stdio.h>
# include <string.h>
# include <tlhelp32.h>
# include <winternl.h>
# include <psapi.h>
#pragma warning(disable:4996)



// MultiTread2.cpp : 定义控制台应用程序的入口点。
//

//
//#define MAX_THREADS 10
//
//typedef struct MyData
//{
//	int val1;
//	int val2;
//	//char key[32];
//}MYDATA;
//
//DWORD WINAPI ThreadProc(LPVOID lpParam)
//{
//	MYDATA *pmd = (MYDATA *)lpParam;
//	printf("%d\n", pmd->val1);
//	printf("%d\n", pmd->val2);
//	return 0;
//}
//
//DWORD(WINAPI *pThreadProc)(LPVOID lpParam);
//
//void fun()
//{
//	pThreadProc = ThreadProc;
//	MYDATA mydt[MAX_THREADS];
//
//	HANDLE hThread[MAX_THREADS];
//	int i;
//	for (i = 0; i < MAX_THREADS; i++)
//	{
//		mydt[i].val1 = i;
//		mydt[i].val2 = i + 1;
//		hThread[i] = CreateThread(
//			NULL,// default security attributes
//			0,// use default stack size
//			pThreadProc,// thread function
//			&mydt[i],// argument to thread function
//			0, // use default creation flags
//			NULL);
//		if (hThread[i] == NULL)
//		{
//			ExitProcess(i);
//		}
//	}
//	// Wait until all threads have terminated.
//	WaitForMultipleObjects(MAX_THREADS, hThread, TRUE, INFINITE); //这样传给回调函数的参数不用定位static或者new出来的了
//	// Close all thread handles upon completion. 
//	for (i = 0; i < MAX_THREADS; i++)
//	{
//		CloseHandle(hThread[i]);
//	}
//
//}
//
//int main(void)
//{
//	fun();
//	getchar();
//	return 0;
//}



//BOOL  InjectDllToProcess(DWORD dwPID, LPCTSTR szDllPath);
//DWORD ProcesstoPid(char *Processname);
//BOOL EnableDebugPrivilege();
//int InjectDll(void);






typedef struct MyData
{
	char cpDllFile[MAX_PATH];
	char ProcessName[MAX_PATH];
	//char key[32];
}MYDATA;


DWORD WINAPI ThreadProc(LPVOID lpParam)
{
	MYDATA *pmd = (MYDATA *)lpParam;
	while (1)
	{
		printf("%s\n", pmd->cpDllFile);
		printf("%s\n", pmd->ProcessName);
	}
	return 0;
}

DWORD(WINAPI *pThreadProc)(LPVOID lpParam);
int main()
{

	pThreadProc = ThreadProc;
	MYDATA mydt;
	strcpy(mydt.cpDllFile, "ReflectDll_Dll.dll");
	strcpy(mydt.cpDllFile, "12345.exe");
	 HANDLE hThread = CreateThread(
		NULL,
		0,
		pThreadProc,
		&mydt,
		0,
		NULL);

	if (hThread == NULL)
	{
		return 1;
	}

	WaitForMultipleObjects(MAXIMUM_WAIT_OBJECTS, &hThread, TRUE, INFINITE);


}

	//HANDLE lpBufBase = GetModuleHandle(NULL);

	//逆序
	//ULONG_PTR uiHeaderValue = 0;
	//ULONG_PTR uiLibraryAddress = (ULONG_PTR)lpBuf + dwFileSize;
	//while (TRUE)
	//{
	//	if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
	//	{
	//		uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
	//		if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
	//		{
	//			uiHeaderValue += uiLibraryAddress;
	//			if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
	//				break;
	//		}
	//	}
	//	uiLibraryAddress--;
	//}

//}

//int main()
//{
//
//	//
//	char FilePath[] = "D:\\Test.exe";
//	HANDLE hFile = CreateFile(FilePath,
//		GENERIC_READ | GENERIC_WRITE, 0, NULL,
//		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//
//	if (hFile == INVALID_HANDLE_VALUE)
//	{
//		printf("%d\n", GetLastError());
//	}
//	DWORD dwFileSize = GetFileSize(hFile, NULL);
//	if (dwFileSize == NULL)
//	{
//		printf("%d\n", GetLastError());
//	}
//	LPBYTE pFileBuf = new BYTE[dwFileSize];
//	DWORD ReadSize = 0;
//	if (FALSE == ReadFile(hFile, pFileBuf, dwFileSize, &ReadSize, NULL))
//	{
//
//		CloseHandle(hFile);
//		return FALSE;
//	}
//	CloseHandle(hFile);
//
//	//获取代码段地址，大小
//	DWORD dwAddress = 0;
//	DWORD dwSize = 0;
//	
//	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
//	PIMAGE_NT_HEADERS pNtHeader =(PIMAGE_NT_HEADERS) (pFileBuf + pDosHeader->e_lfanew);
//	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
//	while (pSectionHeader->Name)
//	{
//		char* SectionName = (char*)(pSectionHeader->Name);
//		if (strcmp(SectionName, ".text") == 0)
//		{
//			dwAddress = pSectionHeader->PointerToRawData;
//			dwSize = pSectionHeader->SizeOfRawData;
//			break;
//		}
//		pSectionHeader++;
//	}
//
//	//反汇编
//	char* pCode = new char[dwSize];
//	memset(pCode, 0, dwSize);
//	memcpy(pCode, (LPBYTE)(pFileBuf+dwAddress), dwSize);
//	csh handle;
//	cs_insn* insn;
//	size_t count;
//
//	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) 
//	{
//		printf("ERROR: Failed to initialize engine!\n");
//		return -1;
//	}
//
//	count = cs_disasm(handle, (unsigned char*)pCode, dwSize, 0x1000, 0, &insn);
//	if (count) 
//	{
//		size_t j;
//		for (j = 0; j < count; j++) 
//		{
//			//printf("0x%x:", insn[j].address);
//			//printf("%s %s\n",  insn[j].mnemonic, insn[j].op_str);
//			//此处进行混淆
//			if (!strcmp(insn[j].mnemonic,"mov"))
//			{
//
//			}
//
//		}
//		cs_free(insn, count);
//	}
//	else
//		printf("ERROR: Failed to disassemble given code!\n");
//	cs_close(&handle);
//
//	return 0;
//
//}



//#include <iostream>
//#include <stdio.h>
//#include <cinttypes>  
//#include "capstone.h"
//using namespace std;
//
//#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
//
//int main(void)
//{
//	csh handle;
//	cs_insn* insn;
//	size_t count;
//
//	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
//		printf("ERROR: Failed to initialize engine!\n");
//		return -1;
//	}
//
//	count = cs_disasm(handle, (unsigned char*)CODE, sizeof(CODE) - 1, 0x1000, 0, &insn);
//	if (count) {
//		size_t j;
//
//		for (j = 0; j < count; j++) {
//			printf("0x%x:", insn[j].address);
//			printf("%s %s\n",  insn[j].mnemonic, insn[j].op_str);
//		}
//
//		cs_free(insn, count);
//	}
//	else
//		printf("ERROR: Failed to disassemble given code!\n");
//
//	cs_close(&handle);
//
//	return 0;
//}
