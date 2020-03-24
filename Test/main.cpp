# include <windows.h>
# include <stdio.h>
# include <string.h>
# include <tlhelp32.h>
#pragma warning(disable:4996)


void FindString();
int main()
{
	int i = 0;
	FindString();
	getchar();
}

void FindString()
{
	LPBYTE lpBaseAddress = (LPBYTE)GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)lpBaseAddress + dos->e_lfanew);
	DWORD ImageSize = nt->OptionalHeader.SizeOfImage;
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
				
				String[Tmp] = lpBaseAddress[i + Tmp];
				Tmp++;
			}
			String[Tmp + 1] = '\0';
			printf("%s\n", String);
			
		}

		i += (Tmp+1);
	}while (i < ImageSize);

}






