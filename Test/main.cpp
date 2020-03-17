# include <windows.h>
# include <stdio.h>
# include <string.h>
# include <tlhelp32.h>
#pragma warning(disable:4996)


void TakeInstruc()
{
	//采用改变指令流来加花
	DWORD p;
	__asm {
		call	l1;
	l1:
		pop		eax;
		mov		p, eax;			//确定当前程序段的位置
		call	f1;
		_EMIT	0xEA;			//花指令，此处永远不会执行到
		jmp		l2;				//call结束以后执行到这里
	f1:							
		pop ebx;
		inc ebx;
		push ebx;
		mov eax, 0x1234567;
		ret;
	l2:
		call f2;				//用ret指令实现跳转
		mov ebx, 0x1234567;	    //这里永远不会执行到
		jmp e;					
	f2:
		mov ebx, 0x1234567;
		pop ebx;				//弹出压栈的地址
		mov ebx, offset e;		//要跳转到的地址
		push ebx;				//压入要跳转到的地址
		ret;					//跳转
	e:
		mov ebx, 0x1234567;
	}
}

void fun1()
{
	__try
	{
		_asm
		{
			mov esi, 0
			mov eax, dword ptr ds : [esi]  //进入异常
			push eax
			mov ebp, esp
			push - 1
			push 3223
			push 1331131
			mov eax, fs:[0]
			push eax
			mov fs : [0], esp
			pop eax
			mov fs : [0], eax
			pop eax
			pop eax
			pop eax
		    pop eax
			mov ebp, eax
			nop
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		_asm nop
	}
	int i = 1;
	MessageBox(NULL, "111", "222", MB_OK);
}
//str1[*input + 48] = str2;
int main(void)
{
	fun1();
	getchar();
}


