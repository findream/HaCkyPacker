# include <windows.h>
# include <stdio.h>
# include <string.h>
# include <tlhelp32.h>
#pragma warning(disable:4996)


void TakeInstruc()
{
	//���øı�ָ�������ӻ�
	DWORD p;
	__asm {
		call	l1;
	l1:
		pop		eax;
		mov		p, eax;			//ȷ����ǰ����ε�λ��
		call	f1;
		_EMIT	0xEA;			//��ָ��˴���Զ����ִ�е�
		jmp		l2;				//call�����Ժ�ִ�е�����
	f1:							
		pop ebx;
		inc ebx;
		push ebx;
		mov eax, 0x1234567;
		ret;
	l2:
		call f2;				//��retָ��ʵ����ת
		mov ebx, 0x1234567;	    //������Զ����ִ�е�
		jmp e;					
	f2:
		mov ebx, 0x1234567;
		pop ebx;				//����ѹջ�ĵ�ַ
		mov ebx, offset e;		//Ҫ��ת���ĵ�ַ
		push ebx;				//ѹ��Ҫ��ת���ĵ�ַ
		ret;					//��ת
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
			mov eax, dword ptr ds : [esi]  //�����쳣
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


