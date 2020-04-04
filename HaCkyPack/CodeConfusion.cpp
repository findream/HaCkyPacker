# include "packer.h"

//能够在现有指令之前，之后和之间插入新指令
//能够在插入或删除指令时修复相对跳转偏移
//能够用其他指令替换现有指令，确保不遗留任何静态数据，这可能有助于创建检测签名
//能够插入跳转指令，这些指令将改变执行流程并将shellcode随机分成单独的块

BOOL Packer::UDisam(DWORD dwVACodeBase, DWORD dwVACodeSize)
{


	return TRUE;


}
