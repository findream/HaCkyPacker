#include "stdafx.h"


BOOL MyOpenFile(TCHAR *szFilePath)
{
	TCHAR szFilePath1[1024] = { 0 };   // 所选择的文件最终的路径
	OPENFILENAME ofn = { 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFilter = L"exe文件(*.exe)\0";//要选择的文件后缀   
	ofn.lpstrInitialDir = L"./";//默认的文件路径   
	ofn.lpstrFile =(LPWSTR)szFilePath1;//存放文件的缓冲区   
	ofn.nMaxFile = sizeof(szFilePath1) / sizeof(*szFilePath1);
	ofn.nFilterIndex = 0;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER; //标志如果是多选要加上OFN_ALLOWMULTISELECT 

	if (!GetOpenFileName(&ofn))
	{
		return FALSE;
	}
	if (lstrcmp(szFilePath1,L"") == 0)
	{
		// 检验是否获取成功
		return FALSE;
	}
	lstrcpy(szFilePath, szFilePath1);
	return TRUE;
}