#include "stdafx.h"


BOOL MyOpenFile(TCHAR *szFilePath)
{
	TCHAR szFilePath1[1024] = { 0 };   // ��ѡ����ļ����յ�·��
	OPENFILENAME ofn = { 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFilter = L"exe�ļ�(*.exe)\0";//Ҫѡ����ļ���׺   
	ofn.lpstrInitialDir = L"./";//Ĭ�ϵ��ļ�·��   
	ofn.lpstrFile =(LPWSTR)szFilePath1;//����ļ��Ļ�����   
	ofn.nMaxFile = sizeof(szFilePath1) / sizeof(*szFilePath1);
	ofn.nFilterIndex = 0;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER; //��־����Ƕ�ѡҪ����OFN_ALLOWMULTISELECT 

	if (!GetOpenFileName(&ofn))
	{
		return FALSE;
	}
	if (lstrcmp(szFilePath1,L"") == 0)
	{
		// �����Ƿ��ȡ�ɹ�
		return FALSE;
	}
	lstrcpy(szFilePath, szFilePath1);
	return TRUE;
}