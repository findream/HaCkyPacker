#include "stdafx.h"
#include "basic_form.h"

const std::wstring BasicForm::kClassName = L"Basic";
TCHAR szFilePath[1024] = { 0 };   // ��ѡ����ļ����յ�·��

BasicForm::BasicForm()
{
}


BasicForm::~BasicForm()
{
}

std::wstring BasicForm::GetSkinFolder()
{
	return L"basic";
}

std::wstring BasicForm::GetSkinFile()
{
	return L"basic.xml";
}

std::wstring BasicForm::GetWindowClassName() const
{
	return kClassName;
}

void BasicForm::InitWindow()
{
	// ������굥���¼�
	m_pRoot->AttachBubbledEvent(ui::kEventClick,
		nbase::Bind(&BasicForm::OnClicked,
		this,
		std::placeholders::_1));

// �� XML �в���ָ���ؼ�
	btn_JieNeng = dynamic_cast<ui::Button*>(FindControl(L"btn_JieNeng"));
	btn_JunHeng = dynamic_cast<ui::Button*>(FindControl(L"btn_JunHeng"));
	btn_AnQuan = dynamic_cast<ui::Button*>(FindControl(L"btn_AnQuan"));
	m_EditColumn = dynamic_cast<ui::RichEdit*>(FindControl(L"edit_total"));
}

bool BasicForm::OnClicked(ui::EventArgs* msg)
{

	std::wstring name = msg->pSender->GetName();

	if (name == L"btn_JieNeng")
	{
		//MessageBox(NULL, L"btn_JieNeng", L"btn_JieNeng", MB_OK);
		//TCHAR szPath[MAX_PATH] = { L"E:\\��ҵ���\\HaCkyPack\\Debug\\HaCkyPack.exe" };
		TCHAR szPath[MAX_PATH] = {0};
		if (GetModuleFileName(NULL,szPath,MAX_PATH) == 0)
			return false;
		PathRemoveFileSpec(szPath);
		lstrcat(szPath, L"\\HaCkyPack.exe");

		TCHAR szCmdLine[MAX_PATH] = {0};
		if (lstrcmp(szFilePath, L"") == 0)
			return false;
		lstrcpy(szCmdLine, szPath);
		lstrcat(szCmdLine, L" ");
		lstrcat(szCmdLine, szFilePath);
		lstrcat(szCmdLine, L" 0");
		STARTUPINFO si = { sizeof(si) };
		si.cb = sizeof(STARTUPINFO);
		si.lpReserved = NULL;
		si.lpDesktop = NULL;
		si.lpTitle = NULL;
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		si.cbReserved2 = NULL;
		si.lpReserved2 = NULL;
		PROCESS_INFORMATION pi = { 0 };
		BOOL bRet = FALSE;

		bRet = CreateProcess(
			szPath,
			szCmdLine,
			NULL,
			NULL,
			FALSE,
			CREATE_NEW_CONSOLE,
			NULL,
			NULL,
			&si,
			&pi);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	else if (name == L"btn_JunHeng")
	{
		//MessageBox(NULL, L"btn_JunHeng", L"btn_JunHeng", MB_OK);
		//TCHAR szPath[MAX_PATH] = { L"E:\\��ҵ���\\HaCkyPack\\Debug\\HaCkyPack.exe" };
		TCHAR szPath[MAX_PATH] = { 0 };
		if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0)
			return false;
		PathRemoveFileSpec(szPath);
		lstrcat(szPath, L"\\HaCkyPack.exe");

		TCHAR szCmdLine[MAX_PATH] = { 0 };
		if (lstrcmp(szFilePath, L"") == 0)
			return false;
		lstrcpy(szCmdLine, szPath);
		lstrcat(szCmdLine, L" ");
		lstrcat(szCmdLine, szFilePath);
		lstrcat(szCmdLine, L" 1");
		STARTUPINFO si = { sizeof(si) };
		si.cb = sizeof(STARTUPINFO);
		si.lpReserved = NULL;
		si.lpDesktop = NULL;
		si.lpTitle = NULL;
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		si.cbReserved2 = NULL;
		si.lpReserved2 = NULL;
		PROCESS_INFORMATION pi = { 0 };
		BOOL bRet = FALSE;

		bRet = CreateProcess(
			szPath,
			szCmdLine,
			NULL,
			NULL,
			FALSE,
			CREATE_NEW_CONSOLE,
			NULL,
			NULL,
			&si,
			&pi);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	else if (name == L"btn_AnQuan")
	{
		//MessageBox(NULL, L"btn_AnQuan", L"btn_AnQuan", MB_OK);
		//TCHAR szPath[MAX_PATH] = { L"E:\\��ҵ���\\HaCkyPack\\Debug\\HaCkyPack.exe" };
		TCHAR szPath[MAX_PATH] = { 0 };
		if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0)
			return false;
		PathRemoveFileSpec(szPath);
		lstrcat(szPath, L"\\HaCkyPack.exe");

		TCHAR szCmdLine[MAX_PATH] = { 0 };
		if (lstrcmp(szFilePath, L"") == 0)
			return false;
		lstrcpy(szCmdLine, szPath);
		lstrcat(szCmdLine, L" ");
		lstrcat(szCmdLine, szFilePath);
		lstrcat(szCmdLine, L" 2");
		STARTUPINFO si = { sizeof(si) };
		si.cb = sizeof(STARTUPINFO);
		si.lpReserved = NULL;
		si.lpDesktop = NULL;
		si.lpTitle = NULL;
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		si.cbReserved2 = NULL;
		si.lpReserved2 = NULL;
		PROCESS_INFORMATION pi = { 0 };
		BOOL bRet = FALSE;

		bRet = CreateProcess(
			szPath,
			szCmdLine,
			NULL,
			NULL,
			FALSE,
			CREATE_NEW_CONSOLE,
			NULL,
			NULL,
			&si,
			&pi);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	else if (name == L"btn_DaKai")
	{
		//MessageBox(NULL, L"btn_DaKai", L"btn_DaKai", MB_OK);
		MyOpenFile(szFilePath);
		m_EditColumn->SetText(szFilePath);
	}
	return true;
}

LRESULT BasicForm::OnClose(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	PostQuitMessage(0L);
	return __super::OnClose(uMsg, wParam, lParam, bHandled);
}
