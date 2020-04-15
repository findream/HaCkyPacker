// stdafx.h: 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 项目特定的包含文件
//

#pragma once

#include "targetver.h"

// C runtime header
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>

//这个地方是为了使用了GetOpenFileName
//包含windows.h发现windows包含的winsock2和winsock造成冲突
//所以定义WIN32_LEAN_AND_MEAN，规避这个冲突
//但是规避完冲突之后导致部分结构体没有被定义
//再次包含commdlg这个.h，然后包含windows为了声明GetOpenFileName
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commDlg.h>
#include <shlwapi.h>


// base header
#include "base/base.h"

// duilib
#include "duilib/UIlib.h"


BOOL MyOpenFile(TCHAR *);