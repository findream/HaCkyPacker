#include "ReflectiveLoader.h"

#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

extern HINSTANCE hAppInstance;
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
		{
			hAppInstance = hinstDLL;
			MessageBoxA(NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK);
			
#if defined(ENVIRONMENT32)
			InstallNtQuerySystemInformationHook_x86();
#endif
#if defined(ENVIRONMENT64)
			InstallNtQuerySystemInformationHook_x64();
#endif
			break;
		}

		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}