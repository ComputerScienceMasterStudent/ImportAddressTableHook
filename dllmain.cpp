#include <windows.h>

void		__stdcall   HookIATFunction(const char* functionName, DWORD functionAddress);
BOOL	    __stdcall Hook();

HMODULE     hMod;


typedef BOOL(__stdcall* FreeLibraryHeader) (HMODULE hLibModule);

BOOL __stdcall FreeLibraryImp(HMODULE hLibModule)
{
	OutputDebugString(L"FreeLibrary Hook");
	return FALSE;
}

BOOL __stdcall Hook()
{
	HookIATFunction("FreeLibrary", (DWORD)&FreeLibraryImp);
	return TRUE;
}

void __stdcall HookIATFunction(const char* functionName, DWORD functionAddress) {

	PIMAGE_IMPORT_BY_NAME	 importByName;
	LPCSTR					 importFunctionName;
	DWORD					 oldFlags;
	PIMAGE_THUNK_DATA		 originalFirstThunk;
	PIMAGE_THUNK_DATA		 firstThunk;
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	PIMAGE_NT_HEADERS		 ntHeaders;

	if (((PIMAGE_DOS_HEADER)hMod)->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return;
	importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!importDesc)
		return;
	importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)importDesc + (UINT_PTR)hMod);

	while (importDesc->OriginalFirstThunk) 
	{
		originalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)importDesc->OriginalFirstThunk + (UINT_PTR)hMod);
		firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)importDesc->FirstThunk + (UINT_PTR)hMod);
		while (originalFirstThunk->u1.Function) 
		{
			importByName = (PIMAGE_IMPORT_BY_NAME)originalFirstThunk->u1.AddressOfData;
			importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)importByName + ((UINT_PTR)hMod));
			importFunctionName = (LPCSTR)((BYTE*)importByName + sizeof(WORD));

			if (strcmp(importFunctionName, functionName) == 0) 
			{
				VirtualProtect(&firstThunk->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &oldFlags);
				firstThunk->u1.Function = functionAddress;
				VirtualProtect(&firstThunk->u1.Function, sizeof(LPVOID), oldFlags, &oldFlags);
			}
			originalFirstThunk++;
			firstThunk++;
		}
		importDesc++;
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		hMod = GetModuleHandle(NULL);
		Hook();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

