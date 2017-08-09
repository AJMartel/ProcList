#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

VOID displayHelp()
{
	_tprintf(TEXT("ProcList - search for process name and list associated modules and threads\n"));
	_tprintf(TEXT("Usage: ProcList.exe [options] <process name>\n"));
	_tprintf(TEXT("Options:\n"));
	_tprintf(TEXT("	-m\tList Modules\n"));
	_tprintf(TEXT("	-t\tList Threads\n"));

	exit(0);
}

void printError(TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, eNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;

	do { 
		*p-- = 0; 
	} while ((p >= sysMsg) && ((*p == '.') || (*p < 33)));

	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}

BOOL ListProcessModules(DWORD dwPID)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
		return(FALSE);
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		printError(TEXT("Module32First"));  // show cause of failure
		CloseHandle(hModuleSnap);           // clean the snapshot object
		return(FALSE);
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		_tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		_tprintf(TEXT("\n     Executable     = %s"), me32.szExePath);
		_tprintf(TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);
		_tprintf(TEXT("\n     Ref count (g)  = 0x%04X"), me32.GlblcntUsage);
		_tprintf(TEXT("\n     Ref count (p)  = 0x%04X"), me32.ProccntUsage);
#ifdef _WIN64
		_tprintf(TEXT("\n     Base address   = 0x%I64X"), (DWORD64)me32.modBaseAddr);
#else
		_tprintf(TEXT("\n     Base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
#endif	
		_tprintf(TEXT("\n     Base size      = %d"), me32.modBaseSize);

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(TRUE);
}

BOOL ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		printError(TEXT("Thread32First")); // show cause of failure
		CloseHandle(hThreadSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			_tprintf(TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
			_tprintf(TEXT("\n     Base priority  = %d"), te32.tpBasePri);
			_tprintf(TEXT("\n     Delta priority = %d"), te32.tpDeltaPri);
			_tprintf(TEXT("\n"));
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return(TRUE);
}

BOOL GetProcessList(wchar_t *pProcname, int nModules, int nThreads)
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return(FALSE);
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		printError(TEXT("Process32First")); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		if (!_wcsicmp(pe32.szExeFile, pProcname))
		{
			_tprintf(TEXT("\n\n==========================================="));
			_tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
			_tprintf(TEXT("\n==========================================="));

			// Retrieve the priority class.
			dwPriorityClass = 0;
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess == NULL)
				printError(TEXT("OpenProcess"));
			else
			{
				dwPriorityClass = GetPriorityClass(hProcess);
				if (!dwPriorityClass)
					printError(TEXT("GetPriorityClass"));
				CloseHandle(hProcess);
			}

			_tprintf(TEXT("\n  Process ID        = 0x%08X (%d)"), pe32.th32ProcessID, pe32.th32ProcessID);
			_tprintf(TEXT("\n  Parent Process ID = 0x%08X (%d)"), pe32.th32ParentProcessID, pe32.th32ParentProcessID);
			_tprintf(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
			_tprintf(TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID);
			_tprintf(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);
			if (dwPriorityClass)
				_tprintf(TEXT("\n  Priority class    = %d"), dwPriorityClass);

			// List the modules and threads associated with this process - might be useful in some cases
			if(nModules)
				ListProcessModules(pe32.th32ProcessID);
			if(nThreads)
				ListProcessThreads(pe32.th32ProcessID);
		}
	} while (Process32Next(hProcessSnap, &pe32));

	_tprintf(TEXT("\n\n"));

	CloseHandle(hProcessSnap);
	return(TRUE);
}

int wmain(int argc, wchar_t * argv[])
{
	wchar_t pProcname[MAXCHAR]; // 128 (0-127)

	if (argc == 1)
		displayHelp();

	if (argc == 2)
	{
		wcsncpy_s(pProcname, argv[1], MAXCHAR);
		GetProcessList(pProcname, 0, 0);
	} else if (argc == 3)
	{
		if (_wcsicmp(argv[1], L"-m") == 0)
		{
			wcsncpy_s(pProcname, argv[2], MAXCHAR);
			GetProcessList(pProcname, 1, 0);
		} else if (_wcsicmp(argv[1], L"-t") == 0)
		{
			wcsncpy_s(pProcname, argv[2], MAXCHAR);
			GetProcessList(pProcname, 0, 1);
		}
		else
			_tprintf(TEXT("[-] Invalid options. Exiting."));
	} else if (argc == 4)
	{
		if ((_wcsicmp(argv[1], L"-m") == 0 && (_wcsicmp(argv[2], L"-t") == 0)) || (_wcsicmp(argv[1], L"-t") == 0 && (_wcsicmp(argv[2], L"-m") == 0)))
		{
			wcsncpy_s(pProcname, argv[3], MAXCHAR);
			GetProcessList(pProcname, 1, 1);
		}
		else
			_tprintf(TEXT("[-] Invalid options. Exiting."));
	}
	else
		_tprintf(TEXT("[-] Invalid options. Exiting."));

	return 0;
}