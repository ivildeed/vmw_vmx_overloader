#include "stdafx.h"
#include "stdlib.h"

#include "stdio.h"

#include "uhde.h"
#include "hook.h"


uhde64 hde;
BYTE op_ret[]={ 0xC3 };
BYTE op_jmp[]={ 0xE9 };
BYTE op_push[]={ 0x68 };
BYTE op_movddesp[]={ 0xC7, 0x44, 0x24, 0x04 };

bool hook::sethook(PVOID hookaddr,PVOID hookingcode, PVOID *restore_code_ptr)
{
	if (hook_active)
		return 0;

	len=0;


	while (len<hooksize)
	{
	 len += hde.disasm(((PBYTE)hookaddr)+len);
	 if (hde.gethdes()->opcode>=0x70 && hde.gethdes()->opcode<=0x7F)
		 return 0;
	 if (hde.gethdes()->opcode==0x0F && hde.gethdes()->modrm>=0x80 && hde.gethdes()->modrm<=0x8F)
		 return 0;
	 if (hde.gethdes()->opcode==0xE8 || hde.gethdes()->opcode==0xE9)
		 return 0;
	 if (hde.gethdes()->opcode==0xCC)
		 return 0;
	}
	if (len > 32) 
		return 0;


	restore_buffer=(PVOID)::VirtualAllocEx(GetCurrentProcess(), 0, len+hooksize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!restore_buffer)
		return 0;


	__try {

		RtlCopyMemory(restore_buffer, hookaddr, len);
		
#ifdef _WIN64
		ULONG p1,p2;
		p1=(ULONG)LODWORD((dptr)((PCHAR)hookaddr+len));
		p2=(ULONG)HIDWORD((dptr)hookaddr);

		RtlCopyMemory((PVOID)((PBYTE)restore_buffer+len), &op_push, sizeof(op_push));
		RtlCopyMemory((PVOID)((PBYTE)restore_buffer+len+sizeof(op_push)), &p1, sizeof(__int32));
		RtlCopyMemory((PVOID)((PBYTE)restore_buffer+len+sizeof(op_push)+sizeof(__int32)), &op_movddesp, sizeof(op_movddesp));
		RtlCopyMemory((PVOID)((PBYTE)restore_buffer+len+sizeof(op_push)+sizeof(__int32)+sizeof(op_movddesp)), &p2, sizeof(__int32));
		RtlCopyMemory((PVOID)((PBYTE)restore_buffer+len+sizeof(op_push)+sizeof(__int32)+sizeof(op_movddesp)+sizeof(__int32)), &op_ret, sizeof(op_ret));
#else
		RtlCopyMemory((PVOID)((PBYTE)coderestore+len), &opcode_jmp, sizeof(opcode_jmp));
		BYTE *jmpto=(PBYTE)((PBYTE)codetohook-(BYTE *)coderestore-hooksize);
		RtlCopyMemory((PVOID)((PBYTE)coderestore+len+1), &jmpto, sizeof(__int32));
#endif
	}__except (EXCEPTION_EXECUTE_HANDLER) {return 0;}

	
	DWORD oldprot;

	::VirtualProtect(hookaddr, hooksize, PAGE_EXECUTE_READWRITE, &oldprot);

	__try {

#ifdef _WIN64
		ULONG p1,p2;
		p1=(ULONG)LODWORD((dptr)hookingcode);
		p2=(ULONG)HIDWORD((dptr)hookingcode);

		RtlCopyMemory((PVOID)((PBYTE)hookaddr),&op_push,sizeof(op_push));
		RtlCopyMemory((PVOID)((PBYTE)hookaddr+sizeof(op_push)), &p1, sizeof(__int32));
		RtlCopyMemory((PVOID)((PBYTE)hookaddr+sizeof(op_push)+sizeof(__int32)),&op_movddesp, sizeof(op_movddesp));
		RtlCopyMemory((PVOID)((PBYTE)hookaddr+sizeof(op_push)+sizeof(__int32)+sizeof(op_movddesp)), &p2, sizeof(__int32));
		RtlCopyMemory((PVOID)((PBYTE)hookaddr+sizeof(op_push)+sizeof(__int32)+sizeof(op_movddesp)+sizeof(__int32)), &op_ret, sizeof(op_ret));

#else
		RtlCopyMemory((PVOID)((PBYTE)codetohook), &opcode_jmp, sizeof(opcode_jmp));
		PBYTE jmptorel=(PBYTE)((PBYTE)hookcode-(PBYTE)codetohook-hooksize);
		RtlCopyMemory((PVOID)((PBYTE)codetohook+1), &jmptorel,4);
#endif

	}__except (EXCEPTION_EXECUTE_HANDLER) {return 0;}

	::VirtualProtect(hookaddr, hooksize, oldprot, &oldprot);

	*restore_code_ptr=(PVOID)restore_buffer;
	hook_active=1;

	return 1;	
}
