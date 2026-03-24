# Compiled

```
Temporary breakpoint 1, 0x000055555555516d in main ()
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000555555555169 <+0>:     push   %rbp
   0x000055555555516a <+1>:     mov    %rsp,%rbp
=> 0x000055555555516d <+4>:     sub    $0x40,%rsp
   0x0000555555555171 <+8>:     movabs $0x4973676e69727453,%rax
   0x000055555555517b <+18>:    movabs $0x626f6f4e726f4673,%rdx
   0x0000555555555185 <+28>:    mov    %rax,-0x40(%rbp)
   0x0000555555555189 <+32>:    mov    %rdx,-0x38(%rbp)
   0x000055555555518d <+36>:    movw   $0x73,-0x30(%rbp)
   0x0000555555555193 <+42>:    mov    0x2e96(%rip),%rax        # 0x555555558030 <stdout@GLIBC_2.2.5>
   0x000055555555519a <+49>:    mov    %rax,%rcx
   0x000055555555519d <+52>:    mov    $0xa,%edx
   0x00005555555551a2 <+57>:    mov    $0x1,%esi
   0x00005555555551a7 <+62>:    lea    0xe56(%rip),%rax        # 0x555555556004
   0x00005555555551ae <+69>:    mov    %rax,%rdi
   0x00005555555551b1 <+72>:    call   0x555555555060 <fwrite@plt>
   0x00005555555551b6 <+77>:    lea    -0x20(%rbp),%rax
   0x00005555555551ba <+81>:    mov    %rax,%rsi
   0x00005555555551bd <+84>:    lea    0xe4b(%rip),%rax        # 0x55555555600f
   0x00005555555551c4 <+91>:    mov    %rax,%rdi
   0x00005555555551c7 <+94>:    mov    $0x0,%eax
   0x00005555555551cc <+99>:    call   0x555555555050 <__isoc99_scanf@plt>
   0x00005555555551d1 <+104>:   lea    -0x20(%rbp),%rax
   0x00005555555551d5 <+108>:   lea    0xe42(%rip),%rdx        # 0x55555555601e
   0x00005555555551dc <+115>:   mov    %rdx,%rsi
   0x00005555555551df <+118>:   mov    %rax,%rdi
   0x00005555555551e2 <+121>:   call   0x555555555040 <strcmp@plt>
   0x00005555555551e7 <+126>:   test   %eax,%eax
   0x00005555555551e9 <+128>:   js     0x555555555205 <main+156>
   0x00005555555551eb <+130>:   lea    -0x20(%rbp),%rax
   0x00005555555551ef <+134>:   lea    0xe28(%rip),%rdx        # 0x55555555601e
   0x00005555555551f6 <+141>:   mov    %rdx,%rsi
   0x00005555555551f9 <+144>:   mov    %rax,%rdi
   0x00005555555551fc <+147>:   call   0x555555555040 <strcmp@plt>
   0x0000555555555201 <+152>:   test   %eax,%eax
   0x0000555555555203 <+154>:   jle    0x55555555524b <main+226>
   0x0000555555555205 <+156>:   lea    -0x20(%rbp),%rax
   0x0000555555555209 <+160>:   lea    0xe1b(%rip),%rdx        # 0x55555555602b
   0x0000555555555210 <+167>:   mov    %rdx,%rsi
   0x0000555555555213 <+170>:   mov    %rax,%rdi
   0x0000555555555216 <+173>:   call   0x555555555040 <strcmp@plt>
   0x000055555555521b <+178>:   test   %eax,%eax
   0x000055555555521d <+180>:   jne    0x555555555235 <main+204>
   0x000055555555521f <+182>:   lea    0xe0b(%rip),%rax        # 0x555555556031
   0x0000555555555226 <+189>:   mov    %rax,%rdi
   0x0000555555555229 <+192>:   mov    $0x0,%eax
   0x000055555555522e <+197>:   call   0x555555555030 <printf@plt>
   0x0000555555555233 <+202>:   jmp    0x55555555525f <main+246>
   0x0000555555555235 <+204>:   lea    0xdfe(%rip),%rax        # 0x55555555603a
   0x000055555555523c <+211>:   mov    %rax,%rdi
   0x000055555555523f <+214>:   mov    $0x0,%eax
   0x0000555555555244 <+219>:   call   0x555555555030 <printf@plt>
   0x0000555555555249 <+224>:   jmp    0x55555555525f <main+246>
   0x000055555555524b <+226>:   lea    0xde8(%rip),%rax        # 0x55555555603a
   0x0000555555555252 <+233>:   mov    %rax,%rdi
   0x0000555555555255 <+236>:   mov    $0x0,%eax
--Type <RET> for more, q to quit, c to continue without paging--
   0x000055555555525a <+241>:   call   0x555555555030 <printf@plt>
   0x000055555555525f <+246>:   mov    $0x0,%eax
   0x0000555555555264 <+251>:   leave
   0x0000555555555265 <+252>:   ret
End of assembler dump.
```

```
23:56:38 ~/Descargas
➤ gdb /home/sebastian/Descargas/Compiled-1688545393558.Compiled

(No debugging symbols found in /home/sebastian/Descargas/Compiled-1688545393558.Compiled)
(gdb) set disable-randomization on
(gdb) start
Punto de interrupción temporal 1 at 0x116d
Starting program: /home/sebastian/Descargas/Compiled-1688545393558.Compiled
[Depuración de hilo usando libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Temporary breakpoint 1, 0x000055555555516d in main ()
(gdb) break *main+104
Punto de interrupción 2 at 0x5555555551d1
(gdb) break *main+173
Punto de interrupción 3 at 0x555555555216
(gdb) c
Continuando.
Password: DoYouEven_initCTF

Breakpoint 2, 0x00005555555551d1 in main ()
(gdb) print $eax
$1 = 1
(gdb) x/s $rbp-0x20
0x7fffffffd630: "_initCTF"
(gdb) c
Continuando.

Breakpoint 3, 0x0000555555555216 in main ()
(gdb) x/s $rsi
0x55555555602b: "_init"
(gdb) c
Continuando.
```
