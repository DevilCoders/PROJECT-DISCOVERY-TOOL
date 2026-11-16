/*
 * x86-64 System V ABI byte counter.
 * Runtime C dispatch checks SSE2 and POPCNT before calling this symbol.
 */
    .text
    .globl pdt_asm_count_byte
    .type pdt_asm_count_byte, @function
pdt_asm_count_byte:
    xorl %r8d, %r8d
    testq %rsi, %rsi
    jz .Ldone

    movd %edx, %xmm0
    punpcklbw %xmm0, %xmm0
    punpcklwd %xmm0, %xmm0
    punpckldq %xmm0, %xmm0
    punpcklqdq %xmm0, %xmm0

.Lvector:
    cmpq $16, %rsi
    jb .Ltail
    movdqu (%rdi), %xmm1
    pcmpeqb %xmm0, %xmm1
    pmovmskb %xmm1, %eax
    popcntl %eax, %eax
    addq %rax, %r8
    addq $16, %rdi
    subq $16, %rsi
    jmp .Lvector

.Ltail:
    testq %rsi, %rsi
    jz .Ldone
.Ltail_loop:
    cmpb %dl, (%rdi)
    jne .Lnext
    incq %r8
.Lnext:
    incq %rdi
    decq %rsi
    jnz .Ltail_loop

.Ldone:
    movq %r8, %rax
    ret
    .size pdt_asm_count_byte, .-pdt_asm_count_byte
    .section .note.GNU-stack,"",@progbits
