.syntax unified
.arm
.section .entry,"ax",%progbits
.global _start
.type _start,%function
_start:
    .space 0x60
entry_code:
    push {r4-r11,lr}
    sub sp,sp,#4
    mov r4,r0
    mov r5,r1
    mov r6,lr
    ldr r2,=__bss_start
    ldr r3,=__bss_end
    mov r0,#0
1:  cmp r2,r3
    strlo r0,[r2],#4
    blo 1b
    mov r0,r4
    mov r1,r5
    mov r2,r6
    bl adapter_main
    add sp,sp,#4
    pop {r4-r11,pc}
.size _start,.-_start
