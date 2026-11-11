/* SPDX-License-Identifier: MIT */
.syntax unified
.arm
.section .entry,"ax",%progbits
.global _start
.type _start,%function
_start:
    mov r3, sp
    ldr sp, =0x58000
    push {r3-r11, lr}
    bl ro_entry
    pop {r3-r11, lr}
    mov sp, r3
    bx lr
.size _start, .-_start
