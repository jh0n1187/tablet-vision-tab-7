/* SPDX-License-Identifier: MIT
 * Controller setup derived from A523-root, copyright 2026 Contributors.
 * Candidate for review only: T307F pinmux/SRAM/BROM compatibility is unproven.
 * No card SWITCH (CMD6), block writes, erase or partition-selection commands.
 * If the card does not already support the conservative 1-bit path, fail.
 */
#include "ro.h"
#define B(n) (1u << (n))
#define S(n) (0x04022000u + (n))
#define GCTRL S(0)
#define CLK S(4)
#define RINT S(0x38)
#define FIFO S(0x200)
#ifdef RO_MMIO_TEST
extern u32 ro_test_rd(u32 address);
extern void ro_test_wr(u32 address, u32 value);
#define LIMIT 128u
static u32 rd(u32 a) { return ro_test_rd(a); }
static void wr(u32 a, u32 v) { ro_test_wr(a, v); }
static void delay(void) {}
#else
#define LIMIT 2000000u
static u32 rd(u32 a) { u32 v = *(volatile u32 *)a; __asm__ volatile("dmb sy" ::: "memory"); return v; }
static void wr(u32 a, u32 v) { __asm__ volatile("dsb sy" ::: "memory"); *(volatile u32 *)a = v; }
static void delay(void) { for (volatile u32 i = 0; i < 10000; ++i) {} }
#endif
static int clear_bits(u32 addr, u32 mask) {
    for (u32 i = 0; i < LIMIT; ++i) if (!(rd(addr) & mask)) return 1;
    return 0;
}
static int clock_update(void) {
    wr(S(0x18), B(31) | B(21));
    return clear_bits(S(0x18), B(31));
}
static int command(struct card *c, u32 cmd, u32 arg, u32 flags, u32 *response) {
    if (!ro_command_allowed(cmd, arg)) { c->error = 0xf001; return 0; }
    wr(RINT, ~0u); wr(S(0x1c), arg); wr(S(0x18), B(31) | flags | cmd);
    for (u32 i = 0; i < LIMIT; ++i) {
        u32 status = rd(RINT);
        if (!ro_status_ok(status)) { c->error = status; return 0; }
        if (status & B(2)) {
            u32 r = rd(S(0x20));
            if (response) *response = r;
            /* R1 errors; CMD1 OCR and CMD2 CID are not R1 responses. */
            if ((cmd == 3 || cmd == 7 || cmd == 8 || cmd == 13 || cmd == 17) &&
                (r & 0xfdffa080u)) { c->error = r; return 0; }
            if (cmd == 7 && !clear_bits(S(0x3c), B(9))) { c->error = 0xf002; return 0; }
            return 1;
        }
    }
    c->error = 0xf003; return 0;
}
static int data_command(struct card *c, u32 cmd, u32 arg, u8 *out) {
    wr(S(0x10), 512); wr(S(0x14), 512);
    if (!command(c, cmd, arg, B(9) | B(8) | B(6), 0)) return 0;
    for (u32 i = 0; i < LIMIT; ++i) {
        u32 status = rd(RINT);
        if (!ro_status_ok(status)) { c->error = status; return 0; }
        if (status & B(3)) {
            wr(GCTRL, rd(GCTRL) | B(31));
            for (u32 n = 0; n < 128; ++n) {
                /* FIFO empty while draining is a transfer failure. */
                if (rd(S(0x3c)) & B(2)) { c->error = 0xf004; return 0; }
                u32 v = rd(FIFO);
                for (u32 b = 0; b < 4; ++b) out[4*n+b] = (u8)(v >> (8*b));
            }
            if (!ro_status_ok(rd(RINT))) { c->error = rd(RINT); return 0; }
            wr(GCTRL, rd(GCTRL) | B(1));
            if (!clear_bits(GCTRL, B(1))) { c->error = 0xf005; return 0; }
            wr(GCTRL, rd(GCTRL) | B(31));
            return 1;
        }
    }
    c->error = 0xf006; return 0;
}
int ro_hw_init(struct card *c, u8 *ext) {
    u32 r = 0;
    wr(0x02000060, 0x33333333); wr(0x02000064, 0x333);
    wr(0x0200184c, rd(0x0200184c) & ~B(18));
    wr(0x0200184c, rd(0x0200184c) & ~B(2));
    wr(0x02001838, B(31));
    wr(0x0200184c, rd(0x0200184c) | B(2));
    wr(0x0200184c, rd(0x0200184c) | B(18));
    delay();
    wr(GCTRL, 7);
    if (!clear_bits(GCTRL, 7)) return 0;
    wr(S(0x0c), 0); /* host width only; never switch the eMMC configuration */
    wr(S(0x54), 3); wr(S(0x50), 0xdeb); wr(S(0x100), (512u<<16)|B(2));
    wr(S(0x144), B(7)); wr(CLK, 29 | B(31));
    if (!clock_update()) return 0;
    wr(CLK, 29 | B(16) | B(31));
    if (!clock_update()) return 0;
    wr(CLK, 29 | B(16));
    if (!clock_update()) return 0;
    wr(S(8), ~0u); wr(S(0x30), 0);
    /* No physical reset pulse, watchdog disable, RTC, DDR or PMIC writes. */
    if (!command(c, 0, 0, B(15), 0)) return 0;
    for (u32 i = 0; i < 1000; ++i) {
        if (!command(c, 1, 0x40ff8080, B(6), &r)) return 0;
        if (r & B(31)) break;
        delay();
    }
    if ((r & (B(31)|B(30))) != (B(31)|B(30))) return 0;
    if (!command(c, 2, 0, B(8)|B(7)|B(6), 0)) return 0;
    for (u32 i = 0; i < 4; ++i) c->cid[i] = rd(S(0x20 + 4*i));
    if (!command(c, 3, 0x10000, B(8)|B(6), 0) ||
        !command(c, 7, 0x10000, B(8)|B(6), 0) ||
        !data_command(c, 8, 0, ext)) return 0;
    c->partition_config = ext[179]; c->bus_width = ext[183];
    c->capacity = (u32)ext[212] | ((u32)ext[213]<<8) |
                  ((u32)ext[214]<<16) | ((u32)ext[215]<<24);
    if (!command(c, 13, 0x10000, B(8)|B(6), &r)) return 0;
    if ((r & 0x1f00u) != 0x900u) { c->error = 0xf007; return 0; }
    return 1;
}
int ro_hw_read(struct card *c, u32 lba, u8 *out) {
    if ((c->partition_config & 7) || c->bus_width || lba >= c->capacity) return 0;
    return data_command(c, 17, lba, out);
}
