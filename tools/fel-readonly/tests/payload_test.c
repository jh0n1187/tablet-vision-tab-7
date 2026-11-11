/* SPDX-License-Identifier: MIT. Linux x86_64 test harness: NO USB/MMIO. */
#include "ro.h"
static u32 stats[2], init_calls, read_calls;
static u32 fail_init, fail_read, area, width, capacity = 1024;
static u8 data[RO_MAX_SECTORS * 512];
#define CHECK(x) do { ++stats[0]; if (!(x)) ++stats[1]; } while (0)
int ro_hw_init(struct card *c, u8 *ext) {
    ++init_calls;
    c->capacity = capacity; c->cid[0] = 123;
    c->partition_config = area; c->bus_width = width;
    if (fail_init) { c->error = 128; return 0; }
    for (u32 i = 0; i < 512; ++i) ext[i] = 0;
    ext[179] = (u8)area; ext[183] = (u8)width;
    for (u32 i = 0; i < 4; ++i) ext[212+i] = (u8)(capacity >> (8*i));
    return 1;
}
int ro_hw_read(struct card *c, u32 lba, u8 *out) {
    ++read_calls;
    if (fail_read) { c->error = 64; return 0; }
    for (u32 i = 0; i < 512; ++i) out[i] = (u8)(lba + i);
    return 1;
}
static struct request req(u32 op, u32 lba, u32 count) {
    struct request q = {RO_MAGIC, RO_VERSION, op, 77, lba, count, 0, 0};
    q.crc = ro_crc(&q, sizeof(q)); return q;
}
static int valid_crc(struct response *r) {
    u32 crc = r->crc; r->crc = 0;
    u32 actual = ro_crc(r, sizeof(*r)); r->crc = crc;
    return actual == crc;
}
int test_main(void) {
    struct response r;
    struct request q;
    CHECK(ro_crc("123456789", 9) == 0xcbf43926u);
#ifdef RO_TEST_LOCKED
    q=req(RO_INFO,0,0);ro_process(&q,&r,data);
    CHECK(r.status==RO_LOCKED && !init_calls && !read_calls && valid_crc(&r));
    q=req(RO_READ,0,1);ro_process(&q,&r,data);
    CHECK(r.status==RO_LOCKED && !init_calls && !read_calls);
    q=req(24,0,1);ro_process(&q,&r,data);
    CHECK(r.status==RO_FORBIDDEN && !init_calls && !read_calls);
#else
    for (u32 op = 0; op < 256; ++op) {
        if (op == RO_INFO || op == RO_READ) continue;
        init_calls = read_calls = 0; q = req(op,0,0);
        ro_process(&q,&r,data);
        CHECK(r.status == RO_FORBIDDEN && init_calls == 0 && read_calls == 0 && valid_crc(&r));
    }
    q = req(RO_INFO,0,0); q.crc ^= 1; init_calls = 0;
    ro_process(&q,&r,data); CHECK(r.status == RO_BAD_REQUEST && !init_calls);
    q = req(RO_INFO,0,0); q.reserved=1; q.crc=0; q.crc=ro_crc(&q,sizeof(q));
    ro_process(&q,&r,data); CHECK(r.status == RO_BAD_REQUEST && !init_calls);
    q = req(RO_READ,0,129); ro_process(&q,&r,data); CHECK(r.status == RO_RANGE && !init_calls);
    q = req(RO_READ,~0u,2); ro_process(&q,&r,data); CHECK(r.status == RO_RANGE && !init_calls);
    q = req(RO_READ,0,0); ro_process(&q,&r,data); CHECK(r.status == RO_RANGE && !init_calls);
    for (u32 bit = 0; bit < 32; ++bit) {
        int permitted = bit == 0 || bit == 1 || bit == 2 || bit == 3 || bit == 7 || bit == 8 || bit == 13 || bit == 17;
        u32 arg = bit == 1 ? 0x40ff8080 : (bit == 3 || bit == 7 || bit == 13 ? 0x10000 : 0);
        CHECK(ro_command_allowed(bit,arg) == permitted);
    }
    CHECK(!ro_command_allowed(6,0x03b70000));
    CHECK(!ro_command_allowed(6,0x03b30000));
    CHECK(!ro_command_allowed(1,0)); CHECK(!ro_command_allowed(7,0));
    for (u32 bit=0;bit<16;++bit)
        if (0xbfc2u & (1u<<bit)) CHECK(!ro_status_ok(1u<<bit));
    CHECK(ro_status_ok((1u<<2)|(1u<<3)));
    q=req(RO_INFO,0,0); fail_init=1; ro_process(&q,&r,data);
    CHECK(r.status==RO_IO && !r.bytes && r.error==128); fail_init=0;
    for (area=1;area<8;++area) { ro_process(&q,&r,data); CHECK(r.status==RO_AREA && !r.bytes); }
    area=0; width=1; ro_process(&q,&r,data); CHECK(r.status==RO_AREA); width=0;
    capacity=0; ro_process(&q,&r,data); CHECK(r.status==RO_RANGE);
    capacity=~0u; ro_process(&q,&r,data); CHECK(r.status==RO_RANGE); capacity=1024;
    ro_process(&q,&r,data); CHECK(r.status==RO_OK && r.bytes==512 && valid_crc(&r) && r.data_crc==ro_crc(data,512));
    q=req(RO_READ,1023,2); read_calls=0; ro_process(&q,&r,data); CHECK(r.status==RO_RANGE && !read_calls);
    q=req(RO_READ,128,128); ro_process(&q,&r,data);
    CHECK(r.status==RO_OK && r.bytes==65536 && r.seq==77 && r.lba==128 && r.count==128 && valid_crc(&r));
    CHECK(r.data_crc==ro_crc(data,65536) && data[512]==129);
    q=req(RO_READ,0,1); fail_read=1; ro_process(&q,&r,data);
    CHECK(r.status==RO_IO && !r.bytes && !r.data_crc); fail_read=0;
#endif
    /* Single raw write to stdout on the PC, reporting assertion counters. */
    register long a __asm__("rax")=1;
    register long d __asm__("rdi")=1;
    register const void *s __asm__("rsi")=stats;
    register long n __asm__("rdx")=sizeof(stats);
    __asm__ volatile("syscall" : "+a"(a) : "D"(d),"S"(s),"d"(n) : "rcx","r11","memory");
    return stats[1] ? 1 : 0;
}
__attribute__((naked,noreturn)) void _start(void) {
    __asm__ volatile("andq $-16, %rsp\ncall test_main\nmov %eax, %edi\nmov $60, %eax\nsyscall\n");
}
