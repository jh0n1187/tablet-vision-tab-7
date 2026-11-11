/* SPDX-License-Identifier: MIT. Register model on PC; no physical I/O. */
#include "ro.h"
static u32 stats[2], registers[128], arg, command_reg, rint, response;
static u32 fifo[128], position, words, cmd_count[64], switch_count, forbidden_count;
static u32 fault_cmd, fault, capacity=4096, area, width, count_writes;
#define BASE 0x04022000u
#define CHECK(x) do { ++stats[0]; if (!(x)) ++stats[1]; } while (0)
u32 ro_test_rd(u32 a) {
    if (a==BASE+0x18) return command_reg;
    if (a==BASE+0x20) return response;
    if (a==BASE+0x38) return rint;
    if (a==BASE+0x3c) return (position>=words ? 4u : 0u) | (fault==5 ? 512u : 0u);
    if (a==BASE+0x200) return fifo[position++];
    if (a>=BASE && a<BASE+512) return registers[(a-BASE)/4];
    return 0;
}
void ro_test_wr(u32 a,u32 v) {
    ++count_writes;
    if (a==BASE+0x38) { rint=0; return; }
    if (a==BASE+0x1c) { arg=v; return; }
    if (a==BASE) { registers[0]=v&~7u; return; }
    if (a==BASE+0x18) {
        command_reg=0;
        if (v&(1u<<21)) { if(fault==6) command_reg=v; return; }
        u32 cmd=v&63;
        ++cmd_count[cmd];
        if(cmd==6) ++switch_count;
        if(!ro_command_allowed(cmd,arg)) ++forbidden_count;
        rint=4; response=cmd==1 ? 0xc0000000u : 0x900u;
        if(cmd==2) response=0x11223344u;
        if(cmd==fault_cmd && fault==1) {rint=1u<<7;return;}
        if(cmd==fault_cmd && fault==2) {rint=0;return;}
        if(cmd==fault_cmd && fault==3) {response=1u<<22;return;}
        if(cmd==1 && fault==7) response=0x80000000u; /* not sector addressed */
        if(cmd==13 && fault==8) response=0; /* not ready/transfer state */
        if(cmd==8 || cmd==17) {
            for(u32 i=0;i<128;++i) fifo[i]=cmd==17 ? arg : 0;
            if(cmd==8) {
                fifo[179/4] |= area<<24;
                fifo[183/4] |= width<<24;
                fifo[212/4]=capacity;
            }
            position=0;words=(fault==4 && cmd==fault_cmd)?127:128;
            rint|=8;
        }
        return;
    }
    if (a>=BASE && a<BASE+512) registers[(a-BASE)/4]=v;
    /* Only the precise volatile setup registers may be touched outside SMHC. */
    else if(a!=0x02000060 && a!=0x02000064 && a!=0x0200184c && a!=0x02001838) ++forbidden_count;
}
static void reset(void) {
    for(u32 i=0;i<128;++i) registers[i]=fifo[i]=0;
    for(u32 i=0;i<64;++i) cmd_count[i]=0;
    arg=command_reg=rint=response=position=words=switch_count=forbidden_count=0;
    fault_cmd=fault=area=width=count_writes=0;capacity=4096;
}
int test_main(void) {
    struct card card; u8 ext[512],data[512];
    reset(); CHECK(ro_hw_init(&card,ext));
    CHECK(card.capacity==4096 && card.partition_config==0 && card.bus_width==0);
    CHECK(cmd_count[8]==1 && cmd_count[13]==1 && !switch_count && !forbidden_count);
    CHECK(ro_hw_read(&card,100,data)); CHECK(data[0]==100 && data[4]==100);
    CHECK(cmd_count[17]==1 && !switch_count && !forbidden_count);
    CHECK(!ro_hw_read(&card,4096,data)); CHECK(cmd_count[17]==1);
    card.partition_config=1; CHECK(!ro_hw_read(&card,0,data));
    card.partition_config=0;card.bus_width=1;CHECK(!ro_hw_read(&card,0,data));
    u32 cmds[]={0,1,2,3,7,8,13};
    for(u32 i=0;i<7;++i) for(u32 f=1;f<=2;++f) {
        reset(); fault_cmd=cmds[i];fault=f;
        CHECK(!ro_hw_init(&card,ext)); CHECK(!switch_count && !forbidden_count);
    }
    reset();fault_cmd=3;fault=3;CHECK(!ro_hw_init(&card,ext));
    reset();fault_cmd=8;fault=4;CHECK(!ro_hw_init(&card,ext));
    reset();fault=5;CHECK(!ro_hw_init(&card,ext));
    reset();fault=6;CHECK(!ro_hw_init(&card,ext));
    reset();fault=7;CHECK(!ro_hw_init(&card,ext));
    reset();fault=8;CHECK(!ro_hw_init(&card,ext));
    for(u32 f=1;f<=4;++f) {
        reset();CHECK(ro_hw_init(&card,ext));fault_cmd=17;fault=f;
        CHECK(!ro_hw_read(&card,0,data));CHECK(!switch_count && !forbidden_count);
    }
    reset();area=1;CHECK(ro_hw_init(&card,ext));CHECK(card.partition_config==1);
    CHECK(!ro_hw_read(&card,0,data));CHECK(!switch_count && !forbidden_count);
    /* End-to-end C core + actual driver, with only MMIO replaced by the model. */
    struct request q={RO_MAGIC,RO_VERSION,RO_INFO,123,0,0,0,0};struct response reply;
    static u8 transfer[65536];
    q.crc=ro_crc(&q,sizeof(q));reset();ro_process(&q,&reply,transfer);
    CHECK(reply.status==RO_OK && reply.bytes==512 && reply.seq==123 && !switch_count);
    q.op=RO_READ;q.lba=100;q.count=1;q.crc=0;q.crc=ro_crc(&q,sizeof(q));
    reset();ro_process(&q,&reply,transfer);
    CHECK(reply.status==RO_OK && reply.bytes==512 && transfer[0]==100 && !forbidden_count);
    reset();fault_cmd=17;fault=1;ro_process(&q,&reply,transfer);
    CHECK(reply.status==RO_IO && !reply.bytes && !switch_count);
    reset();area=1;ro_process(&q,&reply,transfer);CHECK(reply.status==RO_AREA && !cmd_count[17]);
    register long a __asm__("rax")=1;
    register long d __asm__("rdi")=1;
    register const void *s __asm__("rsi")=stats;
    register long n __asm__("rdx")=sizeof(stats);
    __asm__ volatile("syscall" : "+a"(a) : "D"(d),"S"(s),"d"(n) : "rcx","r11","memory");
    return stats[1]?1:0;
}
__attribute__((naked,noreturn)) void _start(void) {
    __asm__ volatile("andq $-16, %rsp\ncall test_main\nmov %eax, %edi\nmov $60, %eax\nsyscall\n");
}
