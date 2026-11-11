/* SPDX-License-Identifier: MIT
 * No Android/root code. The core never calls a write-to-storage interface.
 */
#include "ro.h"
_Static_assert(sizeof(struct request) == 32, "request ABI");
_Static_assert(sizeof(struct response) == 80, "response ABI");
u32 ro_crc(const void *data, u32 size) {
    const u8 *p = data;
    u32 crc = ~0u;
    for (u32 i = 0; i < size; ++i) {
        crc ^= p[i];
        for (u32 b = 0; b < 8; ++b)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
int ro_command_allowed(u32 cmd, u32 arg) {
    switch (cmd) {
    case 0: case 2: case 8: return arg == 0;
    case 1: return arg == 0x40ff8080u;
    case 3: case 7: case 13: return arg == 0x10000u;
    case 17: return 1; /* lba checked at the only caller */
    default: return 0; /* No SWITCH, WRITE, ERASE, RPMB or vendor commands. */
    }
}
int ro_status_ok(u32 s) {
    /* RINT error bits: response, CRC, timeout, FIFO, lock, start/end. */
    return (s & 0xbfc2u) == 0;
}
void ro_process(const struct request *input, struct response *out, u8 *data) {
    struct request q = *input;
    struct card card = {0};
    u8 ext[512];
    u32 want_crc = q.crc;
    q.crc = 0;
    u32 *words = (u32 *)out;
    for (u32 i = 0; i < sizeof(*out) / 4; ++i) words[i] = 0;
    out->magic = RO_MAGIC; out->version = RO_VERSION;
    out->seq = q.seq; out->lba = q.lba; out->count = q.count;
    out->status = RO_BAD_REQUEST;
    if (q.magic != RO_MAGIC || q.version != RO_VERSION || !q.seq ||
        q.reserved || want_crc != ro_crc(&q, sizeof(q))) goto done;
    out->status = RO_FORBIDDEN;
    if (q.op != RO_INFO && q.op != RO_READ) goto done;
    out->status = RO_RANGE;
    if ((q.op == RO_INFO && (q.count || q.lba)) ||
        (q.op == RO_READ && (!q.count || q.count > RO_MAX_SECTORS ||
                            (u64)q.lba + q.count > 0x100000000ull))) goto done;
#if !defined(RO_SIMULATION) && !defined(RO_BOARD_APPROVED)
    /* Shipping/default build is intentionally locked before any MMIO. */
    out->status = RO_LOCKED;
    goto done;
#endif
    for (u32 i = 0; i < sizeof(ext); ++i) ext[i] = 0;
    out->status = RO_IO;
    if (!ro_hw_init(&card, ext)) goto card_done;
    out->status = RO_AREA;
    if ((card.partition_config & 7u) || card.bus_width != 0) goto card_done;
    out->status = RO_RANGE;
    if (!card.capacity || card.capacity == ~0u ||
        (q.op == RO_READ && (u64)q.lba + q.count > card.capacity)) goto card_done;
    out->status = RO_IO;
    if (q.op == RO_INFO) {
        for (u32 i = 0; i < 512; ++i) data[i] = ext[i];
        out->bytes = 512;
    } else {
        for (u32 i = 0; i < q.count; ++i)
            if (!ro_hw_read(&card, q.lba + i, data + 512 * i)) goto card_done;
        out->bytes = 512 * q.count;
    }
    out->data_crc = ro_crc(data, out->bytes);
    out->status = RO_OK;
card_done:
    out->capacity = card.capacity;
    for (u32 i = 0; i < 4; ++i) out->cid[i] = card.cid[i];
    out->error = card.error;
    out->partition_config = card.partition_config;
    out->bus_width = card.bus_width;
    if (out->status != RO_OK) { out->bytes = 0; out->data_crc = 0; }
done:
    out->crc = 0;
    out->crc = ro_crc(out, sizeof(*out));
}
void ro_entry(void) {
    struct response reply;
    ro_process((const struct request *)RO_REQUEST_ADDR, &reply, (u8 *)RO_DATA_ADDR);
    volatile u32 *dst = (volatile u32 *)RO_RESPONSE_ADDR;
    const u32 *src = (const u32 *)&reply;
    /* Publish magic last; host also checks nonce and the complete header CRC. */
    dst[0] = 0;
    for (u32 i = 1; i < sizeof(reply) / 4; ++i) dst[i] = src[i];
    __asm__ volatile("" ::: "memory");
    dst[0] = src[0];
}
