/* SPDX-License-Identifier: MIT */
#ifndef FEL_RO_H
#define FEL_RO_H
typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;
#define RO_MAGIC 0x314f5246u
#define RO_VERSION 1u
#define RO_INFO 1u
#define RO_READ 2u
#define RO_MAX_SECTORS 128u
#define RO_REQUEST_ADDR 0x0002ff00u
#define RO_RESPONSE_ADDR 0x0002ff40u
#define RO_DATA_ADDR 0x00030000u
enum { RO_OK, RO_BAD_REQUEST, RO_FORBIDDEN, RO_RANGE, RO_IO,
       RO_AREA, RO_LOCKED };
struct request { u32 magic, version, op, seq, lba, count, reserved, crc; };
struct response {
    u32 magic, version, seq, status, lba, count, capacity, bytes;
    u32 cid[4], error, partition_config, bus_width, data_crc, crc, reserved[3];
};
struct card { u32 capacity, cid[4], error, partition_config, bus_width; };
u32 ro_crc(const void *data, u32 size);
int ro_command_allowed(u32 cmd, u32 arg);
int ro_status_ok(u32 status);
int ro_hw_init(struct card *card, u8 *ext);
int ro_hw_read(struct card *card, u32 lba, u8 *out);
void ro_process(const struct request *input, struct response *out, u8 *data);
#endif
