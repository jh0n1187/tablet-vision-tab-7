/* Temporary U-Boot diagnostic. No raw MMIO, flash writes, erase or saveenv.
 * Command records are resolved from the running firmware, never old offsets.
 * SPDX-License-Identifier: MIT
 */
typedef unsigned int u32;
typedef unsigned char u8;
struct command {
    const char *name;
    int maxargs, repeatable;
    int (*call)(struct command *, int, int, char *const *);
    const char *usage;
};
static char export_buffer[4096];
static char args_buffer[4608];
static char address[9];
static volatile u32 *const boot_buffer = (u32 *)0x70000000u;

static int within(u32 p, u32 size, u32 lo, u32 hi) {
    return p >= lo && p <= hi && size <= hi - p;
}
static int string_is(const char *p, const char *s, u32 lo, u32 hi) {
    unsigned i;
    for (i = 0; i < 96; ++i) {
        if (!within((u32)p + i, 1, lo, hi) || p[i] != s[i]) return 0;
        if (!s[i]) return 1;
    }
    return 0;
}
static struct command *resolve(const char *name, const char *usage, u32 lo, u32 hi) {
    struct command *found = 0;
    for (u32 p = lo; within(p, sizeof(struct command), lo, hi); p += 4) {
        struct command *cmd = (struct command *)p;
        if (cmd->maxargs < 2 || cmd->maxargs > 128 || cmd->repeatable < 0 || cmd->repeatable > 1) continue;
        u32 fn = (u32)cmd->call;
        if (!(fn & 1) || !within(fn & ~1u, 4, lo, hi)) continue;
        if (!string_is(cmd->name, name, lo, hi) || !string_is(cmd->usage, usage, lo, hi)) continue;
        unsigned short first = *(const unsigned short *)(fn & ~1u);
        if ((first & 0xff00) != 0xb500 && first != 0xe92d && (first & 0xf800) != 0x2800) continue;
        if (found) return 0;
        found = cmd;
    }
    return found;
}
static void hex(u32 value, char *out) {
    const char *digits = "0123456789abcdef";
    for (unsigned i = 0; i < 8; ++i) out[i] = digits[(value >> (28 - 4 * i)) & 15];
    out[8] = 0;
}

/* Only the same calls to other firmware functions may move in a new link.
 * Every other instruction, including branches and literal load placement,
 * must match. The pointed-to variable is read, never executed or modified.
 */
extern const u8 init_cache_pattern[], init_cache_mask[];
static u32 cached_init(u32 lo, u32 hi) {
    u32 match = 0;
    const u32 length = 92;
    for (u32 p = lo; within(p, length + 16, lo, hi); p += 2) {
        if (*(const unsigned short *)p != (unsigned short)(init_cache_pattern[0] | (init_cache_pattern[1] << 8))) continue;
        unsigned i;
        for (i = 0; i < length; ++i)
            if ((((const u8 *)p)[i] ^ init_cache_pattern[i]) & init_cache_mask[i]) break;
        if (i != length) continue;
        if (match) return 0;
        match = p;
    }
    if (!match) return 0;
    /* Decode the LDR r3 literal followed by LDR r0,[r3] at the matched exit. */
    u32 insn_address = match + 86;
    unsigned short insn = *(const unsigned short *)insn_address;
    if ((insn & 0xff00) != 0x4b00 || *(const unsigned short *)(insn_address + 2) != 0x6818) return 0;
    u32 literal = ((insn_address + 4) & ~3u) + ((insn & 255) * 4);
    if (!within(literal, 4, lo, hi)) return 0;
    u32 variable = *(const u32 *)literal;
    if ((variable & 3) || !within(variable, 4, lo, hi)) return 0;
    u32 header = *(const u32 *)variable;
    if ((header & 2047) || !within(header, 4096, 0x40000000, 0x50000000)) return 0;
    const u32 *h = (const u32 *)header;
    if (h[0] != 0x52444e41 || h[1] != 0x2144494f || h[2] != 0 || h[10] != 4) return 0;
    if (h[3] < 1024 || h[3] > 0x800000 - 4096) return 0;
    return header;
}

int adapter_main(u32 unused_argc, void *unused_argv, u32 return_address) {
    (void)unused_argc; (void)unused_argv;
    return_address &= ~1u;
    if (!within(return_address, 4, 0x40100000u, 0xffd00000u)) return 11;
    u32 middle = return_address & ~0xfffffu;
    u32 lo = middle - 0x100000u, hi = middle + 0x200000u;
    struct command *flash = resolve("sunxi_flash", "sunxi_flash sub-system", lo, hi);
    struct command *bootm = resolve("bootm", "boot application image from memory", lo, hi);
    struct command *env = resolve("env", "environment handling commands", lo, hi);
    struct command *setenv = resolve("setenv", "set environment variables", lo, hi);
    if (!flash || !bootm || !env || !setenv) return 12;

    /* The size and partition name come from the already inspected real map. */
    char *read_args[] = {"sunxi_flash", "read", "70000000", "boot_a", "4000000", 0};
    if (flash->call(flash, 0, 5, read_args)) return 13;
    if (boot_buffer[0] != 0x52444e41 || boot_buffer[1] != 0x2144494f || boot_buffer[10] != 4) return 14;
    if (boot_buffer[2] < 0x100000 || boot_buffer[2] > 0x4000000 - 4096) return 15;

    hex((u32)export_buffer, address);
    char *export_args[] = {"env", "export", "-t", "-s", "1000", address, "bootargs", 0};
    if (env->call(env, 0, 7, export_args)) return 16;
    const char prefix[] = "bootargs=";
    for (unsigned i = 0; i < sizeof(prefix) - 1; ++i)
        if (export_buffer[i] != prefix[i]) return 17;
    unsigned length = 0;
    const unsigned skip = sizeof(prefix) - 1;
    while (skip + length < sizeof(export_buffer) && export_buffer[skip + length] && export_buffer[skip + length] != '\n') {
        args_buffer[length] = export_buffer[skip + length];
        ++length;
    }
    if (skip + length == sizeof(export_buffer) || length > 4000) return 18;
    const char *marker = cached_init(lo, hi)
        ? " androidboot.t307_ram_adapter=probe_cache_ok"
        : " androidboot.t307_ram_adapter=probe_cache_miss";
    for (unsigned i = 0; marker[i]; ++i) args_buffer[length++] = marker[i];
    args_buffer[length] = 0;
    char *set_args[] = {"setenv", "bootargs", args_buffer, 0};
    if (setenv->call(setenv, 0, 3, set_args)) return 19;
    char *boot_args[] = {"bootm", "70000000", 0};
    return bootm->call(bootm, 0, 2, boot_args);
}
