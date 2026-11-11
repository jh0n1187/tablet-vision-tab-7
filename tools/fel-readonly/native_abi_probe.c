/* Local Linux headers/ABI only. No open(), ioctl(), USB or device operations. */
#include <stdio.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>

int main(void) {
    unsigned short endian = 1;
    int ok = sizeof(void *) == 8 && *(unsigned char *)&endian == 1 &&
        sizeof(struct usbdevfs_bulktransfer) == 24 &&
        offsetof(struct usbdevfs_bulktransfer, data) == 16 &&
        USBDEVFS_BULK == 0xc0185502UL &&
        USBDEVFS_CLAIMINTERFACE == 0x8004550fUL &&
        USBDEVFS_RELEASEINTERFACE == 0x80045510UL;
    printf("{\"pointer_size\":%zu,\"bulk_size\":%zu,\"data_offset\":%zu,"
           "\"bulk_ioctl\":%lu,\"claim_ioctl\":%lu,\"release_ioctl\":%lu,\"matches_reviewed_abi\":%s}\n",
           sizeof(void *), sizeof(struct usbdevfs_bulktransfer),
           offsetof(struct usbdevfs_bulktransfer, data), (unsigned long)USBDEVFS_BULK,
           (unsigned long)USBDEVFS_CLAIMINTERFACE, (unsigned long)USBDEVFS_RELEASEINTERFACE,
           ok ? "true" : "false");
    return ok ? 0 : 1;
}
