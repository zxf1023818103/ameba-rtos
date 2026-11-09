/* Access to NAN USB reserve: SRT control flag, never packet size or DSCP.
 * SRT header: https://haivision.github.io/srt-rfc/draft-sharabayko-srt.html#section-3
 * Only the configured SRT UDP port is interpreted as an SRT packet. */
#ifndef WHC_DEV_NAN_USB_CONTROL_H
#define WHC_DEV_NAN_USB_CONTROL_H
#include <stdint.h>
#include <stddef.h>
static inline unsigned green2_nan_be16(const uint8_t *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}
static inline int green2_nan_usb_control_frame(const uint8_t *p, size_t n)
{
    size_t off = 14, end, bytes;
    unsigned proto, ether, i;
    if (!p || n < off) return 0;
    ether = green2_nan_be16(p + 12);
    for (i = 0; i < 2 && (ether == 0x8100 || ether == 0x88a8); ++i) {
        if (n - off < 4) return 0;
        ether = green2_nan_be16(p + off + 2); off += 4;
    }
    if (ether == 0x0806) return n - off >= 28 && n - off <= 50;
    if (ether == 0x0800) {
        if (n - off < 20 || p[off] >> 4 != 4) return 0;
        bytes = (p[off] & 15) * 4;
        end = off + green2_nan_be16(p + off + 2);
        if (bytes < 20 || end > n || end < off + bytes ||
            (green2_nan_be16(p + off + 6) & 0x3fff)) return 0;
        proto = p[off + 9]; off += bytes;
    } else if (ether == 0x86dd) {
        if (n - off < 40 || p[off] >> 4 != 6) return 0;
        end = off + 40 + green2_nan_be16(p + off + 4);
        if (end > n) return 0;
        proto = p[off + 6]; off += 40;
        for (i = 0; i < 8 && (proto == 0 || proto == 43 || proto == 60); ++i) {
            if (end - off < 8) return 0;
            bytes = ((size_t)p[off + 1] + 1) * 8;
            if (bytes > end - off) return 0;
            proto = p[off]; off += bytes;
        }
        /* Fragmented traffic is not classified without reassembly. ND must
         * remain usable to establish the link even when video fills the pool. */
        if (proto == 58 && end - off >= 8 && p[off + 1] == 0) {
            unsigned type = p[off];
            return (type == 133 && end - off >= 8) ||
                   (type == 134 && end - off >= 16) ||
                   ((type == 135 || type == 136) && end - off >= 24);
        }
    } else return 0;
    if (proto == 6) {
        if (end - off < 20) return 0;
        bytes = (p[off + 12] >> 4) * 4;
        return bytes >= 20 && bytes == end - off; /* TCP without payload */
    }
    if (proto != 17 || end - off < 8 + 16) return 0;
    if (green2_nan_be16(p + off) != 9000 && green2_nan_be16(p + off + 2) != 9000) return 0;
    bytes = green2_nan_be16(p + off + 4);
    if (bytes < 8 + 16 || bytes > end - off) return 0;
    /* First bit of the SRT header: 1 control, 0 data (including retransmits
     * and tiny JPEG tails). The rest of the header need not be decoded. */
    return (p[off + 8] & 0x80) != 0;
}
#endif
