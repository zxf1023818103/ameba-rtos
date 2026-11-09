#include <assert.h>
#include <string.h>
#include "../whc_dev/whc_dev_nan_usb_control.h"
static void be16(uint8_t *p, unsigned n) { p[0] = n >> 8; p[1] = n; }
int main(void) {
    uint8_t p[128] = {0};
    assert(!green2_nan_usb_control_frame(NULL, 0));
    be16(p + 12, 0x86dd); p[14] = 0x60; be16(p + 18, 24); p[20] = 17;
    be16(p + 54, 9000); be16(p + 56, 12345); be16(p + 58, 24);
    for (unsigned tc = 0; tc < 256; ++tc) {
        p[14] = 0x60 | (tc >> 4); p[15] = tc << 4;
        for (unsigned type = 0; type < 9; ++type) {
            p[62] = 0x80; p[63] = type;
            assert(green2_nan_usb_control_frame(p, 78));
        }
        p[62] = 0x7f; /* Short DATA with every sequence bit set stays low priority. */
        assert(!green2_nan_usb_control_frame(p, 78));
    }
    p[62] = 0x80;
    for (size_t n = 0; n < 78; ++n) assert(!green2_nan_usb_control_frame(p, n));
    be16(p + 54, 9001); assert(!green2_nan_usb_control_frame(p, 78));
    be16(p + 56, 9000); assert(green2_nan_usb_control_frame(p, 78));
    be16(p + 58, 23); assert(!green2_nan_usb_control_frame(p, 78));
    be16(p + 58, 25); assert(!green2_nan_usb_control_frame(p, 78));
    be16(p + 58, 24); p[20] = 44; assert(!green2_nan_usb_control_frame(p, 78));
    p[20] = 0; memmove(p + 62, p + 54, 24); memset(p + 54, 0, 8);
    p[54] = 17; be16(p + 18, 32); assert(green2_nan_usb_control_frame(p, 86));
    p[55] = 255; assert(!green2_nan_usb_control_frame(p, 86));
    memset(p, 0, sizeof(p)); be16(p + 12, 0x0800); p[14] = 0x45;
    be16(p + 16, 44); p[23] = 17; be16(p + 34, 9000); be16(p + 38, 24); p[42] = 0x80;
    assert(green2_nan_usb_control_frame(p, 58));
    p[42] = 0; assert(!green2_nan_usb_control_frame(p, 58));
    p[42] = 0x80; p[20] = 0x20; assert(!green2_nan_usb_control_frame(p, 58));
    p[20] = 0; p[14] = 0x44; assert(!green2_nan_usb_control_frame(p, 58));
    /* IPv4 options move UDP; fragments cannot masquerade as SRT. */
    p[14] = 0x46; memmove(p + 38, p + 34, 24); memset(p + 34, 0, 4);
    be16(p + 16, 48); assert(green2_nan_usb_control_frame(p, 62));
    /* VLAN moves Ethernet payload without changing SRT classification. */
    memmove(p + 18, p + 14, 48); be16(p + 12, 0x8100); be16(p + 16, 0x0800);
    assert(green2_nan_usb_control_frame(p, 66));
    memset(p, 0, sizeof(p)); be16(p + 12, 0x86dd); p[14] = 0x60;
    be16(p + 18, 24); p[20] = 58; p[54] = 135;
    assert(green2_nan_usb_control_frame(p, 78));
    p[55] = 1; assert(!green2_nan_usb_control_frame(p, 78));
    p[55] = 0; p[54] = 128; assert(!green2_nan_usb_control_frame(p, 78));
    p[20] = 6; be16(p + 18, 20); p[66] = 0x50;
    assert(green2_nan_usb_control_frame(p, 74));
    be16(p + 18, 21); assert(!green2_nan_usb_control_frame(p, 75));
    return 0;
}
