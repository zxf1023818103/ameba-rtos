#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int green2_nan_fresh_bootstrap(const uint8_t *, size_t);
int green2_nan_sdf_rx_gate_c(const uint8_t *, size_t, unsigned);

static const uint8_t request[] = {
    0xd0,0,0,0, 0,0xe2,0x4c,0,0x13,0xa2,
    2,0x63,0x1e,0xd0,0x3a,0xa0, 0x50,0x6f,0x9a,1,0,0,0,0,
    4,9,0x50,0x6f,0x9a,0x13,
    3,9,0, 0xe2,0xe6,0x64,0x61,0x95,0x85,2,1,2,
    44,5,0, 0x99,1,0,0x20,0
};

int main(void)
{
    uint8_t frame[256];
    const size_t n = sizeof(request);
    assert(green2_nan_fresh_bootstrap(request, n));
    assert(!green2_nan_sdf_rx_gate_c(request, n, 0x40));
    assert(!green2_nan_fresh_bootstrap(NULL, n));
    for (size_t i = 0; i < n; ++i)
        assert(!green2_nan_fresh_bootstrap(request, i));

    /* Protected, DS, multicast, other action/OUI and malformed SD/NPBA. */
    const unsigned offsets[] = {0,1,4,24,25,26,29,31,32,39,40,41,43,44,45,46,47,48};
    const uint8_t values[] = {0x80,0x40,1,5,8,0,0,8,1,0,0,0,4,1,0,0x11,1,0};
    for (size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); ++i) {
        memcpy(frame, request, n);
        frame[offsets[i]] = values[i];
        assert(!green2_nan_fresh_bootstrap(frame, n));
        assert(green2_nan_sdf_rx_gate_c(frame, n, 0x40));
    }
    for (unsigned id = 0; id < 256; ++id) {
        memcpy(frame, request, n);
        frame[42] = id;
        if (id != 44)
            assert(!green2_nan_fresh_bootstrap(frame, n));
    }
    /* No parsing past the end, duplicate attributes, or appended key attrs. */
    memcpy(frame, request, n);
    memset(frame + n, 0, sizeof(frame) - n);
    assert(!green2_nan_fresh_bootstrap(frame, n + 1));
    memcpy(frame + n, request + 42, 8);
    assert(!green2_nan_fresh_bootstrap(frame, n + 8));
    memcpy(frame + n, request + 30, 12);
    assert(!green2_nan_fresh_bootstrap(frame, n + 12));
    frame[n] = 36; frame[n+1] = 1; frame[n+2] = 0;
    assert(!green2_nan_fresh_bootstrap(frame, n + 4));
    frame[n] = 221;
    assert(green2_nan_fresh_bootstrap(frame, n + 4));
    frame[n+1] = 255;
    assert(!green2_nan_fresh_bootstrap(frame, n + 4));

    /* Preserve the vendor's DA mapping for every DS combination. */
    const uint8_t multicast[] = {0x51,0x6f,0x9a,1,0,0};
    for (unsigned ds = 0; ds < 4; ++ds) {
        memset(frame, 0, sizeof(frame));
        frame[1] = ds;
        memcpy(frame + ((ds & 1) ? 16 : 4), multicast, 6);
        assert(!green2_nan_sdf_rx_gate_c(frame, 24, 0x40));
    }
    puts("bootstrap request bounds and protected-traffic regression: PASS");
    return 0;
}
