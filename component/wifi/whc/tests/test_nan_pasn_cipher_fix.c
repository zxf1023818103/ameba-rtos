/* Host-side boundary test for the private-ABI adapter, not a radio test. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../whc_dev/whc_dev_nan_pasn_cipher_fix.c"

static uint8_t state[436], expected[436];
static unsigned calls;
static int fail_original;

void *__real_rtw_nan_ndp_response_prehandle(void *peer, void *response)
{
    assert(peer && response);
    calls++;
    return fail_original ? NULL : state;
}

int main(void)
{
    uint8_t request[80] = {0};
    int peer;
    for (unsigned cipher = 0; cipher <= 8; cipher++) {
        for (unsigned flags = 0; flags <= 7; flags++) {
            for (unsigned status = 0; status <= 2; status++) {
                memset(state, 0xa5, sizeof(state));
                request[RESPONSE_CIPHER] = cipher;
                state[ENTRY_FLAGS] = flags;
                state[ENTRY_TYPE_STATUS] = (status << 4) | 1;
                state[ENTRY_CIPHER] = CIPHER_SK_128;
                memcpy(expected, state, sizeof(state));
                if (cipher == 7 && (flags & 5) == 4 && status != 2)
                    expected[ENTRY_CIPHER] = 7;
                assert(__wrap_rtw_nan_ndp_response_prehandle(&peer, request) == state);
                assert(!memcmp(expected, state, sizeof(state)));
            }
        }
    }
    assert(calls == 9 * 8 * 3);
    fail_original = 1;
    assert(!__wrap_rtw_nan_ndp_response_prehandle(&peer, request));
    assert(!__wrap_rtw_nan_ndp_response_prehandle(NULL, request));
    assert(!__wrap_rtw_nan_ndp_response_prehandle(&peer, NULL));
    assert(calls == 9 * 8 * 3 + 1);
    puts("NAN cipher wrapper: 216 combinations and failure/null guards passed");
    return 0;
}
