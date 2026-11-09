/* Build with rtw_nan_cmd.c and -ffunction-sections -Wl,--gc-sections.
 * Verify wire metadata: SRT must be UDP/17; existing probes remain TCP/6. */
#include <assert.h>
#include <string.h>
#include "rtw_nan_struct.h"
uint16_t _append_gen_sub_attr(uint8_t, uint8_t *, void *, uint8_t);
int main(void)
{
    struct srvc_info service = {0};
    struct datapath_info path = {.service = &service};
    uint8_t wire[16] = {0};
    const char *names[] = {"_flashstudio._tcp", "_flashstudio._udp", "", "_udp"};
    const uint8_t expected[] = {6, 17, 6, 6};
    for (unsigned i = 0; i < sizeof(expected); i++) {
        strcpy(service.service_name, names[i]);
        assert(_append_gen_sub_attr(NAN_GEN_SRVC_TRANSPORT_PROTOCOL, wire,
                                    &path, NAN_WFA_SRVC_ATTR_NDPE) == 4);
        assert(wire[0] == NAN_GEN_SRVC_TRANSPORT_PROTOCOL);
        assert(wire[1] == 1 && wire[2] == 0 && wire[3] == expected[i]);
    }
    path.service = NULL;
    assert(_append_gen_sub_attr(NAN_GEN_SRVC_TRANSPORT_PROTOCOL, wire,
                                &path, NAN_WFA_SRVC_ATTR_NDPE) == 4);
    assert(wire[3] == 6);
    return 0;
}
