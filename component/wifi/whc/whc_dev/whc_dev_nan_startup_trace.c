/* Optional diagnostics for the SHA-256-pinned Green2 archive. No packet
 * payloads or key material are logged. The optional peer fix initializes
 * an unauthenticated peer before native Auth1 validation; tracing alone
 * leaves receive decisions unchanged. Private recv_frame offsets: length=92,
 * data pointer=100.
 */
#include "whc_dev.h"
#include <stdint.h>
#include <stddef.h>

union recv_frame;
/* The public ROM map header depends on a vendor-private constants header.
 * In this pinned archive validate_mgnt_frame is the pointer at byte 260. */
extern uintptr_t *p_wifi_rom2flash;
extern uintptr_t rtw_mgntframe_dispatcher_tbl[][2];
extern uint8_t *rtw_nan_peer_info_get(const uint8_t *address);
#ifdef GREEN2_NAN_AUTH_PEER_FIX
extern uint8_t *rtw_nan_peer_info_alloc(const uint8_t *address);
#endif
extern uint8_t rtw_is_nan_frame(union recv_frame *frame);
static void (*native_validate)(uint8_t, union recv_frame **);
static int (*native_auth)(uint8_t, union recv_frame *);
extern void __real_wifi_hal_normal_rx_process(union recv_frame *);
extern int __real_rtw_recv_entry(union recv_frame *);

static const uint8_t *auth_data(union recv_frame *frame)
{
    const uint8_t *data;
    uint16_t length;
    if (!frame) return NULL;
    memcpy(&length, (const uint8_t *)frame + 92, sizeof(length));
    memcpy(&data, (const uint8_t *)frame + 100, sizeof(data));
    return data && length >= 30 && length <= 2304 &&
        data[0] == 0xb0 && !(data[1] & 0x43) &&
        data[24] == 7 && data[25] == 0 ? data : NULL;
}

static void trace_validate(uint8_t interface, union recv_frame **frame)
{
    const uint8_t *data = frame ? auth_data(*frame) : NULL;
    if (data)
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] rx t=%u if=%u auth=%u sc=%u peer=%02x:%02x:%02x:%02x:%02x:%02x nan=%u\n",
            (unsigned int)rtos_time_get_current_system_time_ms(), interface,
            data[26] | (data[27] << 8), (data[22] | (data[23] << 8)) >> 4,
            data[10], data[11], data[12], data[13], data[14], data[15],
            rtw_is_nan_frame(*frame));
    native_validate(interface, frame);
    if (data)
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] rx done t=%u frame_kept=%u\n",
            (unsigned int)rtos_time_get_current_system_time_ms(), frame && *frame != NULL);
}

void __wrap_wifi_hal_normal_rx_process(union recv_frame *frame)
{
    const uint8_t *data = auth_data(frame);
    if (data) {
        uint32_t flags[2];
        memcpy(flags, (const uint8_t *)frame + 12, sizeof(flags));
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] hal rx t=%u auth=%u sc=%u peer=%02x:%02x:%02x:%02x:%02x:%02x flags=%08x/%08x\n",
            (unsigned int)rtos_time_get_current_system_time_ms(),
            data[26] | (data[27] << 8), (data[22] | (data[23] << 8)) >> 4,
            data[10], data[11], data[12], data[13], data[14], data[15],
            (unsigned int)flags[0], (unsigned int)flags[1]);
    }
    __real_wifi_hal_normal_rx_process(frame);
}

int __wrap_rtw_recv_entry(union recv_frame *frame)
{
    int traced = auth_data(frame) != NULL;
    if (traced)
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] entry t=%u if=%u\n",
            (unsigned int)rtos_time_get_current_system_time_ms(),
            ((const uint8_t *)frame)[116]);
    int result = __real_rtw_recv_entry(frame);
    if (traced)
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] entry done ret=%d\n", result);
    return result;
}

static int trace_auth(uint8_t interface, union recv_frame *frame)
{
    const uint8_t *data = auth_data(frame);
    uint8_t address[6];
    if (data) {
        memcpy(address, data + 10, sizeof(address));
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] auth dispatch t=%u if=%u\n",
            (unsigned int)rtos_time_get_current_system_time_ms(), interface);
#ifdef GREEN2_NAN_AUTH_PEER_FIX
        /* A cached service may trigger PASN before a new-MAC Subscribe.
         * Initialize only the ordinary, unauthenticated vendor peer object.
         * The original handler still validates RSN/PASN, identity and keys;
         * allocation does not grant authorization or install a key.
         */
        if (interface == 2 && rtw_is_nan_frame(frame) &&
            !(data[4] & 1) && !(address[0] & 1) &&
            data[26] == 1 && data[27] == 0 &&
            data[28] == 0 && data[29] == 0 &&
            !rtw_nan_peer_info_get(address)) {
            uint8_t *peer = rtw_nan_peer_info_alloc(address);
            RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANFIX] Auth1 before Subscribe: peer initialized=%u\n", peer != NULL);
        }
#endif
    }
    int result = native_auth(interface, frame);
    if (data) {
        const uint8_t *peer = rtw_nan_peer_info_get(address);
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] auth done t=%u ret=%d peer=%u state=%u mode=%u role=%u\n",
            (unsigned int)rtos_time_get_current_system_time_ms(), result,
            peer != NULL, peer ? peer[438] : 255, peer ? peer[449] : 255,
            peer ? peer[528] : 255);
    }
    return result;
}

void green2_nan_startup_trace_install(void)
{
    if (native_validate) return;
    _Static_assert(sizeof(uintptr_t) == 4, "Green2 ROM table requires 32-bit pointers");
    native_validate = (void *)p_wifi_rom2flash[65];
    native_auth = (void *)rtw_mgntframe_dispatcher_tbl[11][1];
    if (!native_validate || !native_auth) {
        native_validate = NULL;
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] receive hooks unavailable\n");
        return;
    }
    p_wifi_rom2flash[65] = (uintptr_t)trace_validate;
    rtw_mgntframe_dispatcher_tbl[11][1] = (uintptr_t)trace_auth;
    RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTRACE] metadata-only receive diagnostics installed\n");
}
