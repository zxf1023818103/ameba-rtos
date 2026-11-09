/* Private ABI of archive 9ade71de... (enforced by CMake).
 * rtw_nan_ndi_sec_stainfo_free retains the station when NDI == NMI. This is
 * required for discovery/PASN, but its pending DATA frames must not survive
 * the last NDP. Mirror the pending queue cleanup in rtw_free_stainfo without
 * deleting the management station, pairing state or keys ourselves.
 */
#include "whc_dev.h"
#include <stdint.h>

extern uint8_t *rtw_nan_peer_info_get_by_ndi(const uint8_t *ndi);
extern uint8_t *rtw_sta_get_mlmepriv(uint8_t interface, const uint8_t *address);
extern void *rtw_get_pendingqueue(uint8_t interface);
extern void wifi_hal_pending_queue_free(void *queue, void *station_xmitpriv);
extern uintptr_t g_xmitpriv[];
extern void __real_rtw_nan_ndi_sec_stainfo_free(uint8_t *peer, uint8_t *entry);
extern uint8_t *g_nanpriv;
extern void __real_rtw_nan_start_api(uint8_t, uint8_t, uint8_t);
extern void __real_rtw_nan_stop_api(void);
extern uint8_t __real_rtw_nan_pairwise_key_set(uint8_t *peer, uint8_t *key, const uint8_t *address);
extern void wififw_media_macid_drop_action(uint8_t connected, uint8_t macid);
extern void wifi_hal_nan_macid_release(uint8_t macid);
extern void __real_wifi_hal_nan_macid_pause(uint8_t macid);
#ifdef GREEN2_NAN_RESTART_FIX
extern void green2_nan_arm_discovery_timer(void);
#endif

/* WHC API teardown runs independently of the Wi-Fi TX task. A flag check
 * alone cannot protect the peer-list mutex from being freed after the check.
 * Close admission and drain the in-flight TX call before native teardown.
 */
static unsigned nan_tx_users;
static int nan_tx_closed = 1;
static uint32_t nan_retired_macids;

void __wrap_wifi_hal_nan_macid_pause(uint8_t macid)
{
    rtos_critical_enter(RTOS_CRITICAL_WIFI);
    /* FAW withdrawal happens after the final-NDP callback. Its late pause
     * must not stop hardware discard before the old TXBDs have completed. */
    if (macid >= 32 || !(nan_retired_macids & ((uint32_t)1 << macid)))
        __real_wifi_hal_nan_macid_pause(macid);
    rtos_critical_exit(RTOS_CRITICAL_WIFI);
}

/* The pending queue is only the software half of TX. A final NDP can leave
 * DATA in TXBDs for a MACID whose FAW has been withdrawn. Paused TXBDs never
 * complete, and the vendor's all-queue space check then stalls new peers too.
 * Mark that MACID for hardware discard BEFORE releasing its pause. Do not
 * send obsolete encrypted frames outside the old peer's negotiated windows.
 */
static void nan_retire_macid(uint8_t macid)
{
    if (!macid || macid >= 32) return;
    rtos_critical_enter(RTOS_CRITICAL_WIFI);
    wififw_media_macid_drop_action(0, macid);
    wifi_hal_nan_macid_release(macid);
    nan_retired_macids |= (uint32_t)1 << macid;
    rtos_critical_exit(RTOS_CRITICAL_WIFI);
    RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTX] retire hardware DATA macid=%u\n", macid);
}

uint8_t __wrap_rtw_nan_pairwise_key_set(uint8_t *peer, uint8_t *key, const uint8_t *address)
{
    uint8_t result = __real_rtw_nan_pairwise_key_set(peer, key, address);
    if (result) {
        uint8_t *sta = rtw_sta_get_mlmepriv(NAN_WLAN_INDEX, address);
        uint8_t macid = sta ? sta[242] : 0;
        if (macid && macid < 32) {
            rtos_critical_enter(RTOS_CRITICAL_WIFI);
            if (nan_retired_macids & ((uint32_t)1 << macid)) {
                /* Includes reconnect to the retained NMI station. A newly
                 * allocated station also restores media state natively. */
                wififw_media_macid_drop_action(1, macid);
                nan_retired_macids &= ~((uint32_t)1 << macid);
            }
            rtos_critical_exit(RTOS_CRITICAL_WIFI);
        }
    }
    return result;
}

static void nan_tx_quiesce(void)
{
    unsigned busy;
    do {
        rtos_critical_enter(RTOS_CRITICAL_WIFI);
        nan_tx_closed = 1;
        busy = nan_tx_users;
        rtos_critical_exit(RTOS_CRITICAL_WIFI);
        if (busy) rtos_time_delay_ms(1);
    } while (busy);
}

void __wrap_rtw_nan_stop_api(void)
{
    nan_tx_quiesce();
    __real_rtw_nan_stop_api();
}

void __wrap_rtw_nan_start_api(uint8_t pref, uint8_t bands, uint8_t cmd_type)
{
    int was_enabled = g_nanpriv && (g_nanpriv[2350] & 2);
    if (!was_enabled) nan_tx_quiesce();
    __real_rtw_nan_start_api(pref, bands, cmd_type);
#ifdef GREEN2_NAN_RESTART_FIX
    if (!was_enabled) green2_nan_arm_discovery_timer();
#endif
    rtos_critical_enter(RTOS_CRITICAL_WIFI);
    nan_tx_closed = !(g_nanpriv && (g_nanpriv[2350] & 3) == 3);
    rtos_critical_exit(RTOS_CRITICAL_WIFI);
}

/* rtw_nan_data_ndi.o: remote NDI is entry+14 unless it is our NDI, then
 * entry+429. Only the NMI equality case keeps its station in the native path.
 * In that case peer+67 is necessarily the remote NDI, so no local-NDI global
 * needs to be read. Caller is final-NDP teardown or whole-peer cleanup.
 */
void __wrap_rtw_nan_ndi_sec_stainfo_free(uint8_t *peer, uint8_t *entry)
{
    if (peer && entry &&
        (!memcmp(peer + 67, entry + 14, 6) || !memcmp(peer + 67, entry + 429, 6))) {
        uint8_t *sta = rtw_sta_get_mlmepriv(NAN_WLAN_INDEX, peer + 67);
        if (sta) {
            int before = skbpriv.skb_buff_used;
            rtos_mutex_t lock = (rtos_mutex_t)g_xmitpriv[0];
            rtos_mutex_take(lock, MUTEX_WAIT_TIMEOUT);
            wifi_hal_pending_queue_free(rtw_get_pendingqueue(NAN_WLAN_INDEX), sta - 248);
            rtos_mutex_give(lock);
            nan_retire_macid(sta[242]);
            RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTX] final NDP flush skb_used=%d->%d\n",
                     before, skbpriv.skb_buff_used);
        }
    }
    __real_rtw_nan_ndi_sec_stainfo_free(peer, entry);
}

/* Runs under the TX admission lease below, not in the USB IRQ task. This catches old video
 * already queued by WHC at teardown, and retries from the host's old socket.
 * The native entry counter uses bit 4 at +435 and either NDI at +14/+429.
 */
int green2_nan_data_tx_allowed(const struct sk_buff *skb)
{
    static uint32_t stale_drops;
    uint8_t *peer, *entry;
    rtos_mutex_t lock;
    int allowed = 0;
    unsigned visited = 0;
    if ((uintptr_t)skb->dev != NAN_WLAN_INDEX || skb->len < 14 || (skb->data[0] & 1)) return 1;
    peer = rtw_nan_peer_info_get_by_ndi(skb->data);
    if (peer) {
        memcpy(&lock, peer + 32, sizeof(lock));
        rtos_mutex_take(lock, MUTEX_WAIT_TIMEOUT);
        memcpy(&entry, peer + 24, sizeof(entry));
        while (entry && entry != peer + 24 && visited++ < 64) {
            if ((entry[435] & 0x10) && entry[428] != 10 && entry[428] != 11 &&
                (!memcmp(entry + 14, skb->data, 6) || !memcmp(entry + 429, skb->data, 6))) {
                allowed = 1; break;
            }
            memcpy(&entry, entry, sizeof(entry));
        }
        rtos_mutex_give(lock);
    }
    if (!allowed && (++stale_drops == 1 || stale_drops % 128 == 0))
        RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANTX] drop without active NDP count=%u\n", (unsigned)stale_drops);
    return allowed;
}

void green2_nan_xmit_skb(struct sk_buff *skb)
{
    int admitted;
    if ((uintptr_t)skb->dev != NAN_WLAN_INDEX) {
        wifi_if_send_skb((int)(uintptr_t)skb->dev, skb);
        return;
    }
    rtos_critical_enter(RTOS_CRITICAL_WIFI);
    admitted = !nan_tx_closed;
    if (admitted) ++nan_tx_users;
    rtos_critical_exit(RTOS_CRITICAL_WIFI);
    if (!admitted) {
        dev_kfree_skb_any(skb);
        return;
    }
    if (green2_nan_data_tx_allowed(skb)) wifi_if_send_skb(NAN_WLAN_INDEX, skb);
    else dev_kfree_skb_any(skb);
    rtos_critical_enter(RTOS_CRITICAL_WIFI);
    --nan_tx_users;
    rtos_critical_exit(RTOS_CRITICAL_WIFI);
}
