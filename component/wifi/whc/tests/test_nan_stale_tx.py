#!/usr/bin/env python3
"""Exercise actual stale-TX adapter with mocked vendor ownership/queue calls."""
from pathlib import Path
import subprocess
import tempfile
import unittest

class StaleTxTest(unittest.TestCase):
    def test_final_ndp_flush_and_old_video_admission(self):
        source = Path(__file__).resolve().parents[1] / 'whc_dev/whc_dev_nan_stale_tx_fix.c'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'fix.c').write_text(source.read_text())
            (root / 'whc_dev.h').write_text(r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#define NAN_WLAN_INDEX 2
#define MUTEX_WAIT_TIMEOUT 0xffffffff
#define RTK_LOGS(...) ((void)0)
#define RTOS_CRITICAL_WIFI 3
typedef void *rtos_mutex_t;
struct sk_buff { void *dev; unsigned len; uint8_t *data; };
extern struct pool { int skb_buff_used; } skbpriv;
int rtos_mutex_take(rtos_mutex_t, uint32_t);
void rtos_mutex_give(rtos_mutex_t);
void rtos_critical_enter(uint32_t);
void rtos_critical_exit(uint32_t);
void rtos_time_delay_ms(uint32_t);
void wifi_if_send_skb(int, struct sk_buff *);
void dev_kfree_skb_any(struct sk_buff *);
''')
            (root / 'test.c').write_text(r'''
#include "fix.c"
struct pool skbpriv;
uintptr_t g_xmitpriv[1] = {123};
static uint8_t peer[600], entry[500], station[600], packet[64];
static int available = 1, station_exists = 1, locks, flushes, native_calls;
static uint8_t nanpriv[2360];
uint8_t *g_nanpriv = nanpriv;
static int critical, sends, frees, waits, starts, stops;
static uint8_t key_result = 1;
static unsigned hw_drops, hw_releases, hw_restores, hw_pauses, blocked_txbd = 3;
static int hw_discard;
void __real_wifi_hal_nan_macid_pause(uint8_t macid) {
    assert(critical == 1 && (macid == 9 || macid == 10 || macid == 255));
    ++hw_pauses;
}
void wififw_media_macid_drop_action(uint8_t connected, uint8_t macid) {
    assert(critical == 1 && macid == 9);
    if (connected) { assert(!blocked_txbd); ++hw_restores; hw_discard = 0; }
    else { ++hw_drops; hw_discard = 1; }
}
void wifi_hal_nan_macid_release(uint8_t macid) {
    /* Releasing pause without discard would transmit stale encrypted DATA. */
    assert(critical == 1 && macid == 9 && hw_discard);
    ++hw_releases; blocked_txbd = 0;
}
uint8_t __real_rtw_nan_pairwise_key_set(uint8_t *p, uint8_t *k, const uint8_t *a) {
    assert(!critical && p == peer && k && a == peer+67); return key_result;
}
void rtos_critical_enter(uint32_t id) { assert(id == 3 && !critical); ++critical; }
void rtos_critical_exit(uint32_t id) { assert(id == 3 && critical == 1); --critical; }
void rtos_time_delay_ms(uint32_t ms) {
    assert(ms == 1 && !critical && nan_tx_closed && nan_tx_users == 1);
    ++waits; nan_tx_users = 0; /* in-flight TX returns while stopper sleeps */
}
void __real_rtw_nan_start_api(uint8_t p, uint8_t b, uint8_t c) {
    assert(p == 112 && b == 1 && c == 1 && !critical); ++starts; nanpriv[2350] = 3;
}
void __real_rtw_nan_stop_api(void) {
    assert(nan_tx_closed && !nan_tx_users && !critical); ++stops; nanpriv[2350] = 0;
}
void wifi_if_send_skb(int iface, struct sk_buff *s) {
    assert(s->len && !critical);
    if (iface == 2) assert(!nan_tx_closed && nan_tx_users == 1);
    ++sends;
}
void dev_kfree_skb_any(struct sk_buff *s) { assert(s->len); ++frees; }
static void *queue = (void *)456;
int rtos_mutex_take(rtos_mutex_t m, uint32_t wait) { assert(m == (void *)123); assert(wait == 0xffffffff); ++locks; return 0; }
void rtos_mutex_give(rtos_mutex_t m) { assert(m == (void *)123 && locks == 1); --locks; }
uint8_t *rtw_nan_peer_info_get_by_ndi(const uint8_t *ndi) { assert(ndi == packet); return available ? peer : NULL; }
uint8_t *rtw_sta_get_mlmepriv(uint8_t i, const uint8_t *a) { assert(i == 2 && a == peer+67); return station_exists ? station+248 : NULL; }
void *rtw_get_pendingqueue(uint8_t i) { assert(i == 2); return queue; }
void wifi_hal_pending_queue_free(void *q, void *sta) { assert(locks == 1 && q == queue && sta == station); ++flushes; skbpriv.skb_buff_used = 7; }
void __real_rtw_nan_ndi_sec_stainfo_free(uint8_t *p, uint8_t *e) { assert(p == peer && e == entry && locks == 0); ++native_calls; }
int main(void) {
    uint8_t mac[6] = {2,3,4,5,6,7};
    memcpy(packet, mac, 6); memcpy(peer+67, mac, 6); memcpy(entry+14, mac, 6);
    station[248+242] = 9;
    uint8_t *link = entry; memcpy(peer+24, &link, sizeof(link));
    link = peer+24; memcpy(entry, &link, sizeof(link));
    void *lock = (void *)123; memcpy(peer+32, &lock, sizeof(lock));
    struct sk_buff skb = {(void *)2, sizeof(packet), packet};
    assert(!green2_nan_data_tx_allowed(&skb));
    entry[435] = 0x10; assert(green2_nan_data_tx_allowed(&skb));
    entry[428] = 10; assert(!green2_nan_data_tx_allowed(&skb));
    entry[428] = 11; assert(!green2_nan_data_tx_allowed(&skb));
    entry[428] = 0;
    entry[14] ^= 2; assert(!green2_nan_data_tx_allowed(&skb));
    memcpy(entry+429, mac, 6); assert(green2_nan_data_tx_allowed(&skb));
    skbpriv.skb_buff_used = 150;
    __wrap_rtw_nan_ndi_sec_stainfo_free(peer, entry);
    assert(flushes == 1 && native_calls == 1 && skbpriv.skb_buff_used == 7 && !locks);
    assert(hw_drops == 1 && hw_releases == 1 && !blocked_txbd && hw_discard);
    assert(nan_retired_macids == (1u << 9));
    __wrap_wifi_hal_nan_macid_pause(9); assert(hw_pauses == 0);
    __wrap_wifi_hal_nan_macid_pause(10); assert(hw_pauses == 1);
    __wrap_wifi_hal_nan_macid_pause(255); assert(hw_pauses == 2);
    key_result = 0;
    assert(!__wrap_rtw_nan_pairwise_key_set(peer, packet, peer+67));
    assert(hw_discard && hw_restores == 0);
    key_result = 1;
    assert(__wrap_rtw_nan_pairwise_key_set(peer, packet, peer+67));
    assert(!hw_discard && hw_restores == 1 && !nan_retired_macids);
    __wrap_wifi_hal_nan_macid_pause(9); assert(hw_pauses == 3);
    assert(__wrap_rtw_nan_pairwise_key_set(peer, packet, peer+67));
    assert(hw_restores == 1); /* Do not modify unrelated/native MACID state. */
    entry[429] ^= 2;
    __wrap_rtw_nan_ndi_sec_stainfo_free(peer, entry);
    assert(flushes == 1 && native_calls == 2); /* Distinct NDI uses native teardown. */
    memcpy(entry+14, mac, 6); station_exists = 0;
    __wrap_rtw_nan_ndi_sec_stainfo_free(peer, entry);
    assert(flushes == 1 && native_calls == 3);
    available = 0; assert(!green2_nan_data_tx_allowed(&skb));
    packet[0] |= 1; assert(green2_nan_data_tx_allowed(&skb));
    packet[0] &= ~1; skb.dev = (void *)0; assert(green2_nan_data_tx_allowed(&skb));
    assert(!locks);
    skb.dev = (void *)2; available = 1;
    green2_nan_xmit_skb(&skb); assert(frees == 1 && sends == 0); /* closed before start */
    __wrap_rtw_nan_start_api(112, 1, 1);
    green2_nan_xmit_skb(&skb); assert(sends == 1 && !nan_tx_users);
    __wrap_rtw_nan_start_api(112, 1, 1); assert(starts == 2 && !nan_tx_closed);
    nan_tx_users = 1;
    __wrap_rtw_nan_stop_api(); assert(stops == 1 && waits == 1);
    green2_nan_xmit_skb(&skb); assert(frees == 2 && sends == 1);
    skb.dev = (void *)0;
    green2_nan_xmit_skb(&skb); assert(sends == 2); /* other interfaces unaffected */
    assert(!locks && !critical && !nan_tx_users);
}
''')
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-variable', '-fsanitize=address,undefined',
                            str(root/'test.c'), '-o', str(root/'test')], check=True)
            subprocess.run([str(root/'test')], check=True)

if __name__ == '__main__':
    unittest.main()
