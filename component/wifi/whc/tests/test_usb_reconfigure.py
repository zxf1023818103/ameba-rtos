#!/usr/bin/env python3
"""Compile production lifecycle functions with deterministic ISR/RTOS fakes.

Only the selected production functions are copied into the harness; the USB
controller and RTOS are mocked. Physical enumeration remains a hardware test.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

WHC = Path(__file__).resolve().parents[1]


def function(path, name):
    source = path.read_text()
    match = re.search(r'^(?:static )?(?:void|int) ' + name + r'\([^;]*?\)\n\{',
                      source, re.M)
    if not match:
        raise AssertionError(f'Missing production function {name}')
    depth = 1
    end = match.end()
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


def compile_run(source):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / 'test.c').write_text(source)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-int-to-pointer-cast', '-Wno-pointer-to-int-cast',
                        '-I', str(WHC / 'whc_dev/usb'),
                        str(root / 'test.c'), '-o', str(root / 'test')], check=True)
        subprocess.run([str(root / 'test')], check=True, timeout=5)


class USBReconfigureTest(unittest.TestCase):
    def test_nan_netdev_rejects_up_before_successful_start(self):
        source = WHC / 'whc_host_linux/driver/netdev/whc_host_netdev_ops.c'
        compile_run(r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
struct wireless_dev { bool is_running; };
struct net_device { struct wireless_dev *ieee80211_ptr; };
static struct {
    bool netdev_ready;
    struct wireless_dev *pwdev_global[3];
} global_idev;
static unsigned opens;
#define netdev_warn(...) ((void)0)
static int rtw_ndev_open(struct net_device *dev) {
    assert(dev); ++opens; return 0;
}
''' + function(source, 'rtw_ndev_open_nan') + r'''
int main(void) {
    struct wireless_dev nan = {false}, other = {true};
    struct net_device dev = {&nan};
    global_idev.pwdev_global[2] = &nan;
    assert(rtw_ndev_open_nan(&dev) == -ENODEV);
    global_idev.netdev_ready = true;
    /* Before START_NAN, or after a failed START_NAN, an UP must not
     * reach the normal opener or trigger NETDEV_UP accounting. */
    assert(rtw_ndev_open_nan(&dev) == -EAGAIN);
    assert(!nan.is_running && opens == 0);
    nan.is_running = true; /* cfg80211 records successful START_NAN */
    assert(rtw_ndev_open_nan(&dev) == 0 && opens == 1);
    nan.is_running = false; /* stopped NAN must be started again */
    assert(rtw_ndev_open_nan(&dev) == -EAGAIN && opens == 1);
    dev.ieee80211_ptr = &other;
    assert(rtw_ndev_open_nan(&dev) == -ENODEV && opens == 1);
    dev.ieee80211_ptr = NULL;
    assert(rtw_ndev_open_nan(&dev) == -ENODEV && opens == 1);
    return 0;
}
''')

    def test_bt_rx_callback_copies_without_heap_operations(self):
        source = WHC.parents[1] / 'bluetooth/driver/bt_inic/bt_inic_usb.c'
        # Use the actual queue element layout as well as the actual callback.
        layout = re.search(r'struct bt_usb_rx_packet \{.*?\n\};', source.read_text(), re.S)[0]
        compile_run(r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define BT_USB_RX_CAPACITY 512U
#define BT_TIMEOUT_NONE 0
#define HAL_OK 0
#define HAL_ERR_PARA 1
#define HAL_ERR_HW 2
#define HAL_BUSY 3
''' + layout + r'''
static struct { void *rx_queue; } usb_priv = {(void *)1};
static u8 bt_inic_usb_configured = 1;
static u32 bt_inic_usb_generation = 7;
static struct bt_usb_rx_packet saved;
static int full, copies;
static int osif_msg_send(void *q, const void *p, unsigned timeout) {
    assert(q == (void *)1 && timeout == 0);
    if (full) return 0;
    memcpy(&saved, p, sizeof(saved)); ++copies; return 1;
}
''' + function(source, 'bt_inic_usb_queue_rx') + r'''
int main(void) {
    u8 data[513]; memset(data, 0x55, sizeof(data));
    assert(bt_inic_usb_queue_rx(2, data, 512) == HAL_OK);
    memset(data, 0, sizeof(data));
    assert(saved.len == 512 && saved.type == 2 && saved.generation == 7);
    assert(saved.data[0] == 0x55 && saved.data[511] == 0x55);
    assert(bt_inic_usb_queue_rx(2, data, 513) == HAL_ERR_PARA);
    assert(bt_inic_usb_queue_rx(2, 0, 1) == HAL_ERR_PARA);
    full = 1; assert(bt_inic_usb_queue_rx(2, data, 1) == HAL_BUSY);
    bt_inic_usb_configured = 0;
    assert(bt_inic_usb_queue_rx(2, data, 1) == HAL_ERR_HW);
    assert(copies == 1); return 0;
}
''')

    def test_bt_cancel_failed_submit_and_stale_sender(self):
        component = WHC.parents[1]
        usb = component / 'usb/device/whc/usbd_whc.c'
        bt = component / 'bluetooth/driver/bt_inic/bt_inic_usb.c'
        production = ''.join(function(usb, name) for name in (
            'usbd_whc_deinit_ep', 'usbd_whc_transmit_data', 'usbd_whc_handle_ep_data_in'))
        production += ''.join(function(bt, name) for name in (
            'bt_inic_clear_config', 'bt_inic_usb_reclaim_tx', 'bt_inic_usb_evt_txdone_cb',
            'bt_inic_usb_acl_txdone_cb', 'bt_inic_usb_tx_data'))
        compile_run(r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define USB_MAX_ENDPOINTS 8
#define USB_EP_NUM(a) ((a)&0x7f)
#define USB_EP_IS_IN(a) ((a)&0x80)
#define USB_EP_IS_OUT(a) (!USB_EP_IS_IN(a))
#define USBD_WHC_EP_STATE_IDLE 0
#define USBD_WHC_EP_STATE_BUSY 1
#define USBD_WHC_BT_EP_INTR_IN 0x81
#define USBD_WHC_BT_EP_BULK_IN 0x82
#define HAL_OK 0
#define HAL_ERR_HW 1
#define HAL_ERR_PARA 2
#define HAL_ERR_MEM 3
#define HAL_BUSY 4
#define RTK_LOGS(...) ((void)0)
#define BT_DUMPA(...) ((void)0)
#define USB_IS_MEM_DMA_ALIGNED(p) (((uintptr_t)(p)&3) == 0)
#define BT_INIC_USB_STATUS_ACTIVE 0
#define BT_INIC_USB_STATUS_SUSPEND 1
#define BT_INIC_USB_STATUS_DISABLED 2
#define BT_INIC_USB_WAKE_HOST_MAX_WAIT_CNT 10
#define BT_INIC_USB_WAKE_HOST_UNIT 10
#define BT_TIMEOUT_FOREVER 0xffffffff
#define HCI_EVT 4
#define HCI_ACL 2
typedef struct { unsigned is_ready; } usb_dev_t;
typedef struct {
    struct { u8 addr; } info;
    unsigned xfer_state, xfer_len, skip_dcache_pre_clean;
    u8 *xfer_buf;
} usbd_ep_t;
typedef struct { usbd_ep_t ep; void *userdata; } usbd_whc_ep_t;
struct callbacks { void (*transmitted)(usbd_whc_ep_t *, u8); };
typedef struct callbacks usbd_whc_cb_t;
#define UNUSED(x) ((void)(x))
#define USB_DIAG(...) ((void)0)
typedef struct {
    usb_dev_t *dev; struct callbacks *cb;
    usbd_whc_ep_t in_ep[USB_MAX_ENDPOINTS];
} usbd_whc_dev_t;
static usb_dev_t dev = {1};
static usbd_whc_dev_t usbd_whc_dev;
static struct {
    void *evt_tx_lock, *evt_tx_done_sema, *acl_tx_lock, *acl_tx_done_sema, *work_sema;
    u8 *evt_completed, *acl_completed;
} usb_priv;
static volatile u8 bt_inic_usb_configured;
static volatile u32 bt_inic_usb_generation;
static u8 bt_inic_usb_status;
static unsigned flags_locked, freed, submitted, cancelled, completion_status;
static int tokens[2] = {1,1}, fail_submit, switch_while_waiting, dma_running[8];
static void bt_inic_clear_config(void);
static void DCache_Clean(u32 a, u32 n) { (void)a; (void)n; }
static int usbd_ep_transmit(usb_dev_t *d, usbd_ep_t *ep) {
    assert(d == &dev && flags_locked); ++submitted;
    if (fail_submit) return HAL_ERR_HW;
    dma_running[USB_EP_NUM(ep->info.addr)] = 1; return HAL_OK;
}
static void usbd_ep_deinit(usb_dev_t *d, usbd_ep_t *ep) {
    assert(d == &dev); dma_running[USB_EP_NUM(ep->info.addr)] = 0;
}
static void osif_mem_free(void *p) { assert(p); free(p); ++freed; }
static void osif_sem_give(void *s) {
    if (s == usb_priv.work_sema) return;
    int n = s == usb_priv.acl_tx_done_sema; assert(tokens[n] == 0); ++tokens[n];
}
static void osif_sem_take(void *s, unsigned timeout) {
    (void)timeout; int n = s == usb_priv.acl_tx_done_sema;
    assert(tokens[n] == 1); --tokens[n];
}
static void osif_mutex_take(void *p, unsigned timeout) {
    (void)p; (void)timeout;
    if (switch_while_waiting) {
        switch_while_waiting = 0; bt_inic_clear_config();
        bt_inic_usb_configured = 1; ++bt_inic_usb_generation;
    }
}
static void osif_mutex_give(void *p) { (void)p; }
static u32 osif_lock(void) { assert(!flags_locked); ++flags_locked; return 0; }
static void osif_unlock(u32 f) { (void)f; assert(flags_locked); --flags_locked; }
static void osif_delay(unsigned t) { (void)t; }
static void usbd_wake_host(void) {}
''' + production + r'''
static void complete(usbd_whc_ep_t *ep, u8 status) {
    assert(!dma_running[USB_EP_NUM(ep->ep.info.addr)]);
    ++cancelled; completion_status = status;
    if (ep->ep.info.addr == 0x81) bt_inic_usb_evt_txdone_cb(ep->ep.xfer_buf);
    else bt_inic_usb_acl_txdone_cb(ep->ep.xfer_buf);
}
int main(void) {
    struct callbacks cb = {complete};
    usbd_whc_dev.dev = &dev; usbd_whc_dev.cb = &cb;
    usbd_whc_dev.in_ep[1].ep.info.addr = 0x81;
    usbd_whc_dev.in_ep[2].ep.info.addr = 0x82;
    usb_priv.evt_tx_done_sema = (void *)1; usb_priv.acl_tx_done_sema = (void *)2;
    usb_priv.work_sema = (void *)3;
    bt_inic_usb_configured = 1;
    for (int i=0; i<100; ++i) {
        bt_inic_usb_tx_data(HCI_EVT, malloc(16), 16);
        bt_inic_usb_tx_data(HCI_ACL, malloc(16), 16);
        assert(tokens[0] == 0 && tokens[1] == 0);
        usbd_whc_deinit_ep(&dev, &usbd_whc_dev.in_ep[1].ep);
        usbd_whc_deinit_ep(&dev, &usbd_whc_dev.in_ep[2].ep);
        assert(tokens[0] == 0 && tokens[1] == 0 && freed == (unsigned)i*2);
        bt_inic_usb_reclaim_tx();
        assert(tokens[0] == 1 && tokens[1] == 1);
        /* Duplicate clears must not free twice or create an extra token. */
        usbd_whc_deinit_ep(&dev, &usbd_whc_dev.in_ep[1].ep);
        usbd_whc_handle_ep_data_in(&dev, 0x81, HAL_OK);
        usbd_whc_handle_ep_data_in(&dev, 0x82, HAL_OK);
    }
    assert(freed == 200 && cancelled == 200 && completion_status == HAL_ERR_HW);
    fail_submit = 1; bt_inic_usb_tx_data(HCI_EVT, malloc(16), 16);
    assert(freed == 201 && tokens[0] == 1);
    assert(usbd_whc_dev.in_ep[1].ep.xfer_state == USBD_WHC_EP_STATE_IDLE);
    switch_while_waiting = 1; unsigned before = submitted;
    bt_inic_usb_tx_data(HCI_EVT, malloc(16), 16);
    assert(submitted == before && freed == 202 && tokens[0] == 1);
    bt_inic_clear_config(); bt_inic_usb_tx_data(HCI_ACL, malloc(16), 16);
    assert(submitted == before && freed == 203 && tokens[1] == 1);
    return 0;
}
''')

    def test_rx_ownership_tx_cancel_and_generation(self):
        path = WHC / 'whc_dev/usb/whc_usb_dev.c'
        production = ''.join(function(path, name) for name in (
            'whc_usb_dev_apply_config', 'whc_usb_dev_request_config',
            'whc_usb_dev_send', 'whc_usb_dev_irq_task'))
        compile_run(r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef void *rtos_mutex_t;
typedef void *rtos_sema_t;
#define CONFIG_AMEBAGREEN2 1
#define GREEN2_NAN_USB_RX_RESERVE 1
#define NAN_WLAN_INDEX 2
#define CACHE_LINE_SIZE 4
#define MAXIMUM_ETHERNET_PACKET_SIZE 64
#define SKB_WLAN_TX_EXTRA_LEN 16
#define N_BYTE_ALIGMENT(n,a) (((n)+(a)-1)&~((a)-1))
#define USBD_WHC_WIFI_EP_BULK_IN 0x84
#define USBD_WHC_WIFI_EP_BULK_OUT_1 5
#define USBD_WHC_WIFI_EP_BULK_OUT_2 6
#define USBD_WHC_WIFI_EP_BULK_OUT_3 7
#define RTOS_CRITICAL_USB 4
#define HAL_OK 0
#define HAL_ERR_HW 1
#define MUTEX_WAIT_TIMEOUT 0xffffffff
#define WHC_WIFI_EVT_XIMT_PKTS 42
#define RTK_LOGS(...) ((void)0)
#include "whc_usb_dev.h"
struct whc_msg_info { u32 event; u16 data_len; u8 wlan_idx, pad_len; };
struct sk_buff { u8 *data; void *dev; unsigned len; };
struct whc_buf_info { uintptr_t buf_addr; unsigned buf_size; };
struct whc_txbuf_info_t { struct whc_buf_info txbuf_info; void *ptr; u8 is_skb; };
struct { int skb_buff_num, skb_buff_used; } skbpriv = {160, 7};
static struct whc_usb_priv_t whc_usb_priv;
static volatile u8 whc_usb_configured, whc_usb_reconfigure, whc_usb_should_configure;
static volatile u32 whc_usb_generation;
static u8 wifi_whc_usb_status;
static unsigned critical, sends, arms, freed, payload_freed, allocations, stale_arms;
static int wakes, tokens = 1, tx_fail, switch_while_waiting, switch_during_rx;
static int alloc_fail;
static unsigned exhausted_drops;
static void whc_usb_nan_record_drop(void) { ++exhausted_drops; }
static jmp_buf worker_done;
static struct sk_buff *handed_off;
static void whc_usb_dev_request_config(u8);
static void whc_usb_dev_apply_config(void);
static void whc_usb_dev_irq_task(void);
static void worker(void) {
    if (!setjmp(worker_done)) whc_usb_dev_irq_task();
    assert(!critical);
}
static void rtos_critical_enter(unsigned id) { assert(id == 4); ++critical; }
static void rtos_critical_exit(unsigned id) { assert(id == 4 && critical); --critical; }
static void rtos_sema_give(void *s) {
    if (s == whc_usb_priv.usb_tx_sema) { assert(!tokens); ++tokens; }
    else ++wakes;
}
static void rtos_sema_take(void *s, unsigned timeout) {
    (void)timeout;
    assert(!critical);
    if (s == whc_usb_priv.usb_tx_sema) { assert(tokens == 1); --tokens; }
    else if (wakes) --wakes;
    else longjmp(worker_done, 1);
}
static void rtos_mutex_take(void *m, unsigned timeout) {
    (void)m; (void)timeout; assert(!critical);
    if (switch_while_waiting) {
        switch_while_waiting = 0;
        whc_usb_dev_request_config(0); whc_usb_dev_request_config(1); worker();
    }
}
static void rtos_mutex_give(void *m) { (void)m; }
static void usbd_wake_host(void) {}
static void rtos_time_delay_ms(unsigned t) { (void)t; }
static struct sk_buff *dev_alloc_skb(unsigned n, unsigned reserve) {
    (void)reserve;
    if (alloc_fail) return NULL;
    struct sk_buff *s = calloc(1, sizeof(*s)); assert(s);
    s->data = calloc(1, n); assert(s->data); ++allocations; return s;
}
static void dev_kfree_skb_any(struct sk_buff *s) { free(s->data); free(s); ++payload_freed; }
static void rtos_mem_free(void *p) { free(p); ++payload_freed; }
static struct whc_txbuf_info_t *whc_dev_alloc_buf_info(u8 *b, u16 n, void *p, u8 skb) {
    struct whc_txbuf_info_t *v = calloc(1, sizeof(*v)); assert(v);
    v->txbuf_info.buf_addr = (uintptr_t)b; v->txbuf_info.buf_size = n;
    v->ptr = p; v->is_skb = skb; return v;
}
static void whc_dev_free_txbuf(struct whc_txbuf_info_t *v) {
    assert(v); free(v->ptr); free(v); ++freed; ++payload_freed;
}
static int usbd_whc_receive_data(u8 ep, u8 *b, unsigned n, void *p) {
    (void)p; assert(critical && ep >= 5 && ep <= 7 && n == USB_BUFSZ);
    if (handed_off && b == handed_off->data) ++stale_arms;
    ++arms; return 0;
}
static int usbd_whc_transmit_data(u8 ep, u8 *b, u16 n, void *p) {
    (void)p; assert(critical && ep == 0x84 && b && n); ++sends; return tx_fail;
}
static void skb_reserve(struct sk_buff *s, unsigned n) { (void)s; (void)n; }
static void skb_put(struct sk_buff *s, unsigned n) { s->len = n; }
static void whc_dev_event_int_hdl(u8 *m, struct sk_buff *s) {
    (void)m; handed_off = s;
    if (switch_during_rx) {
        switch_during_rx = 0;
        /* USB resets while the worker is handing this skb to Wi-Fi. */
        whc_usb_dev_request_config(0); whc_usb_dev_request_config(1);
    }
}
static void whc_dev_dispatch_event_copy(u8 *b, unsigned n) { (void)b; (void)n; }
''' + production + r'''
int main(void) {
    whc_usb_priv.usb_tx_sema = (void *)1;
    whc_usb_priv.usb_irq_sema = (void *)2;
    for (unsigned i=0; i<3; ++i)
        whc_usb_priv.rx_skb_addr[i] = (u8 *)dev_alloc_skb(USB_BUFSZ, 0);
    for (unsigned i=0; i<1000; ++i) {
        whc_usb_dev_request_config(0); whc_usb_dev_request_config(1); worker();
        assert(whc_usb_configured && allocations == 3 && tokens == 1);
    }
    assert(arms == 3000);
    /* In-flight IN is cancelled: free once and return precisely one token. */
    u8 *p = malloc(16); whc_usb_dev_send(p,16,p,0);
    assert(sends == 1 && tokens == 0);
    whc_usb_dev_request_config(0); whc_usb_dev_request_config(1); worker();
    assert(freed == 1 && tokens == 1 && !whc_usb_priv.tx_buf);
    whc_usb_dev_request_config(0); worker(); assert(tokens == 1 && freed == 1);
    whc_usb_dev_request_config(1); worker();
    /* A sender blocked before disconnect must not submit into a new session. */
    switch_while_waiting = 1; p = malloc(16); whc_usb_dev_send(p,16,p,0);
    assert(sends == 1 && freed == 2 && tokens == 1);
    tx_fail = 1; p = malloc(16); whc_usb_dev_send(p,16,p,0);
    assert(sends == 2 && freed == 3 && tokens == 1 && !whc_usb_priv.tx_buf);
    /* RX dispatch transfers the old skb; configuration must arm its replacement. */
    struct sk_buff *s = (struct sk_buff *)whc_usb_priv.rx_skb_addr[0];
    struct whc_msg_info *m = (void *)s->data;
    m->event = WHC_WIFI_EVT_XIMT_PKTS; m->data_len = 16; m->wlan_idx = 2;
    whc_usb_priv.irq_info.rxdone_epnum[0] = 5; whc_usb_priv.irq_info.len[0] = 32;
    switch_during_rx = 1; wakes = 1; unsigned before = arms; worker();
    assert(allocations == 4 && arms == before + 3 && !stale_arms);
    assert((void *)whc_usb_priv.rx_skb_addr[0] != handed_off);
    assert(whc_usb_configured && whc_usb_priv.irq_info.task_ridx == 0);
    dev_kfree_skb_any(handed_off);
    handed_off = NULL;
    /* The former 16-buffer early-drop watermark must not reject any
     * Ethernet payload, including TCP and either SRT header flag. */
    for (unsigned variant = 0; variant < 4; ++variant) {
        unsigned free_count = variant == 0 ? 15 : 2;
        skbpriv.skb_buff_used = skbpriv.skb_buff_num - free_count;
        s = (struct sk_buff *)whc_usb_priv.rx_skb_addr[0];
        m = (void *)s->data;
        memset(s->data, variant & 1 ? 0x80 : 0, USB_BUFSZ);
        m->event = WHC_WIFI_EVT_XIMT_PKTS; m->data_len = 16; m->wlan_idx = 2;
        whc_usb_priv.irq_info.task_ridx = 0;
        whc_usb_priv.irq_info.rxdone_epnum[0] = 5;
        whc_usb_priv.irq_info.len[0] = 32;
        before = arms; wakes = 1; worker();
        assert(handed_off == s && arms == before + 1 && !exhausted_drops);
        assert((void *)whc_usb_priv.rx_skb_addr[0] != s && !stale_arms);
        dev_kfree_skb_any(handed_off); handed_off = NULL;
    }
    /* Exhaustion and allocator failure must re-arm the same OUT buffer
     * without transferring its ownership or stalling the command path. */
    for (unsigned variant = 0; variant < 3; ++variant) {
        skbpriv.skb_buff_used = skbpriv.skb_buff_num - variant;
        alloc_fail = variant == 2;
        s = (struct sk_buff *)whc_usb_priv.rx_skb_addr[0];
        m = (void *)s->data;
        m->event = WHC_WIFI_EVT_XIMT_PKTS; m->data_len = 16; m->wlan_idx = 2;
        whc_usb_priv.irq_info.task_ridx = 0;
        whc_usb_priv.irq_info.rxdone_epnum[0] = 5;
        whc_usb_priv.irq_info.len[0] = 32;
        before = arms; wakes = 1; worker();
        assert(!handed_off && arms == before + 1 && exhausted_drops == variant + 1);
        assert((void *)whc_usb_priv.rx_skb_addr[0] == s && !stale_arms);
        assert(!whc_usb_priv.irq_info.wait_xmit_skb);
    }
    alloc_fail = 0;
    for (unsigned i=0; i<3; ++i) dev_kfree_skb_any((void *)whc_usb_priv.rx_skb_addr[i]);
    return 0;
}
''')

    def test_nan_reinit_retires_live_session(self):
        production = function(WHC / 'whc_dev/whc_dev_api_path.c', 'whc_event_nan_init')
        compile_run(r'''
#include <assert.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32;
static int live = 1, stopped, initialized, replies;
static void rtw_nan_intfs_deinit(void) { live = 0; ++stopped; }
static void rtw_nan_intfs_init(void) { assert(!live); live = 1; ++initialized; }
static void whc_send_api_ret_value(u32 id, u8 *ret, unsigned n) {
    assert(id == 4 && n == sizeof(int) && *(int *)ret == 0); ++replies;
}
''' + production + r'''
int main(void) {
    for (int i=0; i<100; ++i) whc_event_nan_init(4, 0);
    assert(stopped == 100 && initialized == 100 && replies == 100);
    return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
