#include "usbd.h"
#include "usbd_whc.h"
#include "whc_dev.h"
#if (defined(CONFIG_BT) && CONFIG_BT) && (defined(CONFIG_BT_INIC_USB) && CONFIG_BT_INIC_USB)
#include "bt_inic.h"
#endif

struct whc_usb_priv_t whc_usb_priv = {0};
static volatile u8 whc_usb_configured;
static volatile u8 whc_usb_reconfigure;
static volatile u8 whc_usb_should_configure;
static volatile u32 whc_usb_generation;

#ifdef GREEN2_NAN_USB_RX_RESERVE
#include "whc_dev_nan_usb_control.h"
/* The USB OUT buffers and Wi-Fi RX/TX share skbpriv. A stalled NAN TX queue
 * must not consume the last RX buffers or hold all three USB OUT endpoints:
 * both PASN reception and host control replies would then be starved.
 */
static u32 nan_usb_congestion_drops;
static u32 nan_usb_drop_log_ms;

static int whc_usb_nan_control(const struct whc_msg_info *msg, u32 length)
{
	u32 offset = sizeof(*msg);
	if (length < offset || msg->pad_len > length - offset) {
		return 0;
	}
	offset += msg->pad_len;
	if (msg->data_len > length - offset) {
		return 0;
	}
	return green2_nan_usb_control_frame((const u8 *)msg + offset, msg->data_len);
}

static void whc_usb_nan_record_drop(void)
{
	u32 now = rtos_time_get_current_system_time_ms();
	nan_usb_congestion_drops++;
	if ((u32)(now - nan_usb_drop_log_ms) >= 1000) {
		nan_usb_drop_log_ms = now;
		/* The USB IRQ task has a small stack: avoid newlib printf here. */
		RTK_LOGS(NOTAG, RTK_LOG_INFO, "[NANUSB] congestion drops=%u skb_free=%d\n",
				 nan_usb_congestion_drops,
				 skbpriv.skb_buff_num - skbpriv.skb_buff_used);
	}
}
#endif

u8 wifi_whc_usb_status = WIFI_WHC_USB_STATUS_ACTIVE;

static const usbd_config_t whc_usb_wifi_cfg = {
	.isr_priority = 4,
#if defined (CONFIG_AMEBAGREEN2)
	.rx_fifo_depth = 292U,
	.ptx_fifo_depth = {16U, 256U, 32U, 256U, 128U, },
#endif
};

/* host->device */
static int whc_usb_dev_rx_done_cb(usbd_whc_ep_t *out_ep, u32 len)
{
	usb_ep_info_t *info = &out_ep->ep.info;
	if (info->addr == WIFI_WHC_USB_BULKOUT_1 || info->addr == WIFI_WHC_USB_BULKOUT_2
		|| info->addr == WIFI_WHC_USB_BULKOUT_3) {
		if (!whc_usb_configured) {
			return RTK_SUCCESS;
		}
		if ((whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.intr_widx] == 0) &&
			(whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.intr_widx] == 0)) {
			whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.intr_widx] = info->addr;
			whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.intr_widx] = len;
			whc_usb_priv.irq_info.intr_widx = (whc_usb_priv.irq_info.intr_widx + 1) % WIFI_WHC_USB_BULKOUT_EP_NUM;
			rtos_sema_give(whc_usb_priv.usb_irq_sema);
		} else {
			usbd_whc_receive_data(info->addr, out_ep->ep.xfer_buf, USB_BUFSZ, NULL);
			RTK_LOGS(NOTAG, RTK_LOG_WARN, "rx cb list full, drop this message!\n");
		}
	}
#if defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB)
	else if (info->addr == USBD_WHC_BT_EP_BULK_OUT) {
		return bt_inic_usb_hci_acl_hdl(out_ep->ep.xfer_buf, len);
	}
#endif
	return RTK_SUCCESS;
}

#ifdef WHCH_TXAGG
static int whch_usb_dev_txagg_pool_init(void)
{
	struct whch_usb_txbuf *txbuf = &whc_usb_priv.usb_rxbuf;
	struct whch_buff *buff;
	int i;
	int ret = 0;

	INIT_LIST_HEAD(&txbuf->usb_rxbuf_list);
	txbuf->usb_rxbuff_num = 0;

	txbuf->usb_rxbuff_pool = (struct whch_buff *)rtos_mem_zmalloc(WHCH_USB_RXBUF_NUM * sizeof(struct whch_buff));
	if (!txbuf->usb_rxbuff_pool) {
		ret = -1;
		goto err;
	}

	for (i = 0; i < WHCH_USB_RXBUF_NUM; i++) {
		buff = &txbuf->usb_rxbuff_pool[i];
		buff->buf = (unsigned char *)rtos_mem_zmalloc(USB_BUFSZ);
		if (!buff->buf) {
			ret = -1;
			goto err;
		}
		INIT_LIST_HEAD(&buff->list);
		list_add_tail(&buff->list, &txbuf->usb_rxbuf_list);
		txbuf->usb_rxbuff_num++;
	}
	goto exit;

err:
	if (txbuf->usb_rxbuff_pool) {
		for (i = 0; i < WHCH_USB_RXBUF_NUM; i++) {
			buff = &txbuf->usb_rxbuff_pool[i];
			if (buff && buff->buf) {
				rtos_mem_free((u8 *)buff->buf);
			} else {
				break;
			}
		}
		rtos_mem_free((u8 *)txbuf->usb_rxbuff_pool);
	}

exit:
	return ret;
}

static struct whch_buff *whch_usb_dev_txagg_buf_alloc(void)
{
	struct whch_usb_txbuf *txbuf = &whc_usb_priv.usb_rxbuf;
	struct whch_buff *buff = NULL;

	rtos_critical_enter(RTOS_CRITICAL_WIFI);
	if (!list_empty(&txbuf->usb_rxbuf_list)) {
		buff = list_first_entry(&txbuf->usb_rxbuf_list, struct whch_buff, list);
		list_del_init(&buff->list);
		txbuf->usb_rxbuff_num--;
	}
	rtos_critical_exit(RTOS_CRITICAL_WIFI);

	return buff;
}

static int whch_usb_dev_txagg_config_rxbuf(u8 ep_idx)
{
	struct whch_buff *buff = whch_usb_dev_txagg_buf_alloc();

	if (!buff) {
		return -1;
	}

	whc_usb_priv.cur_rxbuff[ep_idx] = buff;
	buff->status = 0;
	buff->agg_num = 0;
	usbd_whc_receive_data(EPIDX_TO_NUM(ep_idx), buff->buf, USB_BUFSZ, NULL);

	return 0;
}

int whch_usb_dev_txagg_buf_num(void)
{
	struct whch_usb_txbuf *txbuf = &whc_usb_priv.usb_rxbuf;

	return txbuf->usb_rxbuff_num;
}

void whch_usb_dev_txagg_buf_busy(struct whch_buff *buff, u8 delivered, u8 agg_num)
{
	struct whch_usb_txbuf *txbuf = &whc_usb_priv.usb_rxbuf;
	u32 undelivered;

	rtos_critical_enter(RTOS_CRITICAL_WIFI);
	undelivered = (agg_num >= 32) ? 0xFFFFFFFFU : ((1U << agg_num) - 1U);
	undelivered &= (delivered < 32) ? ~((1U << delivered) - 1U) : 0U;
	buff->status &= ~undelivered;

	if (buff->status == 0) {
		list_add_tail(&buff->list, &txbuf->usb_rxbuf_list);
		txbuf->usb_rxbuff_num++;
	}

	rtos_critical_exit(RTOS_CRITICAL_WIFI);
}

void whch_usb_dev_txagg_buff_free(u32 idx, u8 pktidx)
{
	struct whch_buff *buff;

	if (idx >= (u32)WHCH_USB_RXBUF_NUM) {
		return;
	}
	buff = &whc_usb_priv.usb_rxbuf.usb_rxbuff_pool[idx];

	buff->status &= ~(1U << pktidx);
	if (buff->status == 0) {
		list_add_tail(&buff->list, &whc_usb_priv.usb_rxbuf.usb_rxbuf_list);
		whc_usb_priv.usb_rxbuf.usb_rxbuff_num++;
		whc_usb_dev_trigger_rx_handle();
	}
}

static void whch_usb_dev_txagg_rx_handle(void)
{
	struct whc_msg_info *msg_info;
	u32 event;
	u16 len;
	u8 ep_num;
	u32 generation = whc_usb_generation;

	while (whc_usb_configured && generation == whc_usb_generation &&
		   (whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.task_ridx] != 0) &&
		   (whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.task_ridx] != 0)) {
		struct whch_buff *buff;
		struct whch_buff *new_buff;
		u32 buffidx;
		u8 ep_idx;

		ep_num = whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.task_ridx];
		len = whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.task_ridx];
		ep_idx = EPNUM_TO_IDX(ep_num);
		buff = whc_usb_priv.cur_rxbuff[ep_idx];

		if (!buff) {
			/* no buffer was armed on this EP: drop the spurious completion and move on */
			whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.task_ridx] = 0;
			whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.task_ridx] = 0;
			whc_usb_priv.irq_info.task_ridx = (whc_usb_priv.irq_info.task_ridx + 1) % (WIFI_WHC_USB_BULKOUT_EP_NUM);
			continue;
		}

		event = *(u32 *)buff->buf;
		if (event != WHC_WIFI_EVT_XIMT_PKTS) {
			/* non-TX event: copy it out and reuse this buffer to re-arm the EP (like non-AGG) */
			whc_dev_dispatch_event_copy(buff->buf, len);
			new_buff = buff;
		} else {
			new_buff = whch_usb_dev_txagg_buf_alloc();
			if (!new_buff) {
				RTK_LOGD(NOTAG, "%s %d alloc new buff fail!\n", __func__, __LINE__);
				whc_usb_priv.irq_info.wait_xmit_skb = 1;
				break;
			}

			msg_info = (struct whc_msg_info *)buff->buf;

			buffidx = (u32)(buff - whc_usb_priv.usb_rxbuf.usb_rxbuff_pool);
			whch_dev_txagg_dispatch(buff, buffidx, buff->buf, len, msg_info->agg_num);
		}

		/* consume the completed transfer */
		whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.task_ridx] = 0;
		whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.task_ridx] = 0;
		whc_usb_priv.irq_info.task_ridx = (whc_usb_priv.irq_info.task_ridx + 1) % (WIFI_WHC_USB_BULKOUT_EP_NUM);

		/* re-arm this endpoint with the reserved buffer */
		whc_usb_priv.cur_rxbuff[ep_idx] = new_buff;
		new_buff->status = 0;
		new_buff->agg_num = 0;
		rtos_critical_enter(RTOS_CRITICAL_USB);
		if (whc_usb_configured && generation == whc_usb_generation) {
			usbd_whc_receive_data(EPIDX_TO_NUM(ep_idx), new_buff->buf, USB_BUFSZ, NULL);
		}
		rtos_critical_exit(RTOS_CRITICAL_USB);
	}

	for (u8 i = 0; i < WIFI_WHC_USB_BULKOUT_EP_NUM; i++) {
		if (whc_usb_configured && generation == whc_usb_generation && !whc_usb_priv.cur_rxbuff[i]) {
			whch_usb_dev_txagg_config_rxbuf(i);
		}
	}
}
#endif /* WHCH_TXAGG */

/* SET_CONFIGURATION/clear_config run in the USB ISR. The IRQ worker owns
 * the RX buffers: let an interrupted RX dispatch finish transferring skb
 * ownership before clearing the ring and rearming the new configuration.
 * Reusing these buffers also avoids leaking one skb per OUT EP per reconnect.
 */
static void whc_usb_dev_apply_config(void)
{
	u8 i;
	rtos_critical_enter(RTOS_CRITICAL_USB);
	if (!whc_usb_reconfigure) {
		rtos_critical_exit(RTOS_CRITICAL_USB);
		return;
	}
	whc_usb_reconfigure = 0;
	memset(whc_usb_priv.irq_info.rxdone_epnum, 0, sizeof(whc_usb_priv.irq_info.rxdone_epnum));
	memset(whc_usb_priv.irq_info.len, 0, sizeof(whc_usb_priv.irq_info.len));
	whc_usb_priv.irq_info.intr_widx = 0;
	whc_usb_priv.irq_info.task_ridx = 0;
	whc_usb_priv.irq_info.wait_xmit_skb = 0;
	if (whc_usb_should_configure) {
		for (i = 0; i < WIFI_WHC_USB_BULKOUT_EP_NUM; i++) {
#ifdef WHCH_TXAGG
			struct whch_buff *buff = whc_usb_priv.cur_rxbuff[i];
			if (buff) {
				buff->status = 0;
				buff->agg_num = 0;
				usbd_whc_receive_data(EPIDX_TO_NUM(i), buff->buf, USB_BUFSZ, NULL);
			} else {
				whch_usb_dev_txagg_config_rxbuf(i);
			}
#else
			struct sk_buff *skb = (struct sk_buff *)whc_usb_priv.rx_skb_addr[i];
			usbd_whc_receive_data(EPIDX_TO_NUM(i), skb->data, USB_BUFSZ, NULL);
#endif
		}
		whc_usb_configured = 1;
	}
	rtos_critical_exit(RTOS_CRITICAL_USB);
}

static void whc_usb_dev_irq_task(void)
{
	struct whc_txbuf_info_t *whc_txbuf;
#ifndef WHCH_TXAGG
	u32 generation;
	struct sk_buff *new_skb = NULL;
	struct sk_buff *skb_rcv = NULL;
	struct whc_msg_info *msg_info;
	u32 event = 0;
	u16 len = 0;
	u8 ep_num = 0;
#endif
	do {
		rtos_sema_take(whc_usb_priv.usb_irq_sema, MUTEX_WAIT_TIMEOUT);
		// tx callback
		whc_txbuf = NULL;
		rtos_critical_enter(RTOS_CRITICAL_USB);
		if (whc_usb_priv.irq_info.txdone != 0) {
			whc_txbuf = (struct whc_txbuf_info_t *)whc_usb_priv.tx_buf;
			whc_usb_priv.irq_info.txdone = 0;  // clear tx done flag
			whc_usb_priv.tx_buf = NULL;
		}
		rtos_critical_exit(RTOS_CRITICAL_USB);
		if (whc_txbuf) {
			whc_dev_free_txbuf(whc_txbuf);
			rtos_sema_give(whc_usb_priv.usb_tx_sema);
		}
		whc_usb_dev_apply_config();
#ifndef WHCH_TXAGG
		generation = whc_usb_generation;
#endif
		//rx callback
#ifdef WHCH_TXAGG
		whch_usb_dev_txagg_rx_handle();
#else
		while (whc_usb_configured && generation == whc_usb_generation &&
			   (whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.task_ridx] != 0) &&
			   (whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.task_ridx] != 0)) {

			ep_num = whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.task_ridx];
			skb_rcv = (struct sk_buff *)whc_usb_priv.rx_skb_addr[EPNUM_TO_IDX(ep_num)];
			len = whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.task_ridx];

			event = *(u32 *)skb_rcv->data;

			if (event != WHC_WIFI_EVT_XIMT_PKTS) {
				whc_dev_dispatch_event_copy(skb_rcv->data, len);
				new_skb = skb_rcv;  // not need to malloc new skb
			} else {
				msg_info = (struct whc_msg_info *)skb_rcv->data;
#ifdef GREEN2_NAN_USB_RX_RESERVE
				/* Reserve RX headroom even for short JPEG DATA fragments;
				 * only identified control traffic may use this headroom. */
				if (msg_info->wlan_idx == NAN_WLAN_INDEX &&
					(skbpriv.skb_buff_num - skbpriv.skb_buff_used) < 16 &&
					!whc_usb_nan_control(msg_info, len)) {
					/* No skb offsets have changed yet. Reuse this OUT buffer;
					 * dropping one data packet keeps control/RX progressing. */
					whc_usb_nan_record_drop();
					new_skb = skb_rcv;
					goto rearm_rx;
				}
#endif
				if (((skbpriv.skb_buff_num - skbpriv.skb_buff_used) < 2) ||
					((new_skb = dev_alloc_skb(USB_BUFSZ, USB_SKB_RSVD_LEN)) == NULL)) {
#ifdef GREEN2_NAN_USB_RX_RESERVE
					if (msg_info->wlan_idx == NAN_WLAN_INDEX) {
						whc_usb_nan_record_drop();
						new_skb = skb_rcv;
						goto rearm_rx;
					}
#endif
					whc_usb_priv.irq_info.wait_xmit_skb = 1;
					break;
				}
				skb_reserve(skb_rcv, sizeof(struct whc_msg_info));

				skb_put(skb_rcv, msg_info->data_len);
				skb_rcv->dev = (void *)((u32)msg_info->wlan_idx);
				whc_dev_event_int_hdl((u8 *)msg_info, skb_rcv);
				whc_usb_priv.rx_skb_addr[EPNUM_TO_IDX(ep_num)] = (u8 *)new_skb;
			}

#ifdef GREEN2_NAN_USB_RX_RESERVE
rearm_rx:
#endif
			whc_usb_priv.irq_info.rxdone_epnum[whc_usb_priv.irq_info.task_ridx] = 0;
			whc_usb_priv.irq_info.len[whc_usb_priv.irq_info.task_ridx] = 0;
			whc_usb_priv.irq_info.task_ridx = (whc_usb_priv.irq_info.task_ridx + 1) % (WIFI_WHC_USB_BULKOUT_EP_NUM);
			rtos_critical_enter(RTOS_CRITICAL_USB);
			if (whc_usb_configured && generation == whc_usb_generation) {
				usbd_whc_receive_data(ep_num, new_skb->data, USB_BUFSZ, NULL);
			}
			rtos_critical_exit(RTOS_CRITICAL_USB);
		}
#endif

	} while (1);
}

/* device->host  .transmitted*/
static void whc_usb_dev_tx_done_cb(usbd_whc_ep_t *in_ep, u8 status)
{
	UNUSED(status);
	usb_ep_info_t *info = &in_ep->ep.info;
	if (info->addr == WIFI_WHC_USB_BULKIN_EP) {
		if (whc_usb_priv.irq_info.txdone == 0) {
			whc_usb_priv.irq_info.txdone = 1;
			rtos_sema_give(whc_usb_priv.usb_irq_sema);
		} else {
			RTK_LOGS(NOTAG, RTK_LOG_ERROR, "irq task not process last tx done!\n");
		}
	}
#if defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB)
	else if (info->addr == USBD_WHC_BT_EP_INTR_IN) {
		bt_inic_usb_evt_txdone_cb(in_ep->ep.xfer_buf);
	} else if (info->addr == USBD_WHC_BT_EP_BULK_IN) {
		bt_inic_usb_acl_txdone_cb(in_ep->ep.xfer_buf);
	}
#endif
}

void whc_usb_dev_status_changed_cb(u8 old_status, u8 new_status)
{
	UNUSED(old_status);
	if (new_status == USBD_ATTACH_STATUS_ATTACHED) {
		wifi_whc_usb_status = WIFI_WHC_USB_STATUS_ACTIVE;

#if defined (CONFIG_AMEBAGREEN2)
		/* acquire lock */
		whc_dev_ps_resume_cb();
#endif

	} else if (new_status == USBD_ATTACH_STATUS_DETACHED) {
#if defined(CONFIG_USBD_WHC_HOTPLUG)
		wifi_whc_usb_status = WIFI_WHC_USB_STATUS_DISABLED;
#else
		wifi_whc_usb_status = WIFI_WHC_USB_STATUS_SUSPEND;
#endif

#if defined (CONFIG_AMEBAGREEN2)
		/* release lock */
		whc_dev_ps_set_tickps_cmd(WHC_CMD_TICKPS_R);
#endif
	}

#if defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB)
	bt_inic_status_change_cb(old_status, new_status);
#endif
#if defined(CONFIG_USBD_WHC_HOTPLUG)
	rtos_sema_give(whc_usb_priv.usb_attach_status_sema);
#endif
}

/* Endpoints have already been stopped by the class before clear_config.
 * Cancelled IN transfers do not get a completion callback from the USB core.
 * Wake the worker to retire their buffer and release the one TX token. */
static void whc_usb_dev_request_config(u8 configure)
{
	rtos_critical_enter(RTOS_CRITICAL_USB);
	whc_usb_configured = 0;
	whc_usb_generation++;
	whc_usb_should_configure = configure;
	whc_usb_reconfigure = 1;
	if (whc_usb_priv.tx_buf) {
		whc_usb_priv.irq_info.txdone = 1;
	}
	rtos_critical_exit(RTOS_CRITICAL_USB);
	rtos_sema_give(whc_usb_priv.usb_irq_sema);
}

int whc_usb_dev_rxbuf_config_cb(void)
{
	whc_usb_dev_request_config(1);
#if defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB)
	bt_inic_set_config();
#endif
	return HAL_OK;
}

static int whc_usb_dev_init_cb(void)
{
	int ret = HAL_OK;

#ifndef WHCH_TXAGG
	/* Allocate once in task context, before enumeration can enable DMA. */
	for (u8 i = 0; i < WIFI_WHC_USB_BULKOUT_EP_NUM; i++) {
		struct sk_buff *skb = dev_alloc_skb(USB_BUFSZ, USB_SKB_RSVD_LEN);
		if (!skb) {
			while (i) {
				i--;
				dev_kfree_skb_any((struct sk_buff *)whc_usb_priv.rx_skb_addr[i]);
				whc_usb_priv.rx_skb_addr[i] = NULL;
			}
			return HAL_ERR_MEM;
		}
		whc_usb_priv.rx_skb_addr[i] = (u8 *)skb;
	}
#endif

#ifdef WHCH_TXAGG
	if (whch_usb_dev_txagg_pool_init() != 0) {
		RTK_LOGS(NOTAG, RTK_LOG_ERROR, "whch txagg pool init fail\n");
		return -1;
	}

	if (rtw_xmit_txagg_skb_pool_init() != 0) {
		RTK_LOGS(NOTAG, RTK_LOG_ERROR, "whch txagg skb pool init fail\n");
		return -1;
	}
#endif

#if defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB)
	if (usbd_whc_is_bt_en()) {
		ret = bt_inic_usb_init();
	}
#endif
	return ret;
}

static int whc_usb_dev_deinit_cb(void)
{
#ifndef WHCH_TXAGG
	struct sk_buff *skb_rcv = NULL;
#endif
	struct whc_txbuf_info_t *whc_txbuf = NULL;
	u8 i;
	whc_usb_configured = 0;

	// free tx buffer
	if (whc_usb_priv.tx_buf) {
		whc_txbuf = (struct whc_txbuf_info_t *)whc_usb_priv.tx_buf;

		if (whc_txbuf->is_skb) {
			dev_kfree_skb_any((struct sk_buff *) whc_txbuf->ptr);
		} else {
			rtos_mem_free((u8 *)whc_txbuf->ptr);
		}

		rtos_mem_free((u8 *)whc_txbuf);

		whc_usb_priv.tx_buf = NULL;
		whc_usb_priv.irq_info.txdone = 0;
		rtos_sema_give(whc_usb_priv.usb_tx_sema);
	}

	// free rx skb
#ifdef WHCH_TXAGG
	for (i = 0; i < WIFI_WHC_USB_BULKOUT_EP_NUM; i++) {
		whc_usb_priv.cur_rxbuff[i] = NULL;
		whc_usb_priv.irq_info.rxdone_epnum[i] = 0;
		whc_usb_priv.irq_info.len[i] = 0;
	}
	if (whc_usb_priv.usb_rxbuf.usb_rxbuff_pool) {
		for (i = 0; i < WHCH_USB_RXBUF_NUM; i++) {
			if (whc_usb_priv.usb_rxbuf.usb_rxbuff_pool[i].buf) {
				rtos_mem_free(whc_usb_priv.usb_rxbuf.usb_rxbuff_pool[i].buf);
			}
		}
		rtos_mem_free((u8 *)whc_usb_priv.usb_rxbuf.usb_rxbuff_pool);
		whc_usb_priv.usb_rxbuf.usb_rxbuff_pool = NULL;
	}
	rtw_xmit_txagg_skb_pool_deinit();
#else
	for (i = 0; i < WIFI_WHC_USB_BULKOUT_EP_NUM; i++) {
		skb_rcv = (struct sk_buff *)whc_usb_priv.rx_skb_addr[i];
		dev_kfree_skb_any((struct sk_buff *) skb_rcv);
		whc_usb_priv.rx_skb_addr[i] = NULL;
		whc_usb_priv.irq_info.rxdone_epnum[i] = 0;
		whc_usb_priv.irq_info.len[i] = 0;
	}
#endif

	whc_usb_priv.irq_info.intr_widx = 0;
	whc_usb_priv.irq_info.task_ridx = 0;

#if defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB)
	if (usbd_whc_is_bt_en()) {
		bt_inic_usb_deinit();
	}
#endif

	return HAL_OK;
}

static int whc_usb_dev_setup_cb(usb_setup_req_t *req, u8 *buf)
{
#if !(defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB))
	UNUSED(buf);
#endif
	int ret = HAL_ERR_PARA;
	switch (req->bRequest) {
#if defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB)
	case USBD_WHC_VENDOR_REQ_BT_HCI_CMD:
		ret = bt_inic_usb_hci_cmd_hdl(buf, req->wLength);
		break;
#endif
	default:
		/* Unsupported request, let the core stall EP0 as per USB 2.0 9.2.7 */
		break;
	}
	return ret;
}

static int whc_usb_dev_clear_config_cb(void)
{
	whc_usb_dev_request_config(0);
#if defined(CONFIG_BT) && defined(CONFIG_BT_INIC_USB)
	bt_inic_clear_config();
#endif
	return HAL_OK;
}

static const usbd_whc_cb_t whc_usb_dev_cb = {
	.init = whc_usb_dev_init_cb,
	.deinit = whc_usb_dev_deinit_cb,
	.setup = whc_usb_dev_setup_cb,
	.set_config = whc_usb_dev_rxbuf_config_cb,
	.clear_config = whc_usb_dev_clear_config_cb,
	.received = whc_usb_dev_rx_done_cb,
	.transmitted = whc_usb_dev_tx_done_cb,
	.status_changed = whc_usb_dev_status_changed_cb,
};

#if defined(CONFIG_USBD_WHC_HOTPLUG)
static void whc_usb_hotplug_task(void)
{
	do {
		rtos_sema_take(whc_usb_priv.usb_attach_status_sema, 0xFFFFFFFF);
		if (wifi_whc_usb_status == WIFI_WHC_USB_STATUS_DISABLED) {
			RTK_LOGS(NOTAG, RTK_LOG_INFO, "DETACHED, so reboot\n");
			rtos_time_delay_ms(20);
			System_Reset();
		} else if (wifi_whc_usb_status == WIFI_WHC_USB_STATUS_ACTIVE) {
			RTK_LOGS(NOTAG, RTK_LOG_INFO, "ATTACHED\n");
		}
	} while (1);

	rtos_task_delete(NULL);
}
#endif // CONFIG_USBD_WHC_HOTPLUG

void whc_usb_dev_init(void)
{
	int ret;

#ifndef WHCH_TXAGG
	RTK_LOGI(TAG_WLAN_INIC, "USB bulk RX capacity=%u, SKB capacity=%d, reserve=%u\n",
			 (unsigned int)USB_BUFSZ, skbpriv.skb_buf_max_size, (unsigned int)USB_SKB_RSVD_LEN);
	if (USB_BUFSZ + USB_SKB_RSVD_LEN > (u32)skbpriv.skb_buf_max_size) {
		RTK_LOGE(TAG_WLAN_INIC, "USB RX capacity exceeds SKB pool; refusing DMA init\n");
		return;
	}
#endif

#if defined(CONFIG_AMEBAGREEN2) && CONFIG_AMEBAGREEN2 && defined(CONFIG_BT_INIC_USB) && CONFIG_BT_INIC_USB
	/* btusb can send HCI Reset before WHC's host-side Wi-Fi-on request.
	 * Initialize both radios before starting the USB core, independent of
	 * the order in which the host binds the composite interfaces. */
	if (!wifi_is_running(STA_WLAN_INDEX)) {
		ret = wifi_on(RTW_MODE_STA);
		if (ret != RTK_SUCCESS || !wifi_is_running(STA_WLAN_INDEX)) {
			RTK_LOGE(TAG_WLAN_INIC, "Wi-Fi init failed (%d); USB not started\n", ret);
			return;
		}
	}
	RTK_LOGI(TAG_WLAN_INIC, "Wi-Fi ready before USB\n");
	if (bt_inic_usb_prepare() != HAL_OK) {
		RTK_LOGE(TAG_WLAN_INIC, "BT init failed; USB not started\n");
		return;
	}
	RTK_LOGI(TAG_WLAN_INIC, "BT controller ready before USB\n");
#endif
	rtos_mutex_create_static(&whc_usb_priv.tx_lock);
	rtos_sema_create_static(&whc_usb_priv.usb_tx_sema, 1, 0xFFFFFFFF);
	rtos_sema_create_static(&whc_usb_priv.usb_irq_sema, 0, 0xFFFFFFFF);

#if defined(CONFIG_USBD_WHC_HOTPLUG)
	rtos_sema_create_static(&whc_usb_priv.usb_attach_status_sema, 0, 1);
	if (RTK_SUCCESS != rtos_task_create(NULL, (const char *const)"whc_usb_hotplug_task", (rtos_task_function_t)whc_usb_hotplug_task,
										NULL, 1024, 8)) {
		RTK_LOGI(NOTAG, "Create whc_usb_hotplug_task Err!!\n");
	}
#endif

	if (RTK_SUCCESS != rtos_task_create(NULL, (const char *const)"whc_usb_dev_irq_task", (rtos_task_function_t)whc_usb_dev_irq_task,
										NULL, 512, 1)) {
		RTK_LOGI(NOTAG, "Create whc_usb_dev_irq_task Err!!\n");
	}

	/* All callbacks must be ready before the host can configure USB. */
	ret = usbd_init(&whc_usb_wifi_cfg);
	if (ret != HAL_OK) {
		RTK_LOGE(TAG_WLAN_INIC, "USBdevice init fail!\n");
		return;
	}

	ret = usbd_whc_init(&whc_usb_dev_cb);
	if (ret != HAL_OK) {
		RTK_LOGE(TAG_WLAN_INIC, "USB whc init fail!\n");
		usbd_deinit();
		return;
	}

#if defined (CONFIG_AMEBAGREEN2)
	usbd_cg_register();
	SOCPS_SetAPWakeEvent(WAKE_SRC_USB, ENABLE);
#endif

	RTK_LOGI(TAG_WLAN_INIC, "USB device init done!\n");
}

/*wifi recv pkt, send to host*/
void whc_usb_dev_send(u8 *buf, u16 len, void *buf_alloc, u8 is_skb)
{
	int i = 0;
	int ret;
	u32 generation = whc_usb_generation;
	struct whc_txbuf_info_t *buf_info = NULL;
	struct whc_buf_info *pbuf;

	/* Wi-Fi startup can report netif information before USB is available.
	 * The host's Wi-Fi-on request will replay that information. */
	if (!whc_usb_configured) {
		goto drop;
	}

	buf_info = whc_dev_alloc_buf_info(buf, len, buf_alloc, is_skb);
	if (!buf_info) {
		goto drop;
	}
	pbuf = &buf_info->txbuf_info;

	if (wifi_whc_usb_status == WIFI_WHC_USB_STATUS_SUSPEND) {
		RTK_LOGS(NOTAG, RTK_LOG_ALWAYS, "DEV Send when suspend\n");
		usbd_wake_host();

		/* confirm host already resumed before send data to host*/
		for (i = 0; i < WIFI_WHC_USB_WAKE_HOST_MAX_WAIT_CNT; i++) {
			rtos_time_delay_ms(WIFI_WHC_USB_WAKE_HOST_UNIT);
			if (wifi_whc_usb_status == WIFI_WHC_USB_STATUS_ACTIVE) {
				break;
			}
		}
	}

	rtos_mutex_take(whc_usb_priv.tx_lock, MUTEX_WAIT_TIMEOUT);

	rtos_sema_take(whc_usb_priv.usb_tx_sema, MUTEX_WAIT_TIMEOUT);
	/* clear_config can run while either wait above blocks. Do not submit
	 * a previous session's event into the newly configured endpoint. */
	rtos_critical_enter(RTOS_CRITICAL_USB);
	ret = HAL_ERR_HW;
	if (whc_usb_configured && generation == whc_usb_generation) {
		whc_usb_priv.tx_buf = (u8 *)buf_info;
		ret = usbd_whc_transmit_data((u8)WIFI_WHC_USB_BULKIN_EP,
									(u8 *)pbuf->buf_addr, (u16)pbuf->buf_size, NULL);
		if (ret != HAL_OK) {
			whc_usb_priv.tx_buf = NULL;
		}
	}
	rtos_critical_exit(RTOS_CRITICAL_USB);
	if (ret != HAL_OK) {
		rtos_sema_give(whc_usb_priv.usb_tx_sema);
		rtos_mutex_give(whc_usb_priv.tx_lock);
		goto drop;
	}

	rtos_mutex_give(whc_usb_priv.tx_lock);

	return;

drop:
	/* buf_info owns both its payload and metadata when allocation succeeded. */
	if (buf_info) {
		whc_dev_free_txbuf(buf_info);
		return;
	}
	if (is_skb) {
		dev_kfree_skb_any((struct sk_buff *) buf_alloc);
	} else {
		rtos_mem_free((u8 *)buf_alloc);
	}
}

u8 whc_usb_dev_bus_is_idle(void)
{
	/*Not yet implemented*/
	return TRUE;
}

void whc_usb_dev_trigger_rx_handle(void)
{
	if (whc_usb_priv.irq_info.wait_xmit_skb == 1) {
		whc_usb_priv.irq_info.wait_xmit_skb = 0;
		rtos_sema_give(whc_usb_priv.usb_irq_sema);
	}
}

