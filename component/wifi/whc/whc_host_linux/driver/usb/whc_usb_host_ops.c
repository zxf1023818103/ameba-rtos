// SPDX-License-Identifier: GPL-2.0-only
/*
 * Realtek wireless local area network IC driver.
 *
 * Copyright(c) 2024 Realtek Corporation. All rights reserved.
 */
#include <whc_host_linux.h>

struct rtw_usbreq *whc_usb_host_dequeue(struct list_head *q, int *counter)
{
	struct whc_usb *priv = &whc_usb_host_priv;
	unsigned long flags;
	struct rtw_usbreq  *req;

	spin_lock_irqsave(&priv->usb_qlock, flags);
	if (list_empty(q)) {
		spin_unlock_irqrestore(&priv->usb_qlock, flags);
		return NULL;
	}
	req = list_entry(q->next, struct rtw_usbreq, list);
	list_del(&req->list);
	if (counter) {
		(*counter)--;
	}
	spin_unlock_irqrestore(&priv->usb_qlock, flags);

	return req;

}
void whc_usb_host_enqueue(struct list_head *q, struct rtw_usbreq *req, int *counter)
{
	struct whc_usb *priv = &whc_usb_host_priv;
	unsigned long flags;

	spin_lock_irqsave(&priv->usb_qlock, flags);
	list_add_tail(&req->list, q);
	if (counter) {
		(*counter)++;
	}
	spin_unlock_irqrestore(&priv->usb_qlock, flags);
}

static void whc_usb_host_tx_complete_cb(struct urb *urb)
{
	struct whc_usb *priv = &whc_usb_host_priv;
	struct rtw_usbreq *req = (struct rtw_usbreq *)urb->context;

	if (urb->status != 0) {
		if (!READ_ONCE(priv->usb_disconnecting)) {
			printk("tx urb sts=%d\n", urb->status);
		}
		/* An error/cancellation still completes this request and owns skb. */
	}

	if (req->skb) {
#ifdef WHCH_TXAGG
		if (req->is_txagg) {
			whc_host_xmitbuf_free(req->skb);
		} else
#endif
		{
			if (!req->is_buf) {
				dev_kfree_skb_any(req->skb);
			} else {
				kfree(req->skb);
			}
		}
	}

	req->skb = NULL;
	req->is_buf = 0;
#ifdef WHCH_TXAGG
	req->is_txagg = 0;
#endif
	whc_usb_host_enqueue(&priv->tx_freeq, req, NULL);
	atomic_dec(&priv->tx_inflight);
	priv->txreq_available = 1;
	wake_up(&priv->txreq_wq);

	//USB_TODO: check free urb count, may netif wake queue
}

void whc_usb_host_send_data(u8 *buf, u32 len, struct sk_buff *pskb)
{
#ifdef CONFIG_INIC_USB_ASYNC_SEND
	struct whc_usb *priv = &whc_usb_host_priv;
	struct rtw_usbreq *req;
	int ret = 0;

	if (len > WHC_USB_TX_MAX_BUF_SIZE) {
		printk("usb send data size overflow!\n");
		len = WHC_USB_TX_MAX_BUF_SIZE;
	}

	if (READ_ONCE(priv->usb_disconnecting)) {
		if (pskb) {
			dev_kfree_skb(pskb);
		} else {
			kfree(buf);
		}
		return;
	}
	mutex_lock(&priv->lock);

dequeue_again:
	if (READ_ONCE(priv->usb_disconnecting)) {
		goto exit_free_buf;
	}
	req = whc_usb_host_dequeue(&priv->tx_freeq, NULL);
	if (req == NULL) {
		priv->txreq_available = 0;
		if (!wait_event_timeout(priv->txreq_wq,
			priv->txreq_available == 1 || READ_ONCE(priv->usb_disconnecting), msecs_to_jiffies(500))) {
			printk("wait txreq available timeout\n");
			goto exit_free_buf;
		} else {
			goto dequeue_again;
		}
	}
	if (pskb) {
		req->skb = pskb;
		req->is_buf = 0;
	} else {
		req->skb = buf;
		req->is_buf = 1;
	}

	req->urb->transfer_flags |= URB_ZERO_PACKET;
	usb_fill_bulk_urb(req->urb, priv->usb_dev, priv->tx_pipe[priv->out_pipe_idx],
					  buf, len, whc_usb_host_tx_complete_cb, req);
	priv->out_pipe_idx = (priv->out_pipe_idx + 1) % WIFI_OUT_EP_NUM_TOTAL;
	/* Completion can run before usb_submit_urb returns. */
	atomic_inc(&priv->tx_inflight);
	ret = usb_submit_urb(req->urb, GFP_ATOMIC);
	if (ret) {
		atomic_dec(&priv->tx_inflight);
		printk("%s: Failed to resubmit TX URB: %d\n", __func__, ret);
		req->skb = NULL;
		req->is_buf = 0;
		whc_usb_host_enqueue(&priv->tx_freeq, req, NULL);
		goto exit_free_buf;
	}
	mutex_unlock(&priv->lock);
	return;

exit_free_buf:
	if (pskb) {
		dev_kfree_skb(pskb);
	} else {
		kfree(buf);
	}
	mutex_unlock(&priv->lock);
#else
	struct whc_usb *priv = &whc_usb_host_priv;
	int actual_len = 0;
	char *zlp_buf;

	if (READ_ONCE(priv->usb_disconnecting)) {
		return;
	}

	if (len > WHC_USB_TX_MAX_BUF_SIZE) {
		printk("usb send data size overflow!\n");
		len = WHC_USB_TX_MAX_BUF_SIZE;
	}

	mutex_lock(&priv->lock);
	if (READ_ONCE(priv->usb_disconnecting)) {
		mutex_unlock(&priv->lock);
		return;
	}
	atomic_inc(&priv->tx_inflight);

	usb_bulk_msg(priv->usb_dev, priv->tx_pipe[priv->out_pipe_idx], buf, len, &actual_len, 1000);
	//printk("%s: acutul sen=%d\n", __FUNCTION__, actual_len);
	if (len % priv->tx_mps == 0) {/*send ZLP*/
		zlp_buf = kmalloc(1, GFP_KERNEL);
		usb_bulk_msg(priv->usb_dev, priv->tx_pipe[priv->out_pipe_idx], zlp_buf, 0, &actual_len, 100);
		kfree(zlp_buf);
	}
	atomic_dec(&priv->tx_inflight);
	mutex_unlock(&priv->lock);
#endif
}

#ifdef WHCH_TXAGG
void whc_usb_host_send_xmitbuf(struct whc_xmit_buf *pxmitbuf)
{
	struct whc_usb *priv = &whc_usb_host_priv;
	struct rtw_usbreq *req;
	int ret = 0;
	u8 pipe_idx;
	u32 len = pxmitbuf->len;

	if (len > WHC_USB_TX_MAX_BUF_SIZE) {
		printk("usb send txagg size overflow!\n");
		len = WHC_USB_TX_MAX_BUF_SIZE;
	}

	if (READ_ONCE(priv->usb_disconnecting)) {
		whc_host_xmitbuf_free(pxmitbuf);
		return;
	}
	mutex_lock(&priv->lock);

dequeue_again:
	if (READ_ONCE(priv->usb_disconnecting)) {
		goto exit_free_buf;
	}
	req = whc_usb_host_dequeue(&priv->tx_freeq, NULL);
	if (req == NULL) {
		priv->txreq_available = 0;
		if (!wait_event_timeout(priv->txreq_wq,
			priv->txreq_available == 1 || READ_ONCE(priv->usb_disconnecting), msecs_to_jiffies(500))) {
			printk("wait txreq available timeout\n");
			goto exit_free_buf;
		} else {
			goto dequeue_again;
		}
	}
	req->skb = pxmitbuf;
	req->is_buf = 0;
	req->is_txagg = 1;

	/* one aggregate already spans a single sta+ac queue; no per-frame flow context here, round-robin the EP */
	pipe_idx = priv->out_pipe_idx;
	priv->out_pipe_idx = (priv->out_pipe_idx + 1) % WIFI_OUT_EP_NUM_TOTAL;

	req->urb->transfer_flags |= URB_ZERO_PACKET;
	usb_fill_bulk_urb(req->urb, priv->usb_dev, priv->tx_pipe[pipe_idx],
					  pxmitbuf->pbuf, len, whc_usb_host_tx_complete_cb, req);
	atomic_inc(&priv->tx_inflight);
	ret = usb_submit_urb(req->urb, GFP_ATOMIC);
	if (ret) {
		atomic_dec(&priv->tx_inflight);
		printk("%s: Failed to submit TX URB: %d\n", __func__, ret);
		req->skb = NULL;
		req->is_buf = 0;
		req->is_txagg = 0;
		whc_usb_host_enqueue(&priv->tx_freeq, req, NULL);
		goto exit_free_buf;
	}
	mutex_unlock(&priv->lock);
	return;

exit_free_buf:
	whc_host_xmitbuf_free(pxmitbuf);
	mutex_unlock(&priv->lock);
}
#endif

void whc_usb_host_rx_complete(struct urb *urb)
{
	/*this will run in interrupt, thus just alloc a new skb and put it on usb_req,
	 enqueue the original skb and then notify other task to process */
	struct rtw_usbreq *req;
	struct sk_buff *skb;
	struct sk_buff *skb_copy;
	struct whc_usb *priv = &whc_usb_host_priv;
	int	 ret;
	unsigned long flags;

	req = (struct rtw_usbreq *)urb->context;


	if (urb->status != 0 || READ_ONCE(priv->usb_disconnecting)) {
		return;
	}

	skb = dev_alloc_skb(WHC_USB_RX_MAX_BUF_SIZE);

	if (!skb) {
		printk("cannot alloc skb, drop this packet\n");
		/* Reuse the old buffer to keep RX alive without a NULL dereference. */
		skb = req->skb;
		goto resubmit;
	}

	skb_copy = req->skb;
	req->skb = skb;

	spin_lock_irqsave(&priv->usb_rxskb_lock, flags);
	skb_queue_tail(&priv->rxnode_list, skb_copy);
	spin_unlock_irqrestore(&priv->usb_rxskb_lock, flags);
	//printk("acutul rcv=%d\n", urb->actual_length);
	if (global_idev.host_init_done) {
		whc_host_recv_notify();
	}

resubmit:
	usb_fill_bulk_urb(req->urb, priv->usb_dev, priv->rx_pipe,
					  skb->data, WHC_USB_RX_MAX_BUF_SIZE, whc_usb_host_rx_complete, req);
	ret = usb_submit_urb(req->urb, GFP_ATOMIC);
	if (ret) {
		printk("%s: Failed to resubmit URB: %d\n", __func__, ret);
		return;
	}
}

void whc_usb_host_recv_data(void *intf_priv)
{
	struct whc_usb *priv = (struct whc_usb *)intf_priv;
	struct sk_buff *skb;
	unsigned long flags;
	int budget = 64;

	while (budget--) {
		spin_lock_irqsave(&priv->usb_rxskb_lock, flags);
		skb = skb_dequeue(&priv->rxnode_list);
		spin_unlock_irqrestore(&priv->usb_rxskb_lock, flags);
		if (!skb) {
			break;
		}
		whc_host_recv_dispatch(skb);
	}
}


struct hci_ops_t whc_usb_host_intf_ops = {
	.send_data = whc_usb_host_send_data,
	.recv_data = whc_usb_host_recv_data,
#ifdef WHCH_TXAGG
	.send_xmitbuf = whc_usb_host_send_xmitbuf,
#endif
};

int whc_usb_host_send_event_check(u32 event_id)
{
	struct whc_usb *priv = &whc_usb_host_priv;

	/* Removal drains RX before releasing cfg80211 objects. This applies to
	 * unbind/module removal too; do not wait for replies with RX stopped. */
	if (READ_ONCE(priv->usb_disconnecting)) {
		if (event_id == WHC_API_WIFI_DISCONNECT) {
			whc_host_disconnect_indicate(0, 1, global_idev.bssid);
			complete(&global_idev.mlme_priv.disconnect_done_sema);
		}
		return -1;
	}
	return 0;
}

