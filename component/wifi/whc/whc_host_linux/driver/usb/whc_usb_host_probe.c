// SPDX-License-Identifier: GPL-2.0-only
/*
 * Realtek wireless local area network IC driver.
 *
 * Copyright(c) 2024 Realtek Corporation. All rights reserved.
 */
#include <whc_host_linux.h>
#include <linux/spi/spi.h>
#include <linux/of_gpio.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include "whc_usb_host.h"
#include "whc_host_log_fwd.h"


#define RTK_USB_VID							0x0BDA
#define RTK_USB_PID_DPLUS						0x8722
#define RTK_USB_PID_GREEN2_NIC					0x8006
#define RTK_USB_PID_GREEN2_IOT					0xF851

#ifdef CONFIG_AMEBADPLUS
#define RTW_WHC_WIFI_EP_BULK_IN 						0x03U
#else //GREEN2
#define RTW_WHC_WIFI_EP_BULK_IN 						0x04U
#endif

#define RTW_WHC_WIFI_EP2_BULK_OUT						0x02U
#define RTW_WHC_WIFI_EP4_BULK_OUT						0x04U
#define RTW_WHC_WIFI_EP5_BULK_OUT						0x05U
#define RTW_WHC_WIFI_EP6_BULK_OUT						0x06U
#define RTW_WHC_WIFI_EP7_BULK_OUT						0x07U

#if defined(CONFIG_AMEBAGREEN2) && defined(CONFIG_NAN)
/* Video bursts and overlapping NDP teardown/setup need more in-flight
 * requests. Keep the 1600-byte wire format; the firmware sizes its skb pool
 * separately and applies congestion control before exhausting RX buffers. */
#define RTW_USB_RXQ_NUM						64U
#define RTW_USB_TXQ_NUM						128U
#else
#define RTW_USB_RXQ_NUM						0x0AU
#define RTW_USB_TXQ_NUM						0x20U
#endif


static struct usb_device_id whc_usb_ids[] = {
	{USB_DEVICE(RTK_USB_VID, RTK_USB_PID_DPLUS)},
	{USB_DEVICE(RTK_USB_VID, RTK_USB_PID_GREEN2_IOT)},
	{USB_DEVICE(RTK_USB_VID, RTK_USB_PID_GREEN2_NIC)},
	{}
};

MODULE_DEVICE_TABLE(usb, whc_usb_ids);
struct whc_usb whc_usb_host_priv = {0};
/* This driver has one global WHC instance, including its request arrays. */
static DEFINE_MUTEX(whc_usb_binding_lock);

static bool whc_usb_is_wifi_interface(struct usb_interface *intf)
{
	struct usb_host_interface *alt = intf->cur_altsetting;
	bool bulk_in = false, bulk_out = false;
	int i;

	/* The VID/PID match also covers BT HCI/SCO and optional Ethernet.
	 * Reject those before touching the global Wi-Fi state, even if Wi-Fi
	 * has already bound. Keep matching by endpoints for older firmware. */
	for (i = 0; i < alt->desc.bNumEndpoints; i++) {
		struct usb_endpoint_descriptor *ep = &alt->endpoint[i].desc;
		u8 num = usb_endpoint_num(ep);

		if (!usb_endpoint_xfer_bulk(ep)) {
			continue;
		}
		if (usb_endpoint_dir_in(ep) && num == RTW_WHC_WIFI_EP_BULK_IN) {
			bulk_in = true;
		} else if (usb_endpoint_dir_out(ep)) {
#ifdef CONFIG_AMEBADPLUS
			if (num == RTW_WHC_WIFI_EP4_BULK_OUT || num == RTW_WHC_WIFI_EP2_BULK_OUT)
#else
			if (num == RTW_WHC_WIFI_EP5_BULK_OUT || num == RTW_WHC_WIFI_EP6_BULK_OUT || num == RTW_WHC_WIFI_EP7_BULK_OUT)
#endif
			{
				bulk_out = true;
			}
		}
	}

	return bulk_in && bulk_out;
}

int whc_usb_host_init(struct whc_usb *priv, struct usb_interface *intf)
{
	struct usb_interface_descriptor	*desc;
	struct usb_endpoint_descriptor *endpoint;
	struct usb_device *usb;
	u32 num_of_eps;
	u8 endpoint_num, ep;
	u8 cnt = 0;

	desc = &intf->cur_altsetting->desc;
	num_of_eps = desc->bNumEndpoints;
	usb = interface_to_usbdev(intf);
	for (ep = 0; ep < num_of_eps; ep++) {
		endpoint = &intf->cur_altsetting->endpoint[ep].desc;
		endpoint_num = usb_endpoint_num(endpoint);
		if (!usb_endpoint_xfer_bulk(endpoint)) {
			continue;
		}

		if (usb_endpoint_dir_in(endpoint) && (endpoint_num == RTW_WHC_WIFI_EP_BULK_IN)) {
			priv->rx_pipe = usb_rcvbulkpipe(usb, endpoint_num);
		} else if (usb_endpoint_dir_out(endpoint)) {
#ifdef CONFIG_AMEBADPLUS
			if (endpoint_num == RTW_WHC_WIFI_EP4_BULK_OUT || endpoint_num == RTW_WHC_WIFI_EP2_BULK_OUT)
#else //GREEN2
			if (endpoint_num == RTW_WHC_WIFI_EP5_BULK_OUT || endpoint_num == RTW_WHC_WIFI_EP6_BULK_OUT || endpoint_num == RTW_WHC_WIFI_EP7_BULK_OUT)
#endif
			{
				priv->tx_pipe[cnt++] = usb_sndbulkpipe(usb, endpoint_num);
				priv->tx_mps = usb_endpoint_maxp(endpoint);
			}
		}
	}
	return true;
}

void whc_usb_host_deinit(struct whc_usb *priv)
{
	int i;

	priv->rx_pipe = 0;
	for (i = 0; i < WIFI_OUT_EP_NUM_TOTAL; i++) {
		priv->tx_pipe[i] = 0;
	}
}

static int whc_usb_host_trx_resource_init(struct list_head *q, int qsize, int pre_submit, u8 is_tx)
{
	int i;
	struct rtw_usbreq *req, *reqs;
	struct sk_buff	*skb;
	struct whc_usb *priv = &whc_usb_host_priv;
	int ret;

	reqs = kzalloc(qsize * sizeof(struct rtw_usbreq), GFP_ATOMIC);
	if (reqs == NULL) {
		return false;
	}
	if (is_tx) {
		priv->txreqs = (struct rtw_usbreq *)reqs;
	} else {
		priv->rxreqs = (struct rtw_usbreq *)reqs;
	}

	req = reqs;

	for (i = 0; i < qsize; i++) {
		req->urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!req->urb) {
			goto qinit_fail;
		}

		if (pre_submit) {
			skb = dev_alloc_skb(WHC_USB_RX_MAX_BUF_SIZE);
			if (!skb) {
				goto qinit_fail;
			}
			req->skb = skb;

		}
		INIT_LIST_HEAD(&req->list);
		list_add_tail(&req->list, q);

		req++;
	}

	/* Allocate everything before any completion can run. On failure the
	 * probe unwind kills submitted URBs before freeing the owning array. */
	if (pre_submit) {
		for (i = 0; i < qsize; i++) {
			req = &reqs[i];
			usb_fill_bulk_urb(req->urb, priv->usb_dev, priv->rx_pipe,
							  ((struct sk_buff *)req->skb)->data, WHC_USB_RX_MAX_BUF_SIZE, whc_usb_host_rx_complete, req);

			ret = usb_submit_urb(req->urb, GFP_ATOMIC);
			if (ret) {
				printk("submit rx urb fail=%d\n", ret);
				goto qinit_fail;
			}
		}
	}

	return true;
qinit_fail:
	return false;
}

void whc_usb_host_quiesce(struct whc_usb *priv)
{
	int i;

	WRITE_ONCE(priv->usb_disconnecting, 1);
	wake_up_all(&priv->txreq_wq);
	/* Wait for a submitter that passed the initial gate. All send paths
	 * recheck after acquiring this mutex, so no new URB can follow the kills. */
	mutex_lock(&priv->lock);
	if (priv->txreqs) {
		for (i = 0; i < RTW_USB_TXQ_NUM; i++) {
			usb_kill_urb(priv->txreqs[i].urb);
		}
	}
	if (priv->rxreqs) {
		for (i = 0; i < RTW_USB_RXQ_NUM; i++) {
			usb_kill_urb(priv->rxreqs[i].urb);
		}
	}
	mutex_unlock(&priv->lock);

	/* RX is the producer of API work. Drain it before cancelling the work;
	 * both can dereference netdev/wiphy, which must still be alive here. */
	if (global_idev.recv_priv.initialized) {
		whc_host_recv_deinit();
	}
#ifdef CONFIG_WHC_WIFI_API_PATH
	if (global_idev.host_init_done) {
		cancel_work_sync(&global_idev.event_priv.api_work);
	}
#endif
}

static void whc_usb_host_free_requests(struct whc_usb *priv)
{
	int i;

	/* quiesce() has joined every completion, including busy TX requests that
	 * are absent from tx_freeq. Never free an RX DMA buffer before killing it. */
	if (priv->txreqs) {
		for (i = 0; i < RTW_USB_TXQ_NUM; i++) {
			usb_free_urb(priv->txreqs[i].urb);
		}
		kfree(priv->txreqs);
		priv->txreqs = NULL;
	}
	if (priv->rxreqs) {
		for (i = 0; i < RTW_USB_RXQ_NUM; i++) {
			usb_free_urb(priv->rxreqs[i].urb);
			dev_kfree_skb_any(priv->rxreqs[i].skb);
		}
		kfree(priv->rxreqs);
		priv->rxreqs = NULL;
	}
	INIT_LIST_HEAD(&priv->tx_freeq);
	INIT_LIST_HEAD(&priv->rx_freeq);
	skb_queue_purge(&priv->rxnode_list);
}

static int whc_usb_host_init_phase2(struct whc_usb *priv)
{
	if (whc_usb_host_trx_resource_init(&priv->tx_freeq, RTW_USB_TXQ_NUM, 0, 1) != true) {
		return false;
	}

	if (whc_usb_host_trx_resource_init(&priv->rx_freeq, RTW_USB_RXQ_NUM, 1, 0) != true) {
		return false;
	}

	return true;
}

static int whc_usb_host_probe(struct usb_interface *intf, const struct usb_device_id *id_table)
{
	int i;
	int id_cnt = sizeof(whc_usb_ids) / sizeof(struct usb_device_id);
	struct whc_usb *priv = &whc_usb_host_priv;
	struct usb_device *usb = interface_to_usbdev(intf);
	int status = -ENODEV;

	if (!whc_usb_is_wifi_interface(intf)) {
		return -ENODEV;
	}

	printk("rtw usb probe start\n");
	for (i = 0; i < id_cnt; i++) {
		if ((id_table->idVendor == whc_usb_ids[i].idVendor) &&
			(id_table->idProduct == whc_usb_ids[i].idProduct)) {
			break;
		}
	}
	if (i == id_cnt) {
		printk("USB device descriptor not match\n");
		return -ENODEV;
	}

	mutex_lock(&whc_usb_binding_lock);
	if (priv->dev) {
		mutex_unlock(&whc_usb_binding_lock);
		return -EBUSY;
	}
	memset(priv, 0, sizeof(struct whc_usb));
	mutex_init(&(priv->lock));
	spin_lock_init(&priv->usb_qlock);
	spin_lock_init(&priv->usb_rxskb_lock);
	atomic_set(&priv->tx_inflight, 0);
	init_waitqueue_head(&priv->txreq_wq);
	INIT_LIST_HEAD(&priv->tx_freeq);
	INIT_LIST_HEAD(&priv->rx_freeq);
	skb_queue_head_init(&priv->rxnode_list);

	priv->usb_dev = usb;
	priv->dev = &usb->dev;

	usb_set_intfdata(intf, (void *)priv);

	dev_info(priv->dev, "whc_usb_host_probe: vendor=0x%04x product=0x%04x\n", id_table->idVendor, id_table->idProduct);
	dev_info(priv->dev, "USB bulk buffers: RX=%u TX-limit=%u bytes\n",
			 WHC_USB_RX_MAX_BUF_SIZE, WHC_USB_TX_MAX_BUF_SIZE);
	dev_info(priv->dev, "USB request pools: RX=%u TX=%u\n",
			 RTW_USB_RXQ_NUM, RTW_USB_TXQ_NUM);

	if (whc_usb_host_init(priv, intf) != true) {
		dev_err(priv->dev, "%s: initialize usb Failed!\n", __FUNCTION__);
		goto exit;
	}

#ifdef CONFIG_FW_DOWNLOAD
	/* Try firmware download first, without submitting any RX URBs */
	status = whc_usb_xfer_download(priv);
	if (status == 0) {
		/* Image downloaded, device will reset and re-enumerate */
		dev_info(priv->dev, "Firmware downloaded, waiting for re-enumeration\n");
		whc_usb_host_deinit(priv);
		usb_set_intfdata(intf, NULL);
		priv->dev = NULL;
		priv->usb_dev = NULL;
		mutex_unlock(&whc_usb_binding_lock);
		return 0;
	} else if (status < 0) {
		dev_err(priv->dev, "%s: fw download fail\n", __FUNCTION__);
		goto exit;
	}
	/* status == 1: firmware ready, continue to normal init */
#endif

	if (whc_usb_host_init_phase2(priv) != true) {
		status = -ENOMEM;
		goto exit;
	}

	device_wakeup_enable(&usb->dev);

	status = rtw_netdev_probe(priv->dev);
	if (status) {
		goto exit;
	}
	priv->netdev_registered = true;
	mutex_unlock(&whc_usb_binding_lock);
	return 0;

exit:
	usb_set_intfdata(intf, NULL);
	whc_usb_host_quiesce(priv);
	whc_usb_host_free_requests(priv);
	whc_usb_host_deinit(priv);
	priv->dev = NULL;
	priv->usb_dev = NULL;
	mutex_unlock(&whc_usb_binding_lock);
	return status;
}

static void whc_usb_host_disconnect(struct usb_interface *intf)
{
	struct whc_usb *priv;

	printk("%s\n", __func__);

	mutex_lock(&whc_usb_binding_lock);
	priv = usb_get_intfdata(intf);
	if (!priv) {
		mutex_unlock(&whc_usb_binding_lock);
		return; /* firmware-download interface, or a probe that unwound */
	}
	usb_set_intfdata(intf, NULL);
	if (priv->netdev_registered) {
		rtw_netdev_remove(priv->dev);
		priv->netdev_registered = false;
	} else {
		whc_usb_host_quiesce(priv);
	}
	whc_usb_host_free_requests(priv);
	whc_usb_host_deinit(priv);
	priv->dev = NULL;
	priv->usb_dev = NULL;
	mutex_unlock(&whc_usb_binding_lock);
}

static int whc_usb_host_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct whc_usb *priv = &whc_usb_host_priv;
	struct rtw_usbreq *req, *next;

	/* disable log fwd before killing RX URBs; otherwise device wakes host via usbd_wake_host() */
	if (whc_host_log_forward_pause()) {
		return -EAGAIN;
	}

	/* set wowlan_state, stop schedule rx/tx work */
	global_idev.wowlan_state = 1;
	netif_tx_stop_all_queues(global_idev.pndev[0]);
	if (atomic_read(&priv->tx_inflight)) {
		netif_tx_start_all_queues(global_idev.pndev[0]);
		netif_tx_wake_all_queues(global_idev.pndev[0]);
		goto FAIL;
	}

	req = NULL;
	list_for_each_entry_safe(req, next, &priv->rx_freeq, list) {
		if (!req->urb) {
			break;
		}

		usb_kill_urb(req->urb);
	}

	return 0;

FAIL:
	(void)whc_host_log_forward_resume();
	netif_tx_start_all_queues(global_idev.pndev[0]);
	netif_tx_wake_all_queues(global_idev.pndev[0]);
	global_idev.wowlan_state = 0;
	return -1;
}

static int whc_usb_host_resume(struct usb_interface *intf)
{
	struct whc_usb *priv = &whc_usb_host_priv;
	struct rtw_usbreq *req = NULL, *next;
	struct sk_buff	*skb;
	int ret = 0;

	list_for_each_entry_safe(req, next, &priv->rx_freeq, list) {
		if (!req->urb) {
			break;
		}

		skb = req->skb;
		usb_fill_bulk_urb(req->urb, priv->usb_dev, priv->rx_pipe,
						  skb->data, WHC_USB_RX_MAX_BUF_SIZE, whc_usb_host_rx_complete, req);

		ret = usb_submit_urb(req->urb, GFP_ATOMIC);
		if (ret) {
			printk("resume submit urb fail\n");
		}
	}

	netif_tx_start_all_queues(global_idev.pndev[0]);
	netif_tx_wake_all_queues(global_idev.pndev[0]);

	global_idev.wowlan_state = 0;

	(void)whc_host_log_forward_resume();

	return 0;
}

static struct usb_driver whc_usb_host_driver = {
	.name = "WHC_USB",
	.probe = whc_usb_host_probe,
	.disconnect = whc_usb_host_disconnect,
	.id_table = whc_usb_ids,
	.suspend = whc_usb_host_suspend,
	.resume = whc_usb_host_resume,
	.soft_unbind = 1,
};

static int __init whc_usb_host_init_module(void)
{
	int ret = 0;

	printk("%s\n", __func__);

	/* Probe may run synchronously in usb_register(). Its unwind/removal can
	 * drain the address work, so initialize it before registering the bus. */
	rtw_inetaddr_notifier_register();
	ret = usb_register(&whc_usb_host_driver);
	if (ret != 0) {
		printk("usb register driver Failed!\n");
		rtw_inetaddr_notifier_unregister();
	}

	return ret;
}

static void __exit whc_usb_host_cleanup_module(void)
{
	rtw_inetaddr_notifier_unregister();

	usb_deregister(&whc_usb_host_driver);
}

module_init(whc_usb_host_init_module);
module_exit(whc_usb_host_cleanup_module);

MODULE_AUTHOR("Realtek");
MODULE_DESCRIPTION("RealTek Ameba WHC");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

