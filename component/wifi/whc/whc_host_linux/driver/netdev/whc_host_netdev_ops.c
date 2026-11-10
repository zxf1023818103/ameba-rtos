// SPDX-License-Identifier: GPL-2.0-only
/*
* Realtek wireless local area network IC driver.
*   This is an interface between cfg80211 and firmware in other core. The
*   commnunication between driver and firmware is IPC（Inter Process
*   Communication）bus.
*
* Copyright (C) 2023, Realtek Corporation. All rights reserved.
*/

#include <whc_host_linux.h>
#ifdef CONFIG_WHC_HOST_LOG_FWD
#include "whc_host_log_fwd.h"

static bool log_fwd_enable;
module_param(log_fwd_enable, bool, 0444);
MODULE_PARM_DESC(log_fwd_enable, "Enable FW log forwarding to host (default: 0)");
#endif /* CONFIG_WHC_HOST_LOG_FWD */

static struct work_struct whc_netinfo_update_work;

static void whc_netinfo_update_work_handler(struct work_struct *work)
{
	whc_host_update_ip_addr();
}

/*
 * Set wlan0 mac address: 1) ip link set dev wlan0 down, 2) ip link set dev wlan0 address 86:EF:EB:92:A2:FF, 3) ip link set dev wlan0 up
 * Set wlan1 mac address: 1) ifconfig wlan1 up, 2) ip link set dev wlan0 address 86:EF:EB:92:A2:F0, 3) hostapd /etc/hostapd.conf -B -i wlan1
 * NOTE for Soft AP: when wlan1 down, cannot set mac address. but if mac address changed, need restart hostapd. Recomment to change bssid inside hostapd.conf.
*/
int rtw_ndev_set_mac_address(struct net_device *pnetdev, void *p)
{
	int ret = 0;
#if defined(CONFIG_WHC_WIFI_API_PATH)
	struct sockaddr *addr = p;

	if (rtw_netdev_idx(pnetdev) >= WHC_MAX_NET_PORT_NUM) {
		dev_err(global_idev.pwhc_dev, "Netdevice index err.");
		return -1;
	}

	dev_dbg(global_idev.pwhc_dev,
			"[netdev] %s: set wlan-%d mac addr to [%02x:%02x:%02x:%02x:%02x:%02x]", __func__, rtw_netdev_idx(pnetdev),
			*(u8 *)(addr->sa_data), *(u8 *)(addr->sa_data + 1), *(u8 *)(addr->sa_data + 2), *(u8 *)(addr->sa_data + 3), *(u8 *)(addr->sa_data + 4),
			*(u8 *)(addr->sa_data + 5));

	ret = whc_host_set_mac_addr(rtw_netdev_idx(pnetdev), addr->sa_data);

	if (ret == 0) {
		/* Set mac address success, then change the dev_addr inside net_device. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0))
		memcpy((void *)global_idev.pndev[rtw_netdev_idx(pnetdev)]->dev_addr, addr->sa_data, ETH_ALEN);
#else
		eth_hw_addr_set(global_idev.pndev[rtw_netdev_idx(pnetdev)], addr->sa_data);
#endif
	}
#endif
	return ret;
}

struct net_device_stats *rtw_ndev_get_stats(struct net_device *pnetdev)
{
	dev_dbg(global_idev.pwhc_dev, "[netdev]: %s", __func__);
	return &global_idev.stats[rtw_netdev_idx(pnetdev)];
}

/* Given a data frame determine the 802.1p/1d tag to use. */
static unsigned int rtw_classify8021d(struct sk_buff *skb)
{
	unsigned int dscp;

	/* skb->priority values from 256->263 are magic values to
	 * directly indicate a specific 802.1d priority.  This is used
	 * to allow 802.1d priority to be passed directly in from VLAN
	 * tags, etc.
	 */
	if (skb->priority >= 256 && skb->priority <= 263) {
		return skb->priority - 256;
	}

	switch (skb->protocol) {
	case htons(0x0800):
		dscp = ip_hdr(skb)->tos & 0xfc;
		break;
	default:
		return 0;
	}

	return dscp >> 5;
}

/*
 * AC to queue mapping
 *
 * AC_VO -> queue 0
 * AC_VI -> queue 1
 * AC_BE -> queue 2
 * AC_BK -> queue 3
 */
u16 rtw_ndev_select_queue(struct net_device *pnetdev, struct sk_buff *skb, struct net_device *sb_dev)
{
	/* int acm_mask = 0;*/
	u16 rtw_1d_to_queue[8] = { 2, 3, 3, 2, 1, 1, 0, 0 };

	skb->priority = rtw_classify8021d(skb);

	/* acm_mask != 0 is qos packet. tmp. */
	/*if (acm_mask != 0) {
		skb->priority = qos_acm(acm_mask, skb->priority);
	}*/

	return rtw_1d_to_queue[skb->priority];
}

int rtw_ndev_init(struct net_device *pnetdev)
{
	dev_dbg(global_idev.pwhc_dev, "[whc]: %s %d\n", __func__, rtw_netdev_idx(pnetdev));
#ifdef CONFIG_WHCH
	whc_host_sta_init(rtw_netdev_idx(pnetdev));
	whc_host_hal_pending_q_init(rtw_netdev_idx(pnetdev));
	whc_host_init_default_value(rtw_netdev_idx(pnetdev));
	sema_init(&global_idev.whchpriv.netif_rx_sema[rtw_netdev_idx(pnetdev)], 1);
#endif
	return 0;
}

void rtw_ndev_uninit(struct net_device *pnetdev)
{
	dev_dbg(global_idev.pwhc_dev, "[whc]: %s %d\n", __func__, rtw_netdev_idx(pnetdev));
}

static int rtw_ndev_open(struct net_device *pnetdev)
{
	dev_dbg(global_idev.pwhc_dev, "[whc]: %s %d\n", __func__, rtw_netdev_idx(pnetdev));
	rtw_netdev_priv_is_on(pnetdev) = true;
#ifdef CONFIG_NAN
	if (rtw_netdev_idx(pnetdev) == 2) {
		netif_carrier_on(pnetdev);
	}
#endif
	netif_tx_start_all_queues(pnetdev);
	netif_tx_wake_all_queues(pnetdev);

	return 0;
}

static int rtw_ndev_close(struct net_device *pnetdev)
{
#if defined(CONFIG_WHC_WIFI_API_PATH)
	struct cfg80211_scan_info info;
	int ret = 0;
	u8 is_mp = 0;
#endif

	dev_dbg(global_idev.pwhc_dev, "[whc]: %s %d\n", __func__, rtw_netdev_idx(pnetdev));
#if defined(CONFIG_WHC_WIFI_API_PATH)
	/* Removal has already stopped USB RX. Finish local queue/scan cleanup
	 * even though firmware can no longer acknowledge a scan-abort command. */
	if (global_idev.netdev_ready) {
		whc_host_dev_driver_is_mp(&is_mp);
		if (is_mp != 1) {
			ret = whc_host_scan_abort();
			if (ret) {
				dev_err(global_idev.pwhc_dev, "[whc]: %s abort wifi scan failed!\n", __func__);
				return -EPERM;
			}
		}
	}

	if (global_idev.mlme_priv.pscan_req_global) {
		memset(&info, 0, sizeof(info));
		info.aborted = 1;
		cfg80211_scan_done(global_idev.mlme_priv.pscan_req_global, &info);
		global_idev.mlme_priv.pscan_req_global = NULL;
		global_idev.mlme_priv.b_in_scan = false;
	}
#endif
	netif_tx_stop_all_queues(pnetdev);
#ifdef CONFIG_IEEE80211R
	netif_dormant_on(pnetdev);
#endif
	netif_carrier_off(pnetdev);
	rtw_netdev_priv_is_on(pnetdev) = false;

	return 0;
}

static int rtw_ndev_open_ap(struct net_device *pnetdev)
{
#if defined(CONFIG_WHC_WIFI_API_PATH)
	u8 is_mp = 0;

	dev_dbg(global_idev.pwhc_dev, "[whc]: %s %d\n", __func__, rtw_netdev_idx(pnetdev));

	rtw_netdev_priv_is_on(pnetdev) = true;

	whc_host_dev_driver_is_mp(&is_mp);
	if (is_mp != 1) {
		/* if2 init(SW + part of HW) */
		whc_host_init_ap();
	}

	netif_tx_start_all_queues(pnetdev);
	netif_tx_wake_all_queues(pnetdev);
#elif defined(CONFIG_WHC_HOST_RTW_CLI)
	dev_dbg(global_idev.pwhc_dev, "[whc]: %s %d\n", __func__, rtw_netdev_idx(pnetdev));

	rtw_netdev_priv_is_on(pnetdev) = true;
	netif_carrier_off(pnetdev);
	netif_tx_stop_all_queues(pnetdev);
#endif

	return 0;
}

static int rtw_ndev_close_ap(struct net_device *pnetdev)
{
#if defined(CONFIG_WHC_WIFI_API_PATH)
	struct cfg80211_scan_info info;
	int ret = 0;
	u8 is_mp = 0;

	dev_dbg(global_idev.pwhc_dev, "[whc]: %s %d\n", __func__, rtw_netdev_idx(pnetdev));

	if (global_idev.netdev_ready) {
		whc_host_dev_driver_is_mp(&is_mp);
		if (is_mp != 1) {
			ret = whc_host_scan_abort();
			if (ret) {
				dev_err(global_idev.pwhc_dev, "[whc]: %s abort wifi scan failed!\n", __func__);
				return -EPERM;
			}
		}
	}

	if (global_idev.mlme_priv.pscan_req_global) {
		memset(&info, 0, sizeof(info));
		info.aborted = 1;
		cfg80211_scan_done(global_idev.mlme_priv.pscan_req_global, &info);
		global_idev.mlme_priv.pscan_req_global = NULL;
		global_idev.mlme_priv.b_in_scan = false;
	}

	netif_tx_stop_all_queues(pnetdev);
	netif_carrier_off(pnetdev);

	if (global_idev.netdev_ready && is_mp != 1) {
		/* if2 deinit (SW) */
		whc_host_deinit_ap();
	}
	rtw_netdev_priv_is_on(pnetdev) = false;
#elif defined(CONFIG_WHC_HOST_RTW_CLI)
	dev_dbg(global_idev.pwhc_dev, "[whc]: %s %d\n", __func__, rtw_netdev_idx(pnetdev));

	rtw_netdev_priv_is_on(pnetdev) = false;
	netif_carrier_off(pnetdev);
	netif_tx_stop_all_queues(pnetdev);
#endif
	return 0;
}

enum netdev_tx rtw_xmit_entry(struct sk_buff *skb, struct net_device *pnetdev)
{
	int ret = 0;
	int wlan_idx = 0;

	if (pnetdev) {
		wlan_idx = rtw_netdev_idx(pnetdev);
	} else {
		ret = -EINVAL;
		goto func_exit;
	}

	ret = whc_host_xmit_entry(wlan_idx, skb);

func_exit:
	return ret;
}

static void rtw_set_rx_mode(struct net_device *dev)
{
#if defined(CONFIG_WHC_WIFI_API_PATH)
	if ((rtw_netdev_flags(dev) ^ dev->flags) & IFF_PROMISC) {
		if (dev->flags & IFF_PROMISC) {
			dev_dbg(global_idev.pwhc_dev, "[whc]: %s enable promisc mode!\n", __func__);
			whc_host_set_promisc_enable(1, RTW_PROMISC_FILTER_ALL_PKT);
		} else {
			dev_dbg(global_idev.pwhc_dev, "[whc]: %s disable promisc mode!\n", __func__);
			whc_host_set_promisc_enable(0, RTW_PROMISC_FILTER_ALL_PKT);
		}
	}

	if (rtw_netdev_flags(dev) ^ dev->flags) {
		rtw_netdev_flags(dev) = dev->flags;
	}
#endif
}

static const struct net_device_ops rtw_ndev_ops = {
	.ndo_init = rtw_ndev_init,
	.ndo_uninit = rtw_ndev_uninit,
	.ndo_open = rtw_ndev_open,
	.ndo_stop = rtw_ndev_close,
	.ndo_start_xmit = rtw_xmit_entry,
	.ndo_select_queue = rtw_ndev_select_queue,
	.ndo_set_mac_address = rtw_ndev_set_mac_address,
	.ndo_get_stats = rtw_ndev_get_stats,
	.ndo_set_rx_mode = rtw_set_rx_mode,
};

static const struct net_device_ops rtw_ndev_ops_ap = {
	.ndo_init = rtw_ndev_init,
	.ndo_uninit = rtw_ndev_uninit,
	.ndo_open = rtw_ndev_open_ap,
	.ndo_stop = rtw_ndev_close_ap,
	.ndo_start_xmit = rtw_xmit_entry,
	.ndo_select_queue = rtw_ndev_select_queue,
	.ndo_set_mac_address = rtw_ndev_set_mac_address,
	.ndo_get_stats = rtw_ndev_get_stats,
	.ndo_do_ioctl = NULL,
};

#ifdef CONFIG_NAN
static int rtw_ndev_open_nan(struct net_device *pnetdev)
{
	struct wireless_dev *wdev = pnetdev->ieee80211_ptr;

	if (!global_idev.netdev_ready || !wdev ||
		wdev != global_idev.pwdev_global[2]) {
		return -ENODEV;
	}

	/* cfg80211 normally gives NAN no netdev. With our vendor data netdev,
	 * wdev_running() instead sees IFF_UP: an early UP makes START_NAN fail
	 * with EEXIST before it sets is_running or acquires its open reference.
	 * STOP_NAN/NETDEV_GOING_DOWN can then release a reference never acquired,
	 * leaving wiphy_unregister() waiting forever for opencount == 0.
	 * ndo_open and START_NAN are serialized by RTNL. Only let the data
	 * netdev open after cfg80211 has recorded a successful START_NAN. */
	if (!wdev->is_running) {
		netdev_warn(pnetdev, "START_NAN must succeed before bringing the NAN data interface UP\n");
		return -EAGAIN;
	}

	return rtw_ndev_open(pnetdev);
}

const struct net_device_ops rtw_ndev_ops_nan = {
	.ndo_init = rtw_ndev_init,
	.ndo_uninit = rtw_ndev_uninit,
	.ndo_open = rtw_ndev_open_nan,
	.ndo_stop = rtw_ndev_close,
	.ndo_start_xmit = rtw_xmit_entry,
	.ndo_select_queue = rtw_ndev_select_queue,
	.ndo_set_mac_address = rtw_ndev_set_mac_address,
	.ndo_get_stats = rtw_ndev_get_stats,
};

static void rtw_nan_ndev_destructor(struct net_device *ndev)
{
	/* nl80211_post_doit still uses wdev->netdev after del_virtual_intf
	 * returns. Keep wdev until the netdev's outstanding references drain. */
	kfree(ndev->ieee80211_ptr);
	ndev->ieee80211_ptr = NULL;
}

int rtw_nan_iface_alloc(struct wiphy *wiphy,
						const char *name,
						struct wireless_dev **nan_wdev,
						struct vif_params *params)
{
	struct wireless_dev *wdev = NULL;
	struct net_device *ndev = NULL;
	int ret = 0;
	int softap_addr_offset_idx = global_idev.wifi_user_config.softap_addr_offset_idx;
	unsigned char nan_mac[ETH_ALEN];

	/* Keep this check in the allocator as well as add_virtual_intf: neither
	 * a stale wiphy nor a partially initialized/removed STA can supply a MAC. */
	if (!global_idev.netdev_ready || !wiphy ||
		wiphy != global_idev.pwiphy_global || !global_idev.pwhc_dev ||
		!global_idev.pndev[0]) {
		return -ENODEV;
	}

	if (global_idev.pwdev_global[2] || global_idev.pndev[2]) {
		dev_info(global_idev.pwhc_dev, "%s: nan_wdev already exists", __func__);
		return -EBUSY;
	}

	/* alloc and init netdev */
	ndev = alloc_etherdev_mq(sizeof(struct whc_netdev_priv_t), 1);
	if (!ndev) {
		goto exit;
	}
	global_idev.pndev[2] = ndev;
	rtw_netdev_idx(ndev) = 2;
	memcpy(rtw_netdev_label(ndev), WHC_LABEL, sizeof(WHC_LABEL));
	ndev->netdev_ops = &rtw_ndev_ops_nan;
	ndev->watchdog_timeo = HZ * 3; /* 3 second timeout */
#ifndef CONFIG_WHC_HCI_IPC
	ndev->needed_headroom = max(SIZE_RX_DESC, SIZE_TX_DESC) + sizeof(struct whc_msg_info) + 4;
#endif
	SET_NETDEV_DEV(ndev, global_idev.pwhc_dev);

	netdev_set_default_ethtool_ops(global_idev.pndev[2], &global_idev.rtw_ethtool_ops);
	if (dev_alloc_name(global_idev.pndev[2], "nan0") < 0) {
		dev_err(global_idev.pwhc_dev, "dev_alloc_name, fail!\n");
	}

	netif_carrier_off(global_idev.pndev[2]);
	/* set nan port mac address */
	memcpy(nan_mac, global_idev.pndev[0]->dev_addr, ETH_ALEN);

	if (softap_addr_offset_idx == 0) {
		nan_mac[softap_addr_offset_idx] = global_idev.pndev[0]->dev_addr[softap_addr_offset_idx] + (2 << 1);
	} else {
		nan_mac[softap_addr_offset_idx] = global_idev.pndev[0]->dev_addr[softap_addr_offset_idx] + 2;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0))
	memcpy((void *)global_idev.pndev[2]->dev_addr, nan_mac, ETH_ALEN);
#else
	eth_hw_addr_set(global_idev.pndev[2], nan_mac);
#endif

	ret = (register_netdevice(global_idev.pndev[2]) == 0) ? true : false;
	if (ret != true) {
		dev_err(global_idev.pwhc_dev, "netdevice register fail!\n");
		goto exit;
	}

	/* alloc and init wireless_dev */
	wdev = (struct wireless_dev *)kzalloc(sizeof(struct wireless_dev), in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if (!wdev) {
		dev_err(global_idev.pwhc_dev, "%s: allocate wdev fail", __func__);
		ret = -ENOMEM;
		goto exit;
	}
	/* Do not expose a working NAN interface when firmware initialization
	 * failed or its USB reply timed out. No wdev owns ndev on this path yet. */
	ret = whc_host_init_nan();
	if (ret) {
		kfree(wdev);
		goto exit;
	}
	wdev->wiphy = global_idev.pwiphy_global;
	wdev->netdev = ndev;
	wdev->iftype = NL80211_IFTYPE_NAN;
	ndev->ieee80211_ptr = wdev;
	ndev->priv_destructor = rtw_nan_ndev_destructor;
	ndev->needs_free_netdev = true;
	global_idev.pwdev_global[2] = wdev;

	*nan_wdev = wdev;

	return 0;

exit:
	if (global_idev.pwdev_global[2]) { //wdev
		kfree((u8 *)global_idev.pwdev_global[2]);
		global_idev.pwdev_global[2] = NULL;
	}

	if (global_idev.pndev[2]) {
		if (global_idev.pndev[2]->reg_state == NETREG_REGISTERED) {
			unregister_netdevice(global_idev.pndev[2]);
		}
		free_netdev(global_idev.pndev[2]);
		global_idev.pndev[2] = NULL;
	}
	return -ENODEV;

}

void rtw_nan_iface_free(struct wiphy *wiphy)
{
	/* del_virtual_intf supplies wiphy and owns RTNL + the wiphy mutex.
	 * Bus removal passes NULL and must acquire both itself. rtnl_is_locked()
	 * cannot tell whether this task or an unrelated task owns the lock. */
	bool lock_needed = !wiphy;
	struct wireless_dev *wdev;
	struct net_device *ndev;

	if (lock_needed) {
		rtnl_lock();
		wiphy = global_idev.pwiphy_global;
		if (!wiphy) {
			rtnl_unlock();
			return;
		}
		/* NETDEV_GOING_DOWN takes the wiphy mutex itself. Match
		 * nl80211_del_interface: close before acquiring that mutex. */
		if (global_idev.pndev[2]) {
			dev_close(global_idev.pndev[2]);
		}
		wiphy_lock(wiphy);
	}
	wdev = global_idev.pwdev_global[2];
	ndev = global_idev.pndev[2];
	if (!wdev && !ndev) {
		goto unlock;
	}

	if (wdev) {
		/* NAN uses is_running, even after nl80211 has closed its vendor
		 * data netdev. Restore the pointer before returning to nl80211. */
		wdev->netdev = NULL;
		cfg80211_unregister_wdev(wdev);
		wdev->netdev = ndev;
	}

	if (ndev && ndev->reg_state == NETREG_REGISTERED) {
		unregister_netdevice(ndev);
	}

	/* Core releases ndev and its wdev through priv_destructor after
	 * nl80211_post_doit drops its reference and releases RTNL. */
	global_idev.pwdev_global[2] = NULL;
	global_idev.pndev[2] = NULL;
	whc_host_deinit_nan();
	dev_info(global_idev.pwhc_dev, "unregistered NAN; freeing after last reference.\n");

unlock:
	if (lock_needed) {
		wiphy_unlock(wiphy);
		rtnl_unlock();
	}
}

#endif

int rtw_ndev_alloc(void)
{
	int i, ret = false;
	struct net_device *ndev = NULL;
#if defined(CONFIG_WHC_WIFI_API_PATH)
	struct wireless_dev *wdev;
#endif

	for (i = 0; i < TOTAL_IFACE_NUM; i++) {
		/* alloc and init netdev */
		ndev = alloc_etherdev_mq(sizeof(struct whc_netdev_priv_t), 1);
		if (!ndev) {
			goto fail;
		}
		global_idev.pndev[i] = ndev;
		rtw_netdev_idx(ndev) = i;
		memcpy(rtw_netdev_label(ndev), WHC_LABEL, sizeof(WHC_LABEL));
		rtw_netdev_flags(ndev) = ndev->flags;

		ndev->netdev_ops = (i ? &rtw_ndev_ops_ap : &rtw_ndev_ops);
		ndev->watchdog_timeo = HZ * 3; /* 3 second timeout */
#ifndef CONFIG_WHC_HCI_IPC
		ndev->needed_headroom = max(SIZE_RX_DESC, SIZE_TX_DESC) + sizeof(struct whc_msg_info) + 4;
#endif
		SET_NETDEV_DEV(ndev, global_idev.pwhc_dev);

#if defined(CONFIG_WHC_WIFI_API_PATH)
		/* alloc and init wireless_dev */
		wdev = (struct wireless_dev *)kzalloc(sizeof(struct wireless_dev), in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
		if (!wdev) {
			goto fail;
		}
		wdev->wiphy = global_idev.pwiphy_global;
		wdev->netdev = ndev;
		wdev->iftype = (i ? NL80211_IFTYPE_AP : NL80211_IFTYPE_STATION);
		ndev->ieee80211_ptr = wdev;
		global_idev.pwdev_global[i] = wdev;
#endif
	}
	global_idev.mlme_priv.b_in_scan = false;
	global_idev.mlme_priv.b_in_disconnect = false;
	global_idev.mlme_priv.b_in_linking = false;

	init_completion(&global_idev.mlme_priv.disconnect_done_sema);

	return ret;

fail:
	for (i = 0; i < TOTAL_IFACE_NUM; i++) {
#if defined(CONFIG_WHC_WIFI_API_PATH)
		if (global_idev.pwdev_global[i]) { //wdev
			kfree((u8 *)global_idev.pwdev_global[i]);
			global_idev.pwdev_global[i] = NULL;
		}
#endif
		if (global_idev.pndev[i]) {
			free_netdev(global_idev.pndev[i]);
			global_idev.pndev[i] = NULL;
		}
	}
	return -ENODEV;

}

int rtw_ndev_register(void)
{
	int i, ret = false;
	char *wlan_name = WHC_HOST_PORT_NAME;

	for (i = 0; i < TOTAL_IFACE_NUM; i++) {
		rtw_ethtool_ops_init();
		netdev_set_default_ethtool_ops(global_idev.pndev[i], &global_idev.rtw_ethtool_ops);
		if (dev_alloc_name(global_idev.pndev[i], wlan_name) < 0) {
			dev_err(global_idev.pwhc_dev, "dev_alloc_name, fail!\n");
		}
#ifdef CONFIG_IEEE80211R
		if (i == WHC_STA_PORT) {
			netif_dormant_on(global_idev.pndev[i]);
		}
#endif
		netif_carrier_off(global_idev.pndev[i]);
		if (register_netdev(global_idev.pndev[i]) != 0) {
			dev_err(global_idev.pwhc_dev, "netdevice register fail!\n");
			return -ENODEV;
		}
	}

	return ret;
}

void rtw_ndev_unregister(void)
{
	int i;

	/* Virtual interfaces may still need their STA parent during teardown. */
#ifdef CONFIG_NAN
	rtw_nan_iface_free(NULL);
#endif
#ifdef CONFIG_P2P
	whc_host_p2p_pdwdev_free();
#endif
	for (i = 0; i < TOTAL_IFACE_NUM; i++) {
		if (global_idev.pndev[i] && global_idev.pndev[i]->reg_state == NETREG_REGISTERED) {
			/* hold rtnl_lock in unregister_netdev. */
			unregister_netdev(global_idev.pndev[i]);
		}
		dev_dbg(global_idev.pwhc_dev, "remove netdev done for interface %d.", i);

		if (global_idev.pwdev_global[i]) { //wdev
			kfree((u8 *)global_idev.pwdev_global[i]);
			global_idev.pwdev_global[i] = NULL;
			/* remove wireless_dev in ndev. */
			if (global_idev.pndev[i]) {
				global_idev.pndev[i]->ieee80211_ptr = NULL;
			}
		}

		if (global_idev.pndev[i]) {
			free_netdev(global_idev.pndev[i]);
			global_idev.pndev[i] = NULL;
		}
		dev_dbg(global_idev.pwhc_dev, "free netdev %d ok.", i);
	}
}

/* Address notifiers receive events for every netdev, including loopback
 * devices with no private allocation. Identify our devices without touching
 * another driver's netdev_priv(), which is neither sized nor typed for WHC. */
static bool rtw_is_whc_netdev(const struct net_device *ndev)
{
	return ndev->netdev_ops == &rtw_ndev_ops ||
		   ndev->netdev_ops == &rtw_ndev_ops_ap
#ifdef CONFIG_NAN
		   || ndev->netdev_ops == &rtw_ndev_ops_nan
#endif
		   ;
}

/* IPv4, IPv6 IP addr notifier */
static int rtw_inetaddr_notifier_call(struct notifier_block *nb, unsigned long action, void *data)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)data;
	struct net_device *ndev;

	if (!ifa || !ifa->ifa_dev || !ifa->ifa_dev->dev) {
		return NOTIFY_DONE;
	}

	ndev = ifa->ifa_dev->dev;
	if (!rtw_is_whc_netdev(ndev)) {
		return NOTIFY_DONE;
	}

	switch (action) {
	case NETDEV_UP:
		memcpy(global_idev.ip_addr, &ifa->ifa_address, RTW_IP_ADDR_LEN);
		dev_dbg(global_idev.pwhc_dev, "%s[%s]: up IP: [%pI4]\n", __func__, ifa->ifa_label, global_idev.ip_addr);
		schedule_work(&whc_netinfo_update_work);
		break;
	case NETDEV_DOWN:
		memset(global_idev.ip_addr, 0, RTW_IP_ADDR_LEN);
		dev_dbg(global_idev.pwhc_dev, "%s[%s]: down IP: [%pI4]\n", __func__, ifa->ifa_label, global_idev.ip_addr);
		break;
	default:
		dev_dbg(global_idev.pwhc_dev, "%s: default action\n", __func__);
		break;
	}
	return NOTIFY_DONE;
}

#if IS_ENABLED(CONFIG_IPV6)
static int rtw_inet6addr_notifier_call(struct notifier_block *nb, unsigned long action, void *data)
{
	struct inet6_ifaddr *inet6_ifa = (struct inet6_ifaddr *)data;
	struct net_device *ndev;

	if (!inet6_ifa || !inet6_ifa->idev || !inet6_ifa->idev->dev) {
		return NOTIFY_DONE;
	}

	ndev = inet6_ifa->idev->dev;
	if (!rtw_is_whc_netdev(ndev)) {
		return NOTIFY_DONE;
	}

	switch (action) {
	case NETDEV_UP:
		memcpy(global_idev.ipv6_addr, &inet6_ifa->addr, RTW_IPv6_ADDR_LEN);
		schedule_work(&whc_netinfo_update_work);
		dev_dbg(global_idev.pwhc_dev, "%s: up IP: [%pI6]\n", __func__, global_idev.ipv6_addr);
		break;
	case NETDEV_DOWN:
		memset(global_idev.ipv6_addr, 0, RTW_IPv6_ADDR_LEN);
		dev_dbg(global_idev.pwhc_dev, "%s: down IP: [%pI6]\n", __func__, global_idev.ipv6_addr);
		break;
	default:
		dev_dbg(global_idev.pwhc_dev, "%s: default action\n", __func__);
		break;
	}
	return NOTIFY_DONE;
}
#endif

static struct notifier_block rtw_inetaddr_notifier = {
	.notifier_call = rtw_inetaddr_notifier_call
};

#if IS_ENABLED(CONFIG_IPV6)
static struct notifier_block rtw_inet6addr_notifier = {
	.notifier_call = rtw_inet6addr_notifier_call
};
#endif

void rtw_inetaddr_notifier_register(void)
{
	INIT_WORK(&whc_netinfo_update_work, whc_netinfo_update_work_handler);
	register_inetaddr_notifier(&rtw_inetaddr_notifier);
#if IS_ENABLED(CONFIG_IPV6)
	register_inet6addr_notifier(&rtw_inet6addr_notifier);
#endif
}

void rtw_inetaddr_notifier_unregister(void)
{
	unregister_inetaddr_notifier(&rtw_inetaddr_notifier);
#if IS_ENABLED(CONFIG_IPV6)
	unregister_inet6addr_notifier(&rtw_inet6addr_notifier);
#endif
	/* Stop producers before draining work they can schedule. */
	cancel_work_sync(&whc_netinfo_update_work);
}

int rtw_netdev_probe(struct device *pdev)
{
	int ret = false;
	bool host_started = false;

	memset(&global_idev, 0, sizeof(struct whc_device));

	/* Initialize axi_priv */
	global_idev.pwhc_dev = pdev;

#if defined(CONFIG_WHC_WIFI_API_PATH)
	/*step1: alloc and init wiphy */
	ret = rtw_wiphy_init();
	if (ret == false) {
		dev_err(global_idev.pwhc_dev, "wiphy init fail");
		goto exit;
	}

	/*step3: register wiphy */
	if (wiphy_register(global_idev.pwiphy_global) != 0) {
		dev_err(global_idev.pwhc_dev, "wiphy register fail");
		goto os_ndevs_deinit;
	}
	global_idev.wiphy_registered = true;
#endif
	/*step4: register netdev */
	ret = rtw_ndev_alloc();
	if (ret < 0) {
		dev_err(global_idev.pwhc_dev, "ndev alloc fail");
		goto os_ndevs_deinit;
	}

	ret = whc_host_init();
	host_started = global_idev.host_init_done;
	if (ret < 0) {
		dev_err(global_idev.pwhc_dev, "llhw init fail");
		goto os_ndevs_deinit;
	}

	ret = rtw_ndev_register();
	if (ret < 0) {
		dev_err(global_idev.pwhc_dev, "ndev register fail");
		goto os_ndevs_deinit;
	}

#if defined(CONFIG_WHC_WIFI_API_PATH)
	whc_host_regd_init();
	rtw_drv_proc_init();
#ifdef CONFIG_IEEE80211R
	whc_host_ft_init();
#endif

#ifdef CONFIG_WAR_OFFLOAD
	rtw_proxy_init();
#endif
#endif

#if defined(CONFIG_WHC_CMD_PATH)
	whc_host_register_genl_family();

#ifdef CONFIG_WHC_HOST_LOG_FWD
	whc_host_log_fwd_enable(log_fwd_enable);
#endif /* CONFIG_WHC_HOST_LOG_FWD */
#endif

	rtnl_lock();
	global_idev.netdev_ready = true;
	rtnl_unlock();
	return 0; /* probe success */

os_ndevs_deinit:
#ifdef CONFIG_WHC_HCI_USB
	whc_usb_host_quiesce(&whc_usb_host_priv);
#endif
	rtw_ndev_unregister();
	if (host_started) {
		whc_host_deinit();
	}
#if defined(CONFIG_WHC_WIFI_API_PATH)
	rtw_wiphy_deinit();

exit:
#endif
	return -ENODEV;
}

int rtw_netdev_remove(struct device *pdev)
{
	/* add_virtual_intf also owns RTNL. Once this lock is released every new
	 * request returns -ENODEV, even while this wiphy remains discoverable. */
	rtnl_lock();
	global_idev.netdev_ready = false;
	rtnl_unlock();

	dev_dbg(global_idev.pwhc_dev, "%s start.", __func__);

#ifdef CONFIG_WHC_HCI_USB
	/* Stop completions and their RX/event consumers before freeing objects
	 * they can reference. USB removal cannot depend on firmware replies. */
	whc_usb_host_quiesce(&whc_usb_host_priv);
#endif
#if defined(CONFIG_WHC_WIFI_API_PATH)
	rtw_drv_proc_deinit();
#endif
	rtw_ndev_unregister();
	cancel_work_sync(&whc_netinfo_update_work);
	dev_dbg(global_idev.pwhc_dev, "unregister netdev done.");
#if defined(CONFIG_WHC_WIFI_API_PATH)
	rtw_wiphy_deinit();
#endif
	dev_dbg(global_idev.pwhc_dev, "unregister and deinit wiphy done.");

	whc_host_deinit();
	dev_dbg(global_idev.pwhc_dev, "remove llhw done.");

	pr_info("%s done\n", __func__);
	memset(&global_idev, 0, sizeof(struct whc_device));
#if defined(CONFIG_WHC_CMD_PATH)
	whc_host_unregister_genl_family();
#endif
	return 0;
}

