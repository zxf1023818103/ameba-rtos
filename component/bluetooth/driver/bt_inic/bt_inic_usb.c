// #include "usbd.h"
#include "usbd_whc.h"
#include "osif.h"
#include "bt_inic.h"
#include "hci_if_inic.h"
#include "hci_controller.h"
#include "bt_debug.h"

#define BT_INIC_USB_STATUS_ACTIVE                       0
#define BT_INIC_USB_STATUS_SUSPEND                      1
#define BT_INIC_USB_STATUS_DISABLED                     2

#define BT_INIC_USB_WAKE_HOST_MAX_WAIT_CNT              10
#define BT_INIC_USB_WAKE_HOST_UNIT                      10

/* USB callbacks run in interrupt context. FreeRTOS heap_5 only suspends
 * the scheduler, so allocating/freeing there can corrupt a task's heap walk.
 * Queue bounded packets by value and reclaim TX in USB_BT_TX_THREAD. */
#define BT_USB_RX_CAPACITY 512U
struct bt_usb_rx_packet {
	u32 generation;
	u16 len;
	u8 type;
	u8 data[BT_USB_RX_CAPACITY];
};

#define USBD_INIC_BT_EP1_INTR_IN_BUF_SIZE               256U   /* BT EP1 INTR IN buffer size */
#define USBD_INIC_BT_EP2_BULK_IN_BUF_SIZE               512U  /* BT EP2 BULK IN buffer size */
#define USBD_INIC_BT_EP2_BULK_OUT_BUF_SIZE              512U  /* BT EP2 BULK OUT buffer size */

struct bt_inic_usb_priv {
	void *rx_queue;
	void *work_sema;
	u8 *evt_completed;
	u8 *acl_completed;
	u8 rx_req_flag;
	u8 tx_req_flag;
	void *evt_tx_lock;
	void *evt_tx_done_sema;
	void *acl_tx_lock;
	void *acl_tx_done_sema;
};

typedef struct {
	u8 *buf;
	u16 buf_len;
} usbd_inic_app_ep_t;

typedef struct {
	usbd_inic_app_ep_t in_ep[USB_MAX_ENDPOINTS];
	usbd_inic_app_ep_t out_ep[USB_MAX_ENDPOINTS];
} usbd_inic_app_t;

enum {
	USB_CLOSED = 0,  /* BT host uart is closed. */
	USB_RUNNING,     /* BT host uart is running. */
	USB_CLOSING,     /* BT host uart is closing. */
};

static struct bt_inic_usb_priv usb_priv = {0};
static u8 bt_inic_usb_status = BT_INIC_USB_STATUS_ACTIVE;
static volatile u8 bt_inic_usb_configured;
static volatile u32 bt_inic_usb_generation;
/* INIC Device */
static usbd_inic_app_t usbd_inic_app;

static void bt_inic_usb_tx_data(u8 type, u8 *data, u32 len)
{
	u8 i = 0;
	u8 ep_addr;
	void *lock, *sema;
	u32 flags, generation = bt_inic_usb_generation;
	int ret = HAL_ERR_HW;

	if (!bt_inic_usb_configured || bt_inic_usb_status == BT_INIC_USB_STATUS_DISABLED) {
		goto drop;
	}
	if (bt_inic_usb_status == BT_INIC_USB_STATUS_SUSPEND) {
		usbd_wake_host();
		for (i = 0; i < BT_INIC_USB_WAKE_HOST_MAX_WAIT_CNT; i++) {
			osif_delay(BT_INIC_USB_WAKE_HOST_UNIT);
			if (bt_inic_usb_status == BT_INIC_USB_STATUS_ACTIVE) {
				break;
			}
		}
		if (i == BT_INIC_USB_WAKE_HOST_MAX_WAIT_CNT) {
			goto drop;
		}
	}
	if (type == HCI_EVT) {
		BT_DUMPA("HOST RX EVT: ", data, len);
		lock = usb_priv.evt_tx_lock;
		sema = usb_priv.evt_tx_done_sema;
		ep_addr = USBD_WHC_BT_EP_INTR_IN;
	} else if (type == HCI_ACL) {
		BT_DUMPA("HOST RX ACL: ", data, len);
		lock = usb_priv.acl_tx_lock;
		sema = usb_priv.acl_tx_done_sema;
		ep_addr = USBD_WHC_BT_EP_BULK_IN;
	} else {
		goto drop;
	}
	osif_mutex_take(lock, BT_TIMEOUT_FOREVER);
	osif_sem_take(sema, BT_TIMEOUT_FOREVER);
	flags = osif_lock();
	if (bt_inic_usb_configured && generation == bt_inic_usb_generation) {
		ret = usbd_whc_transmit_data(ep_addr, data, len, NULL);
	}
	osif_unlock(flags);
	if (ret != HAL_OK) {
		/* A rejected submission has no completion to release this token. */
		osif_sem_give(sema);
	}
	osif_mutex_give(lock);
	if (ret == HAL_OK) {
		return; /* completion/cancellation owns data */
	}
drop:
	osif_mem_free(data);
}

void bt_inic_send_to_host(u8 type, u8 *pdata, u32 len)
{
	u8 *buf = NULL;

	buf = osif_mem_alloc(RAM_TYPE_DATA_ON, len);
	if (!(buf)) {
		return;
	}
	memcpy(buf, pdata, len);
	bt_inic_usb_tx_data(type, buf, len);
	return;
}

static int bt_inic_usb_queue_rx(u8 type, const u8 *buf, u16 len)
{
	struct bt_usb_rx_packet packet;
	if (!buf || len > sizeof(packet.data)) {
		return HAL_ERR_PARA;
	}
	if (!bt_inic_usb_configured || !usb_priv.rx_queue) {
		return HAL_ERR_HW;
	}
	packet.generation = bt_inic_usb_generation;
	packet.len = len;
	packet.type = type;
	memcpy(packet.data, buf, len);
	if (!osif_msg_send(usb_priv.rx_queue, &packet, BT_TIMEOUT_NONE)) {
		return HAL_BUSY;
	}
	return HAL_OK;
}

int bt_inic_usb_hci_cmd_hdl(u8 *buf, u16 len)
{
	return bt_inic_usb_queue_rx(HCI_CMD, buf, len);
}

int bt_inic_usb_hci_acl_hdl(u8 *buf, u16 len)
{
	return bt_inic_usb_queue_rx(HCI_ACL, buf, len);
}

void bt_inic_status_change_cb(u8 old_status, u8 status)
{

	if (status == USBD_ATTACH_STATUS_ATTACHED) {
		bt_inic_usb_status = BT_INIC_USB_STATUS_ACTIVE;
	} else if (status == USBD_ATTACH_STATUS_DETACHED) {
		if (old_status == USBD_ATTACH_STATUS_ATTACHED) {
			bt_inic_usb_status = BT_INIC_USB_STATUS_SUSPEND;
		} else {
			bt_inic_usb_status = BT_INIC_USB_STATUS_DISABLED;
		}
	}
}

static void bt_inic_usb_reclaim_tx(void)
{
	u32 flags = osif_lock();
	u8 *evt = usb_priv.evt_completed;
	u8 *acl = usb_priv.acl_completed;
	usb_priv.evt_completed = NULL;
	usb_priv.acl_completed = NULL;
	osif_unlock(flags);
	if (evt) {
		osif_mem_free(evt);
		osif_sem_give(usb_priv.evt_tx_done_sema);
	}
	if (acl) {
		osif_mem_free(acl);
		osif_sem_give(usb_priv.acl_tx_done_sema);
	}
}

static void _usb_tx_complete_thread(void *param)
{
	(void)param;
	for (;;) {
		osif_sem_take(usb_priv.work_sema, BT_TIMEOUT_FOREVER);
		bt_inic_usb_reclaim_tx();
		if (usb_priv.tx_req_flag != USB_RUNNING) {
			break;
		}
	}
	usb_priv.tx_req_flag = USB_CLOSED;
	osif_task_delete(NULL);
}

static void _usb_rx_thread(void *pData)
{
	(void)pData;
	struct bt_usb_rx_packet packet;
	while (osif_msg_recv(usb_priv.rx_queue, &packet, BT_TIMEOUT_FOREVER)) {
		if (usb_priv.rx_req_flag != USB_RUNNING) {
			break;
		}
		if (bt_inic_usb_configured && packet.generation == bt_inic_usb_generation) {
			bt_inic_recv_from_host(packet.type, packet.data, packet.len);
		}
	}
	usb_priv.rx_req_flag = USB_CLOSED;
	osif_task_delete(NULL);
}

static bool _usb_rx_queue_init(void)
{
	if (!osif_msg_queue_create(&usb_priv.rx_queue, 32, sizeof(struct bt_usb_rx_packet))) {
		return FALSE;
	}
	if (!osif_sem_create(&usb_priv.work_sema, 0, 0xFFFFFFFF)) {
		osif_msg_queue_delete(usb_priv.rx_queue);
		usb_priv.rx_queue = NULL;
		return FALSE;
	}
	usb_priv.tx_req_flag = USB_RUNNING;
	if (!osif_task_create(NULL, "USB_BT_TX_THREAD", _usb_tx_complete_thread, NULL, 2048, 7)) {
		usb_priv.tx_req_flag = USB_CLOSED;
		goto fail;
	}
	usb_priv.rx_req_flag = USB_RUNNING;
	if (!osif_task_create(NULL, "USB_BT_RX_THREAD", _usb_rx_thread, NULL, 1024 * 4, 7)) {
		usb_priv.rx_req_flag = USB_CLOSED;
		usb_priv.tx_req_flag = USB_CLOSING;
		osif_sem_give(usb_priv.work_sema);
		while (usb_priv.tx_req_flag != USB_CLOSED) osif_delay(1);
		goto fail;
	}
	return TRUE;
fail:
	osif_sem_delete(usb_priv.work_sema);
	osif_msg_queue_delete(usb_priv.rx_queue);
	usb_priv.work_sema = NULL;
	usb_priv.rx_queue = NULL;
	return FALSE;
}

static void _usb_rx_queue_deinit(void)
{
	struct bt_usb_rx_packet packet = {0};
	bt_inic_clear_config();
	usb_priv.rx_req_flag = USB_CLOSING;
	osif_msg_send(usb_priv.rx_queue, &packet, BT_TIMEOUT_FOREVER);
	while (usb_priv.rx_req_flag != USB_CLOSED) osif_delay(5);
	usb_priv.tx_req_flag = USB_CLOSING;
	osif_sem_give(usb_priv.work_sema);
	while (usb_priv.tx_req_flag != USB_CLOSED) osif_delay(5);
	osif_msg_queue_delete(usb_priv.rx_queue);
	osif_sem_delete(usb_priv.work_sema);
	usb_priv.rx_queue = NULL;
	usb_priv.work_sema = NULL;
}

static int _usb_trx_buf_init(void)
{
	int ret = HAL_OK;
	usbd_inic_app_t *iapp = &usbd_inic_app;
	usbd_inic_app_ep_t *ep;
	u8 ep_num;

	ep_num = USB_EP_NUM(USBD_WHC_BT_EP_INTR_IN);
	ep = &iapp->in_ep[ep_num];
	ep->buf_len = USBD_INIC_BT_EP1_INTR_IN_BUF_SIZE;
	ep->buf = (u8 *)usb_os_malloc(ep->buf_len);
	if (ep->buf == NULL) {
		ret = HAL_ERR_MEM;
		goto bt_init_exit;
	}

	ep_num = USB_EP_NUM(USBD_WHC_BT_EP_BULK_IN);
	ep = &iapp->in_ep[ep_num];
	ep->buf_len = USBD_INIC_BT_EP2_BULK_IN_BUF_SIZE;
	ep->buf = (u8 *)usb_os_malloc(ep->buf_len);
	if (ep->buf == NULL) {
		ret = HAL_ERR_MEM;
		goto bt_init_clean_intr_in_buf_exit;
	}

	ep_num = USB_EP_NUM(USBD_WHC_BT_EP_BULK_OUT);
	ep = &iapp->out_ep[ep_num];
	ep->buf_len = USBD_INIC_BT_EP2_BULK_OUT_BUF_SIZE;
	ep->buf = (u8 *)usb_os_malloc(ep->buf_len);
	if (ep->buf == NULL) {
		ret = HAL_ERR_MEM;
		goto bt_init_clean_bulk_in_buf_exit;
	}

	return HAL_OK;

bt_init_clean_bulk_in_buf_exit:
	ep = &iapp->in_ep[USB_EP_NUM(USBD_WHC_BT_EP_BULK_IN)];
	usb_os_mfree(ep->buf);
	ep->buf = NULL;

bt_init_clean_intr_in_buf_exit:
	ep = &iapp->in_ep[USB_EP_NUM(USBD_WHC_BT_EP_INTR_IN)];
	usb_os_mfree(ep->buf);
	ep->buf = NULL;

bt_init_exit:
	return ret;
}

static void _usb_trx_buf_deinit(void)
{
	usbd_inic_app_t *iapp = &usbd_inic_app;
	usbd_inic_app_ep_t *ep;

	ep = &iapp->in_ep[USB_EP_NUM(USBD_WHC_BT_EP_INTR_IN)];
	if (ep->buf != NULL) {
		usb_os_mfree(ep->buf);
		ep->buf = NULL;
	}

	ep = &iapp->in_ep[USB_EP_NUM(USBD_WHC_BT_EP_BULK_IN)];
	if (ep->buf != NULL) {
		usb_os_mfree(ep->buf);
		ep->buf = NULL;
	}

	ep = &iapp->out_ep[USB_EP_NUM(USBD_WHC_BT_EP_BULK_OUT)];
	if (ep->buf != NULL) {
		usb_os_mfree(ep->buf);
		ep->buf = NULL;
	}
}

void bt_inic_usb_evt_txdone_cb(u8 *buf)
{
	usb_priv.evt_completed = buf;
	osif_sem_give(usb_priv.work_sema);
}

void bt_inic_usb_acl_txdone_cb(u8 *buf)
{
	usb_priv.acl_completed = buf;
	osif_sem_give(usb_priv.work_sema);
}

#if defined(CONFIG_AMEBAGREEN2) && CONFIG_AMEBAGREEN2 && defined(CONFIG_WHC_INTF_USB) && CONFIG_WHC_INTF_USB
int bt_inic_usb_prepare(void)
{
	/* Keep the standalone HCI receiver until USB queues/locks exist. The
	 * controller patch download and reset must finish before USB enumeration. */
	return (hci_controller_is_opened() || hci_controller_open()) ? HAL_OK : HAL_ERR_HW;
}
#endif

int bt_inic_usb_init(void)
{
	int ret = HAL_OK;

	ret = _usb_trx_buf_init();
	if (ret != HAL_OK) {
		goto init_exit;
	}

	if (!_usb_rx_queue_init()) {
		_usb_trx_buf_deinit();
		ret = HAL_ERR_MEM;
		goto init_exit;
	}
	osif_mutex_create(&usb_priv.evt_tx_lock);
	osif_mutex_create(&usb_priv.acl_tx_lock);
	osif_sem_create(&usb_priv.evt_tx_done_sema, 0, 1);
	osif_sem_create(&usb_priv.acl_tx_done_sema, 0, 0xFFFFFFFF);
	osif_sem_give(usb_priv.evt_tx_done_sema);
	osif_sem_give(usb_priv.acl_tx_done_sema);
#if defined(CONFIG_AMEBAGREEN2) && CONFIG_AMEBAGREEN2 && defined(CONFIG_WHC_INTF_USB) && CONFIG_WHC_INTF_USB
	/* prepare() already opened the controller; now hand events to USB. */
	if (!bt_inic_open()) {
		bt_inic_usb_deinit();
		return HAL_ERR_HW;
	}
#endif
	BT_LOGA("USB device init done!\n");
init_exit:
	return ret;
}

void bt_inic_usb_deinit(void)
{
	_usb_rx_queue_deinit();
	osif_sem_delete(usb_priv.evt_tx_done_sema);
	usb_priv.evt_tx_done_sema = NULL;
	osif_sem_delete(usb_priv.acl_tx_done_sema);
	usb_priv.acl_tx_done_sema = NULL;
	osif_mutex_delete(usb_priv.evt_tx_lock);
	usb_priv.evt_tx_lock = NULL;
	osif_mutex_delete(usb_priv.acl_tx_lock);
	usb_priv.acl_tx_lock = NULL;
	_usb_trx_buf_deinit();
	BT_LOGA("USB device deinit done!\n");
}

void bt_inic_clear_config(void)
{
	/* Called after the class cancels IN transfers and releases their tokens. */
	bt_inic_usb_configured = 0;
	bt_inic_usb_generation++;
}

void bt_inic_set_config(void)
{
	usbd_inic_app_t *iapp = &usbd_inic_app;
	usbd_inic_app_ep_t *ep;
	// Prepare to RX

	if (usbd_whc_is_bt_en()) {
		bt_inic_usb_generation++;
		bt_inic_usb_configured = 1;
		ep = &iapp->out_ep[USB_EP_NUM(USBD_WHC_BT_EP_BULK_OUT)];
		usbd_whc_receive_data(USBD_WHC_BT_EP_BULK_OUT, ep->buf, ep->buf_len, NULL);
	}
}
