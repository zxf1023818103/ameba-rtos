/* Synthetic nl80211 events: exercise ordering beyond the former 100 KiB
 * rotation threshold, interface/OUI filters and short/variable payloads.
 * Does not access hardware, create event logs or write pairing caches.
 */
#include <assert.h>
#include "../whc_host_linux/app/wifi_nan_utility/src/rtw_nan_api/nan_event.c"

char *nan_intf = "no-such-nan";
static unsigned int callbacks;
static unsigned int expected_id;

static void receive_event(uint8_t id, void *data, uint32_t len)
{
	assert(id == expected_id);
	assert(data && len);
	callbacks++;
}

static void deliver(unsigned int event_id, const void *data, size_t len,
			int expected, unsigned int ifindex, unsigned int oui)
{
	struct nl_msg *msg = nlmsg_alloc_size(len + 512);
	unsigned int before = callbacks;
	assert(msg);
	assert(genlmsg_put(msg, 0, 0, NLMSG_MIN_TYPE, 0, 0,
			  NL80211_CMD_VENDOR, 0));
	assert(nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) == 0);
	assert(nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, oui) == 0);
	assert(nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, event_id) == 0);
	assert(nla_put(msg, NL80211_ATTR_VENDOR_DATA, len, data) == 0);
	expected_id = expected;
	_vendor_event(msg, NULL);
	assert(callbacks == before + (expected >= 0));
	nlmsg_free(msg);
}

int main(void)
{
	struct vendor_evt_data_indication_info indication = {.publish_id = 1, .ndp_id = 1};
	struct vendor_evt_data_confirm_info confirm = {.ndp_id = 1};
	struct rtw_nan_datapath_established_event_data established = {.datapath_id = 1};
	struct rtw_nan_datapath_end_event_data end = {.datapath_id = 1};
	struct rtw_nan_datapath_request_received_event_data request = {.datapath_id = 1};
	unsigned char full_request[sizeof(request) + 4] = {0};
	size_t bytes = 0;

	g_evt_ifindex = 7;
	rtw_nan_api_register_evt_cb(receive_event);
	confirm.srvc_info_len = 13;
	memcpy(confirm.srvc_info, WFA_OUI, 3);
	confirm.srvc_info[3] = NAN_SRVC_PROTOCOL_GENIC;
	memcpy(confirm.srvc_info + 4, "\x00\x02\x00\x40\x1f\x01\x01\x00\x06", 9);
	for (int i = 0; i < 2000; i++) {
		deliver(RTW_VENDOR_EVT_NAN_DATA_INDICATION, &indication, sizeof(indication),
				NAN_EVT_DATA_INDICATION, 7, 0xe04c);
		deliver(RTW_VENDOR_EVT_NAN_DATA_COMFIRM, &confirm, sizeof(confirm),
				NAN_EVT_DATA_CONFIRM, 7, 0xe04c);
		deliver(RTW_VENDOR_EVT_NAN_DATAPATH_ESTABLISHED, &established, sizeof(established),
				NAN_EVT_DATAPATH_ESTABLISHED, 7, 0xe04c);
		deliver(RTW_VENDOR_EVT_NAN_DATAPATH_END, &end, sizeof(end),
				NAN_EVT_DATAPATH_END, 7, 0xe04c);
		bytes += sizeof(indication) + sizeof(confirm) + sizeof(established) + sizeof(end);
	}
	assert(bytes > 102400);
	assert(callbacks == 8000);
	deliver(RTW_VENDOR_EVT_NAN_DATAPATH_END, &end, sizeof(end), -1, 8, 0xe04c);
	deliver(RTW_VENDOR_EVT_NAN_DATAPATH_END, &end, sizeof(end), -1, 7, 0x1234);
	deliver(RTW_VENDOR_EVT_NAN_DATA_COMFIRM, &confirm, 1, -1, 7, 0xe04c);
	/* Fixed header is present, but its claimed flexible tail is absent. */
	request.attribute_list_length = 4;
	deliver(RTW_VENDOR_EVT_NAN_DATAPATH_REQ_RECEIVED, &request, sizeof(request), -1, 7, 0xe04c);
	memcpy(full_request, &request, sizeof(request));
	deliver(RTW_VENDOR_EVT_NAN_DATAPATH_REQ_RECEIVED, full_request, sizeof(full_request),
			NAN_EVT_DATAPATH_RECV_REQ, 7, 0xe04c);
	assert(callbacks == 8001);
	assert(!rtw_nan_evt_init());
	rtw_nan_evt_deinit();
	printf("NAN events: 2000 ordered NDP sequences (%zu payload bytes), filters and bounds passed\n", bytes);
	return 0;
}
