#include <stdio.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <stddef.h>
#include <sys/stat.h>
#include "nan_event.h"
#include "nan_cache_file.h"
#include "rtw_nan_cmd_api.h"
#include "rtw_nan_vendor_def.h"

#define PRINT_DBG_ADDR(_str, _addr) \
	DEBUG_PRINT("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", \
	            _str, *(_addr), *((_addr) + 1), *((_addr) + 2), \
	            *((_addr) + 3), *((_addr) + 4), *((_addr) + 5));

extern char *nan_intf;
rtw_nan_evt_cb g_nan_evt_cb;
static struct nl_sock *g_evt_sock;
static pthread_t g_evt_thread;
static int g_evt_wake[2] = {-1, -1};
static unsigned int g_evt_ifindex;

void _print_data(uint8_t *start, uint16_t len)
{
	uint16_t index = 0;
	for (index = 0; index < len; index++) {
		if (!(index % 16)) {
			DEBUG_PRINT("\n");
		}
		DEBUG_PRINT("%02x ", start[index]);
	}
	DEBUG_PRINT("\n");
}

void _print_data_confirm_evt(struct vendor_evt_data_confirm_info *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] type:%d, status:%d, ndp_id:%d, mc_id:%d, nmsg_id:%d\n",
				evt_data->type, evt_data->status, evt_data->ndp_id,
				evt_data->mc_id, evt_data->nmsg_id);

	PRINT_DBG_ADDR("[rtw_event] initiator_data_address",
				   evt_data->initiator_data_address);
	PRINT_DBG_ADDR("[rtw_event] responder_data_address",
				   evt_data->responder_data_address);

	DEBUG_PRINT("[rtw_event] srvc_info (%d):", evt_data->srvc_info_len);
	_print_data(evt_data->srvc_info, evt_data->srvc_info_len);
}
void _print_disc_result_evt(struct rtw_nan_discovery_result_received_event_data *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] subscribe_id:%d, publisher_id:%d, publish_rssi:%d\n",
				evt_data->subscribe_id, evt_data->publisher_id, evt_data->publish_rssi);
	PRINT_DBG_ADDR("[rtw_event] peer_nan_address",
				   evt_data->peer_nan_address.ether_addr_octet);
	DEBUG_PRINT("[rtw_event] channel:%d, flags:0x%x\n",
				evt_data->channel.channel, evt_data->channel.flags);
	DEBUG_PRINT("[rtw_event] cipher_suite_id:0x%x\n", evt_data->cipher_suite_id);

	DEBUG_PRINT("[rtw_event] publish_attribute_list (%d):",
				evt_data->publish_attribute_list_length);
	_print_data(evt_data->publish_attribute_list, evt_data->publish_attribute_list_length);
}
void _print_datapath_req_recv_evt(struct rtw_nan_datapath_request_received_event_data *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] datapath_id:%d, publish_id:%d, security:%d\n",
				evt_data->datapath_id, evt_data->publish_id, evt_data->security);
	PRINT_DBG_ADDR("[rtw_event] initiator_management_address",
				   evt_data->initiator_management_address.ether_addr_octet);
	PRINT_DBG_ADDR("[rtw_event] initiator_data_address",
				   evt_data->initiator_data_address.ether_addr_octet);
	DEBUG_PRINT("[rtw_event] attribute_list (%d):", evt_data->attribute_list_length);
	_print_data(evt_data->attribute_list, evt_data->attribute_list_length);
}
void _print_datapath_rsp_recv_evt(struct rtw_nan_datapath_response_received_event_data *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] datapath_id:%d, publish_id:%d\n",
				evt_data->datapath_id, evt_data->publish_id);
	PRINT_DBG_ADDR("[rtw_event] initiator_data_address",
				   evt_data->initiator_data_address.ether_addr_octet);
	PRINT_DBG_ADDR("[rtw_event] responder_management_address",
				   evt_data->responder_management_address.ether_addr_octet);
	PRINT_DBG_ADDR("[rtw_event] responder_data_address",
				   evt_data->responder_data_address.ether_addr_octet);
	DEBUG_PRINT("[rtw_event] attribute_list (%d):", evt_data->attribute_list_length);
	_print_data(evt_data->attribute_list, evt_data->attribute_list_length);
}
void _print_datapath_established_evt(struct rtw_nan_datapath_established_event_data *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] type:%d, datapath_id:%d, pub_id:%d\n",
				evt_data->type, evt_data->datapath_id, evt_data->pub_id);

	PRINT_DBG_ADDR("[rtw_event] initiator_data_address",
				   evt_data->initiator_data_address.ether_addr_octet);
	PRINT_DBG_ADDR("[rtw_event] responder_data_address",
				   evt_data->responder_data_address.ether_addr_octet);
	PRINT_DBG_ADDR("[rtw_event] peer_management_address",
				   evt_data->peer_management_address.ether_addr_octet);

	DEBUG_PRINT("[rtw_event] peer_interface_identifier: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
				evt_data->peer_interface_identifier[0],
				evt_data->peer_interface_identifier[1],
				evt_data->peer_interface_identifier[2],
				evt_data->peer_interface_identifier[3],
				evt_data->peer_interface_identifier[4],
				evt_data->peer_interface_identifier[5],
				evt_data->peer_interface_identifier[6],
				evt_data->peer_interface_identifier[7]);

	DEBUG_PRINT("[rtw_event] service_specific_info(%d):", evt_data->service_specific_info.length);
	_print_data(evt_data->service_specific_info.info, evt_data->service_specific_info.length);
}
void _print_datapath_end_evt(struct rtw_nan_datapath_end_event_data *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] datapath_id:%d, publish_id:%d, reason:%d\n",
				evt_data->datapath_id, evt_data->publish_id, evt_data->reason);
	PRINT_DBG_ADDR("[rtw_event] initiator_data_address",
				   evt_data->initiator_data_address.ether_addr_octet);
	PRINT_DBG_ADDR("[rtw_event] peer_data_address",
				   evt_data->peer_data_address.ether_addr_octet);
	PRINT_DBG_ADDR("[rtw_event] peer_management_address",
				   evt_data->peer_management_address.ether_addr_octet);
}
void _print_datapth_follow_up_recv_evt(struct rtw_nan_follow_up_received_event_data *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] local_service_id:%d, peer_service_id:%d\n",
				evt_data->local_service_id, evt_data->peer_service_id);
	PRINT_DBG_ADDR("[rtw_event] peer_nan_address",
				   evt_data->peer_nan_address.ether_addr_octet);
	DEBUG_PRINT("[rtw_event] follow_up_rssi:%d\n",
				evt_data->follow_up_rssi);
	DEBUG_PRINT("[rtw_event] channel:%d, flags:0x%x\n",
				evt_data->channel.channel, evt_data->channel.flags);
	DEBUG_PRINT("[rtw_event] attribute_list (%d):",
				evt_data->attribute_list_length);
	_print_data(evt_data->attribute_list, evt_data->attribute_list_length);
}
void _print_data_indication_evt(struct vendor_evt_data_indication_info *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] type:%d, publish_id:%d, ndp_id:%d, mc_id:%d, security:%d\n",
				evt_data->type, evt_data->publish_id, evt_data->ndp_id,
				evt_data->mc_id, evt_data->security);

	PRINT_DBG_ADDR("[rtw_event] initiator_data_address", evt_data->initiator_data_address);
	PRINT_DBG_ADDR("[rtw_event] responder_data_address", evt_data->responder_data_address);
	DEBUG_PRINT("[rtw_event] ipv6_interfac_id: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
				evt_data->ipv6_interfac_id[0],
				evt_data->ipv6_interfac_id[1],
				evt_data->ipv6_interfac_id[2],
				evt_data->ipv6_interfac_id[3],
				evt_data->ipv6_interfac_id[4],
				evt_data->ipv6_interfac_id[5],
				evt_data->ipv6_interfac_id[6],
				evt_data->ipv6_interfac_id[7]);
	DEBUG_PRINT("[rtw_event] srvc_info (%d):", evt_data->srvc_info_len);
	_print_data(evt_data->srvc_info, evt_data->srvc_info_len);
}
void _print_data_bstrap_res_evt(struct vendor_evt_bstrap_result *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] status:%d, \n", evt_data->type_status);
	DEBUG_PRINT("[rtw_event] remote_inst_id:%d, local_inst_id=%d, \n",
				evt_data->remote_inst_id, evt_data->local_inst_id);
	DEBUG_PRINT("[rtw_event] rsp_bstrap_method:%d\n", evt_data->rsp_bstrap_method);
	PRINT_DBG_ADDR("[rtw_event] peer_management_address", evt_data->peer_nmi);
}
void _print_data_pasn_res_evt(struct vendor_evt_pasn_result *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] status:%d\n", evt_data->status);
	DEBUG_PRINT("[rtw_event] local_role:%d\n", evt_data->local_role);
	DEBUG_PRINT("[rtw_event] remote_nik_caching:%d\n", evt_data->remote_nik_caching);
	PRINT_DBG_ADDR("[rtw_event] peer_management_address", evt_data->peer_nmi);
}
void _print_data_recv_pasn_upd_pmkid(struct vendor_evt_pasn_upd_pmkid *evt_data)
{
	DEBUG_PRINT("[rtw_event] %s:\n", __func__);
	DEBUG_PRINT("[rtw_event] role:%d\n", evt_data->role);
	DEBUG_PRINT("[rtw_event] status:%d\n", evt_data->status);
	PRINT_DBG_ADDR("[rtw_event] peer_management_address", evt_data->peer_nmi);
	DEBUG_PRINT("[rtw_event] auth_method:%d\n", evt_data->auth_method);
}

/**
 * _tlv_get_len
 * @attr_id: attribute id
 * @tlv_buf_len: length of tlv list
 * @tlv_buf: start address of tlv list
 * return: attribute length
 */
uint16_t _tlv_get_len(uint8_t attr_id, uint16_t tlv_list_len, uint8_t *tlv_list)
{
	uint16_t attr_len = 0;
	uint16_t index = 0;

	while ((index + 3) < tlv_list_len) {
		GET_TLV_ATTR_LEN(tlv_list + index, &attr_len);
		if (tlv_list[index] == attr_id) {
			break;
		}
		index += (attr_len + 3);
		attr_len = 0;
	}
	if (!attr_len)
		DEBUG_PRINT("[rtw_event] %s: attr_id(0x%02x) not found!\n",
					__func__, attr_id);
	return attr_len;
}
/**
 * _tlv_get_info
 * @attr_id: attribute id
 * @attr_info: pre-allocated buffer, use the _tlv_get_len to get length info first.
 * @tlv_list_len: length of tlv list
 * @tlv_list: start address of tlv list
 * return: attribute length
 */
uint16_t _tlv_get_info(uint8_t attr_id, uint8_t *attr_info, uint16_t tlv_list_len, uint8_t *tlv_list)
{
	uint16_t attr_len = 0;
	uint16_t index = 0;

	while ((index + 3) < tlv_list_len) {
		GET_TLV_ATTR_LEN(tlv_list + index, &attr_len);
		if (tlv_list[index] == attr_id) {
			if ((index + attr_len + 3) > tlv_list_len) {
				INFO_PRINT("[rtw_event] %s: tlv_list_len(%d) not enough\n",
						   __func__, tlv_list_len);
				attr_len = 0;
			} else {
				memcpy(attr_info, tlv_list + index + 3, attr_len);
			}
			break;
		}
		index += (attr_len + 3);
		attr_len = 0;
	}
	if (!attr_len)
		DEBUG_PRINT("[rtw_event] %s: attr_id(0x%02x) not found!\n",
					__func__, attr_id);
	return attr_len;
}

bool _parse_nan_attr_generic_srvc_proto(uint8_t *tlv_list,
										uint16_t tlv_list_len,
										struct nan_generic_srvc_proto *result)
{
	uint8_t attr_id = 0;
	uint16_t attr_len = 0;
	uint16_t i = 0;

	DEBUG_PRINT("[rtw_event] %s\n", __func__);

	if (!tlv_list_len || !tlv_list || !result) {
		INFO_PRINT("[rtw_event] generic list len(%d), empty!\n", tlv_list_len);
		return false;
	}

	/* transport port */
	attr_id = NAN_GEN_SRVC_TRANSPORT_PORT;
	attr_len = _tlv_get_len(attr_id, tlv_list_len, tlv_list);
	if (attr_len) {
		_tlv_get_info(attr_id, (uint8_t *)&result->port_number, tlv_list_len, tlv_list);
		DEBUG_PRINT("[rtw_event] trans_port(%d)\n", result->port_number);
	}
	/* transport protocol */
	attr_id = NAN_GEN_SRVC_TRANSPORT_PROTOCOL;
	attr_len = _tlv_get_len(attr_id, tlv_list_len, tlv_list);
	if (attr_len) {
		_tlv_get_info(attr_id, &result->trans_proto, tlv_list_len, tlv_list);
		DEBUG_PRINT("[rtw_event] trans_proto(%d)\n", result->trans_proto);
	}
	/* service name */
	attr_id = NAN_GEN_SRVC_SERVICE_NAME;
	attr_len = _tlv_get_len(attr_id, tlv_list_len, tlv_list);
	if (attr_len) {
		memset(result->service_name, '\0', sizeof(result->service_name));
		_tlv_get_info(attr_id, result->service_name, tlv_list_len, tlv_list);
		DEBUG_PRINT("[rtw_event] service_name(%s)\n", result->service_name);
	}
	/* service instance */
	attr_id = NAN_GEN_SRVC_NAME_OF_SRVC_INST;
	attr_len = _tlv_get_len(attr_id, tlv_list_len, tlv_list);
	if (attr_len) {
		memset(result->service_inst, '\0', sizeof(result->service_inst));
		_tlv_get_info(attr_id, result->service_inst, tlv_list_len, tlv_list);
		DEBUG_PRINT("[rtw_event] service_instance(%s)\n", result->service_inst);
	}
	/* text info */
	attr_id = NAN_GEN_SRVC_TEXT_INFO;
	attr_len = _tlv_get_len(attr_id, tlv_list_len, tlv_list);
	if (attr_len >= NAN_MAX_SERVICE_INFO_LEN) {
		INFO_PRINT("[rtw_event] text info len(%d) > max(%d)\n", attr_len, NAN_MAX_SERVICE_INFO_LEN);
		return false;
	}
	if (attr_len) {
		result->text_info_len = attr_len;
		_tlv_get_info(attr_id, result->text_info, tlv_list_len, tlv_list);
		DEBUG_PRINT("[rtw_event] text_info(len=%d) ", result->text_info_len);
		for (i = 0; i < result->text_info_len; i++) {
			DEBUG_PRINT("%02x ", result->text_info[i]);
		}
		DEBUG_PRINT("\n");
	}

	return true;
}

/**
 * service info field format:
 * OUI (3) / service protocol type (1) / service specific info (variable)
 */
bool _parse_nan_attr_srvc_info(uint8_t *info,
							   uint16_t info_len,
							   struct nan_generic_srvc_proto *result)
{
	uint16_t i = 0;
	uint8_t srvc_proto_type = 0;

	DEBUG_PRINT("[rtw_event] %s\n", __func__);

	if (info_len < 4) {
		INFO_PRINT("[rtw_event] parse srvc info, len(%d) not enough\n", info_len);
		return false;
	}

	/* check OUI */
	if (memcmp(info, WFA_OUI, 3)) {
		INFO_PRINT("[rtw_event] OUI(0x%02x-%02x-%02x) not match!\n",
				   info[0], info[1], info[2]);
		return false;
	}

	/* srvc protocol type */
	srvc_proto_type = info[i + 3];
	DEBUG_PRINT("[rtw_event] info_len(%d) srvc_proto_type(%d)\n", info_len, srvc_proto_type);

	/* srvc specific info */
	if (srvc_proto_type == NAN_SRVC_PROTOCOL_GENIC) {
		_parse_nan_attr_generic_srvc_proto(info + 4,
										   info_len - 4,
										   result);
	}

	return true;
}
/**
 * Note for SDEA format: field (size)
 * attr id (1) / length (2) / instance id (1) / control (2) /
 * range limit (0 or 4) / srvc update indicatot (0 or 1)
 * srvc info len (0 or 1) / srvc info (variable)
 */
bool _parse_nan_attr_sdea(uint8_t *attr,
						  uint16_t attr_len,
						  struct nan_attr_sdea *result)
{
	uint8_t inst_id = 0;
	uint16_t ctrl = 0;
	uint16_t i = 0;

	DEBUG_PRINT("[rtw_event] %s\n", __func__);

	/* check for attr_id and min length (instance id + control) */
	if (attr_len < 3 || attr[0] != NAN_ATTR_ID_SRVC_DESC_EXT) {
		INFO_PRINT("[rtw_event] sdea attr_id(%d) or attr_len(%d) not enough!\n",
				   attr[0], attr_len);
		return false;
	}

	/* inst_id and ctrl */
	GET_SDEA_INST_ID(attr, &inst_id);
	GET_SDEA_CTRL(attr, &ctrl);
	i += 6;
	DEBUG_PRINT("[rtw_event] attr_len(%d) inst_id(%d) ctrl(0x%02x)\n",
				attr_len, inst_id, ctrl);
	result->inst_id = inst_id;
	result->ctrl = ctrl;

	/* range limit */
	if (ctrl & 0x0100) {
		if (attr_len < (i + 1)) { /* (attr_len + 3) < (i + 4) */
			INFO_PRINT("[rtw_event] sdea range limit present, attr_len(%d) not enough!\n",
					   attr_len);
			return false;
		}
		DEBUG_PRINT("[rtw_event] sdea range limit present.\n");
		i += 4;
	}
	/* srvc update indicator */
	if (ctrl & 0x0200) {
		if (attr_len < (i - 2)) { /* (attr_len + 3) < (i + 1) */
			INFO_PRINT("[rtw_event] sdea srvc update indicator present, attr_len(%d) not enough!\n",
					   attr_len);
			return false;
		}
		DEBUG_PRINT("[rtw_event] sdea srvc update indicator(%d)\n", attr[i]);
		i += 1;
	}
	/* srvc info */
	if (attr_len > (i - 1)) { /* (attr_len + 3) > (i + 2) */
		uint16_t srvc_info_len = (attr[i + 1] << 8) | attr[i];
		i += 2;
		/* check length */
		if (attr_len < (i + srvc_info_len - 3)) { /* (attr_len + 3) < (i + srvc_info_len) */
			INFO_PRINT("[rtw_event] sdea srvc_info_len(%d), attr_len(%d) not match!\n",
					   srvc_info_len, attr_len);
			return false;
		}
		_parse_nan_attr_srvc_info(attr + i, srvc_info_len, &result->gene_srvc_info);
	}

	return true;
}

/**
 * _parse_nan_attr_sda:
 * @attr: sda start addr
 * @attr_len: sda length
 * @disc_reault:
 *
 * Note for SDA format: field (size)
 * attr id (1) / length (2) / service id (6) / instance id (1) /
 * requestor instance (1) / service control (1) /
 * binding bitmap (0 or 2) /
 * matching filter len (0 or 1) / matching filter (variable) /
 * srvc rsp filter len (0 or 1) / srvc rsp filter (variable) /
 * srvc info len (0 or 1) / srvc info (variable)
 */
bool _parse_nan_attr_sda(uint8_t *attr,
						 uint16_t attr_len,
						 struct nan_attr_sda *result)
{
	uint8_t srvc_id[6] = {0};
	uint8_t inst_id = 0;
	uint8_t req_inst_id = 0;
	uint8_t srvc_ctrl = 0;

	DEBUG_PRINT("[rtw_event] %s\n", __func__);

	/* check for attr_id and min length (srvc id + inst id + requestor inst + srvc ctrl) */
	if (attr_len < 9 || attr[0] != NAN_ATTR_ID_SRVC_DESC) {
		INFO_PRINT("[rtw_event] sda attr_id(%d) or attr_len(%d) not enough\n",
				   attr[0], attr_len);
		return false;
	}

	GET_SDA_SRVC_ID(attr, srvc_id);
	GET_SDA_INST_ID(attr, &inst_id);
	GET_SDA_REQ_INST_ID(attr, &req_inst_id);
	GET_SDA_SRVC_CTRL(attr, &srvc_ctrl);
	DEBUG_PRINT("[rtw_event] attr_len(%d), srvc_id(%02x:%02x:%02x:%02x:%02x:%02x)\n",
				attr_len, srvc_id[0], srvc_id[1], srvc_id[2], srvc_id[3], srvc_id[4], srvc_id[5]);
	DEBUG_PRINT("[rtw_event] inst_id(%d), req_inst_id(%d), srvc_ctrl(0x%02x)\n",
				inst_id, req_inst_id, srvc_ctrl);

	memcpy(result->service_id, srvc_id, SRVC_ID_LEN);
	result->inst_id = inst_id;
	result->req_inst_id = req_inst_id;
	result->service_ctrl = srvc_ctrl;

	return true;
}

void _parse_disc_result_nan_attr(uint8_t *attr_list,
								 uint16_t attr_list_len,
								 struct nan_evt_disc_result_info *disc_result)
{
	uint16_t cur_idx = 0;
	uint8_t attr_id = 0;
	uint16_t attr_len = 0;

	DEBUG_PRINT("[rtw_event] %s\n", __func__);

	while ((cur_idx + 3) < attr_list_len) {
		attr_id = attr_list[cur_idx];
		GET_TLV_ATTR_LEN(attr_list + cur_idx, &attr_len);

		/* check remaining length */
		if ((cur_idx + 3 + attr_len) > attr_list_len) {
			INFO_PRINT("[rtw_event] nan attr_id(0x%02x) attr_len(%d) cur_idx(%d), attr_list_len(%d) not enough\n",
					   attr_id, attr_len, cur_idx, attr_list_len);
			break;
		}

		switch (attr_id) {
		case NAN_ATTR_ID_SRVC_DESC: {
			struct nan_attr_sda sda_result = {0};
			if (_parse_nan_attr_sda(attr_list + cur_idx, attr_len, &sda_result)) {
				memcpy(disc_result->service_id, sda_result.service_id, SRVC_ID_LEN);
			}
		}
		break;
		case NAN_ATTR_ID_SRVC_DESC_EXT: {
			struct nan_attr_sdea sdea_attr = {0};
			if (_parse_nan_attr_sdea(attr_list + cur_idx, attr_len, &sdea_attr)) {
				memcpy(disc_result->service_name, sdea_attr.gene_srvc_info.service_name, MAX_SRVC_NAME_LEN);
				memcpy(disc_result->service_inst, sdea_attr.gene_srvc_info.service_inst, MAX_SRVC_INST_LEN);
				disc_result->port_number = sdea_attr.gene_srvc_info.port_number;
				disc_result->trans_proto = sdea_attr.gene_srvc_info.trans_proto;
				disc_result->text_info_len = sdea_attr.gene_srvc_info.text_info_len;
				memset(disc_result->text_info, 0, sizeof(disc_result->text_info));
				memcpy(disc_result->text_info,
					   sdea_attr.gene_srvc_info.text_info,
					   sdea_attr.gene_srvc_info.text_info_len);
			}
		}
		break;
		default:
			DEBUG_PRINT("[rtw_event] nan attr_id(0x%02x), attr_len(%d) skip\n",
						attr_id, attr_len);
			break;
		}
		cur_idx += (3 + attr_len);
	}
}

/* Each callback owns a complete vendor payload; no text files or reader
 * rotation can interrupt delivery of NDP confirmation/establishment events.
 * Variable-length events may first read their fixed header, then the full body.
 */
static bool _copy_evt_data(void *dst, size_t size,
			   const void *payload, size_t payload_len)
{
	if (!dst || size > payload_len) {
		INFO_PRINT("[rtw_event] short vendor payload: %zu/%zu bytes\n",
				   payload_len, size);
		return false;
	}
	memcpy(dst, payload, size);
	return true;
}

static void _evt_handler(int evt_id, const void *payload, size_t payload_len)
{
	void *tmp_data;

	if (evt_id >= RTW_VENDOR_EVT_MAX) {
		INFO_PRINT("[rtw_event] evt id(%d) >= MAX(%d)\n", evt_id, RTW_VENDOR_EVT_MAX);
		return;
	}

	switch (evt_id) {
	case RTW_VENDOR_EVT_NAN_DATA_COMFIRM: {
		struct vendor_evt_data_confirm_info evt_data = {0};
		struct nan_evt_data_confirm_info confirm_result = {0};
		struct nan_generic_srvc_proto gene_srvc = {0};

		if (!_copy_evt_data((char *)(&evt_data), sizeof(evt_data), payload, payload_len)) {
			break;
		}
		_print_data_confirm_evt(&evt_data);

		confirm_result.type = evt_data.type;
		confirm_result.status = evt_data.status;
		confirm_result.ndp_id = evt_data.ndp_id;
		confirm_result.mc_id = evt_data.mc_id;
		confirm_result.nmsg_id = evt_data.nmsg_id;
		memcpy(confirm_result.initiator_data_address, evt_data.initiator_data_address, ETH_ALEN);
		memcpy(confirm_result.responder_data_address, evt_data.responder_data_address, ETH_ALEN);
		if (_parse_nan_attr_srvc_info(evt_data.srvc_info, evt_data.srvc_info_len, &gene_srvc)) {
			confirm_result.port_number = gene_srvc.port_number;
			confirm_result.trans_proto = gene_srvc.trans_proto;
			memset(confirm_result.host_name, '\0', sizeof(confirm_result.host_name));
			memcpy(confirm_result.host_name, gene_srvc.service_inst, MAX_SRVC_INST_LEN);
		}

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DATA_CONFIRM, (void *)(&confirm_result), sizeof(confirm_result));
		}
	}
	break;
	case RTW_VENDOR_EVT_NAN_CLUSTER_CHANGED: {
		struct rtw_nan_cluster_changed_event_data evt_data = {0};
		size_t size = sizeof(struct rtw_nan_cluster_changed_event_data);
		struct nan_evt_cluster_changed_info cluster_info = {0};

		if (!_copy_evt_data((char *)(&evt_data), sizeof(evt_data), payload, payload_len)) {
			break;
		}
		PRINT_DBG_ADDR("[rtw_event] cluster_id", cluster_info.cluster_id);

		memcpy(cluster_info.cluster_id, evt_data.cluster_id.ether_addr_octet, ETH_ALEN);
		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_CLUSTER_CHANGE, (void *)(&cluster_info), sizeof(cluster_info));
		}
	}
	break;
	case RTW_VENDOR_EVT_NAN_DISC_RESULT_RECEIVED: {
		struct rtw_nan_discovery_result_received_event_data *p_evt_data = NULL;
		size_t size = sizeof(struct rtw_nan_discovery_result_received_event_data);
		struct nan_evt_disc_result_info disc_result = {0};

		/* note: free the memory at the end of case */
		p_evt_data = (struct rtw_nan_discovery_result_received_event_data *)calloc(1, size);

		/* get the attr len */
		if (!_copy_evt_data((char *)p_evt_data, size, payload, payload_len)) {
			free(p_evt_data);
			break;
		}
		/* realloc memory for attr list */
		if (p_evt_data->publish_attribute_list_length) {
			size = offsetof(struct rtw_nan_discovery_result_received_event_data, publish_attribute_list[0]) +
				   p_evt_data->publish_attribute_list_length;
			tmp_data = realloc(p_evt_data, size);
			if (tmp_data == NULL) {
				free(p_evt_data);
				p_evt_data = NULL;
				break;
			}
			p_evt_data = (struct rtw_nan_discovery_result_received_event_data *)tmp_data;
			memset(p_evt_data, 0, size);
			if (!_copy_evt_data((char *)p_evt_data, size, payload, payload_len)) {
				free(p_evt_data);
				break;
			}
		}

		/* print original event data */
		_print_disc_result_evt(p_evt_data);

		/* convert to struct nan_evt_disc_result_info */
		disc_result.subscirbe_id = p_evt_data->subscribe_id;
		disc_result.publish_id = p_evt_data->publisher_id;
		memcpy(disc_result.peer_nmi, p_evt_data->peer_nan_address.ether_addr_octet, ETH_ALEN);
		disc_result.peer_rssi = p_evt_data->publish_rssi;
		disc_result.channel = p_evt_data->channel.channel;
		if (p_evt_data->cipher_suite_id & BIT(NAN_CIPHER_SUITE_BIT_NCS_SK_128)) {
			disc_result.pmk_set = true;
		}
		if (p_evt_data->cipher_suite_id & BIT(NAN_CIPHER_SUITE_BIT_NCS_PASN_128)) {
			disc_result.pairing_enable = true;
		}
		disc_result.nira_paired = p_evt_data->nira_paired;

		// csid should be parsed from the nan attr
		_parse_disc_result_nan_attr(p_evt_data->publish_attribute_list,
									p_evt_data->publish_attribute_list_length,
									&disc_result);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DISCOVERY_RESULT, (void *)&disc_result, sizeof(disc_result));
		}

		free(p_evt_data);
	}
	break;
	case RTW_VENDOR_EVT_NAN_DATAPATH_REQ_RECEIVED: {
		struct rtw_nan_datapath_request_received_event_data *p_evt_data = NULL;
		size_t size = sizeof(struct rtw_nan_datapath_request_received_event_data);

		/* note: free the memory at the end of case */
		p_evt_data = (struct rtw_nan_datapath_request_received_event_data *)calloc(1, size);

		/* get the attr len */
		if (!_copy_evt_data((char *)p_evt_data, size, payload, payload_len)) {
			free(p_evt_data);
			break;
		}
		/* realloc memory for attr list */
		if (p_evt_data->attribute_list_length) {
			size = offsetof(struct rtw_nan_datapath_request_received_event_data, attribute_list[0]) +
				   p_evt_data->attribute_list_length;
			tmp_data = realloc(p_evt_data, size);
			if (tmp_data == NULL) {
				free(p_evt_data);
				p_evt_data = NULL;
				break;
			}
			p_evt_data = (struct rtw_nan_datapath_request_received_event_data *)tmp_data;
			memset(p_evt_data, 0, size);
			if (!_copy_evt_data((char *)p_evt_data, size, payload, payload_len)) {
				free(p_evt_data);
				break;
			}
		}

		_print_datapath_req_recv_evt(p_evt_data);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DATAPATH_RECV_REQ, (void *)p_evt_data, size);
		}

		free(p_evt_data);
	}
	break;
	case RTW_VENDOR_EVT_NAN_DATAPATH_RSP_RECEIVED: {
		struct rtw_nan_datapath_response_received_event_data *p_evt_data = NULL;
		size_t size = sizeof(struct rtw_nan_datapath_response_received_event_data);

		/* note: free the memory at the end of case */
		p_evt_data = (struct rtw_nan_datapath_response_received_event_data *)calloc(1, size);

		/* get the attr len */
		if (!_copy_evt_data((char *)p_evt_data, size, payload, payload_len)) {
			free(p_evt_data);
			break;
		}
		/* realloc memory for attr list */
		if (p_evt_data->attribute_list_length) {
			size = offsetof(struct rtw_nan_datapath_response_received_event_data, attribute_list[0]) +
				   p_evt_data->attribute_list_length;
			tmp_data = realloc(p_evt_data, size);
			if (tmp_data == NULL) {
				free(p_evt_data);
				p_evt_data = NULL;
				break;
			}
			p_evt_data = (struct rtw_nan_datapath_response_received_event_data *)tmp_data;
			memset(p_evt_data, 0, size);
			if (!_copy_evt_data((char *)p_evt_data, size, payload, payload_len)) {
				free(p_evt_data);
				break;
			}
		}

		_print_datapath_rsp_recv_evt(p_evt_data);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DATAPATH_RECV_RSP, (void *)p_evt_data, size);
		}

		free(p_evt_data);
	}
	break;
	case RTW_VENDOR_EVT_NAN_DATAPATH_ESTABLISHED: {
		struct rtw_nan_datapath_established_event_data evt_data = {0};
		struct nan_evt_data_established_info info = {0};

		if (!_copy_evt_data((char *)(&evt_data), sizeof(evt_data), payload, payload_len)) {
			break;
		}
		_print_datapath_established_evt(&evt_data);

		info.publish_id = evt_data.pub_id;
		info.type = evt_data.type;
		info.ndp_id = evt_data.datapath_id;
		memcpy(info.responder_data_address, evt_data.responder_data_address.ether_addr_octet, ETH_ALEN);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DATAPATH_ESTABLISHED, (void *)(&info), sizeof(info));
		}
	}
	break;
	case RTW_VENDOR_EVT_NAN_DATAPATH_END: {
		struct rtw_nan_datapath_end_event_data evt_data = {0};
		struct nan_evt_data_end_info info = {0};

		if (!_copy_evt_data((char *)(&evt_data), sizeof(evt_data), payload, payload_len)) {
			break;
		}

		info.ndp_id = evt_data.datapath_id;
		info.publish_id = evt_data.publish_id;
		info.reason = evt_data.reason;

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DATAPATH_END, (void *)(&info), sizeof(info));
		}
	}
	break;
	case RTW_VENDOR_EVT_NAN_FOLLOW_UP_RECEIVED: {
		struct rtw_nan_follow_up_received_event_data *p_evt_data = NULL;
		size_t size = sizeof(struct rtw_nan_follow_up_received_event_data);

		/* note: free the memory at the end of case */
		p_evt_data = (struct rtw_nan_follow_up_received_event_data *)calloc(1, size);

		/* get the attr len */
		if (!_copy_evt_data((char *)p_evt_data, size, payload, payload_len)) {
			free(p_evt_data);
			break;
		}
		/* realloc memory for attr list */
		if (p_evt_data->attribute_list_length) {
			size = offsetof(struct rtw_nan_follow_up_received_event_data, attribute_list[0]) +
				   p_evt_data->attribute_list_length;
			tmp_data = realloc(p_evt_data, size);
			if (tmp_data == NULL) {
				free(p_evt_data);
				p_evt_data = NULL;
				break;
			}
			p_evt_data = (struct rtw_nan_follow_up_received_event_data *)tmp_data;
			memset(p_evt_data, 0, size);
			if (!_copy_evt_data((char *)p_evt_data, size, payload, payload_len)) {
				free(p_evt_data);
				break;
			}
		}

		_print_datapth_follow_up_recv_evt(p_evt_data);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DATAPATH_RECV_FOLLOW_UP, (void *)p_evt_data, size);
		}

		free(p_evt_data);
	}
	break;
	case RTW_VENDOR_EVT_NAN_DATA_INDICATION: {
		struct vendor_evt_data_indication_info evt_data = {0};
		struct nan_evt_data_indication_info indic_result = {0};
		if (!_copy_evt_data((char *)(&evt_data), sizeof(evt_data), payload, payload_len)) {
			break;
		}
		_print_data_indication_evt(&evt_data);

		indic_result.type = evt_data.type;
		indic_result.publish_id = evt_data.publish_id;
		indic_result.ndp_id = evt_data.ndp_id;
		indic_result.mc_id = evt_data.mc_id;
		memcpy(indic_result.initiator_data_address, evt_data.initiator_data_address, ETH_ALEN);
		memcpy(indic_result.responder_data_address, evt_data.responder_data_address, ETH_ALEN);
		indic_result.security = evt_data.security;
		memcpy(indic_result.ipv6_interfac_id, evt_data.ipv6_interfac_id, MAX_IPV6_INFO_LEN);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DATA_INDICATION, (void *)(&indic_result), sizeof(indic_result));
		}
	}
	break;
	case RTW_VENDOR_EVT_NAN_PASN_START:
	case RTW_VENDOR_EVT_NAN_PASN_RX:
		/* These carry PASN Authentication frames. A NAN-aware supplicant must
		 * process them and return the Authentication response and derived keys. */
		break;
	case RTW_VENDOR_EVT_NAN_BSTRAP_RESULT: {
		struct vendor_evt_bstrap_result evt_data = {0};
		struct nan_evt_bstrap_result bstrap_result = {0};

		if (!_copy_evt_data((char *)(&evt_data), sizeof(evt_data), payload, payload_len)) {
			break;
		}
		_print_data_bstrap_res_evt(&evt_data);

		if (IS_BSTRAP_TYPE_REQ(evt_data.type_status)) {
			bstrap_result.local_role = PAIRING_ROLE_INITIATOR;
		} else {
			bstrap_result.local_role = PAIRING_ROLE_RESPONDER;
		}
		bstrap_result.status = GET_BSTRAP_STATUS(evt_data.type_status);
		bstrap_result.remote_inst_id = evt_data.remote_inst_id;
		bstrap_result.local_inst_id = evt_data.local_inst_id;
		bstrap_result.bstrap_method = evt_data.rsp_bstrap_method;
		memcpy(bstrap_result.peer_nmi, evt_data.peer_nmi, ETH_ALEN);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_BSTRAP_RESULT, (void *)(&bstrap_result), sizeof(bstrap_result));
		}
	}
	break;
	case RTW_VENDOR_EVT_NAN_PASN_RESULT: {
		struct vendor_evt_pasn_result evt_data = {0};
		struct nan_evt_pasn_result pasn_result = {0};
		if (!_copy_evt_data((char *)(&evt_data), sizeof(evt_data), payload, payload_len)) {
			break;
		}
		_print_data_pasn_res_evt(&evt_data);

		pasn_result.status = evt_data.status;
		pasn_result.local_role = evt_data.local_role;
		pasn_result.pairing_type = evt_data.pairing_type;
		pasn_result.remote_nik_caching = evt_data.remote_nik_caching;
		memcpy(pasn_result.peer_nmi, evt_data.peer_nmi, ETH_ALEN);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_PASN_RESULT, (void *)(&pasn_result), sizeof(pasn_result));
		}
	}
	break;
	case RTW_VENDOR_EVT_NAN_PASN_UPD_PMKID: {
		struct vendor_evt_pasn_upd_pmkid evt_data = {0};
		if (!_copy_evt_data((char *)(&evt_data), sizeof(evt_data), payload, payload_len)) {
			break;
		}
		_print_data_recv_pasn_upd_pmkid(&evt_data);
		/* tmp remove as update pmkid evt is not used currently. */
#if 0
		struct nan_evt_data_recv_shared_key shared_key = {0};

		shared_key.role = evt_data.role;
		shared_key.status = evt_data.status;
		memcpy(shared_key.peer_nmi, evt_data.peer_nmi, ETH_ALEN);

		if (g_nan_evt_cb) {
			g_nan_evt_cb(NAN_EVT_DATA_SHARED_KEY, (void *)(&shared_key), sizeof(shared_key));
		}
#endif
	}
	break;
	case RTW_VENDOR_EVT_NAN_NIK_CACHE: {
		struct nan_nik_cache_data nik_cache_data;
		if (!_copy_evt_data((char *)&nik_cache_data, sizeof(nik_cache_data), payload, payload_len)) {
			break;
		}
		mkdir("/var/lib/nan", 0700);
		if (!nan_cache_write_atomic("/var/lib/nan/nik_cache", &nik_cache_data,
					    sizeof(nik_cache_data))) {
			INFO_PRINT("[rtw_event] save nik cache data\n");
		} else {
			INFO_PRINT("[rtw_event] failed to save nik cache data\n");
		}
		break;
	}
	default:
		DEBUG_PRINT("[rtw_event] evt id(%d) not handle.\n", evt_id);
		break;
	}
}

static int _vendor_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *genl;
	struct nlattr *attrs[NL80211_ATTR_MAX + 1];
	unsigned int event_id;
	(void)arg;

	if (!genlmsg_valid_hdr(hdr, 0))
		return NL_SKIP;
	genl = nlmsg_data(hdr);
	if (genl->cmd != NL80211_CMD_VENDOR ||
		genlmsg_parse(hdr, 0, attrs, NL80211_ATTR_MAX, NULL) < 0)
		return NL_SKIP;
	if (!attrs[NL80211_ATTR_VENDOR_ID] ||
		nla_len(attrs[NL80211_ATTR_VENDOR_ID]) != 4 ||
		nla_get_u32(attrs[NL80211_ATTR_VENDOR_ID]) != 0xe04c ||
		!attrs[NL80211_ATTR_VENDOR_SUBCMD] ||
		nla_len(attrs[NL80211_ATTR_VENDOR_SUBCMD]) != 4 ||
		!attrs[NL80211_ATTR_IFINDEX] ||
		nla_len(attrs[NL80211_ATTR_IFINDEX]) != 4 ||
		nla_get_u32(attrs[NL80211_ATTR_IFINDEX]) != g_evt_ifindex ||
		!attrs[NL80211_ATTR_VENDOR_DATA])
		return NL_SKIP;
	event_id = nla_get_u32(attrs[NL80211_ATTR_VENDOR_SUBCMD]);
	if (event_id >= RTW_VENDOR_EVT_MAX)
		return NL_SKIP;
	_evt_handler(event_id, nla_data(attrs[NL80211_ATTR_VENDOR_DATA]),
			 nla_len(attrs[NL80211_ATTR_VENDOR_DATA]));
	return NL_OK;
}

static void *_wait_evt_thread(void *arg)
{
	struct pollfd fds[2] = {
		{.fd = nl_socket_get_fd(g_evt_sock), .events = POLLIN},
		{.fd = g_evt_wake[0], .events = POLLIN}
	};
	int ret;
	(void)arg;

	for (;;) {
		ret = poll(fds, 2, -1);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 || fds[1].revents)
			break;
		if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			INFO_PRINT("[rtw_event] vendor event socket error\n");
			break;
		}
		if (fds[0].revents & POLLIN) {
			ret = nl_recvmsgs_default(g_evt_sock);
			if (ret < 0 && ret != -NLE_AGAIN && ret != -NLE_INTR)
				INFO_PRINT("[rtw_event] receive error: %s\n", nl_geterror(ret));
		}
	}
	return NULL;
}

int rtw_nan_evt_init(void)
{
	int group, ret;

	if (g_evt_sock)
		return true;
	g_evt_ifindex = nan_intf ? if_nametoindex(nan_intf) : 0;
	if (!g_evt_ifindex)
		return false;
	g_evt_sock = nl_socket_alloc();
	if (!g_evt_sock || genl_connect(g_evt_sock) < 0)
		goto fail;
	group = genl_ctrl_resolve_grp(g_evt_sock, "nl80211", "vendor");
	if (group < 0 || nl_socket_add_membership(g_evt_sock, group) < 0)
		goto fail;
	/* Keep bursts queued while a callback executes a vendor command. */
	if (nl_socket_set_buffer_size(g_evt_sock, 1024 * 1024, 0) < 0)
		INFO_PRINT("[rtw_event] using default receive buffer size\n");
	nl_socket_disable_seq_check(g_evt_sock);
	if (nl_socket_modify_cb(g_evt_sock, NL_CB_VALID, NL_CB_CUSTOM,
				   _vendor_event, NULL) < 0 ||
		nl_socket_set_nonblocking(g_evt_sock) < 0 || pipe(g_evt_wake) < 0)
		goto fail;
	ret = pthread_create(&g_evt_thread, NULL, _wait_evt_thread, NULL);
	if (ret) {
		INFO_PRINT("[rtw_event] thread create failed: %s\n", strerror(ret));
		goto fail;
	}
	INFO_PRINT("[rtw_event] continuous vendor events on %s (ifindex %u)\n",
			   nan_intf, g_evt_ifindex);
	return true;
fail:
	INFO_PRINT("[rtw_event] cannot start vendor event receiver\n");
	if (g_evt_sock)
		nl_socket_free(g_evt_sock);
	g_evt_sock = NULL;
	for (int i = 0; i < 2; i++) {
		if (g_evt_wake[i] >= 0)
			close(g_evt_wake[i]);
		g_evt_wake[i] = -1;
	}
	return false;
}

void rtw_nan_evt_reinit(void)
{
	/* Retain the exported API, but never unsubscribe a running receiver. */
	if (!g_evt_sock)
		rtw_nan_evt_init();
}

void rtw_nan_evt_deinit(void)
{
	if (!g_evt_sock)
		return;
	/* Wake only our receiver; do not kill unrelated iw commands/readers. */
	while (write(g_evt_wake[1], "x", 1) < 0 && errno == EINTR)
		;
	pthread_join(g_evt_thread, NULL);
	nl_socket_free(g_evt_sock);
	g_evt_sock = NULL;
	close(g_evt_wake[0]);
	close(g_evt_wake[1]);
	g_evt_wake[0] = g_evt_wake[1] = -1;
	INFO_PRINT("[rtw_event] deinit complete.\n");
}

void rtw_nan_evt_send(uint8_t id, void *buf, uint32_t len)
{
	if (id >= NAN_EVT_MAX) {
		INFO_PRINT("[rtw_event] error: send evt id(%d)\n", id);
		return;
	}
	DEBUG_PRINT("[rtw_event] send evt id(%d), len(%d)\n", id, len);
	if (g_nan_evt_cb) {
		g_nan_evt_cb(id, buf, len);
	}
}

void rtw_nan_api_register_evt_cb(rtw_nan_evt_cb cb)
{
	g_nan_evt_cb = cb;
}
