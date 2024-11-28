#include "driver_at24cxx_basic.h"
#include "example_mofang_v10.h"
#include "os_wrapper.h"
#include "sys_api.h"
#include <stdlib.h>
#include "wifi_fast_connect.h"
#include "wifi_intf_drv_to_app_basic.h"
#include "lwip_netconf.h"
#include "mbedtls/md.h"
#include "MQTTClient.h"
#include "cJSON.h"
#include "rtc_api.h"
#include <time.h>

static void bootstrap_youzhiyun(void);

static void dhcp_client_routine(void *args)
{
    (void) args;

#ifdef CONFIG_LWIP_LAYER
    for (;;) {
        /* Start DHCPClient */
        if (LwIP_DHCP(0, DHCP_START) == DHCP_ADDRESS_ASSIGNED) {
            break;
        }
        rtos_time_delay_ms(1000);
    }
#endif

    static int init;
    if (!init) {
        bootstrap_youzhiyun();
        init = 1;
    }
    
    rtos_task_delete(NULL);
}

void start_dhcp_client(void)
{
    rtos_task_create(NULL, ((const char *)"dhcp_client"), dhcp_client_routine, NULL, 1024 * 2, 1);
}

static struct rtw_scan_result* get_maximum_rssi_ap(char *scan_buf, int scanned_ap_num)
{
    struct rtw_scan_result *best_ap = (struct rtw_scan_result*)scan_buf;
    for (int i = 1; i < scanned_ap_num; i++) {
        struct rtw_scan_result *scanned_ap_info = (struct rtw_scan_result *)(scan_buf + i * sizeof(struct rtw_scan_result));
        if (best_ap->signal_strength < scanned_ap_info->signal_strength) {
            best_ap = scanned_ap_info;
        }
    }
    return best_ap;
}

static int try_to_connect_wifi(const char *ssid, const char *psk_passphrase)
{
    int ret = 0;
    struct _rtw_scan_param_t scan_param;
    memset(&scan_param, 0, sizeof(struct _rtw_scan_param_t));
	scan_param.ssid = (char*)ssid;
    int scanned_ap_num = wifi_scan_networks(&scan_param, 1);
    if (scanned_ap_num > 0) {
        char *scan_buf = (char *)rtos_mem_zmalloc(scanned_ap_num * sizeof(struct rtw_scan_result));
        if (scan_buf) {
            if (wifi_get_scan_records((unsigned int *)(&scanned_ap_num), scan_buf) >= 0) {
                struct rtw_scan_result *best_ap = get_maximum_rssi_ap(scan_buf, scanned_ap_num);
                if (best_ap) {
                    struct _rtw_network_info_t wifi = { 0 };
                    memcpy(&wifi.ssid, &best_ap->SSID, sizeof(struct _rtw_ssid_t));
                    memcpy(&wifi.bssid, &best_ap->BSSID, sizeof(struct _rtw_mac_t));
                    wifi.security_type = best_ap->security;
                    wifi.password = (unsigned char*)psk_passphrase;
                    wifi.password_len = strlen(psk_passphrase);
                    wifi.channel = best_ap->channel;
                    wifi.pscan_option = PSCAN_FAST_SURVEY;
                    ret = wifi_connect(&wifi, 1);
                    if (ret == RTW_SUCCESS) {
                        ret = 1;
                    }
                    start_dhcp_client();
                }
            }
            rtos_mem_free(scan_buf);
        }
    }

    return ret;
}

static void wifi_connect_routine(void *args)
{
    (void) args;

    char ssid[WIFI_SSID_LEN] = { 0 };
    char psk_passphrase[WIFI_PASSWORD_LEN] = { 0 };
    at24cxx_basic_read(WIFI_SSID_ADDR, (uint8_t*)ssid, WIFI_SSID_LEN);
    at24cxx_basic_read(WIFI_PASSWORD_ADDR, (uint8_t*)psk_passphrase, WIFI_PASSWORD_LEN);

    printf("ssid=%s psk=%s\n", ssid, psk_passphrase);

    for (;;) {
        if (try_to_connect_wifi(ssid, psk_passphrase)) {
            break;
        }
        rtos_time_delay_ms(3000);
    }

    rtos_task_delete(NULL);
}

static void start_wifi_connect_routine(void)
{
    rtos_task_create(NULL, ((const char *)"wifi_connect"), wifi_connect_routine, NULL, 1024 * 4, 1);
}

int my_wifi_do_fast_connect(void)
{
    extern int wifi_do_fast_connect(void);

    wifi_config_autoreconnect(RTW_AUTORECONNECT_INFINITE);
    wifi_do_fast_connect();
    
    if (wifi_get_join_status() != RTW_JOINSTATUS_SUCCESS) {
        start_wifi_connect_routine();
    }

    return 0;
}

#pragma pack(1)
struct yzy_config_item {
    uint8_t checksum;
    uint8_t len;
    uint8_t data[1];
};
#pragma pack()

static char* yzy_config_read_string(int addr, char *buf, int len)
{
    at24cxx_basic_read(addr, (uint8_t*)buf, len);
    struct yzy_config_item *item = (struct yzy_config_item*)buf;

    if (len - 2 >= item->len) {
        uint8_t checksum = 0;
        for (int i = 1; i < buf[1]; i++) {
			checksum += buf[i];
		}
		checksum += 0x01;

        if (checksum == buf[0]) {
            len = item->len;
            memmove(buf, item->data, item->len);
            buf[len] = 0;
            return buf;
        }
    }

    memset(buf, 0, len);
    return NULL;
}

struct mqtt_client_routine_args {
    const char *host;
    int port;
    const char *client_id;
    const char *username;
    const char *password;
    const char *product_key;
    const char *device_name;
    const char *user_get_topic;
    const char *ntp_response_topic;
    const char *ntp_request_topic;
    rtos_queue_t publish_args_queue;
};

static void on_mqtt_message_recv(MessageData *data, void *param)
{
    (void) param;

    char *topic = rtos_mem_zmalloc(data->topicName->lenstring.len + 1);
    memcpy(topic, data->topicName->lenstring.data, data->topicName->lenstring.len);
    topic[data->topicName->lenstring.len] = 0;

    char *payload = rtos_mem_zmalloc(data->message->payloadlen + 1);
    memcpy(payload, data->message->payload, data->message->payloadlen);
    payload[data->message->payloadlen] = 0;

    printf("aliyun >> %s: %s\n", topic, payload);

    struct mqtt_client_routine_args *args = param;
    if (strcmp(args->ntp_response_topic, topic) == 0) {
        
        time_t device_recv_time = rtos_time_get_current_system_time_ms();
        
        cJSON *root = cJSON_Parse(data->message->payload);
        if (root) {
            cJSON *device_send_time_node = cJSON_GetObjectItem(root, "deviceSendTime");
            cJSON *server_send_time_node = cJSON_GetObjectItem(root, "serverSendTime");
            cJSON *server_recv_time_node = cJSON_GetObjectItem(root, "serverRecvTime");
            if (cJSON_IsString(device_send_time_node) && cJSON_IsString(server_send_time_node) && cJSON_IsString(server_recv_time_node)) {

                const char *fmt = sizeof(time_t) == 4 ? "%" PRIu32 : "%" PRIu64;
                
                time_t device_send_time, server_send_time, server_recv_time;
                sscanf(device_send_time_node->valuestring, fmt, &device_send_time);
                sscanf(server_send_time_node->valuestring, fmt, &server_send_time);
                sscanf(server_recv_time_node->valuestring, fmt, &server_recv_time);

                time_t now_ms = server_recv_time;
                now_ms += server_send_time;
                now_ms += device_recv_time;
                now_ms -= device_send_time;
                now_ms /= 2;

                time_t now = now_ms / 1000;
                rtc_write(now);

                struct tm *timeinfo = localtime(&now);
                printf("Time Synced: %d-%02d-%02d %02d:%02d:%02d\n", timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
            }
            cJSON_Delete(root);
        }
    }

    rtos_mem_free(topic);
    rtos_mem_free(payload);
}

static void start_mqtt_client_rpc_server(struct mqtt_client_routine_args *args, int rpc_server_fd)
{
    Network network;
    NetworkInit(&network);
    network.rpc_server_fd = rpc_server_fd;
    for (;;) {
        int ret = NetworkConnect(&network, (char*)args->host, args->port);
        if (ret == 0) {
            break;
        }
        else {
            mqtt_printf(MQTT_ERROR, "NetworkConnect(): %d", ret);
        }
        rtos_time_delay_ms(1000);
    }

    MQTTPacket_connectData connect_data = MQTTPacket_connectData_initializer;
    connect_data.MQTTVersion = 4;
	connect_data.clientID.cstring = (char *)args->client_id;
    connect_data.username.cstring = (char *)args->username;
    connect_data.password.cstring = (char *)args->password;

    MQTTClient client;
    int read_buf_len = 4096;
    int send_buf_len = 4096;
    uint8_t *read_buf = rtos_mem_zmalloc(read_buf_len);
    uint8_t *send_buf = rtos_mem_zmalloc(send_buf_len);
    MQTTClientInit(&client, &network, 30000, send_buf, send_buf_len, read_buf, read_buf_len);
    client.defaultMessageHandler = on_mqtt_message_recv;
    client.cb = args;

    int ret = MQTTConnect(&client, &connect_data);
    if (ret == 0) {
        if ((ret = MQTTSubscribe(&client, args->user_get_topic, QOS0, NULL)) == 0) {
            for (;;) {
                if (ret == 0 || network.rpc_server_has_data) {
                    for (;;) {
                        int dummy_data;
                        if (recvfrom(network.rpc_server_fd, &dummy_data, sizeof dummy_data, 0, NULL, NULL) < 0) {
                            break;
                        }
                    }

                    for (;;) {
                        struct mqtt_client_publish_args *publish_args;
                        if (rtos_queue_receive(args->publish_args_queue, &publish_args, 0) == SUCCESS) {

                            printf("aliyun << %s: %s\n", publish_args->topic, publish_args->data);

                            MQTTMessage msg = {
                                .dup = publish_args->dup,
                                .payload = publish_args->data,
                                .payloadlen = publish_args->len,
                                .qos = publish_args->qos,
                                .retained = publish_args->retained,
                            };
                            MQTTPublish(&client, publish_args->topic, &msg);
                            rtos_mem_free(publish_args);
                        }
                        else {
                            break;
                        }
                    }
                }
                else {
                    mqtt_printf(MQTT_ERROR, "MQTTYield(): %d", ret);
                    break;
                }
                ret = MQTTYield(&client, portMAX_DELAY);
            }
        }
        else {
            mqtt_printf(MQTT_ERROR, "MQTTSubscribe(): %d", ret);
        }
    }
    else {
        mqtt_printf(MQTT_ERROR, "MQTTConnect(): %d", ret);
    }

    rtos_mem_free(read_buf);
    rtos_mem_free(send_buf);
}

static void start_mqtt_client_routine(struct mqtt_client_routine_args *args);

static void mqtt_client_routine(void *p)
{
    struct mqtt_client_routine_args *args = p;

    printf("host=%s\n", args->host);
    printf("port=%d\n", args->port);
    printf("client_id=%s\n", args->client_id);
    printf("username=%s\n", args->username);
    printf("password=%s\n", args->password);
    printf("product_key=%s\n", args->product_key);
    printf("device_name=%s\n", args->device_name);

    int rpc_server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rpc_server_fd >= 0) {

        int reuse = 1;
        setsockopt(rpc_server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);

        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            .sin_port = htons(RPC_PORT),
        };
        socklen_t addrlen = sizeof addr;

        if (bind(rpc_server_fd, (struct sockaddr*)&addr, addrlen) == 0) {
            fcntl(rpc_server_fd, F_SETFL, fcntl(rpc_server_fd, F_GETFL, 0) | O_NONBLOCK);
            start_mqtt_client_rpc_server(args, rpc_server_fd);
            closesocket(rpc_server_fd);
        }
        else {
            rpc_server_log_error("bind(): %d", errno);
        }
        
        closesocket(rpc_server_fd);

        rtos_time_delay_ms(1000);
    }
    else {
        rpc_server_log_error("socket(): %d", errno);
    }
    start_mqtt_client_routine(args);

    rtos_task_delete(NULL);
}

static void start_mqtt_client_routine(struct mqtt_client_routine_args *args)
{
    rtos_task_create(NULL, ((const char *)"mqtt_client"), mqtt_client_routine, args, 1024 * 4, 1);
}

void mqtt_ntp_client_routine(void *p)
{
    struct mqtt_client_routine_args *args = p;

    int rpc_client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rpc_client_fd >= 0) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            .sin_port = htons(RPC_PORT),
        };
        socklen_t addrlen = sizeof addr;
        if (connect(rpc_client_fd, (struct sockaddr*)&addr, addrlen) == 0) {
            for (;;) {
                const char *ntp_request_fmt = "{\"deviceSendTime\":\"%d\"}";
                struct mqtt_client_publish_args *publish_args = rtos_mem_zmalloc(strlen(ntp_request_fmt) + 22 + offsetof(struct mqtt_client_publish_args, data));
                publish_args->len = sprintf(publish_args->data, ntp_request_fmt, (int)rtos_time_get_current_system_time_ms());
                publish_args->topic = args->ntp_request_topic;
                publish_args->qos = 0;
                publish_args->retained = 0;
                publish_args->dup = 0;

                rtos_queue_send(args->publish_args_queue, &publish_args, 0);

                int dummy_data;
                if (send(rpc_client_fd, &dummy_data, sizeof dummy_data, 0) >= 0) {
                    printf("ntp request sent\n");
                }
                else {
                    rpc_client_log_error("send(): %d", errno);
                }

                rtos_time_delay_ms(1000 * 5);
            }
        }
        else {
            rpc_client_log_error("connect(): %d", errno);
        }

        closesocket(rpc_client_fd);
    }
    else {
        rpc_client_log_error("socket(): %d", errno);
    }
    
    rtos_task_delete(NULL);
}

static void start_mqtt_ntp_client_routine(struct mqtt_client_routine_args *args)
{
    rtos_task_create(NULL, ((const char *)"mqtt_ntp_client"), mqtt_ntp_client_routine, args, 1024, 1);
}

static void start_mqtt_client(const char *host, int port, const char *client_id, const char *username, const char *password, const char *product_key, const char *device_name)
{
    struct mqtt_client_routine_args *args = rtos_mem_zmalloc(sizeof(struct mqtt_client_routine_args));
    args->host = host;
    args->port = port;
    args->client_id = client_id;
    args->username = username;
    args->password = password;
    args->product_key = product_key;
    args->device_name = device_name;

    const char *user_get_topic_fmt = "/%s/%s/user/get";
    args->user_get_topic = rtos_mem_zmalloc(strlen(user_get_topic_fmt) + strlen(args->product_key) + strlen(args->device_name));
    sprintf((char*)(args->user_get_topic), user_get_topic_fmt, args->product_key, args->device_name);

    const char *ntp_response_topic_fmt = "/ext/ntp/%s/%s/response";
    args->ntp_response_topic = rtos_mem_zmalloc(strlen(ntp_response_topic_fmt) + strlen(args->product_key) + strlen(args->device_name));
    sprintf((char*)(args->ntp_response_topic), ntp_response_topic_fmt, args->product_key, args->device_name);

    const char *ntp_request_topic_fmt = "/ext/ntp/%s/%s/request";
    args->ntp_request_topic = rtos_mem_zmalloc(strlen(ntp_request_topic_fmt) + strlen(args->product_key) + strlen(args->device_name));
    sprintf((char*)(args->ntp_request_topic), ntp_request_topic_fmt, args->product_key, args->device_name);

    start_mqtt_client_routine(args);

    rtos_queue_create(&args->publish_args_queue, 10, sizeof(struct mqtt_client_publish_args*));
    start_mqtt_ntp_client_routine(args);
}

static void bootstrap_youzhiyun_routine(void *args)
{
    (void) args;

    char *appkey = rtos_mem_zmalloc(d_yzy_appkey_addr_len);
    yzy_config_read_string(d_yzy_appkey_addr, appkey, d_yzy_appkey_addr_len);

    printf("appkey=%s\n", appkey);
    
    rtos_mem_free(appkey);

    char *product_key = rtos_mem_zmalloc(d_yzy_product_key_addr_len);
    char *device_name = rtos_mem_zmalloc(d_yzy_device_name_addr_len);
    char *device_secret = rtos_mem_zmalloc(d_yzy_device_key_addr_len);
    const char *timestamp = "588";

    yzy_config_read_string(d_yzy_product_key_addr, product_key, d_yzy_product_key_addr_len);
    yzy_config_read_string(d_yzy_device_name_addr, device_name, d_yzy_device_name_addr_len);
    yzy_config_read_string(d_yzy_device_key_addr, device_secret, d_yzy_device_key_addr_len);

    int product_key_len = strlen(product_key);
    int device_name_len = strlen(device_name);
    int device_secret_len = strlen(device_secret);
    int timestamp_len = strlen(timestamp);

    // printf("device_secret=%s\n", device_secret);

    const char *client_id_fmt = "%s.%s|securemode=3,signmethod=hmacmd5,timestamp=%s|";
    char *client_id = rtos_mem_zmalloc(strlen(client_id_fmt) + product_key_len + device_name_len + timestamp_len);
    int client_id_len = sprintf(client_id, client_id_fmt, product_key, device_name, timestamp);

    char *username = rtos_mem_zmalloc(device_name_len + product_key_len + 2);
    int username_len = sprintf(username, "%s&%s", device_name, product_key);

    const char *password_plaintext_fmt = "clientId%s.%sdeviceName%sproductKey%stimestamp%s";
    char *password_plaintext = rtos_mem_zmalloc(strlen(password_plaintext_fmt) + product_key_len + device_name_len + device_name_len + product_key_len + timestamp_len);
    int password_plaintext_len = sprintf(password_plaintext, password_plaintext_fmt, product_key, device_name, device_name, product_key, timestamp);
    printf("password_plaintext=%s\n", password_plaintext);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    int password_digest_len = mbedtls_md_get_size(md_info);
    uint8_t *password_digest = rtos_mem_zmalloc(password_digest_len);

    mbedtls_md_hmac(md_info, (uint8_t*)device_secret, device_secret_len, (uint8_t*)password_plaintext, password_plaintext_len, password_digest);

    rtos_mem_free(device_secret);
    rtos_mem_free(password_plaintext);

    char *password = rtos_mem_zmalloc(password_digest_len * 2 + 1);
    int password_len = 0;
    for (int i = 0; i < password_digest_len; i++) {
        password_len += sprintf(password + (i * 2), "%02x", password_digest[i]);
    }

    rtos_mem_free(password_digest);

    (void) username_len;
    (void) password_len;
    (void) client_id_len;

    const char *host_fmt = "%s.iot-as-mqtt.cn-shanghai.aliyuncs.com";
    char *host = rtos_mem_zmalloc(strlen(host_fmt) + product_key_len);
    sprintf(host, host_fmt, product_key);

    start_mqtt_client(host, 1883, client_id, username, password, product_key, device_name);

    rtos_task_delete(NULL);
}

static void bootstrap_youzhiyun(void)
{
    rtos_task_create(NULL, ((const char *)"bootstrap_youzhiyun"), bootstrap_youzhiyun_routine, NULL, 1024 * 4, 1);
}

void app_pre_example(void)
{
    at24cxx_basic_init(AT24C16, AT24CXX_ADDRESS_A000);
}
