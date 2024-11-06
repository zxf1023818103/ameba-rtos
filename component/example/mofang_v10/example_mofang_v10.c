#include "driver_at24cxx_basic.h"
#include "example_mofang_v10.h"
#include "os_wrapper.h"
#include "sys_api.h"
#include <stdlib.h>
#include "wifi_fast_connect.h"
#include "wifi_intf_drv_to_app_basic.h"
#include "lwip_netconf.h"

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

    rtos_task_delete(NULL);
}

static void start_dhcp_client(void)
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

    printf("ssid = %s psk = %s\n", ssid, psk_passphrase);

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

    wifi_do_fast_connect();
    
    if (wifi_get_join_status() != RTW_JOINSTATUS_SUCCESS) {
        start_wifi_connect_routine();
    }

    return 0;
}

void app_pre_example(void)
{
    at24cxx_basic_init(AT24C16, AT24CXX_ADDRESS_A000);
}

