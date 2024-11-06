#include "os_wrapper.h"
#include "rtk_bt_le_gap.h"

static void ble_scan_routine(void *args)
{
    (void) args;

    rtk_bt_le_scan_param_t scan_param = {
        0
    };

    rtk_bt_le_gap_set_scan_param(&scan_param);
    rtk_bt_le_gap_start_scan();

    rtos_task_delete(NULL);
}

void app_example(void)
{
    rtos_task_create(NULL, ((const char *)"ble_scan"), ble_scan_routine, NULL, 1024 * 4, 1);
}
