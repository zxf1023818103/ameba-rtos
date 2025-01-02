#include "platform_stdlib.h"
#include "basic_types.h"
#include "FreeRTOS.h"
#include "task.h"

#if !defined(configSUPPORT_STATIC_ALLOCATION) || (configSUPPORT_STATIC_ALLOCATION != 1)
/* #define configSUPPORT_STATIC_ALLOCATION 1 */
#error configSUPPORT_STATIC_ALLOCATION must be defined in FreeRTOSConfig.h as 1.
#endif

extern int aws_main(void);

static void example_amazon_freertos_thread(void *pvParameters)
{
    (void) pvParameters;
    
    printf("Dleay 5 seconds to wait wifi ready\n");
    vTaskDelay(5000);

    aws_main();

    vTaskDelete(NULL);
    return;
}

void example_amazon_freertos(void)
{
    if(xTaskCreate(example_amazon_freertos_thread, ((const char*)"example_amazon_freertos_thread"), 2048, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS)
        printf("\n\r%s xTaskCreate(example_amazon_freertos_thread) failed", __FUNCTION__);
}

