ameba_internal_library(example_blufi)

set(MODULE_C_OPTIONS -Wno-format)

target_sources(
    ${CURRENT_LIB_NAME} PRIVATE
    aiio_ble.c
    aiio_blufi_api.c
    aiio_blufi.c
    aiio_blufi_export.c
    aiio_blufi_hal.c
    aiio_btc.c
    aiio_wifi.c
    app_example.c
    blufi_init.c
    blufi_main.c
    blufi_prf.c
    blufi_protocol.c
    example_blufi.c
)
