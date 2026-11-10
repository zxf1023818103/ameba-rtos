##########################################################################################
## * This part defines public part of the component
## * Public part will be used as global build configures for all component

set(public_includes)                #public include directories, NOTE: relative path is OK
set(public_definitions)             #public definitions
set(public_libraries)               #public libraries(files), NOTE: linked with whole-archive options

#----------------------------------------#
# Component public part, user config begin

# You may use if-else condition to set or update predefined variable above
set(release_target_name)
set(release_sources)
if(CONFIG_WLAN AND CONFIG_WHC_HOST AND CONFIG_WHC_INTF_IPC)
    set(release_target_name whc_ap)
    ameba_list_append(public_libraries
        ${c_SDK_LIB_APPLICATION_DIR}/lib_${release_target_name}.a
    )
endif()

ameba_list_append(public_includes
    ${CMAKE_CURRENT_SOURCE_DIR}
    whc_common
    whc_common/ipc
    whc_dev
    whc_host_rtos
    whc_dev/spi
    whc_dev/spdio
    whc_dev/usb
    whc_dev/ipc
    whc_host_rtos/spi
    whc_host_rtos/ipc
)
# Component public part, user config end
#----------------------------------------#

#WARNING: Fixed section, DO NOT change!
ameba_global_include(${public_includes})
ameba_global_define(${public_defines})
ameba_global_library(${public_libraries}) #default: whole-archived

##########################################################################################
## * This part defines private part of the component
## * Private part is used to build target of current component
## * NOTE: The build API guarantees the global build configures(mentioned above)
## *       applied to the target automatically. So if any configure was already added
## *       to public above, it's unnecessary to add again below.

#NOTE: User defined section, add your private build configures here
# You may use if-else condition to set these predefined variable
# They are only for ameba_add_internal_library/ameba_add_external_app_library/ameba_add_external_soc_library
set(private_sources)                 #private source files, NOTE: relative path is OK
set(private_includes)                #private include directories, NOTE: relative path is OK
set(private_definitions)             #private definitions
set(private_compile_options)         #private compile_options

option(AMEBA_GREEN2_NAN_PASN_CIPHER_FIX
    "Experimental PASN response cipher fix for the verified Green2 WHC library" OFF)
set(green2_nan_cipher_fix_active FALSE)
if(AMEBA_GREEN2_NAN_PASN_CIPHER_FIX AND CONFIG_AMEBAGREEN2 AND CONFIG_WHC_DEV)
    # SDIO and USB use the same WHC device archive and NAN object layouts.
    # Keep the library/ABI checks below for both host transports.
    if(NOT CONFIG_WIFI_NAN_ENABLE OR
       NOT (CONFIG_WHC_INTF_SPDIO OR CONFIG_WHC_INTF_USB) OR
       CONFIG_WHC_WPA_SUPPLICANT_OFFLOAD OR CONFIG_WHC_DEV_TCPIP_KEEPALIVE OR CONFIG_MP_INCLUDED)
        message(FATAL_ERROR "Green2 NAN cipher fix requires NAN with SDIO/USB WHC in WPAoH mode")
    endif()
    # The wrappers use private layouts across NDL, NDP and peer helpers.
    file(SHA256 "${c_SDK_LIB_APPLICATION_DIR}/lib_wifi_whc_dev.a" nan_vendor_sha256)
    if(NOT nan_vendor_sha256 STREQUAL "9ade71dee6186bfb5bdc634869d577e38746971bcbf09d908d87a87015cdbe6a")
        message(FATAL_ERROR "Unverified Green2 NAN library: ${nan_vendor_sha256}")
    endif()
    # The vendor's NDP types are private. Fail closed if their object changes.
    set(nan_abi_object "${CMAKE_CURRENT_BINARY_DIR}/nan_cipher_abi_check.o")
    execute_process(COMMAND ${CMAKE_AR} p
        "${c_SDK_LIB_APPLICATION_DIR}/lib_wifi_whc_dev.a" rtw_nan_data_ndp.o
        OUTPUT_FILE "${nan_abi_object}" RESULT_VARIABLE nan_abi_result)
    if(NOT nan_abi_result EQUAL 0)
        message(FATAL_ERROR "Cannot inspect Green2 NDP library ABI")
    endif()
    file(SHA256 "${nan_abi_object}" nan_abi_sha256)
    if(NOT nan_abi_sha256 STREQUAL "f749782b63c6d8c658709943c2c7d1d79522328d757aed3a37e0c174313db4ec")
        message(FATAL_ERROR "Unverified Green2 NDP object: ${nan_abi_sha256}")
    endif()
    set(green2_nan_cipher_fix_active TRUE)
    if(NOT AMEBA_GREEN2_NAN_PREBUILT_LIBRARY)
        list(APPEND private_sources whc_dev/whc_dev_nan_pasn_cipher_fix.c
            whc_dev/whc_dev_nan_bootstrap_fix.c
            whc_dev/whc_dev_nan_ndl_peer_fix.c
            whc_dev/whc_dev_nan_ndl_immutable_fix.c
            whc_dev/whc_dev_nan_ndc_control_fix.c)
        # The same experiment also fixes the proven u32 -> u8 FAW bitmap loss.
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        set(nan_faw_fix_object "${CMAKE_CURRENT_BINARY_DIR}/nan_faw_id_fix.o")
        execute_process(COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/whc_dev/make_nan_faw_id_fix.py"
            "${CMAKE_AR}" "${CMAKE_OBJCOPY}"
            "${c_SDK_LIB_APPLICATION_DIR}/lib_wifi_whc_dev.a"
            "${nan_faw_fix_object}" RESULT_VARIABLE nan_faw_fix_result)
        if(NOT nan_faw_fix_result EQUAL 0)
            message(FATAL_ERROR "Cannot generate verified Green2 FAW ID fix")
        endif()
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/whc_dev/make_nan_faw_id_fix.py"
            "${c_SDK_LIB_APPLICATION_DIR}/lib_wifi_whc_dev.a")
        set_source_files_properties("${nan_faw_fix_object}" PROPERTIES EXTERNAL_OBJECT TRUE)
        list(APPEND private_sources "${nan_faw_fix_object}")
        set(nan_bootstrap_object "${CMAKE_CURRENT_BINARY_DIR}/nan_bootstrap_fix.o")
        execute_process(COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/whc_dev/make_nan_bootstrap_fix.py"
            "${CMAKE_AR}" "${CMAKE_OBJCOPY}"
            "${c_SDK_LIB_APPLICATION_DIR}/lib_wifi_whc_dev.a"
            "${nan_bootstrap_object}" RESULT_VARIABLE nan_bootstrap_result)
        if(NOT nan_bootstrap_result EQUAL 0)
            message(FATAL_ERROR "Cannot generate verified Green2 bootstrap RX fix")
        endif()
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/whc_dev/make_nan_bootstrap_fix.py")
        set_source_files_properties("${nan_bootstrap_object}" PROPERTIES EXTERNAL_OBJECT TRUE)
        list(APPEND private_sources "${nan_bootstrap_object}")
        set(nan_ndl_object "${CMAKE_CURRENT_BINARY_DIR}/nan_ndl_peer_fix.o")
        execute_process(COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/whc_dev/make_nan_ndl_peer_fix.py"
            "${CMAKE_AR}" "${CMAKE_OBJCOPY}"
            "${c_SDK_LIB_APPLICATION_DIR}/lib_wifi_whc_dev.a"
            "${nan_ndl_object}" RESULT_VARIABLE nan_ndl_result)
        if(NOT nan_ndl_result EQUAL 0)
            message(FATAL_ERROR "Cannot generate verified Green2 NDL peer fix")
        endif()
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/whc_dev/make_nan_ndl_peer_fix.py")
        set_source_files_properties("${nan_ndl_object}" PROPERTIES EXTERNAL_OBJECT TRUE)
        list(APPEND private_sources "${nan_ndl_object}")
    endif()
endif()

#------------------------------#
# Component private part, user config begin
set(target_name)

option(AMEBA_GREEN2_NAN_STARTUP_TRACE "Metadata-only Green2 NAN startup diagnostics" OFF)
option(AMEBA_GREEN2_NAN_AUTH_PEER_FIX "Experimental Auth1-before-Subscribe peer initialization" OFF)
option(AMEBA_GREEN2_NAN_USB_RX_RESERVE "Enlarge NAN USB skb pool and recover OUT endpoints on buffer exhaustion" OFF)
option(AMEBA_GREEN2_NAN_STALE_TX_FIX "Flush data TX on final NDP teardown and reject stale NDI traffic" OFF)
option(AMEBA_GREEN2_NAN_RESTART_FIX "Restore native discovery scheduling after a new NAN start" OFF)
if(AMEBA_GREEN2_NAN_RESTART_FIX)
    if(NOT green2_nan_cipher_fix_active OR NOT AMEBA_GREEN2_NAN_STALE_TX_FIX)
        message(FATAL_ERROR "NAN restart fix requires the hash-pinned library and stale TX lifecycle guard")
    endif()
    list(APPEND private_sources whc_dev/whc_dev_nan_restart_fix.c)
    list(APPEND private_definitions GREEN2_NAN_RESTART_FIX=1)
endif()
if(AMEBA_GREEN2_NAN_STALE_TX_FIX)
    if(NOT green2_nan_cipher_fix_active)
        message(FATAL_ERROR "NAN stale TX fix requires the hash-pinned Green2 NAN library")
    endif()
    list(APPEND private_definitions GREEN2_NAN_STALE_TX_FIX=1)
    list(APPEND private_sources whc_dev/whc_dev_nan_stale_tx_fix.c)
endif()
if(AMEBA_GREEN2_NAN_USB_RX_RESERVE)
    if(NOT green2_nan_cipher_fix_active OR NOT CONFIG_WHC_INTF_USB)
        message(FATAL_ERROR "NAN USB reserve requires the verified Green2 USB NAN build")
    endif()
    list(APPEND private_definitions GREEN2_NAN_USB_RX_RESERVE=1)
endif()
if(AMEBA_GREEN2_NAN_AUTH_PEER_FIX)
    if(NOT AMEBA_GREEN2_NAN_STARTUP_TRACE)
        message(FATAL_ERROR "Experimental Auth1 peer fix requires startup diagnostics")
    endif()
    list(APPEND private_definitions GREEN2_NAN_AUTH_PEER_FIX=1)
endif()
if(AMEBA_GREEN2_NAN_STARTUP_TRACE)
    if(NOT green2_nan_cipher_fix_active)
        message(FATAL_ERROR "NAN startup trace requires the hash-pinned Green2 NAN library")
    endif()
    list(APPEND private_sources whc_dev/whc_dev_nan_startup_trace.c)
    list(APPEND private_definitions GREEN2_NAN_STARTUP_TRACE=1)
endif()

if(CONFIG_WHC_DEV AND NOT CONFIG_WHC_INTF_IPC)
    ameba_list_append(private_sources
        whc_dev/whc_dev_init.c
        whc_dev/whc_dev_msg_queue.c
        whc_dev/whc_dev_trx.c
        whc_dev/whc_dev_api.c
        whc_dev/whc_dev_powersave.c
    )

    if(CONFIG_WAR_OFFLOAD)
        ameba_list_append(private_sources
            whc_dev/whc_dev_protocal_offload.c
        )
    endif()

    if(CONFIG_WHC_DEV_TCPIP_KEEPALIVE)
        ameba_list_append(private_sources
            whc_dev/whc_dev_tcpip.c
        )
    endif()

    if(CONFIG_WHC_WIFI_API_PATH)
        ameba_list_append(private_sources
            whc_dev/whc_dev_api_path.c
        )
    endif()

    if(CONFIG_WHC_CMD_PATH)
        ameba_list_append(private_sources
            whc_dev/whc_dev_app.c
            whc_dev/whc_dev_ota.c
        )
        if(CONFIG_RTW_CLI AND CONFIG_WPA_LITE)
            ameba_list_append(private_sources
                whc_dev/whc_dev_rtw_cli/whc_dev_rtw_cli_cmd_parse.c
                whc_dev/whc_dev_rtw_cli/whc_dev_rtw_cli_common.c
                whc_dev/whc_dev_rtw_cli/wpa_lite_intf/whc_wpa_lite_app.c
            )
        elseif(CONFIG_RTW_CLI AND CONFIG_WPA_STD)
            ameba_list_append(private_sources
                whc_dev/whc_dev_rtw_cli/whc_dev_rtw_cli_cmd_parse.c
                whc_dev/whc_dev_rtw_cli/whc_dev_rtw_cli_common.c
                whc_dev/whc_dev_rtw_cli/wpas_std_intf/whc_wpas_std_app.c
            )
        endif()

    endif()
endif()


if(CONFIG_WHC_HOST AND NOT CONFIG_WHC_INTF_IPC)
    ameba_list_append(private_sources
        whc_host_rtos/whc_host_common.c
    )

    if(CONFIG_WHC_CMD_PATH)
        ameba_list_append(private_sources
        whc_host_rtos/whc_host_app.c
        )
    endif()

    if(CONFIG_WHC_WIFI_API_PATH)
        ameba_list_append(private_sources
            whc_host_rtos/whc_host_api.c
            whc_host_rtos/whc_host_api_basic.c
            whc_host_rtos/whc_host_api_ext.c
        )
    endif()
endif()

if(CONFIG_WHC_DEV)
    if(CONFIG_WHC_INTF_SPI)
        ameba_list_append(private_sources
            whc_dev/spi/whc_spi_dev.c
        )
        set(target_name wifi_whc_spi_dev)
    elseif(CONFIG_WHC_INTF_SPDIO)
        ameba_list_append(private_sources
            whc_dev/spdio/whc_spdio_dev.c
        )
        set(target_name wifi_whc_spdio_dev)
    elseif(CONFIG_WHC_INTF_USB)
        ameba_list_append(private_sources
            whc_dev/usb/whc_usb_dev.c
        )
        set(target_name wifi_whc_usb_dev)
    elseif(CONFIG_WHC_INTF_UART)
        ameba_list_append(private_sources
            whc_dev/uart/whc_uart_dev.c
        )
        set(target_name wifi_whc_spdio_dev)
    endif()
elseif(CONFIG_WHC_HOST)
    if(CONFIG_WHC_INTF_SPI)
        ameba_list_append(private_sources
            whc_host_rtos/whc_host_init.c
            whc_host_rtos/spi/whc_spi_host.c
            whc_host_rtos/spi/whc_spi_host_trx.c
        )

        set(target_name wifi_whc_spi_host)
    elseif(CONFIG_WHC_INTF_SPDIO)
        ameba_list_append(private_sources
            whc_host_rtos/whc_host_init.c
            whc_host_rtos/sdio/rtw_sdio_drvio.c
            whc_host_rtos/sdio/whc_sdio_host.c
            whc_host_rtos/sdio/whc_sdio_host_trx.c
            whc_host_rtos/sdio/whc_sdio_init.c
        )
        set(target_name wifi_whc_sdio_host)
    elseif(CONFIG_WHC_INTF_UART)
        ameba_list_append(private_sources
            whc_host_rtos/whc_host_init.c
            whc_host_rtos/uart/whc_uart_host.c
            whc_host_rtos/uart/whc_uart_host_trx.c
        )

        set(target_name wifi_whc_spi_host)
    else()
        ameba_list_append(private_sources
            whc_host_rtos/ipc/whc_ipc_host.c
            whc_host_rtos/ipc/whc_ipc_host_trx.c
            whc_host_rtos/ipc/whc_ipc_host_api.c
            whc_host_rtos/ipc/whc_ipc_host_api_basic.c
            whc_host_rtos/ipc/whc_ipc_host_api_ext.c
            whc_host_rtos/ipc/whc_ipc_host_msg_queue.c
        )
        ameba_list_append(release_sources
            whc_host_rtos/ipc/whc_ipc_host_rom_to_flash.c
        )
        if(CONFIG_WIFI_NAN_HOST_APP)
            ameba_list_append(private_sources
                whc_host_rtos/ipc/whc_ipc_host_nan.c
            )
            ameba_list_append(private_definitions
                CONFIG_WIFI_NAN_HOST_APP
            )
        endif()
        if(CONFIG_PLATFORM_ZEPHYR)
            ameba_list_append(private_sources
                whc_host_rtos/ipc/whc_ipc_host_zephyr.c
            )
        endif()
        set(target_name wifi_whc_ipc_host)
    endif()
endif()


ameba_list_append(private_includes
    ${c_CMPT_WIFI_DIR}/common
    ${c_CMPT_WIFI_DIR}/driver
    ${c_CMPT_WIFI_DIR}/driver/halmac
    ${c_CMPT_WIFI_DIR}/driver/halcommon
    ${c_CMPT_WIFI_DIR}/driver/halbtc
    ${c_CMPT_WIFI_DIR}/driver/phl
    ${c_CMPT_BLUETOOTH_DIR}/driver/bt_inic
    ${c_CMPT_WIFI_DIR}/wpa_supplicant/wpa_supplicant
)

if(CONFIG_AMEBALITE)
    ameba_list_append(private_includes
        ${c_CMPT_WIFI_DIR}/driver/phy_g6/bb
        ${c_CMPT_WIFI_DIR}/driver/phy_g6/rf
        ${c_CMPT_WIFI_DIR}/driver/rtl8720e
        ${c_CMPT_WIFI_DIR}/driver/rtl8720e_rom
        ${c_CMPT_WIFI_DIR}/wifi_fw/amebalite/include
    )
elseif(CONFIG_AMEBADPLUS)
    ameba_list_append(private_includes
        ${c_CMPT_WIFI_DIR}/driver/phydm
        ${c_CMPT_WIFI_DIR}/driver/rtl8721da
        ${c_CMPT_WIFI_DIR}/driver/rtl8721da_rom
        ${c_CMPT_WIFI_DIR}/wifi_fw/amebadplus/include
    )
elseif(CONFIG_AMEBASMART)
    ameba_list_append(private_includes
        ${c_CMPT_WIFI_DIR}/driver/phy_g6
        ${c_CMPT_WIFI_DIR}/driver/phy_g6/bb
        ${c_CMPT_WIFI_DIR}/driver/phy_g6/rf
        ${c_CMPT_WIFI_DIR}/driver/rtl8730e
        ${c_CMPT_WIFI_DIR}/driver/rtl8730e_rom
        ${c_CMPT_WIFI_DIR}/wifi_fw/amebasmart/include
    )
endif()

if(CONFIG_WHC_INTF_USB)
    ameba_list_append(private_includes
        ${c_CMPT_USB_DIR}/common
        ${c_CMPT_USB_DIR}/device/core
    )
    if(CONFIG_AMEBADPLUS)
        ameba_list_append(private_includes ${c_CMPT_USB_DIR}/device/whc_dplus)
    elseif(CONFIG_AMEBAGREEN2)
        ameba_list_append(private_includes ${c_CMPT_USB_DIR}/device/whc)
    endif()
endif()


if(CONFIG_WHC_DEV AND NOT CONFIG_WHC_INTF_IPC)
    if(CONFIG_WHC_CMD_PATH)
        if(CONFIG_RTW_CLI)
            ameba_list_append(private_includes ${c_CMPT_WIFI_DIR}/whc/whc_dev/whc_dev_rtw_cli)

            if(CONFIG_WPA_LITE)
                ameba_list_append(private_includes ${c_CMPT_WIFI_DIR}/whc/whc_dev/whc_dev_rtw_cli/wpa_lite_intf)
            elseif(CONFIG_WPA_STD)
                ameba_list_append(private_includes ${c_CMPT_WIFI_DIR}/whc/whc_dev/whc_dev_rtw_cli/wpas_std_intf)
            endif()

        endif()
    endif()
endif()

# Component private part, user config end
#------------------------------#

#WARNING: Select right API based on your component's release/not-release/standalone
if(private_sources)
    if(CONFIG_PLATFORM_ZEPHYR)
        ameba_add_external_app_library(${target_name}
            p_SOURCES
            ${private_sources}
            p_INCLUDES
                ${private_includes}
            p_DEFINITIONS
                ${private_definitions}
            p_COMPILE_OPTIONS
                ${private_compile_options}
        )
        ameba_global_library(${c_SDK_LIB_APPLICATION_DIR}/lib_${target_name}.a)
    else()
    ###NOTE: For open-source component, always build from source
        ameba_add_internal_library(${target_name}
            p_SOURCES
            ${private_sources}
            p_INCLUDES
                ${private_includes}
            p_DEFINITIONS
                ${private_definitions}
            p_COMPILE_OPTIONS
                ${private_compile_options}
        )
        if(AMEBA_GREEN2_NAN_STARTUP_TRACE)
            target_link_options(${c_CURRENT_TARGET_NAME} INTERFACE
                "-Wl,--wrap=wifi_hal_normal_rx_process"
                "-Wl,--wrap=rtw_recv_entry")
        endif()
        if(AMEBA_GREEN2_NAN_STALE_TX_FIX)
            target_link_options(${c_CURRENT_TARGET_NAME} INTERFACE
                "-Wl,--wrap=rtw_nan_ndi_sec_stainfo_free"
                "-Wl,--wrap=rtw_nan_pairwise_key_set"
                "-Wl,--wrap=wifi_hal_nan_macid_pause"
                "-Wl,--wrap=rtw_nan_start_api"
                "-Wl,--wrap=rtw_nan_stop_api")
        endif()
        if(green2_nan_cipher_fix_active)
            target_link_options(${c_CURRENT_TARGET_NAME} INTERFACE
                "-Wl,--wrap=rtw_nan_ndp_response_prehandle"
                "-Wl,--wrap=rtw_nan_schdl_faw_act_add"
                "-Wl,--wrap=rtw_nan_sdf_rx"
                "-Wl,--wrap=rtw_nan_ndl_nego_rx"
                "-Wl,--wrap=rtw_nan_ndl_attri_construct"
                "-Wl,--wrap=rtw_nan_ndc_attri_contruct")
        endif()
    endif()

endif()

if(release_sources)
    ameba_add_external_app_library(${release_target_name}
        p_SOURCES
            ${release_sources}
        p_INCLUDES
            ${private_includes}
        p_DEFINITIONS
            ${private_definitions}
        p_COMPILE_OPTIONS
            ${private_compile_options}
    )
endif()
##########################################################################################
