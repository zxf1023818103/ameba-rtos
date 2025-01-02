set(GLOBAL_IFLAGS)

list(
    APPEND GLOBAL_IFLAGS
    ${OSDIR}/freertos
    ${OSDIR}/os_wrapper/include

    ${TARGETDIR}/cmsis
    ${TARGETDIR}/cmsis-dsp/Include
    ${TARGETDIR}/cmsis-dsp/PrivateInclude
    ${TARGETDIR}/fwlib/include
    ${TARGETDIR}/lib/include
    ${TARGETDIR}/app/monitor/include
    ${TARGETDIR}/app/xmodem
    ${TARGETDIR}/swlib
    ${TARGETDIR}/misc
    ${TARGETDIR}/hal/include
    ${TARGETDIR}/hal/src
    ${TARGETDIR}/usrcfg/include
    ${BASEDIR}/component/soc/common

    ${INCDIR}
    ${INCDIR}/..

    ${BASEDIR}/component/stdlib
)

#wifi 
include(${WIFIMAKEDIR}/wifi_include.cmake)
list(
    APPEND GLOBAL_IFLAGS
    ${WIFI_IFLAGS}
)


list(
    APPEND GLOBAL_IFLAGS
    ${BASEDIR}/component/example


    ${BASEDIR}/component/network
    #${BASEDIR}/component/network/libcoap/include
    ${BASEDIR}/component/lwip/lwip_${LWIP_VER}/src/include
    #${BASEDIR}/component/lwip/lwip_${LWIP_VER}/src/include/lwip
    ${BASEDIR}/component/lwip/lwip_${LWIP_VER}/src/include/lwip/apps
    #${BASEDIR}/component/lwip/lwip_${LWIP_VER}/src/include/ipv4
    ${BASEDIR}/component/lwip/lwip_${LWIP_VER}/port/realtek
    ${BASEDIR}/component/lwip/lwip_${LWIP_VER}/port/realtek/freertos
    ${BASEDIR}/component/lwip/api

    ${BASEDIR}/component/os_dep

    ${BASEDIR}/component/wifi/wifi_fw/amebadplus/include
    ${BASEDIR}/component/wifi/wifi_fw/common
    

    #RTSP
    ${BASEDIR}/component/network/rtsp

    #SSL
    #${BASEDIR}/component/ssl/ssl_ram_map/rom

    #MBEDTLS
    # ${BASEDIR}/component/ssl/mbedtls-${MBEDTLS_VER}/include
    # ${BASEDIR}/component/ssl/mbedtls_ram_map/rom

    #apple
    ${BASEDIR}/component/application/apple/WACServer/External/Curve25519
    ${BASEDIR}/component/application/apple/WACServer/External/GladmanAES
    ${BASEDIR}/component/application/apple/homekit/crypto/chacha
    ${BASEDIR}/component/application/apple/homekit/crypto/poly1305
    ${BASEDIR}/component/application/apple/homekit/crypto/ed25519
    ${BASEDIR}/component/application/apple/homekit/crypto/ed25519/core
    ${BASEDIR}/component/application/apple/homekit/crypto/rom_ed25519
    ${BASEDIR}/component/application/apple/homekit/crypto/sha512

    #filesystem
    ${BASEDIR}/component/file_system/fatfs/${FATFS_VER}/include
    ${BASEDIR}/component/file_system/fatfs
    ${BASEDIR}/component/file_system/ftl
    ${BASEDIR}/component/file_system/ftl_common
    ${BASEDIR}/component/file_system/dct
    ${BASEDIR}/component/file_system/littlefs
    ${BASEDIR}/component/file_system/littlefs/${LITTLEFS_VER}
    ${BASEDIR}/component/file_system/kv
    ${BASEDIR}/component/file_system/vfs

    #amazon
    ${FREERTOSDIR}/include
    ${FREERTOSDIR}/portable/GCC/AmebaDplus_KM4/non_secure
    ${FREERTOSDIR}/portable/GCC/AmebaDplus_KM4/secure
    ${BASEDIR}/component/application/amazon/amazon-freertos/demos/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/demos/common/http_demo_helpers
    ${BASEDIR}/component/application/amazon/amazon-freertos/demos/common/mqtt_demo_helpers
    ${BASEDIR}/component/application/amazon/amazon-freertos/demos/common/mqtt_subscription_manager
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/corePKCS11/source/dependency/3rdparty/pkcs11/published/2-40-errata-1
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/corePKCS11/source/dependency/3rdparty/pkcs11
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/corePKCS11/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/demos/common/pkcs11_helpers
    ${BASEDIR}/component/application/amazon/amazon-freertos/demos/device_defender_for_aws
    ${BASEDIR}/component/application/amazon/amazon-freertos/demos/dev_mode_key_provisioning/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/3rdparty/jsmn
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/3rdparty/mbedtls/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/3rdparty/mbedtls/include/mbedtls
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/3rdparty/mbedtls_config
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/3rdparty/mbedtls_utils
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/3rdparty/tinycbor/src
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/abstractions/mqtt_agent/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/abstractions/platform/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/abstractions/platform/include/platform
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/abstractions/platform/freertos/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/abstractions/secure_sockets/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/abstractions/transport/secure_sockets
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/abstractions/wifi/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/c_sdk/standard/common/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/c_sdk/standard/common/include/private
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/freertos_plus/standard/crypto/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/freertos_plus/standard/utils/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/freertos_plus/standard/tls/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/common/logging/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/backoffAlgorithm/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/coreHTTP/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/coreHTTP/source/interface
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/coreHTTP/source/dependency/3rdparty/llhttp/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/coreJSON/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/coreMQTT/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/coreMQTT/source/interface
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/coreMQTT-Agent/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/device_defender_for_aws/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/device_shadow_for_aws/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/jobs_for_aws/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/jobs_for_aws/source/otaJobParser/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/ota_for_aws/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/ota_for_aws/source
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/ota_for_aws/source/portable
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/ota_for_aws/source/portable/os
    ${BASEDIR}/component/application/amazon/amazon-freertos/libraries/mqtt_file_streams_for_aws/source/include
    ${BASEDIR}/component/application/amazon/amazon-freertos/ports/amebaDplus/config_files
    ${BASEDIR}/component/application/amazon/amazon-freertos/ports/amebaDplus/ota
    ${BASEDIR}/component/application/amazon/amazon-freertos/demos/ota/ota_demo_mqtt_streams
    )

if(CONFIG_EMWIN_EN)
    list(
        APPEND GLOBAL_IFLAGS
        ${BASEDIR}/component/ui/emwin/emWinLibrary/include
    )
endif()


#bluetooth
if(CONFIG_BT)
    include(bluetooth_include.cmake)
endif()

#openthread
if(CONFIG_802154_THREAD_EN)
    list(
        APPEND GLOBAL_IFLAGS
        ${BASEDIR}/component/wpan/openthread/openthread/include
        ${BASEDIR}/component/wpan/openthread/openthread/src/core
        ${BASEDIR}/component/wpan/openthread/config
        ${BASEDIR}/component/wpan/openthread/openthread/third_party/mbedtls
    )
endif()

if(CONFIG_SPEEX_LIB)
    list(
        APPEND GLOBAL_IFLAGS
        ${BASEDIR}/component/example/audio/speexdsp
        ${BASEDIR}/component/audio/third_party/speexdsp/include
    )
endif()