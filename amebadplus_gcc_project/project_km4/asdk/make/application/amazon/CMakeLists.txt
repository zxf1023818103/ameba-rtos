set(DIR ${BASEDIR}/component/application/amazon/amazon-freertos)

# set(MODULE_DEFINES __RTOS__)
set(MODULE_OPTIONS
    -Wno-error)

set(SRC
    # mbedtls-2.28.1
    ${DIR}/libraries/3rdparty/mbedtls_rtk/net_sockets.c
    ${DIR}/libraries/3rdparty/mbedtls/library/aes.c
    ${DIR}/libraries/3rdparty/mbedtls/library/aesni.c
    ${DIR}/libraries/3rdparty/mbedtls/library/arc4.c
    ${DIR}/libraries/3rdparty/mbedtls/library/aria.c
    ${DIR}/libraries/3rdparty/mbedtls/library/asn1parse.c
    ${DIR}/libraries/3rdparty/mbedtls/library/asn1write.c
    ${DIR}/libraries/3rdparty/mbedtls/library/base64.c
    ${DIR}/libraries/3rdparty/mbedtls/library/bignum.c
    ${DIR}/libraries/3rdparty/mbedtls/library/blowfish.c
    ${DIR}/libraries/3rdparty/mbedtls/library/camellia.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ccm.c
    ${DIR}/libraries/3rdparty/mbedtls/library/certs.c
    ${DIR}/libraries/3rdparty/mbedtls/library/chacha20.c
    ${DIR}/libraries/3rdparty/mbedtls/library/chachapoly.c
    ${DIR}/libraries/3rdparty/mbedtls/library/cipher.c
    ${DIR}/libraries/3rdparty/mbedtls/library/cipher_wrap.c
    ${DIR}/libraries/3rdparty/mbedtls/library/cmac.c
    ${DIR}/libraries/3rdparty/mbedtls/library/constant_time.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ctr_drbg.c
    ${DIR}/libraries/3rdparty/mbedtls/library/debug.c
    ${DIR}/libraries/3rdparty/mbedtls/library/des.c
    ${DIR}/libraries/3rdparty/mbedtls/library/dhm.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ecdh.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ecdsa.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ecjpake.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ecp.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ecp_curves.c
    ${DIR}/libraries/3rdparty/mbedtls/library/entropy.c
    ${DIR}/libraries/3rdparty/mbedtls/library/entropy_poll.c
    ${DIR}/libraries/3rdparty/mbedtls/library/error.c
    ${DIR}/libraries/3rdparty/mbedtls/library/gcm.c
    ${DIR}/libraries/3rdparty/mbedtls/library/havege.c
    ${DIR}/libraries/3rdparty/mbedtls/library/hkdf.c
    ${DIR}/libraries/3rdparty/mbedtls/library/hmac_drbg.c
    ${DIR}/libraries/3rdparty/mbedtls/library/md.c
    ${DIR}/libraries/3rdparty/mbedtls/library/md2.c
    ${DIR}/libraries/3rdparty/mbedtls/library/md4.c
    ${DIR}/libraries/3rdparty/mbedtls/library/md5.c
    ${DIR}/libraries/3rdparty/mbedtls/library/memory_buffer_alloc.c
    ${DIR}/libraries/3rdparty/mbedtls/library/nist_kw.c
    ${DIR}/libraries/3rdparty/mbedtls/library/oid.c
    ${DIR}/libraries/3rdparty/mbedtls/library/padlock.c
    ${DIR}/libraries/3rdparty/mbedtls/library/pem.c
    ${DIR}/libraries/3rdparty/mbedtls/library/pk.c
    ${DIR}/libraries/3rdparty/mbedtls/library/pk_wrap.c
    ${DIR}/libraries/3rdparty/mbedtls/library/pkcs11.c
    ${DIR}/libraries/3rdparty/mbedtls/library/pkcs12.c
    ${DIR}/libraries/3rdparty/mbedtls/library/pkcs5.c
    ${DIR}/libraries/3rdparty/mbedtls/library/pkparse.c
    ${DIR}/libraries/3rdparty/mbedtls/library/pkwrite.c
    ${DIR}/libraries/3rdparty/mbedtls/library/platform.c
    ${DIR}/libraries/3rdparty/mbedtls/library/platform_util.c
    ${DIR}/libraries/3rdparty/mbedtls/library/poly1305.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ripemd160.c
    ${DIR}/libraries/3rdparty/mbedtls/library/rsa.c
    ${DIR}/libraries/3rdparty/mbedtls/library/rsa_internal.c
    ${DIR}/libraries/3rdparty/mbedtls/library/sha1.c
    ${DIR}/libraries/3rdparty/mbedtls/library/sha256.c
    ${DIR}/libraries/3rdparty/mbedtls/library/sha512.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ssl_cache.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ssl_ciphersuites.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ssl_cli.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ssl_cookie.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ssl_msg.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ssl_srv.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ssl_ticket.c
    ${DIR}/libraries/3rdparty/mbedtls/library/ssl_tls.c
    ${DIR}/libraries/3rdparty/mbedtls/library/threading.c
    ${DIR}/libraries/3rdparty/mbedtls/library/timing.c
    ${DIR}/libraries/3rdparty/mbedtls/library/version.c
    ${DIR}/libraries/3rdparty/mbedtls/library/version_features.c
    ${DIR}/libraries/3rdparty/mbedtls/library/x509.c
    ${DIR}/libraries/3rdparty/mbedtls/library/x509_create.c
    ${DIR}/libraries/3rdparty/mbedtls/library/x509_crl.c
    ${DIR}/libraries/3rdparty/mbedtls/library/x509_crt.c
    ${DIR}/libraries/3rdparty/mbedtls/library/x509_csr.c
    ${DIR}/libraries/3rdparty/mbedtls/library/x509write_crt.c
    ${DIR}/libraries/3rdparty/mbedtls/library/x509write_csr.c
    ${DIR}/libraries/3rdparty/mbedtls/library/xtea.c
    
    # mbedtls_utils
    ${DIR}/libraries/3rdparty/mbedtls_utils/mbedtls_error.c
    ${DIR}/libraries/3rdparty/mbedtls_utils/mbedtls_utils.c

    # tinycbor
    ${DIR}/libraries/3rdparty/tinycbor/src/cborencoder.c
    ${DIR}/libraries/3rdparty/tinycbor/src/cborencoder_close_container_checked.c
    ${DIR}/libraries/3rdparty/tinycbor/src/cborerrorstrings.c
    ${DIR}/libraries/3rdparty/tinycbor/src/cborparser.c
    ${DIR}/libraries/3rdparty/tinycbor/src/cborparser_dup_string.c
    ${DIR}/libraries/3rdparty/tinycbor/src/cborpretty.c
    ${DIR}/libraries/3rdparty/tinycbor/src/cborpretty_stdio.c
    ${DIR}/libraries/3rdparty/tinycbor/src/cborvalidation.c

    ## common
    # mqtt_agent
    ${DIR}/libraries/common/abstractions/mqtt_agent/freertos_agent_message.c
    ${DIR}/libraries/common/abstractions/mqtt_agent/freertos_command_pool.c

    # transport - secure_sockets
    ${DIR}/libraries/common/abstractions/transport/secure_sockets/transport_secure_sockets.c

    ## freertos_plus - standard
    # crypto
    ${DIR}/libraries/common/freertos_plus/standard/crypto/src/iot_crypto.c

    # tls
    ${DIR}/libraries/common/freertos_plus/standard/tls/src/iot_tls.c

    ## logging
    ${DIR}/libraries/common/logging/iot_logging.c
    ${DIR}/libraries/common/logging/iot_logging_task_dynamic_buffers.c

    ## backoffAlgorithm
    ${DIR}/libraries/backoffAlgorithm/source/backoff_algorithm.c

    ## coreHTTP + llhttp
    ${DIR}/libraries/coreHTTP/source/dependency/3rdparty/llhttp/src/api.c
    ${DIR}/libraries/coreHTTP/source/dependency/3rdparty/llhttp/src/http.c
    ${DIR}/libraries/coreHTTP/source/dependency/3rdparty/llhttp/src/llhttp.c
    ${DIR}/libraries/coreHTTP/source/core_http_client.c

    ## coreJSON
    ${DIR}/libraries/coreJSON/source/core_json.c

    ## coreMQTT
    ${DIR}/libraries/coreMQTT/source/core_mqtt.c
    ${DIR}/libraries/coreMQTT/source/core_mqtt_serializer.c
    ${DIR}/libraries/coreMQTT/source/core_mqtt_state.c

    ## coreMQTT-Agent
    ${DIR}/libraries/coreMQTT-Agent/source/core_mqtt_agent.c
    ${DIR}/libraries/coreMQTT-Agent/source/core_mqtt_agent_command_functions.c

    ## corePKCS11
    ${DIR}/libraries/corePKCS11/source/portable/mbedtls/core_pkcs11_mbedtls.c
    ${DIR}/libraries/corePKCS11/source/core_pkcs11.c
    ${DIR}/libraries/corePKCS11/source/core_pki_utils.c

    ## device_defender_for_aws
    ${DIR}/libraries/device_defender_for_aws/source/defender.c

    ## device_shadow_for_aws
    ${DIR}/libraries/device_shadow_for_aws/source/shadow.c

    ## ota_for_aws
    ${DIR}/libraries/ota_for_aws/source/portable/os/ota_os_freertos.c
    ${DIR}/libraries/ota_for_aws/source/ota.c
    ${DIR}/libraries/ota_for_aws/source/ota_base64.c
    ${DIR}/libraries/ota_for_aws/source/ota_cbor.c
    ${DIR}/libraries/ota_for_aws/source/ota_http.c
    ${DIR}/libraries/ota_for_aws/source/ota_interface.c
    ${DIR}/libraries/ota_for_aws/source/ota_mqtt.c

    ## jobs_for_aws
    ${DIR}/libraries/jobs_for_aws/source/jobs.c
    ${DIR}/libraries/jobs_for_aws/source/otaJobParser/job_parser.c
    ${DIR}/libraries/jobs_for_aws/source/otaJobParser/ota_job_handler.c

    ## mqtt_file_streams_for_aws
    ${DIR}/libraries/mqtt_file_streams_for_aws/source/MQTTFileDownloader.c
    ${DIR}/libraries/mqtt_file_streams_for_aws/source/MQTTFileDownloader_cbor.c
    ${DIR}/libraries/mqtt_file_streams_for_aws/source/MQTTFileDownloader_base64.c
    
    ## amazon_freertos_LTS - demos
    # common
    ${DIR}/demos/common/http_demo_helpers/http_demo_utils.c
    ${DIR}/demos/common/mqtt_demo_helpers/mqtt_demo_helpers.c
    ${DIR}/demos/common/mqtt_subscription_manager/mqtt_subscription_manager.c
    ${DIR}/demos/common/ota_demo_helpers/ota_application_version.c
    ${DIR}/demos/common/pkcs11_helpers/pkcs11_helpers.c
    ${DIR}/demos/dev_mode_key_provisioning/src/aws_dev_mode_key_provisioning.c
    
    # coreHTTP
    ${DIR}/demos/coreHTTP/http_demo_mutual_auth.c
    
    # coreMQTT
    ${DIR}/demos/coreMQTT/mqtt_demo_mutual_auth.c
    
    # device_shadow_for_aws
    ${DIR}/demos/device_shadow_for_aws/shadow_demo_main.c

    # device_defender_for_aws
    ${DIR}/demos/device_defender_for_aws/metrics_collector/lwip/metrics_collector.c
    ${DIR}/demos/device_defender_for_aws/defender_demo.c
    ${DIR}/demos/device_defender_for_aws/report_builder.c

    # jobs_for_aws
    ${DIR}/demos/jobs_for_aws/jobs_demo.c
    
    # ota
    ${DIR}/demos/ota/ota_demo_core_mqtt/ota_demo_core_mqtt.c

    # ota w/ mqtt file streams aws
    ${DIR}/demos/ota/ota_demo_mqtt_streams/mqtt_agent_task.c
    ${DIR}/demos/ota/ota_demo_mqtt_streams/ota_demo_mqtt_streams.c
    ${DIR}/demos/ota/ota_demo_mqtt_streams/ota_event_freertos.c
    ${DIR}/demos/ota/ota_demo_mqtt_streams/mqtt_wrapper.c
    
    ## vendor
    # port
    ${DIR}/ports/amebaDplus/ota/aws_ota_amebaDplus.c
    ${DIR}/ports/amebaDplus/ota/aws_ota_streams_amebaDplus.c
    ${DIR}/ports/amebaDplus/ota/ota_pal.c
    ${DIR}/ports/amebaDplus/ota/ota_pal_streams.c
    ${DIR}/ports/amebaDplus/pkcs11/core_pkcs11_pal.c
    ${DIR}/ports/amebaDplus/secure_sockets/iot_secure_sockets.c
    ${DIR}/ports/amebaDplus/aws_main.c
    )

ameba_internal_library(amazon-freertos)
# target_compile_definitions(${CURRENT_LIB_NAME} PRIVATE ${MODULE_DEFINES})
target_compile_options(${CURRENT_LIB_NAME} PRIVATE ${MODULE_OPTIONS})
# target_include_directories(${CURRENT_LIB_NAME} PRIVATE ${MODULE_IFLAGS})
target_sources(${CURRENT_LIB_NAME} PRIVATE ${SRC})
