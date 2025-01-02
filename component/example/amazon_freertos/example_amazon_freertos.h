#ifndef EXAMPLE_AMAZON_FREERTOS_H
#define EXAMPLE_AMAZON_FREERTOS_H

/**
* For amazon freertos usage  // Tail of OTA1 section for example
*/
// use in aws_ota
#define AWS_OTA_IMAGE_STATE_FLASH_OFFSET     ( 0x1FB000 ) //Flash location for aws ota state
// Use in core_pkcs11_pal.c
#define pkcs11OBJECT_CERT_FLASH_OFFSET       ( 0x1FC000 ) //Flash location for CERT
#define pkcs11OBJECT_PRIV_KEY_FLASH_OFFSET   ( 0x1FD000 ) //Flash location for Priv Key
#define pkcs11OBJECT_PUB_KEY_FLASH_OFFSET    ( 0x1FE000 ) //Flash location for Pub Key
#define pkcs11OBJECT_VERIFY_KEY_FLASH_OFFSET ( 0x1FF000 ) //Flash location for code verify Key

void example_amazon_freertos(void);

#endif /* EXAMPLE_AMAZON_FREERTOS_H */
