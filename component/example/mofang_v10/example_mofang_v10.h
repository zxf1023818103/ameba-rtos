#ifndef EXAMPLE_MOFANG_V10_H
#define EXAMPLE_MOFANG_V10_H

#define I2C0_SCL PA_26
#define I2C0_SDA PB_21
#define I2C0_FREQ 400000

#define RPC_PORT 6666


//0
#define EPPROM_CHECK_ADDR			(0)
#define EPPROM_CHECK_SIZE			10
//10
#define APPID_ADDR					(EPPROM_CHECK_ADDR + EPPROM_CHECK_SIZE)
#define APPID_SIZE					(32 + 1 + 1)
//44
#define KEY_ADDR					(APPID_ADDR + APPID_SIZE)
#define KEY_SIZE					(32 + 1 + 1)
// //78
// #define COIN_PRIOD_ADDR				(KEY_ADDR + KEY_SIZE)
// #define COIN_PRIOD_SIZE				(2 + 1)
// //81
// #define COIN_WIDTH_ADDR				(COIN_PRIOD_ADDR + COIN_PRIOD_SIZE)
// #define COIN_WIDTH_SIZE				(2 + 1)
//78
#define STORE_ID_ADDR		(KEY_ADDR + KEY_SIZE)
#define STORE_ID_SIZE		(4 + 1)
//83
#define COIN_MACHINE_MODE_ADDR		(STORE_ID_ADDR + STORE_ID_SIZE)
#define COIN_MACHINE_MODE_SIZE		(1 + 1)
//85
#define COIN_NORMAL_LEVEL_ADDR		(COIN_MACHINE_MODE_ADDR + COIN_MACHINE_MODE_SIZE)
#define COIN_NORMAL_LEVEL_SIZE		(1 + 1)
//87
#define COIN_DETECT_WIDTH_MIN_ADDR	(COIN_NORMAL_LEVEL_ADDR + COIN_NORMAL_LEVEL_SIZE)
#define COIN_DETECT_WIDTH_MIN_SIZE	(1 + 1)
//89
#define WIFI_SSID_ADDR				(COIN_DETECT_WIDTH_MIN_ADDR + COIN_DETECT_WIDTH_MIN_SIZE)
#define WIFI_SSID_LEN				(32 + 1 + 1)
//157
#define WIFI_PASSWORD_ADDR			(WIFI_SSID_ADDR + WIFI_SSID_LEN)
#define WIFI_PASSWORD_LEN			(32 + 1 + 1)
//191
#define COIN_IN_SENT_ADDR				(WIFI_PASSWORD_ADDR + WIFI_PASSWORD_LEN)
#define COIN_IN_SENT_LEN				(4 + 1)
//196
#define COIN_IN_UNSENT_ADDR				(COIN_IN_SENT_ADDR + COIN_IN_SENT_LEN)
#define COIN_IN_UNSENT_LEN				(4 + 1)
//201
#define COIN_IN_TRANSID_ADDR				(COIN_IN_UNSENT_ADDR + COIN_IN_UNSENT_LEN)
#define COIN_IN_TRANSID_LEN					(32 + 1 + 1)
//235
#define RETURN_PHY_COIN_SENT_ADDR			(COIN_IN_TRANSID_ADDR + COIN_IN_TRANSID_LEN)
#define RETURN_PHY_COIN_SENT_LEN			(4 + 1)
//240
#define RETURN_GAME_OUT_TRANSID_ADDR		(RETURN_PHY_COIN_SENT_ADDR + RETURN_PHY_COIN_SENT_LEN)
#define RETURN_GAME_OUT_TRANSID_LEN			(32 + 1 + 1)
//274
#define RETURN_PHY_COIN_UNSENT_ADDR			(RETURN_GAME_OUT_TRANSID_ADDR + RETURN_GAME_OUT_TRANSID_LEN)
#define RETURN_PHY_COIN_UNSENT_LEN			(4 + 1)
//279
#define RETURN_PHY_TICK_SENT_ADDR			(RETURN_PHY_COIN_UNSENT_ADDR + RETURN_PHY_COIN_UNSENT_LEN)
#define RETURN_PHY_TICK_SENT_LEN			(4 + 1)
//284
#define RETURN_PHY_TICK_UNSENT_ADDR			(RETURN_PHY_TICK_SENT_ADDR + RETURN_PHY_TICK_SENT_LEN)
#define RETURN_PHY_TICK_UNSENT_LEN			(4 + 1)
//289
#define RETURN_GIFT_SENT_ADDR				(RETURN_PHY_TICK_UNSENT_ADDR + RETURN_PHY_TICK_UNSENT_LEN)
#define RETURN_GIFT_SENT_LEN				(4 + 1)
//294
#define RETURN_GIFT_UNSENT_ADDR				(RETURN_GIFT_SENT_ADDR + RETURN_GIFT_SENT_LEN)
#define RETURN_GIFT_UNSENT_LEN				(4 + 1)
//299
#define QRCODE_TRANSID_ADDR					(RETURN_GIFT_UNSENT_ADDR + RETURN_GIFT_UNSENT_LEN)
#define QRCODE_TRANSID_LEN					(32 + 1 + 1)
//333
#define MQ_CONSUME_TRANSID_ADDR				(QRCODE_TRANSID_ADDR + QRCODE_TRANSID_LEN)
#define MQ_CONSUME_TRANSID_LEN				(40 + 1 + 1)
//375
#define MQ_CONSUME_PROCESS_STEP_ADDR	    (MQ_CONSUME_TRANSID_ADDR + MQ_CONSUME_TRANSID_LEN)
#define MQ_CONSUME_PROCESS_STEP_LEN			(1 + 1)
//377
#define HOST_PORT_ADDR			(MQ_CONSUME_PROCESS_STEP_ADDR + MQ_CONSUME_PROCESS_STEP_LEN)
#define HOST_PORT_LEN			(4 + 1)
//382
#define HOST_DOMAIN_ADDR		(HOST_PORT_ADDR + HOST_PORT_LEN)
#define HOST_DOMAIN_LEN			(64 + 1 + 1)
//448
#define PALY_LOG_ID_ADDR		(HOST_DOMAIN_ADDR + HOST_DOMAIN_LEN)
#define PALY_LOG_ID_LEN			(36 + 1 + 1)

//486
#define TICKET_NORMAL_LEVEL_ADDR		(PALY_LOG_ID_ADDR + PALY_LOG_ID_LEN)
#define TICKET_NORMAL_LEVEL_SIZE		(1 + 1)

//488
#define TICKET_EN_NORMAL_LEVEL_ADDR		(TICKET_NORMAL_LEVEL_ADDR + TICKET_NORMAL_LEVEL_SIZE)
#define TICKET_EN_NORMAL_LEVEL_SIZE		(1 + 1)

//490
#define DIS_PLAY_ROTATE_ADDR		(TICKET_EN_NORMAL_LEVEL_ADDR + TICKET_EN_NORMAL_LEVEL_SIZE)
#define DIS_PLAY_ROTATE_SIZE		(1 + 1)

//492
#define WIFI_CONFIG_STEP_ADDR		(DIS_PLAY_ROTATE_ADDR + DIS_PLAY_ROTATE_SIZE)
#define WIFI_CONFIG_STEP_SIZE		(1 + 1)

//494
#define IS_SAFE_BOX_ADDR		(WIFI_CONFIG_STEP_ADDR + WIFI_CONFIG_STEP_SIZE)
#define IS_SAFE_BOX_SIZE		(1 + 1)

//496
#define FACTORY_AGING_TIME_ADDR		(IS_SAFE_BOX_ADDR + IS_SAFE_BOX_SIZE)
#define FACTORY_AGING_TIME_SIZE		(4 + 1)

//501
#define LIGHT_PERCENT_ADDR		(FACTORY_AGING_TIME_ADDR + FACTORY_AGING_TIME_SIZE)
#define LIGHT_PERCENT_SIZE		(1 + 1)

//503
#define WORK_MODE_ADDR		(LIGHT_PERCENT_ADDR + LIGHT_PERCENT_SIZE)
#define WORK_MODE_SIZE		(1 + 1)

//505
#define AMPLIFICATION_FACTOR_ADDR		(WORK_MODE_ADDR + WORK_MODE_SIZE)
#define AMPLIFICATION_FACTOR_SIZE		(2 + 1)

//512
#define LEAGUER_ID_ADDR			512
#define LEAGUER_ID_LEN			(36 + 1 + 1)
//550
#define RETURN_SCORE_SENT_ADDR              (LEAGUER_ID_ADDR + LEAGUER_ID_LEN)
#define RETURN_SCORE_SENT_LEN				(4 + 1)
//555
#define RETURN_SCORE_UNSENT_ADDR			(RETURN_SCORE_SENT_ADDR + RETURN_SCORE_SENT_LEN)
#define RETURN_SCORE_UNSENT_LEN				(4 + 1)
//560
#define RETURN_ELE_TICK_SENT_ADDR			(RETURN_SCORE_UNSENT_ADDR + RETURN_SCORE_UNSENT_LEN)
#define RETURN_ELE_TICK_SENT_LEN			(4 + 1)
//565
#define RETURN_ELE_TICK_UNSENT_ADDR			(RETURN_ELE_TICK_SENT_ADDR + RETURN_ELE_TICK_SENT_LEN)
#define RETURN_ELE_TICK_UNSENT_LEN			(4 + 1)
//570
#define RETURN_ELE_COIN_SENT_ADDR			(RETURN_ELE_TICK_UNSENT_ADDR + RETURN_ELE_TICK_UNSENT_LEN)
#define RETURN_ELE_COIN_SENT_LEN			(4 + 1)
//575
#define RETURN_ELE_COIN_UNSENT_ADDR			(RETURN_ELE_COIN_SENT_ADDR + RETURN_ELE_COIN_SENT_LEN)
#define RETURN_ELE_COIN_UNSENT_LEN			(4 + 1)
//580
#define PICTURE_VER_ADDR			        (RETURN_ELE_COIN_UNSENT_ADDR + RETURN_ELE_COIN_UNSENT_LEN)
#define PICTURE_VER_ADDR_LEN			    (4 + 1)
//585
#define CURRENT_COIN_IN_ADDR			    (PICTURE_VER_ADDR + PICTURE_VER_ADDR_LEN)
#define CURRENT_COIN_IN_LEN			        (4 + 1)
//590
#define CURRENT_GIFT_OUT_ADDR			    (CURRENT_COIN_IN_ADDR + CURRENT_COIN_IN_LEN)
#define CURRENT_GIFT_OUT_LEN			    (4 + 1)

// 20240521 --cwh test
//595
#define GIFT_OUT_SEND_MEMBER_FLAG_ADDR		(CURRENT_GIFT_OUT_ADDR + CURRENT_GIFT_OUT_LEN)
#define GIFT_OUT_SEND_MEMBER_FLAG_LEN		(1 + 1)
// 20240521 --cwh test

// 20240620 --cwh test
// ticket out ele
//597
#define TICKET_OUT_ELE_UNSEND_ADDR		(GIFT_OUT_SEND_MEMBER_FLAG_ADDR + GIFT_OUT_SEND_MEMBER_FLAG_LEN)
#define TICKET_OUT_ELE_UNSEND_LEN		(4 + 2)
//603
#define TICKET_OUT_ELE_SEND_ADDR		(TICKET_OUT_ELE_UNSEND_ADDR + TICKET_OUT_ELE_UNSEND_LEN)
#define TICKET_OUT_ELE_SEND_LEN			(4 + 2)
// coin out ele
//609
#define COIN_OUT_ELE_UNSEND_ADDR		(TICKET_OUT_ELE_SEND_ADDR + TICKET_OUT_ELE_SEND_LEN)
#define COIN_OUT_ELE_UNSEND_LEN			(4 + 2)
//615
#define COIN_OUT_ELE_SEND_ADDR			(COIN_OUT_ELE_UNSEND_ADDR + COIN_OUT_ELE_UNSEND_LEN)
#define COIN_OUT_ELE_SEND_LEN			(4 + 2)
// ticket out phy
//521
#define TICKET_OUT_PHY_UNSEND_ADDR		(COIN_OUT_ELE_SEND_ADDR + COIN_OUT_ELE_SEND_LEN)
#define TICKET_OUT_PHY_UNSEND_LEN		(4 + 2)
//627
#define TICKET_OUT_PHY_SEND_ADDR		(TICKET_OUT_PHY_UNSEND_ADDR + TICKET_OUT_PHY_UNSEND_LEN)
#define TICKET_OUT_PHY_SEND_LEN			(4 + 2)
// coin out phy
//633
#define COIN_OUT_PHY_UNSEND_ADDR		(TICKET_OUT_PHY_SEND_ADDR + TICKET_OUT_PHY_SEND_LEN)
#define COIN_OUT_PHY_UNSEND_LEN			(4 + 2)
//639
#define COIN_OUT_PHY_SEND_ADDR			(COIN_OUT_PHY_UNSEND_ADDR + COIN_OUT_PHY_UNSEND_LEN)
#define COIN_OUT_PHY_SEND_LEN			(4 + 2)
// coin in
//645
#define COIN_IN_UNSEND_ADDR				(COIN_OUT_PHY_SEND_ADDR + COIN_OUT_PHY_SEND_LEN)
#define COIN_IN_UNSEND_LEN				(4 + 2)
//651
#define COIN_IN_SEND_ADDR				(COIN_IN_UNSEND_ADDR + COIN_IN_UNSEND_LEN)
#define COIN_IN_SEND_LEN				(4 + 2)
// gift
//657
#define GIFT_UNSEND_ADDR				(COIN_IN_SEND_ADDR + COIN_IN_SEND_LEN)
#define GIFT_UNSEND_LEN					(4 + 2)
//663
#define GIFT_SEND_ADDR					(GIFT_UNSEND_ADDR + GIFT_UNSEND_LEN)
#define GIFT_SEND_LEN					(4 + 2)
// score
//669
#define SCORE_UNSEND_ADDR				(GIFT_SEND_ADDR + GIFT_SEND_LEN)
#define SCORE_UNSEND_LEN				(4 + 2)
//675
#define SCORE_SEND_ADDR					(SCORE_UNSEND_ADDR + SCORE_UNSEND_LEN)
#define SCORE_SEND_LEN					(4 + 2)
// 20240620 --cwh test

// 20240628 --cwh test
//681
#define DEVICE_CNGPI_INTERFACE_ADDR		(SCORE_SEND_ADDR + SCORE_SEND_LEN)
#define DEVICE_CNGPI_INTERFACE_LEN		(1 + 1)
// 20240628 --cwh test

// 20240716 --cwh test
//683
#define COIN_AMPLIFICATION_FACTOR_ADDR		(DEVICE_CNGPI_INTERFACE_ADDR + DEVICE_CNGPI_INTERFACE_LEN)
#define COIN_AMPLIFICATION_FACTOR_SIZE		(2 + 1)
// 20240716 --cwh test


#define YZY_BASE_ADDR 1024

#define d_yzy_appkey_addr YZY_BASE_ADDR
#define d_yzy_appkey_addr_len  48

#define d_yzy_product_key_addr  (d_yzy_appkey_addr+d_yzy_appkey_addr_len)//48
#define d_yzy_product_key_addr_len  16

#define d_yzy_device_name_addr  (d_yzy_product_key_addr+d_yzy_product_key_addr_len)//64
#define d_yzy_device_name_addr_len  16

#define d_yzy_device_key_addr  (d_yzy_device_name_addr+d_yzy_device_name_addr_len)//80
#define d_yzy_device_key_addr_len  48

#define d_yzy_ReturnPTickey_addr (d_yzy_device_key_addr+d_yzy_device_key_addr_len)//128
#define d_yzy_ReturnPTickey_addr_len 5

#define d_yzy_ReturnETickey_addr (d_yzy_ReturnPTickey_addr+d_yzy_ReturnPTickey_addr_len)//133
#define d_yzy_ReturnETickey_addr_len 5

#define d_yzy_ElectricCount_addr (d_yzy_ReturnETickey_addr+d_yzy_ReturnETickey_addr_len)//138
#define d_yzy_ElectricCount_addr_len 5

#define d_yzy_ReturnElectric_addr (d_yzy_ElectricCount_addr+d_yzy_ElectricCount_addr_len)//143
#define d_yzy_ReturnElectric_addr_len 5


#define d_yzy_PhysicalCount_addr (d_yzy_ReturnElectric_addr+d_yzy_ReturnElectric_addr_len)//148
#define d_yzy_PhysicalCount_addr_len 5

#define d_yzy_ReturnPhysical_addr (d_yzy_PhysicalCount_addr+d_yzy_PhysicalCount_addr_len)//153
#define d_yzy_ReturnPhysical_addr_len 5

#define d_yzy_RemoteStartCount_addr (d_yzy_ReturnPhysical_addr+d_yzy_ReturnPhysical_addr_len)//158
#define d_yzy_RemoteStartCount_addr_len 5

#define d_yzy_GiftCount_addr (d_yzy_RemoteStartCount_addr+d_yzy_RemoteStartCount_addr_len)//163
#define d_yzy_GiftCount_addr_len 5

#define d_yzy_DisturbCount_addr (d_yzy_GiftCount_addr+d_yzy_GiftCount_addr_len)//168
#define d_yzy_DisturbCount_addr_len 5

#define d_yzy_ScanCode_addr (d_yzy_DisturbCount_addr+d_yzy_DisturbCount_addr_len)//173

#define d_yzy_ScanCode_addr_len 5

#define d_yzy_ReadCardMagic_addr (d_yzy_ScanCode_addr+d_yzy_ScanCode_addr_len)//178
#define d_yzy_ReadCardMagic_addr_len 5

#define d_yzy_ReadCardSucc_addr (d_yzy_ReadCardMagic_addr+d_yzy_ReadCardMagic_addr_len)//183
#define d_yzy_ReadCardSucc_addr_len 5

#define d_yzy_ReconnectCount_addr (d_yzy_ReadCardSucc_addr+d_yzy_ReadCardSucc_addr_len)//188
#define d_yzy_ReconnectCount_addr_len 5

#define d_yzy_ConnServerCount_addr (d_yzy_ReconnectCount_addr+d_yzy_ReconnectCount_addr_len)//193
#define d_yzy_ConnServerCount_addr_len 5

#define d_yzy_ServerAddress_addr (d_yzy_ConnServerCount_addr+d_yzy_ConnServerCount_addr_len)//198
#define d_yzy_ServerAddress_addr_len  64

#define d_yzy_RequestSlow_addr (d_yzy_ServerAddress_addr+d_yzy_ServerAddress_addr_len)//262
#define d_yzy_RequestSlow_addr_len 5

#define d_yzy_RequestFail_addr (d_yzy_RequestSlow_addr+d_yzy_RequestSlow_addr_len)//267
#define d_yzy_RequestFail_addr_len 5

#define d_yzy_RequestSucc_addr (d_yzy_RequestFail_addr+d_yzy_RequestFail_addr_len)//272
#define d_yzy_RequestSucc_addr_len 5

#define d_yzy_StartCount_addr (d_yzy_RequestSucc_addr+d_yzy_RequestSucc_addr_len)//277
#define d_yzy_StartCount_addr_len 5

#endif // EXAMPLE_MOFANG_V10_H