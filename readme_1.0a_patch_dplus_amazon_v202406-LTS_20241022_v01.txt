1.0a_patch_dplus_amazon_v202406-LTS_20241022_(v01)

[Description]
    Support amazon-freertos-202406.xx-LTS with MQTT/HTTP/DeviceDefender/DeviceShadow/OTA/StreamsOTA demos with GCC

	The patch is base on sdk-ameba-all_v1.0a.tgz + 1.0a_patch_dplus_amazon_v202406-LTS_20241022_(v01).zip
	Work with: https://github.com/Ameba-AIoT/ameba-amazon-freertos/commit/d602f5dc18863c7799e4ca4aa11ec507624f49d0
	
	Please merge the following files to project, do not replace these files directly, there would be some compile error.
	
	!!! Only support Dplus which with PSRAM. !!!

1.	Notes:
	1. Support aws_demo (MQTT/HTTP/DeviceDefender/DeviceShadow/OTA/StreamsOTA) on AmebaDplus
	2. Version update for AWS libraries to 202406.xx LTS (https://github.com/FreeRTOS/FreeRTOS-LTS/blob/202406.01-LTS/README.md)
	3. Add new demo using OTA with AWS MQTT File Streams library. Older OTA mechanism will be retained, however as of 202406.xx LTS it has been deprecated
	4. Add additional signing script in amazon_ota_tools
	5. Git repo for RTK Amazon-FreeRTOS opensource code has been changed, please read the following section for setup instructions
	
	Modified files
		amebadplus_gcc_project/project_km4/asdk/Makefile.include.gen
		amebadplus_gcc_project/project_km4/asdk/make/application/Makefile
	Add files
		component/application/amazon/amazon_ota_tools/python_custom_ecdsa_Dplus_gcc.py

2.  For AWS IoT document, please refer to the Amazon Web
   - https://docs.aws.amazon.com/iot/latest/developerguide/what-is-aws-iot.html
   

3.  Clone the Realtek FreeRTOS-LTS 202406-LTS repository from our Github (https://github.com/Ameba-AIoT/ameba-amazon-freertos/tree/FreeRTOS-LTS-202406.xx)
	Run the following command under the path: component\application\amazon

	$ git clone --recurse-submodules -b FreeRTOS-LTS-202406.xx --depth 1 https://github.com/Ameba-AIoT/ameba-amazon-freertos.git amazon-freertos

	then you will see all the source code in file: component\application\amazon\amazon-freertos

4.  Configure aws_clientcredential.h and aws_clientcredential_keys.h
	Refer to https://docs.aws.amazon.com/freertos/latest/userguide/freertos-configure.html, which will have the instructions. 

	-In aws_clientcredential.h(component/application/amazon/amazon-freertos/demos/include), set network connection related info

	#define clientcredentialMQTT_BROKER_ENDPOINT	"xxxxxxxxxxxxxx.amazonaws.com"

	#define clientcredentialIOT_THING_NAME		"TestDevice"

	-In aws_clientcredential_keys.h(component/application/amazon/amazon-freertos/demos/include), set MQTT Demo required credentials
			
	#define keyCLIENT_CERTIFICATE_PEM 			"CERTIFICATE"
	#define keyCLIENT_PRIVATE_KEY_PEM			"PRIVATE_KEY"

5.  For running Amazon SDK example, the following configuration is set.

	- make all EXAMPLE=amazon
	
	- In aws_main.c(component/application/amazon/amazon-freertos/ports/amebaDplus/)

		//mqtt mutual auto demo
		RunCoreMqttMutualAuthDemo(0, NULL, NULL, NULL, NULL);

		//http mutual auto demo
		//RunCoreHttpMutualAuthDemo(0, NULL, NULL, NULL, NULL);

		//device shadow demo
		//RunDeviceShadowDemo(0, NULL, NULL, NULL, NULL);

		//device defender demo
		//RunDeviceDefenderDemo(0, NULL, NULL, NULL, NULL);

		// ota over mqtt demo
		//RunOtaCoreMqttDemo(0, NULL, NULL, NULL, NULL);
		
		//ota over mqtt streams demo (NEW!)
		//RunOtaCoreMqttStreamsDemo(0, NULL, NULL, NULL, NULL);
        
	- Default will run MQTT example

6.  OTA update prerequisites (https://docs.aws.amazon.com/freertos/latest/userguide/ota-prereqs.html)
	Step1. Prerequisites for OTA updates using MQTT
	Step2. Create an Amazon S3 bucket to store your update
	Step3. Create an OTA Update service role
	Step4. Create an OTA user policy
	---
	Step5. Create esdsasigner.key and ecdsasigner.crt by openSSL (optional)
		EX:	sudo openssl ecparam -name prime256v1 -genkey -out ecdsa-sha256-signer.key.pem
			sudo openssl req -new -x509 -days 3650 -key ecdsa-sha256-signer.key.pem -out ecdsa-sha256-signer.crt.pem

7.  Additional OTA firmware preparation steps
	a.	Change the MINOR/MAJOR version of "app" in sdk-ameba-all_v1.0a/amebadplus_gcc_project/manifest.json.
	It should be at least +1 of last version. This is used for the bootloader to recognize which OTA partition to read from when the device resets
	"app":
	{
		"IMG_ID": "1",
		"IMG_VER_MAJOR": 1,
		"IMG_VER_MINOR": 2,	// 1
			...
	}
	b. 	Change the APP_VERSION_* in sdk-ameba-all_v1.0a/component/application/amazon/amazon-freertos/ports/amebaDplus/config_files/ota_demo_config.h
	It should be at least +1 of last version. This is used for OTA Updater to recognize if the OTA version requires upgrading
	#ifndef APP_VERSION_MAJOR
		#define APP_VERSION_MAJOR    0
	#endif

	#ifndef APP_VERSION_MINOR
		#define APP_VERSION_MINOR    9
	#endif

	#ifndef APP_VERSION_BUILD
		#define APP_VERSION_BUILD    3	// 2
	#endif

8.  How is the OTA firmware signature generated:
	a.	Build the project and ensure that OTA_All.bin is generated
	b.	Run component/application/amazon/amazon_ota_tools/python_custom_ecdsa_Dplus_gcc.py to output IDT-OTA-Signature
		i.	The script requires the following pre-requisites to work
			1.	Python must be installed in the system with version 3.7.x or later
			2.	Pyopenssl library must be installed using 'pip install pyopenssl'
			3.	The ECDSA signing key and the Certificate pair must be present in the same folder as the python script and must be named 'ecdsa-sha256-signer.key.pem' and 'ecdsa-sha256-signer.crt.pem' respectively.
			
			!!!!!!! The key pair in SDK are just for example, please generated new key by openssl !!!!!!
			!!!!!!! The key pair in SDK are just for example, please generated new key by openssl !!!!!!
			!!!!!!! The key pair in SDK are just for example, please generated new key by openssl !!!!!!
			
	       There might be some error if there are packages lack in your environment (like openssl...). Please install the package and run the script again.
	c.	After getting the IDT-OTA-Signature, you can upload sdk-ameba-all_v1.0a/amebadplus_gcc_project/OTA_All.bin to the S3 bucket.

9.  How to trigger a custom signed OTA job in amazon AWS IOT core. 
	a.	Add certificate pem(ecdsa-sha256-signer.crt.pem) into component/application/amazon/amazon-freertos/ports/amebaDplus/config_files/ota_demo_config.h
	b.	Click on 'Create OTA update job', select your thing/things group and then select next.
	c.	In the following page, choose the option 'Use my custom signed firmware image'
	d.	Choose your custom signed firmware binary that was generated by the python script, and pick a S3 bucket to upload to
	e.	In the signature field please enter the content of 'IDT-OTA-Signature'
	f.	Choose hash algorithm as 'SHA-256'
	g.	Choose encryption algorithm as 'ECDSA'.
	h.	In "pathname of code signing certificate" and the "Pathname of file on device", both enter '/'
	i.	Choose the IAM role for OTA update job.(This is the same IAM role as any OTA update job)
	j.	Click next, give a unique name for the job and create.				
=============================================================================================================

1.0a_patch_dplus_amazon_v202210-LTS_20240510_(v01)

[Description]
    Support amazon-freertos-202210.00-LTS with MQTT/SHADOWS/OTA demos with GCC

	The patch is base on sdk-ameba-all_v1.0a.tgz + 1.0a_patch_dplus_amazon_v202210-LTS_20240510_(v01).tar.bz2
	
	Please merge the following files to project, do not replace these files directly, there would be some compile error.
	
	!!! Only support Dplus which with PSRAM. !!!

1.	Notes:
	1. Support aws_demo (MQTT/SHADOWS/OTA) on AmebaDplus
	2. Replace mbedtls by amazon mbedtls with LTS version (amazon-freertos/libraries/3rdparty/mbedtls/library)
	3. Add amazon_ota_tools for output AWS_OTA firmware

	Modified files
		amebadplus_gcc_project/project_km4/asdk/make/application/Makefile
		amebadplus_gcc_project/project_km4/asdk/make/mbedtls/Makefile
		amebadplus_gcc_project/project_km4/asdk/Makefile.include.gen
		amebadplus_gcc_project/project_km4/inc/FreeRTOSConfig.h
		component/lwip/api/lwipopts.h
		component/soc/amebadplus/fwlib/include/ameba_ota.h
		component/wifi/wpa_supplicant/src/crypto/tls_polarssl.c

	Add files
		AmebaDplus_Amazon_FreeRTOS_Getting_Started_Guide_v2.1.pdf
		amebadplus_gcc_project/project_km4/asdk/make/application/amazon/Makefile
		component/application/amazon/amazon_ota_tools/*
		component/example/amazon/*
	

2.  For AWS IoT document, please refer to the Amazon Web
   - https://docs.aws.amazon.com/iot/latest/developerguide/what-is-aws-iot.html
   

3.  Clone the Realtek FreeRTOS-LTS 202210-LTS repository from our Github (https://github.com/ambiot/amazon-freertos/tree/FreeRTOS-LTS-202210.xx)
	Run the following command under the path: component\application\amazon

	$ git clone --recurse-submodules -b FreeRTOS-LTS-202210.xx --depth 1 https://github.com/ambiot/amazon-freertos.git amazon-freertos
	$ git checkout 03cdffa49f0b1f21a87cb5c61bdf6fa31280bc9f 

	then you will see all the source code in file: component\application\amazon\amazon-freertos

4.  Configure aws_clientcredential.h and aws_clientcredential_keys.h
	Refer to https://docs.aws.amazon.com/freertos/latest/userguide/freertos-configure.html, which will have the instructions. 

	-In aws_clientcredential.h(component/application/amazon/amazon-freertos/demos/include), set network connection related info

	#define clientcredentialMQTT_BROKER_ENDPOINT	"xxxxxxxxxxxxxx.amazonaws.com"

	#define clientcredentialIOT_THING_NAME		"TestDevice"

	-In aws_clientcredential_keys.h(component/application/amazon/amazon-freertos/demos/include), set MQTT Demo required credentials
			
	#define keyCLIENT_CERTIFICATE_PEM 			"CERTIFICATE"
	#define keyCLIENT_PRIVATE_KEY_PEM			"PRIVATE_KEY"

5.  For running Amazon SDK example, the following configuration is set.

	- make all EXAMPLE=amazon
	
	- In aws_main.c(component/application/amazon/amazon-freertos/ports/amebaDplus/)

		//mqtt mutual auto demo
		RunCoreMqttMutualAuthDemo(0, NULL, NULL, NULL, NULL);

		//http mutual auto demo
		//RunCoreHttpMutualAuthDemo(0, NULL, NULL, NULL, NULL);

		//device shadow demo
		//RunDeviceShadowDemo(0, NULL, NULL, NULL, NULL);

		//device defender demo
		//RunDeviceDefenderDemo(0, NULL, NULL, NULL, NULL);

		// ota over mqtt demo
		//RunOtaCoreMqttDemo(0, NULL, NULL, NULL, NULL);
        
	- Default will run MQTT example

6.  OTA update prerequisites (https://docs.aws.amazon.com/freertos/latest/userguide/ota-prereqs.html)
	Step1. Prerequisites for OTA updates using MQTT
	Step2. Create an Amazon S3 bucket to store your update
	Step3. Create an OTA Update service role
	Step4. Create an OTA user policy
	---
	Step5. Create esdsasigner.key and ecdsasigner.crt by openSSL (optional)
		EX:	sudo openssl ecparam -name prime256v1 -genkey -out ecdsa-sha256-signer.key.pem
			sudo openssl req -new -x509 -days 3650 -key ecdsa-sha256-signer.key.pem -out ecdsa-sha256-signer.crt.pem

7.  How is the OTA firmware signature generated:
	a.	Run component/application/amazon/amazon_ota_tools/signer_gcc.sh to output IDT-OTA-Signature
		i.	The script requires the following pre-requisites to work
			1.	Python must be installed in the windows system with version 3.7.x or later
			2.	Pyopenssl library must be installed using 'pip install pyopenssl'
			3.	The ECDSA signing key and the Certificate pair must be present in the same folder as the python script and must be named 'ecdsa-sha256-signer.key.pem' and 'ecdsa-sha256-signer.crt.pem' respectively.
			
			!!!!!!! The key pair in SDK are just for example, please generated new key by openssl !!!!!!
			!!!!!!! The key pair in SDK are just for example, please generated new key by openssl !!!!!!
			!!!!!!! The key pair in SDK are just for example, please generated new key by openssl !!!!!!
			
	       There might be some error if there are packages lack in your environment (like openssl...). Please install the package and run the script again.
	b.	After getting the IDT-OTA-Signature, you can upload project/realtek_amebaDplus_va0_example/GCC-RELEASE/auto_build/OTA_All.bin to the S3 bucket.

8.  How to trigger a custom signed OTA job in amazon AWS IOT core. 
	a.	Click on 'Create OTA update job', select your thing/things group and then select next.
	b.	In the following page, choose the option 'Use my custom signed firmware image'
	c.	Choose your custom signed firmware binary that was generated by the python script from S3 bucket.
	d.	In the signature field please enter the content of 'IDT-OTA-Signature' and add certificate pem(ecdsa-sha256-signer.crt.pem) into component/application/amazon/amazon-freertos/ports/amebaDplus/config_files/ota_demo_config.h
	e.	Choose hash algorithm as 'SHA-256'
	f.	Choose encryption algorithm as 'ECDSA'.
	g.	In "pathname of code signing certificate" and the "Pathname of file on device", both enter '/'
	h.	Choose the IAM role for OTA update job.(This is the same IAM role as any OTA update job)
	i.	Click next, give a unique name for the job and create.
