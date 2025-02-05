
include $(MAKE_INCLUDE_GEN)
MODULE_IFLAGS += -I$(BASEDIR)/component/network/mqtt/MQTTClient
MODULE_IFLAGS += -I$(BASEDIR)/component/network/mqtt/MQTTPacket

.PHONY: all clean

#*****************************************************************************#
#                                 VARIABLES                                   #
#*****************************************************************************#
APP_DIR = $(TARGETDIR)/app/monitor
DIR = $(BASEDIR)/component/at_cmd

ifeq ($(CONFIG_IMQ_EN),y)
COMPONENT += ipc_app
COMPONENT_CLEAN += ipc_app
endif

#*****************************************************************************#
#                               Source FILE LIST                              #
#*****************************************************************************#
vpath %.c $(APP_DIR) $(shell find $(APP_DIR) -type d)

CSRC = $(APP_DIR)/ram/monitor_km4.c \
       $(APP_DIR)/ram/shell_ram.c \
       $(APP_DIR)/ram/low_level_io.c

ifeq ($(CONFIG_LONGER_CMD),y)
CSRC += $(APP_DIR)/rom/shell_rom_patch.c
endif


# note: apply new atcmd, add your config here!!!
vpath %.c $(DIR)

CSRC += $(DIR)/atcmd_service.c \
		$(DIR)/atcmd_sys.c \
		$(DIR)/atcmd_bt_mp.c

ifeq ($(CONFIG_WLAN),y)
CSRC +=	$(DIR)/atcmd_wifi.c \
		$(DIR)/atcmd_mqtt.c \
		$(DIR)/atcmd_lwip.c 
endif

ifeq ($(CONFIG_BT), y)
CSRC += $(DIR)/atcmd_bt_ext.c
endif

ifeq ($(CONFIG_ATCMD_IO_UART), y)
CSRC += $(DIR)/at_intf_uart.c
endif

#*****************************************************************************#
#                               Object FILE LIST                              #
#*****************************************************************************#
OBJS = $(notdir $(CSRC:.c=.o))

#*****************************************************************************#
#                               Include Dependency                            #
#*****************************************************************************#
MODULE_IFLAGS += -I$(DIR) \
				-I$(APP_DIR)/include \
				-I$(FREERTOSDIR)/include/ \
				-I$(FREERTOSDIR)/portable/GCC/AmebaDplus_KM4/non_secure \
				-I$(FREERTOSDIR)/portable/GCC/AmebaDplus_KM4/secure

#*****************************************************************************#
#                        RULES TO GENERATE TARGETS                            #
#*****************************************************************************#
# Define the Rules to build the core targets
$(foreach n, $(COMPONENT), $(eval $(call GenerateTargets, $(n),all)))

COPY_RAM_OBJS: CORE_TARGETS
all: COPY_RAM_OBJS $(addsuffix -all, $(COMPONENT))

#*****************************************************************************#
#              GENERATE OBJECT FILE                                           #
#*****************************************************************************#
CORE_TARGETS:	$(OBJS)

#*****************************************************************************#
#                        RULES TO CLEAN TARGETS                               #
#*****************************************************************************#
$(foreach n, $(COMPONENT_CLEAN), $(eval $(call GenerateTargets,$(n),clean)))

clean: CLEAN_OBJS $(addsuffix -clean, $(COMPONENT_CLEAN))
	$(call CLEAN_FUNC)

-include $(DEPS)
