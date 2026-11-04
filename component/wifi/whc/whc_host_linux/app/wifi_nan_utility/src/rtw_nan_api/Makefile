APP_PATH=../../rtw_aware
LIB_NAME=libnanapi.so
EXT_HDR=rtw_nan_struct.h rtw_nan_cmd_api.h rtw_nan_scenario_api.h
PKG_CONFIG ?= pkg-config
NL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libnl-3.0 libnl-genl-3.0)
NL_LIBS := $(shell $(PKG_CONFIG) --libs libnl-3.0 libnl-genl-3.0)

all:
	@$(CC) $(CFLAGS) $(NL_CFLAGS) -pthread -c -fpic *.c
	@$(CC) $(LDFLAGS) -shared -o $(LIB_NAME) *.o $(NL_LIBS) -pthread
	@rm -rf *.o
	cp $(LIB_NAME) $(APP_PATH)
	cp $(EXT_HDR) $(APP_PATH)
	@echo "libnanapi success!"
clean:
	rm -rf *.o $(LIB_NAME)
