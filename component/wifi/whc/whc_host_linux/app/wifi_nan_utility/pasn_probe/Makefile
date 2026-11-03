HOSTAP_DIR ?= ../hostap-pasn
HOSTAP_SRC := $(HOSTAP_DIR)/src
PKG_CONFIG ?= pkg-config
LIBNL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libnl-3.0 libnl-genl-3.0)
LIBNL_LIBS ?= $(shell $(PKG_CONFIG) --libs libnl-3.0 libnl-genl-3.0)
CFLAGS += -std=gnu11 -O2 -Wall -DCONFIG_SAE -DCONFIG_PASN
CFLAGS += -I$(HOSTAP_SRC) -I$(HOSTAP_SRC)/utils
LDFLAGS += -L$(HOSTAP_DIR)/wpa_supplicant -Wl,-rpath,'$$ORIGIN'
LDLIBS += -lpasn -lcrypto

.PHONY: all clean
all: pasn_probe send_auth2 pasn_live pasn_vendor_events

pasn_probe: pasn_probe.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

send_auth2: send_auth2.c
	$(CC) -std=gnu11 -O2 -Wall $(LIBNL_CFLAGS) -o $@ $< $(LIBNL_LIBS)

pasn_live: pasn_live.c
	$(CC) $(CFLAGS) $(LIBNL_CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS) $(LIBNL_LIBS)

pasn_vendor_events: pasn_vendor_events.c
	$(CC) -std=gnu11 -O2 -Wall -Wextra -Werror $(LIBNL_CFLAGS) -o $@ $< $(LIBNL_LIBS)

clean:
	rm -f pasn_probe send_auth2 pasn_live pasn_vendor_events
