/* Offline Green2 NAN PASN Auth1 -> Auth2 probe.
 *
 * Uses the hostap PASN responder for cryptography. It never transmits a frame
 * or installs a key. The input is a full 645-byte NAN_EVENT_PASN_START payload
 * printed by wpa_supplicant -dd -K as a single hex line.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/nan_defs.h"
#include "common/sae.h"
#include "pasn/pasn_common.h"

#define GREEN2_PASN_EVENT_LEN 645
#define GREEN2_AUTH_MAX 512
#define GREEN2_ATTR_MAX 64
#define GREEN2_PASS_MAX 16

struct green2_pasn_start {
	uint8_t deinit;
	uint8_t role;
	uint8_t pairing_type;
	uint8_t peer_nmi[6];
	uint8_t bssid[6];
	uint8_t auth_method;
	uint8_t nik_caching;
	uint8_t passphrase_len;
	uint8_t passphrase[GREEN2_PASS_MAX];
	uint16_t auth_frame_len;
	uint8_t auth_frame[GREEN2_AUTH_MAX];
	uint8_t append_nan_attr_len;
	uint8_t append_nan_attr[GREEN2_ATTR_MAX];
	uint8_t own_pmkid[16];
	uint8_t peer_pmkid[16];
} __attribute__((packed));

_Static_assert(sizeof(struct green2_pasn_start) == GREEN2_PASN_EVENT_LEN,
	       "Green2 event ABI changed");
_Static_assert(offsetof(struct green2_pasn_start, auth_frame) == 36,
	       "Green2 Auth frame offset changed");

struct response {
	uint8_t frame[1024];
	size_t len;
};

/* libpasn.so also links the AP PMKSA cache. These AP-only hooks are never
 * reached by this offline probe because no AP station or RADIUS state exists.
 */
struct hostapd_data;
struct sta_info;
struct vlan_description;
struct radius_class_data;

int ap_sta_set_vlan(struct hostapd_data *hapd, struct sta_info *sta,
		    struct vlan_description *desc)
{
	(void) hapd;
	(void) sta;
	(void) desc;
	return -1;
}

void radius_free_class(struct radius_class_data *data)
{
	(void) data;
}

int radius_copy_class(struct radius_class_data *dst,
		      const struct radius_class_data *src)
{
	(void) dst;
	(void) src;
	return -1;
}

static int capture_auth2(void *ctx, const u8 *data, size_t len, int noack,
			 unsigned int freq, unsigned int wait)
{
	struct response *resp = ctx;

	(void) noack;
	(void) freq;
	(void) wait;
	if (len > sizeof(resp->frame) || resp->len)
		return -1;
	memcpy(resp->frame, data, len);
	resp->len = len;
	return 0;
}

static int parse_hex_line(const char *line, uint8_t *out, size_t out_len)
{
	const char *p = strstr(line, "hexdump(len=645):");
	size_t n = 0;
	unsigned int byte;

	if (p)
		p += strlen("hexdump(len=645):");
	else
		p = line;
	while (*p && n < out_len) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (sscanf(p, "%2x", &byte) != 1)
			break;
		out[n++] = (uint8_t) byte;
		if (!p[0] || !p[1])
			break;
		p += 2;
		if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\0')
			return -1;
	}
	return n == out_len ? 0 : -1;
}

static int write_frame(const char *path, const struct response *resp)
{
	FILE *f = fopen(path, "wb");
	int ok;

	if (!f)
		return -1;
	ok = fwrite(resp->frame, 1, resp->len, f) == resp->len;
	if (fclose(f))
		ok = 0;
	return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
	struct green2_pasn_start evt;
	struct response resp = {0};
	struct pasn_data *pasn = NULL;
	struct sae_pt *pt = NULL;
	struct ieee80211_mgmt *auth;
	char passphrase[GREEN2_PASS_MAX + 1] = {0};
	char *line = NULL;
	size_t line_cap = 0;
	uint8_t extra[2 + 4 + GREEN2_ATTR_MAX];
	uint8_t rsnxe[4];
	uint16_t auth_len;
	int ret = 1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s AUTH2_OUTPUT.bin < event_hex_line\n", argv[0]);
		return 2;
	}
	if (getline(&line, &line_cap, stdin) < 0 ||
	    parse_hex_line(line, (uint8_t *) &evt, sizeof(evt))) {
		fprintf(stderr, "invalid 645-byte PASN event line\n");
		goto done;
	}
	auth_len = evt.auth_frame_len; /* little endian on Green2 and Linux */
	if (evt.deinit || evt.role != 2 || evt.auth_method != 1 ||
	    evt.passphrase_len == 0 || evt.passphrase_len > GREEN2_PASS_MAX ||
	    auth_len < offsetof(struct ieee80211_mgmt, u.auth.variable) ||
	    auth_len > GREEN2_AUTH_MAX ||
	    evt.append_nan_attr_len > GREEN2_ATTR_MAX) {
		fprintf(stderr, "unsupported or malformed Green2 PASN event\n");
		goto done;
	}
	auth = (struct ieee80211_mgmt *) evt.auth_frame;
	if (memcmp(auth->sa, evt.peer_nmi, 6) ||
	    memcmp(auth->bssid, evt.bssid, 6) ||
	    le_to_host16(auth->u.auth.auth_alg) != WLAN_AUTH_PASN ||
	    le_to_host16(auth->u.auth.auth_transaction) != 1) {
		fprintf(stderr, "Auth1 does not match event peer/BSSID\n");
		goto done;
	}
	memcpy(passphrase, evt.passphrase, evt.passphrase_len);
	if (os_program_init() || eloop_init()) {
		fprintf(stderr, "hostap initialization failed\n");
		goto done;
	}
	wpa_debug_level = MSG_INFO;
	pasn = pasn_data_init();
	if (!pasn)
		goto done;
	pasn_set_own_addr(pasn, auth->da);
	pasn_set_peer_addr(pasn, evt.peer_nmi);
	pasn_set_bssid(pasn, evt.bssid);
	pasn->group = 19;
	pasn->pasn_groups = calloc(2, sizeof(*pasn->pasn_groups));
	if (!pasn->pasn_groups)
		goto done;
	pasn->pasn_groups[0] = 19;
	pasn_set_cipher(pasn, WPA_CIPHER_CCMP);
	pasn_set_akmp(pasn, WPA_KEY_MGMT_SAE);
	pasn_set_rsn_pairwise(pasn, WPA_CIPHER_CCMP);
	pasn_set_wpa_key_mgmt(pasn, WPA_KEY_MGMT_SAE);
	pasn_enable_kdk_derivation(pasn);
	pt = sae_derive_pt(pasn->pasn_groups, (const u8 *) NAN_PASN_SSID,
			   strlen(NAN_PASN_SSID), (const u8 *) passphrase,
			   evt.passphrase_len, NULL, 0);
	if (!pt || pasn_set_pt(pasn, pt)) {
		fprintf(stderr, "SAE password element derivation failed\n");
		goto done;
	}
	rsnxe[0] = WLAN_EID_RSNX;
	rsnxe[1] = 2;
	rsnxe[2] = 1 | (1 << WLAN_RSNX_CAPAB_SAE_H2E);
	rsnxe[3] = 0;
	pasn_set_rsnxe_ie(pasn, rsnxe);
	extra[0] = WLAN_EID_VENDOR_SPECIFIC;
	extra[1] = 4 + evt.append_nan_attr_len;
	extra[2] = 0x50;
	extra[3] = 0x6f;
	extra[4] = 0x9a;
	extra[5] = 0x13;
	memcpy(extra + 6, evt.append_nan_attr, evt.append_nan_attr_len);
	if (pasn_set_extra_ies(pasn, extra, 6 + evt.append_nan_attr_len))
		goto done;
	pasn_register_callbacks(pasn, &resp, capture_auth2, NULL, NULL, NULL);
	if (handle_auth_pasn_1(pasn, auth->da, evt.peer_nmi, auth,
			       auth_len, false) || !resp.len) {
		fprintf(stderr, "PASN responder did not generate Auth2\n");
		goto done;
	}
	if (write_frame(argv[1], &resp)) {
		fprintf(stderr, "could not write Auth2\n");
		goto done;
	}
	printf("Auth2 generated: %zu bytes, status=%u, peer=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       resp.len, (unsigned int) resp.frame[28] |
	       ((unsigned int) resp.frame[29] << 8),
	       evt.peer_nmi[0], evt.peer_nmi[1], evt.peer_nmi[2],
	       evt.peer_nmi[3], evt.peer_nmi[4], evt.peer_nmi[5]);
	ret = 0;
done:
	if (pasn)
		pasn_data_deinit(pasn);
	if (pt)
		sae_deinit_pt(pt);
	if (line) {
		memset(line, 0, line_cap);
		free(line);
	}
	memset(passphrase, 0, sizeof(passphrase));
	memset(&evt, 0, sizeof(evt));
	return ret;
}
