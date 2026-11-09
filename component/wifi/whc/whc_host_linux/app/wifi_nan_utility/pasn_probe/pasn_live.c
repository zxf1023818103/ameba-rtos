/* Experimental Green2 NAN PASN responder for pasn_vendor_events input
 * (also accepts the equivalent debug wpa_supplicant event format).
 * Keeps the PASN state through Auth3 and installs the derived keys.
 */
#include <net/if.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/nan_defs.h"
#include "common/sae.h"
#include "common/wpa_common.h"
#include "crypto/sha256.h"
#include "pasn/pasn_common.h"

#define PASN_START_LEN 645
#define PASN_RX_LEN 598
#define AUTH_MAX 512
#define ATTR_MAX 64
#define PASS_MAX 16
#define REALTEK_OUI 0x00e04c
#define NAN_SUBCMD_PASN_SET_KEY 0x1909
#define PAIRING_SETUP 1
#define PAIRING_VERIFICATION 2
#define NIK_CACHE_FILE "/var/lib/nan/nik_cache"

struct pasn_start_event {
	u8 deinit, role, pairing_type, peer[6], bssid[6];
	u8 auth_method, nik_caching, pass_len, pass[PASS_MAX];
	u16 frame_len;
	u8 frame[AUTH_MAX];
	u8 attrs_len, attrs[ATTR_MAX], own_pmkid[16], peer_pmkid[16];
} __attribute__((packed));

struct pasn_rx_event {
	u8 seq, pairing_type, pass_len, pass[PASS_MAX];
	u16 frame_len;
	u8 frame[AUTH_MAX];
	u8 attrs_len, attrs[ATTR_MAX];
} __attribute__((packed));

struct nik_cache_entry {
	u32 lifetime, start_ms;
	u8 role, auth, peer_inst, nik[16], pmkid[16], pass_len, pass[16];
};

struct nik_cache_file {
	u8 version, reserved[3], own_nik[16];
	struct nik_cache_entry entries[8];
};

_Static_assert(sizeof(struct pasn_start_event) == PASN_START_LEN,
	       "PASN start event ABI changed");
_Static_assert(sizeof(struct pasn_rx_event) == PASN_RX_LEN,
	       "PASN rx event ABI changed");
_Static_assert(sizeof(struct nik_cache_file) == 500,
	       "Green2 NIK cache ABI changed");

struct bridge {
	struct nl_sock *nl;
	int family;
	unsigned int ifindex;
	unsigned int freq;
	struct rsn_pmksa_cache *pmksa;
	struct pasn_data *pasn;
	struct sae_pt *pt;
	u8 own[6], peer[6], bssid[6];
	u8 pairing_type;
	u8 verified_peer_pmkid[16];
	bool peer_pmkid_valid;
	unsigned int auth2_sent;
	u8 auth1_frame[AUTH_MAX], auth2_frame[AUTH_MAX];
	size_t auth1_len, auth2_len;
	struct timespec auth1_started;
	bool keys_installed;
};

static int store_npk(struct bridge *b)
{
	const char *path = getenv("GREEN2_NPK_FILE");
	char tmp[PATH_MAX];
	u8 record[4 + 32];
	int fd, ok;

	if (!path || !*path || pasn_get_pmk_len(b->pasn) != 32)
		return -1;
	memcpy(record, "NPK1", 4);
	memcpy(record + 4, pasn_get_pmk(b->pasn), 32);
	if (snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) >=
	    (int) sizeof(tmp) || (fd = mkstemp(tmp)) < 0) {
		forced_memzero(record, sizeof(record));
		return -1;
	}
	ok = write(fd, record, sizeof(record)) == sizeof(record);
	if (close(fd) < 0) ok = 0;
	if (ok && rename(tmp, path) < 0) ok = 0;
	if (!ok) unlink(tmp);
	forced_memzero(record, sizeof(record));
	return ok ? 0 : -1;
}

static int prepare_verification(struct bridge *b, const u8 *frame,
				 size_t frame_len, const u8 own_pmkid[16])
{
	const char *path = getenv("GREEN2_NPK_FILE");
	struct nik_cache_file cache = {0};
	struct wpa_ie_data rsn = {0};
	u8 record[4 + 32] = {0}, message[3 + 6 + 8], digest[32];
	const u8 *nonce = NULL, *tag = NULL;
	size_t pos = 30;
	FILE *fp;
	int i, match = -1, ret = -1;
	const char *failure = "malformed verification frame";

	if (!path || !*path || frame_len < pos)
		goto done;
	while (pos + 2 <= frame_len) {
		u8 id = frame[pos], len = frame[pos + 1];
		const u8 *value = frame + pos + 2;
		size_t end = pos + 2 + len;
		if (end > frame_len) goto done;
		if (id == WLAN_EID_RSN &&
		    wpa_parse_wpa_ie_rsn(frame + pos, 2 + len, &rsn))
			goto done;
		if (id == WLAN_EID_VENDOR_SPECIFIC && len >= 4 &&
		    !memcmp(value, "\x50\x6f\x9a\x13", 4)) {
			size_t ap = 4;
			while (ap + 3 <= len) {
				u8 aid = value[ap];
				u16 alen = value[ap + 1] | (value[ap + 2] << 8);
				ap += 3;
				if (ap + alen > len) goto done;
				if (aid == NAN_ATTR_NIRA && alen == 17 &&
				    value[ap] == NAN_NIRA_CIPHER_VER_128) {
					nonce = value + ap + 1;
					tag = value + ap + 9;
				}
				ap += alen;
			}
		}
		pos = end;
	}
	if (!nonce || !tag || rsn.num_pmkid != 1 || !rsn.pmkid ||
	    memcmp(rsn.pmkid, nonce, 8) || memcmp(rsn.pmkid + 8, tag, 8))
		goto done;
	failure = "NIK snapshot unavailable";
	fp = fopen(NIK_CACHE_FILE, "rb");
	if (!fp) goto done;
	i = fread(&cache, 1, sizeof(cache), fp) == sizeof(cache);
	fclose(fp);
	failure = "NIK snapshot incomplete or invalid";
	if (!i || cache.version != 1) goto done;
	memcpy(message, "NIR", 3);
	memcpy(message + 3, b->peer, 6);
	memcpy(message + 9, nonce, 8);
	for (i = 0; i < 8; i++) {
		if (hmac_sha256(cache.entries[i].nik, 16,
				message, sizeof(message), digest) == 0 &&
		    os_memcmp_const(digest, tag, 8) == 0) {
			match = i;
			break;
		}
	}
	failure = "NIRA does not match cached identity";
	if (match < 0) goto done;
	failure = "NPK snapshot unavailable";
	fp = fopen(path, "rb");
	if (!fp) goto done;
	i = fread(record, 1, sizeof(record), fp) == sizeof(record);
	fclose(fp);
	failure = "NPK snapshot incomplete or invalid";
	if (!i || memcmp(record, "NPK1", 4)) goto done;
	failure = "PMKSA insertion failed";
	if (pasn_responder_pmksa_cache_add(b->pmksa, b->own, b->peer,
				    record + 4, 32, rsn.pmkid,
				    WPA_KEY_MGMT_SAE))
		goto done;
	pasn_set_custom_pmkid(b->pasn, own_pmkid);
	memcpy(b->verified_peer_pmkid, rsn.pmkid,
	       sizeof(b->verified_peer_pmkid));
	b->peer_pmkid_valid = true;
	printf("Validated NIRA and loaded NPK for verification peer="
	       MACSTR "\n", MAC2STR(b->peer));
	fflush(stdout);
	ret = 0;
done:
	if (ret) fprintf(stderr, "Verification rejected: %s\n", failure);
	forced_memzero(&cache, sizeof(cache));
	forced_memzero(record, sizeof(record));
	forced_memzero(digest, sizeof(digest));
	return ret;
}

/* hostap requires this callback whenever a custom outgoing PMKID is set.
 * Accept only the incoming PMKID whose NIRA was authenticated for this peer
 * by prepare_verification(); never accept an arbitrary cached-key request.
 */
static int validate_custom_pmkid(void *ctx, const u8 *addr, const u8 *pmkid)
{
	struct bridge *b = ctx;

	if (!addr || !pmkid || b->pairing_type != PAIRING_VERIFICATION ||
	    !b->peer_pmkid_valid || memcmp(addr, b->peer, sizeof(b->peer)))
		return -1;
	return os_memcmp_const(pmkid, b->verified_peer_pmkid,
			      sizeof(b->verified_peer_pmkid)) ? -1 : 0;
}

/* libpasn.so includes AP PMKSA objects. No AP/RADIUS state exists here. */
struct hostapd_data;
struct sta_info;
struct vlan_description;
struct radius_class_data;
int ap_sta_set_vlan(struct hostapd_data *hapd, struct sta_info *sta,
		    struct vlan_description *desc)
{
	(void) hapd; (void) sta; (void) desc;
	return -1;
}
void radius_free_class(struct radius_class_data *data)
{
	(void) data;
}
int radius_copy_class(struct radius_class_data *dst,
		      const struct radius_class_data *src)
{
	(void) dst; (void) src;
	return -1;
}

static int hex_line(const char *line, u8 *out, size_t len)
{
	const char *p = strstr(line, "hexdump(len=");
	size_t n = 0;
	unsigned int byte;

	if (!p || !(p = strstr(p, "): ")))
		return -1;
	p += 3;
	while (*p && n < len) {
		while (*p == ' ' || *p == '\t') p++;
		if (sscanf(p, "%2x", &byte) != 1) break;
		out[n++] = byte;
		if (!p[0] || !p[1]) break;
		p += 2;
		if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\0')
			return -1;
	}
	return n == len ? 0 : -1;
}

static int send_mgmt(void *ctx, const u8 *frame, size_t len, int noack,
		     unsigned int freq, unsigned int wait)
{
	struct bridge *b = ctx;
	struct nl_msg *msg;
	int ret;

	(void) noack; (void) freq; (void) wait;
	if (len < 30 || len > AUTH_MAX || frame[0] != 0xb0 || frame[1] != 0 ||
	    frame[24] != 7 || frame[26] != 2 || frame[28] != 0 ||
	    frame[29] != 0 || memcmp(frame + 4, b->peer, 6) ||
	    memcmp(frame + 10, b->own, 6)) {
		fprintf(stderr, "refusing invalid Auth2\n");
		return -1;
	}
	msg = nlmsg_alloc();
	if (!msg)
		return -1;
	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, b->family, 0, 0,
			 NL80211_CMD_FRAME, 0) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, b->ifindex) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, b->freq) ||
	    nla_put(msg, NL80211_ATTR_FRAME, len, frame)) {
		nlmsg_free(msg);
		return -1;
	}
	ret = nl_send_auto(b->nl, msg);
	if (ret >= 0) ret = nl_wait_for_ack(b->nl);
	nlmsg_free(msg);
	if (ret < 0) {
		fprintf(stderr, "Auth2 rejected by nl80211: %s\n", nl_geterror(ret));
		return -1;
	}
	b->auth2_sent++;
	if (frame != b->auth2_frame)
		memcpy(b->auth2_frame, frame, len);
	b->auth2_len = len;
	printf("Auth2 submitted: %zu bytes, peer=" MACSTR "\n",
	       len, MAC2STR(b->peer));
	fflush(stdout);
	return 0;
}

/* Firmware ABI recovered from rtw_cfgvendor_nan_pasn_setkeys in the matching
 * Green2 lib_wifi_whc_dev.a: TK[16] | KDK[32] | peer NMI[6] | ND-PMK[32].
 * rtw_nan_kdk_to_kek and rtw_nan_kdk_to_pmk consume the field at offset 16.
 */
static int install_keys(struct bridge *b)
{
	u8 payload[16 + 32 + 6 + 32] = {0};
	u8 nmi_pair[12];
	struct nl_msg *msg = NULL;
	int ret = -1;

	if (b->pasn->ptk.tk_len != 16 || b->pasn->ptk.kdk_len != 32)
		return -1;
	memcpy(payload, b->pasn->ptk.tk, 16);
	memcpy(payload + 16, b->pasn->ptk.kdk, 32);
	memcpy(nmi_pair, b->peer, 6); /* iPhone is pairing initiator */
	memcpy(nmi_pair + 6, b->own, 6);
	if (sha256_prf(b->pasn->ptk.kdk, 32, "NDP PMK Derivation",
		       nmi_pair, sizeof(nmi_pair), payload + 54, 32))
		goto done;
	memcpy(payload + 48, b->peer, 6);
	msg = nlmsg_alloc();
	if (!msg || !genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, b->family,
				 0, 0, NL80211_CMD_VENDOR, 0) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, b->ifindex) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, REALTEK_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			NAN_SUBCMD_PASN_SET_KEY) ||
	    nla_put(msg, NL80211_ATTR_VENDOR_DATA,
		    sizeof(payload), payload)) {
		fprintf(stderr, "could not construct PASN set-key command\n");
		goto done;
	}
	ret = nl_send_auto(b->nl, msg);
	if (ret >= 0) ret = nl_wait_for_ack(b->nl);
	if (ret < 0)
		fprintf(stderr, "PASN set-key rejected: %s\n", nl_geterror(ret));
	else {
		const char *path = getenv("GREEN2_PASN_RESULT_FILE");
		char tmp[PATH_MAX];
		int fd, write_ok, close_ok;

		printf("PASN keys submitted for peer=" MACSTR "\n",
		       MAC2STR(b->peer));
		fflush(stdout);
		if (path && *path) {
			if (snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) >=
			    (int) sizeof(tmp) || (fd = mkstemp(tmp)) < 0) {
				fprintf(stderr, "PASN completion notification failed\n");
			} else {
				u8 result[1 + 6];
				result[0] = b->pairing_type;
				memcpy(result + 1, b->peer, 6);
				write_ok = write(fd, result, sizeof(result)) ==
					   sizeof(result);
				close_ok = close(fd) == 0;
				if (!write_ok || !close_ok || rename(tmp, path) < 0) {
					unlink(tmp);
					fprintf(stderr, "PASN completion notification failed\n");
				} else {
					printf("PASN completion notification queued for peer="
					       MACSTR "\n", MAC2STR(b->peer));
					fflush(stdout);
				}
			}
		}
	}
done:
	nlmsg_free(msg);
	forced_memzero(payload, sizeof(payload));
	forced_memzero(nmi_pair, sizeof(nmi_pair));
	return ret < 0 ? -1 : 0;
}

static void reset_session(struct bridge *b)
{
	if (b->pasn) pasn_data_deinit(b->pasn);
	if (b->pt) sae_deinit_pt(b->pt);
	b->pasn = NULL;
	b->pt = NULL;
	b->auth2_sent = 0;
	b->auth1_len = b->auth2_len = 0;
	b->keys_installed = false;
	memset(b->auth1_frame, 0, sizeof(b->auth1_frame));
	memset(b->auth2_frame, 0, sizeof(b->auth2_frame));
	b->pairing_type = 0;
	b->peer_pmkid_valid = false;
	memset(b->verified_peer_pmkid, 0, sizeof(b->verified_peer_pmkid));
	memset(b->own, 0, sizeof(b->own));
	memset(b->peer, 0, sizeof(b->peer));
	memset(b->bssid, 0, sizeof(b->bssid));
}

/* After a previous verification, Green2 may label a new PIN Auth1 as
 * verification. Only recognize an unambiguous SAE setup on the wire: no
 * cached PMKID/NIRA, SAE commit, matching PASN parameters and bootstrap IE.
 * This selects the handshake; libpasn still authenticates the PIN and MIC.
 */
static bool auth1_is_sae_setup(const u8 *frame, size_t len,
			       const u8 **npba, size_t *npba_len)
{
	bool rsn_seen = false, wrapped_seen = false, params_seen = false;
	bool bootstrap_seen = false;
	size_t pos = offsetof(struct ieee80211_mgmt, u.auth.variable);
	struct wpa_ie_data rsn;
	struct wpa_pasn_params_data params;

	if (!frame || len < pos)
		return false;
	while (pos < len) {
		const u8 *ie = frame + pos;
		const u8 *data = ie + 2;
		size_t n;
		if (len - pos < 2 || (n = ie[1]) > len - pos - 2)
			return false;
		if (ie[0] == WLAN_EID_RSN) {
			if (rsn_seen || wpa_parse_wpa_ie_rsn(ie, n + 2, &rsn) ||
			    rsn.key_mgmt != WPA_KEY_MGMT_SAE || rsn.num_pmkid ||
			    rsn.pairwise_cipher != WPA_CIPHER_CCMP)
				return false;
			rsn_seen = true;
		} else if (ie[0] == WLAN_EID_EXTENSION && n) {
			if (data[0] == WLAN_EID_EXT_WRAPPED_DATA) {
				if (wrapped_seen || n < 9 ||
				    WPA_GET_LE16(data + 1) != WLAN_AUTH_SAE ||
				    WPA_GET_LE16(data + 3) != 1 ||
				    WPA_GET_LE16(data + 5) != WLAN_STATUS_SAE_HASH_TO_ELEMENT ||
				    WPA_GET_LE16(data + 7) != 19)
					return false;
				wrapped_seen = true;
			} else if (data[0] == WLAN_EID_EXT_PASN_PARAMS) {
				if (params_seen || n > 253 ||
				    wpa_pasn_parse_parameter_ie(ie, n + 2, false, &params) ||
				    params.wrapped_data_format != WPA_PASN_WRAPPED_DATA_SAE ||
				    params.group != 19 || !params.pubkey_len)
					return false;
				params_seen = true;
			}
		} else if (ie[0] == WLAN_EID_VENDOR_SPECIFIC && n >= 4 &&
			   !memcmp(data, "\x50\x6f\x9a\x13", 4)) {
			size_t a = 4;
			while (a < n) {
				u16 size;
				if (n - a < 3 || (size = WPA_GET_LE16(data + a + 1)) > n - a - 3)
					return false;
				if (data[a] == NAN_ATTR_NIRA)
					return false;
				if (data[a] == NAN_ATTR_NPBA) {
					if (bootstrap_seen || size < 5)
						return false;
					bootstrap_seen = true;
					if (npba) *npba = data + a;
					if (npba_len) *npba_len = 3 + size;
				}
				a += 3 + size;
			}
		}
		pos += 2 + n;
	}
	return rsn_seen && wrapped_seen && params_seen && bootstrap_seen;
}

/* The stale firmware state affects the Auth2 attributes as well as the event
 * type. Keep its local CSIA (including publish IDs), replace verification NIRA
 * with local DCEA and echo the setup NPBA. hostap's nan_bootstrap_rx_request()
 * saves the initiator's NPBA for nan_pairing_prepare_pasn_elems() in this role.
 * Build separately so a malformed/oversized event is never partially changed.
 */
static int correct_setup_event(struct pasn_start_event *e)
{
	u8 attrs[ATTR_MAX], dcea[] = { NAN_ATTR_DCEA, 2, 0, 0,
		NAN_DEV_CAPA_EXT_INFO_1_PAIRING_SETUP };
	const u8 *npba = NULL;
	size_t npba_len = 0, pos = 0, used = 0;
	bool csia_seen = false, dcea_seen = false;

	if (e->frame_len > AUTH_MAX || e->attrs_len > ATTR_MAX)
		return -1;
	if (e->pairing_type != PAIRING_VERIFICATION ||
	    !auth1_is_sae_setup(e->frame, e->frame_len, &npba, &npba_len))
		return 0;
	if (e->nik_caching)
		dcea[4] |= NAN_DEV_CAPA_EXT_INFO_1_NPK_NIK_CACHING;
	while (pos < e->attrs_len) {
		const u8 *a = e->attrs + pos;
		size_t n;
		if (e->attrs_len - pos < 3 ||
		    (n = WPA_GET_LE16(a + 1)) > e->attrs_len - pos - 3)
			return -1;
		if (a[0] == NAN_ATTR_CSIA) {
			if (csia_seen || n < 3 || !(n & 1))
				return -1;
			csia_seen = true;
		}
		if (a[0] == NAN_ATTR_DCEA) {
			if (dcea_seen || n != 2)
				return -1;
			dcea_seen = true;
			dcea[3] = a[3]; /* local regulatory capability, if supplied */
		} else if (a[0] != NAN_ATTR_NIRA && a[0] != NAN_ATTR_NPBA) {
			memcpy(attrs + used, a, n + 3);
			used += n + 3; /* subset of the already bounded event */
		}
		pos += n + 3;
	}
	if (!csia_seen || sizeof(dcea) + npba_len > sizeof(attrs) - used)
		return -1;
	memcpy(attrs + used, dcea, sizeof(dcea));
	used += sizeof(dcea);
	memcpy(attrs + used, npba, npba_len);
	used += npba_len;
	memcpy(e->attrs, attrs, used);
	e->attrs_len = used;
	e->pairing_type = PAIRING_SETUP;
	return 1;
}

static bool auth1_is_retry(const struct bridge *b,
			   const struct pasn_start_event *e)
{
	struct timespec now;
	if (!b->pasn || !b->auth2_len || b->auth1_len != e->frame_len ||
	    e->frame_len < 30 || e->frame_len > AUTH_MAX ||
	    b->pairing_type != e->pairing_type ||
	    memcmp(b->auth1_frame + 4, e->frame + 4, 18) ||
	    memcmp(b->auth1_frame + 24, e->frame + 24, e->frame_len - 24) ||
	    clock_gettime(CLOCK_MONOTONIC, &now))
		return false;
	/* Ignore only MAC retry/sequence/duration changes. A changed SAE commit,
	 * PASN public key, bootstrap token or peer always starts a new exchange. */
	return now.tv_sec >= b->auth1_started.tv_sec &&
	       now.tv_sec - b->auth1_started.tv_sec < 10;
}

static int on_start(struct bridge *b, const char *line)
{
	struct pasn_start_event e;
	const struct ieee80211_mgmt *auth;
	char password[PASS_MAX + 1] = {0};
	u8 extra[2 + 4 + ATTR_MAX];
	u8 rsnxe[4];
	int ret = -1;

	if (hex_line(line, (u8 *) &e, sizeof(e)))
		return -1;
	if (e.deinit || e.role != 2 || e.auth_method != 1 ||
	    !e.pass_len || e.pass_len > PASS_MAX ||
	    e.frame_len < offsetof(struct ieee80211_mgmt, u.auth.variable) ||
	    e.frame_len > AUTH_MAX || e.attrs_len > ATTR_MAX)
		goto done;
	auth = (const struct ieee80211_mgmt *) e.frame;
	if (memcmp(auth->sa, e.peer, 6) ||
	    memcmp(auth->bssid, e.bssid, 6) ||
	    le_to_host16(auth->u.auth.auth_alg) != WLAN_AUTH_PASN ||
	    le_to_host16(auth->u.auth.auth_transaction) != 1)
		goto done;
	ret = correct_setup_event(&e);
	if (ret < 0) goto done;
	if (ret > 0)
		fprintf(stderr, "Corrected stale verification event and Auth2 attributes to SAE setup\n");
	if (auth1_is_retry(b, &e)) {
		printf("Auth1 retransmission: retaining PASN handshake%s\n",
		       b->keys_installed ? " (already completed)" : ", resending Auth2");
		ret = b->keys_installed ? 0 :
			send_mgmt(b, b->auth2_frame, b->auth2_len, 0, b->freq, 0);
		goto done;
	}
	reset_session(b);
	ret = -1;
	if (clock_gettime(CLOCK_MONOTONIC, &b->auth1_started))
		goto done;
	b->auth1_len = e.frame_len;
	memcpy(b->auth1_frame, e.frame, e.frame_len);
	memcpy(b->own, auth->da, 6);
	memcpy(b->peer, e.peer, 6);
	memcpy(b->bssid, e.bssid, 6);
	b->pairing_type = e.pairing_type;
	memcpy(password, e.pass, e.pass_len);
	b->pasn = pasn_data_init();
	if (!b->pasn) goto done;
	pasn_set_responder_pmksa(b->pasn, b->pmksa);
	pasn_set_own_addr(b->pasn, b->own);
	pasn_set_peer_addr(b->pasn, b->peer);
	pasn_set_bssid(b->pasn, b->bssid);
	b->pasn->group = 19;
	b->pasn->pasn_groups = calloc(2, sizeof(int));
	if (!b->pasn->pasn_groups) goto done;
	b->pasn->pasn_groups[0] = 19;
	pasn_set_cipher(b->pasn, WPA_CIPHER_CCMP);
	pasn_set_akmp(b->pasn, WPA_KEY_MGMT_SAE);
	pasn_set_rsn_pairwise(b->pasn, WPA_CIPHER_CCMP);
	pasn_set_wpa_key_mgmt(b->pasn, WPA_KEY_MGMT_SAE);
	pasn_enable_kdk_derivation(b->pasn);
	if (e.pairing_type == PAIRING_SETUP) {
		b->pt = sae_derive_pt(b->pasn->pasn_groups,
				      (const u8 *) NAN_PASN_SSID,
				      strlen(NAN_PASN_SSID),
				      (const u8 *) password, e.pass_len,
				      NULL, 0);
		if (!b->pt || pasn_set_pt(b->pasn, b->pt)) goto done;
	} else if (e.pairing_type == PAIRING_VERIFICATION) {
		if (prepare_verification(b, e.frame, e.frame_len,
					 e.own_pmkid)) {
			fprintf(stderr, "Verification NIRA/NPK unavailable\n");
			goto done;
		}
	} else {
		goto done;
	}
	rsnxe[0] = WLAN_EID_RSNX;
	rsnxe[1] = 2;
	rsnxe[2] = 1 | (1 << WLAN_RSNX_CAPAB_SAE_H2E);
	rsnxe[3] = 0;
	pasn_set_rsnxe_ie(b->pasn, rsnxe);
	extra[0] = WLAN_EID_VENDOR_SPECIFIC;
	extra[1] = 4 + e.attrs_len;
	extra[2] = 0x50; extra[3] = 0x6f;
	extra[4] = 0x9a; extra[5] = 0x13;
	memcpy(extra + 6, e.attrs, e.attrs_len);
	if (pasn_set_extra_ies(b->pasn, extra, 6 + e.attrs_len)) goto done;
	pasn_register_callbacks(b->pasn, b, send_mgmt, validate_custom_pmkid,
				NULL, NULL);
	ret = handle_auth_pasn_1(b->pasn, b->own, b->peer, auth,
				 e.frame_len, false);
	if (!b->auth2_sent) ret = -1;
done:
	memset(password, 0, sizeof(password));
	memset(&e, 0, sizeof(e));
	if (ret) {
		fprintf(stderr, "Auth1 processing failed\n");
		reset_session(b);
	}
	return ret;
}

static int on_rx(struct bridge *b, const char *line)
{
	struct pasn_rx_event e;
	const struct ieee80211_mgmt *auth;
	int ret;

	if (!b->pasn || !b->auth2_sent ||
	    hex_line(line, (u8 *) &e, sizeof(e)))
		return -1;
	if (e.seq != 3 || e.frame_len < 30 || e.frame_len > AUTH_MAX)
		return -1;
	auth = (const struct ieee80211_mgmt *) e.frame;
	if (memcmp(auth->da, b->own, 6) || memcmp(auth->sa, b->peer, 6) ||
	    memcmp(auth->bssid, b->bssid, 6) ||
	    le_to_host16(auth->u.auth.auth_alg) != WLAN_AUTH_PASN ||
	    le_to_host16(auth->u.auth.auth_transaction) != 3)
		return -1;
	if (b->keys_installed) {
		printf("Ignoring Auth3 after keys already installed\n");
		memset(&e, 0, sizeof(e));
		return 0;
	}
	ret = handle_auth_pasn_3(b->pasn, b->own, b->peer, auth, e.frame_len);
	printf("Auth3 verification %s: peer=" MACSTR ", TK=%zu, KDK=%zu\n",
	       ret ? "FAILED" : "OK", MAC2STR(b->peer),
	       b->pasn->ptk.tk_len, b->pasn->ptk.kdk_len);
	fflush(stdout);
	if (!ret)
		ret = install_keys(b);
	if (!ret)
		b->keys_installed = true;
	if (!ret && b->pairing_type == PAIRING_SETUP) {
		if (store_npk(b))
			fprintf(stderr, "Could not retain NPK for pairing verification\n");
		else
			printf("NPK retained for pairing verification\n");
		fflush(stdout);
	}
	memset(&e, 0, sizeof(e));
	return ret;
}

int main(int argc, char **argv)
{
	struct bridge b = {0};
	char *line = NULL;
	size_t cap = 0;
	int pending = 0;
	char *end;
	unsigned long freq;

	if (argc != 3) {
		fprintf(stderr, "usage: %s IFACE FREQ_MHZ < supplicant.log.stream\n",
			argv[0]);
		return 2;
	}
	b.ifindex = if_nametoindex(argv[1]);
	freq = strtoul(argv[2], &end, 10);
	if (!b.ifindex || *end || freq < 2400 || freq > 7125)
		return 2;
	b.freq = freq;
	if (os_program_init() || eloop_init())
		return 1;
	wpa_debug_level = MSG_INFO;
	b.pmksa = pasn_responder_pmksa_cache_init();
	if (!b.pmksa) {
		fprintf(stderr, "PASN responder PMKSA cache unavailable\n");
		return 1;
	}
	b.nl = nl_socket_alloc();
	if (!b.nl || genl_connect(b.nl) < 0 ||
	    (b.family = genl_ctrl_resolve(b.nl, "nl80211")) < 0) {
		fprintf(stderr, "nl80211 unavailable\n");
		return 1;
	}
	while (getline(&line, &cap, stdin) >= 0) {
		if (strstr(line, "Vendor event: wiphy=")) {
			pending = 0;
			if (strstr(line, "vendor_id=0xe04c subcmd=29"))
				pending = 29;
			else if (strstr(line, "vendor_id=0xe04c subcmd=30"))
				pending = 30;
			continue;
		}
		if (pending == 29 && strstr(line, "hexdump(len=645):")) {
			pending = 0;
			on_start(&b, line);
		} else if (pending == 30 && strstr(line, "hexdump(len=598):")) {
			pending = 0;
			on_rx(&b, line);
		}
	}
	reset_session(&b);
	pasn_responder_pmksa_cache_deinit(b.pmksa);
	nl_socket_free(b.nl);
	if (line) {
		memset(line, 0, cap);
		free(line);
	}
	eloop_destroy();
	os_program_deinit();
	return 0;
}
