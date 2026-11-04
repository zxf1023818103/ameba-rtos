/* Classification/attribute repair; no frame transmission or pairing caches. */
#include <assert.h>
#define main pasn_live_main
#include "../whc_host_linux/app/wifi_nan_utility/pasn_probe/pasn_live.c"
#undef main

int main(void)
{
	u8 frame[512] = {0}, copy[512];
	const u8 rsn[] = {48, 26, 1, 0, 0, 15, 172, 7,
		1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 8,
		0, 0, 0, 0, 0, 15, 172, 6};
	const u8 nan[] = {221, 12, 0x50, 0x6f, 0x9a, 0x13,
		NAN_ATTR_NPBA, 5, 0, 0, 0, 0, 0, 0};
	size_t n = 30, wrapped, params;
	memcpy(frame + n, rsn, sizeof(rsn)); n += sizeof(rsn);
	memcpy(frame + n, nan, sizeof(nan)); n += sizeof(nan);
	wrapped = n;
	frame[n++] = WLAN_EID_EXTENSION; frame[n++] = 105;
	frame[n++] = WLAN_EID_EXT_WRAPPED_DATA;
	frame[n++] = WLAN_AUTH_SAE; frame[n++] = 0;
	frame[n++] = 1; frame[n++] = 0;
	frame[n++] = WLAN_STATUS_SAE_HASH_TO_ELEMENT; frame[n++] = 0;
	frame[n++] = 19; frame[n++] = 0;
	n += 96; /* SAE scalar/element: libpasn performs crypto validation later. */
	params = n;
	frame[n++] = WLAN_EID_EXTENSION; frame[n++] = 39;
	frame[n++] = WLAN_EID_EXT_PASN_PARAMS;
	frame[n++] = WPA_PASN_CTRL_GROUP_AND_KEY_PRESENT;
	frame[n++] = WPA_PASN_WRAPPED_DATA_SAE;
	frame[n++] = 19; frame[n++] = 0;
	frame[n++] = 33; frame[n++] = WPA_PASN_PUBKEY_COMPRESSED_0;
	n += 32;
	assert(auth1_is_sae_setup(frame, n, NULL, NULL));
	assert(!auth1_is_sae_setup(NULL, n, NULL, NULL));
	for (size_t i = 0; i < n; i++) assert(!auth1_is_sae_setup(frame, i, NULL, NULL));
	/* Verification cannot enter the setup path, even with a wrapped IE. */
	memcpy(copy, frame, n); copy[30 + sizeof(rsn) + 6] = NAN_ATTR_NIRA;
	assert(!auth1_is_sae_setup(copy, n, NULL, NULL));
	memcpy(copy, frame, n); copy[30 + 22] = 1; /* PMKID count, missing PMKID */
	assert(!auth1_is_sae_setup(copy, n, NULL, NULL));
	memcpy(copy, frame, 30 + 24);
	memset(copy + 30 + 24, 0x42, 16);
	memcpy(copy + 30 + 40, frame + 30 + 24, n - 30 - 24);
	copy[31] += 16; copy[30 + 22] = 1; /* valid RSNE with a cached PMKID */
	assert(!auth1_is_sae_setup(copy, n + 16, NULL, NULL));
	memcpy(copy, frame, n); copy[30 + 19] = 2; /* PSK, not SAE */
	assert(!auth1_is_sae_setup(copy, n, NULL, NULL));
	memcpy(copy, frame, n); copy[wrapped + 3] = 0; /* not SAE auth */
	assert(!auth1_is_sae_setup(copy, n, NULL, NULL));
	memcpy(copy, frame, n); copy[wrapped + 5] = 3; /* Auth3, not commit */
	assert(!auth1_is_sae_setup(copy, n, NULL, NULL));
	memcpy(copy, frame, n); copy[params + 4] = WPA_PASN_WRAPPED_DATA_NO;
	assert(!auth1_is_sae_setup(copy, n, NULL, NULL));
	memcpy(copy, frame, n); copy[params + 5] = 20; /* unsupported group */
	assert(!auth1_is_sae_setup(copy, n, NULL, NULL));
	memcpy(copy, frame, n); copy[30 + sizeof(rsn) + 7] = 255; /* invalid attr */
	assert(!auth1_is_sae_setup(copy, n, NULL, NULL));
	memcpy(copy, frame, n); memcpy(copy + n, rsn, sizeof(rsn));
	assert(!auth1_is_sae_setup(copy, n + sizeof(rsn), NULL, NULL));
	memcpy(copy, frame, n); memcpy(copy + n, nan, sizeof(nan));
	assert(!auth1_is_sae_setup(copy, n + sizeof(nan), NULL, NULL));
	/* Real stale-event shape: local CSIA followed by a verification NIRA. */
	struct pasn_start_event e = {0}, before;
	const u8 stale[] = { NAN_ATTR_CSIA, 5, 0, 0, 7, 1, 5, 1,
		NAN_ATTR_NIRA, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0 };
	e.pairing_type = PAIRING_VERIFICATION;
	e.nik_caching = 1;
	e.frame_len = n; memcpy(e.frame, frame, n);
	e.attrs_len = sizeof(stale); memcpy(e.attrs, stale, sizeof(stale));
	before = e;
	assert(correct_setup_event(&e) == 1);
	assert(e.pairing_type == PAIRING_SETUP && e.attrs_len == 21);
	assert(!memcmp(e.attrs, stale, 8)); /* exact local cipher list/instance IDs */
	assert(!memcmp(e.attrs + 8, (u8[]){NAN_ATTR_DCEA, 2, 0, 0, 3}, 5));
	assert(!memcmp(e.attrs + 13, nan + 6, 8)); /* original bootstrap token/method */
	struct pasn_start_event once = e;
	assert(correct_setup_event(&e) == 0 && !memcmp(&e, &once, sizeof(e)));
	e = before; e.nik_caching = 0;
	assert(correct_setup_event(&e) == 1 && e.attrs[12] == 1);
	e = before; e.attrs_len = 13;
	memcpy(e.attrs + 8, (u8[]){NAN_ATTR_DCEA, 2, 0, 0x05, 0}, 5);
	assert(correct_setup_event(&e) == 1 && e.attrs[11] == 0x05 && e.attrs[12] == 3);
	e = before; e.attrs_len = 0; once = e;
	assert(correct_setup_event(&e) == -1 && !memcmp(&e, &once, sizeof(e)));
	/* Ordinary verification (NIRA present in Auth1) remains byte-for-byte intact. */
	e = before; e.frame[30 + sizeof(rsn) + 6] = NAN_ATTR_NIRA; once = e;
	assert(correct_setup_event(&e) == 0 && !memcmp(&e, &once, sizeof(e)));
	/* Invalid response TLVs, missing CSIA, duplicate CSIA and capacity failure. */
	for (size_t i = 1; i < sizeof(stale); i++) {
		if (i == 8) continue; /* a complete CSIA alone can be repaired */
		e = before; e.attrs_len = i; once = e;
		assert(correct_setup_event(&e) == -1 && !memcmp(&e, &once, sizeof(e)));
	}
	e = before; e.attrs[0] = 99; once = e;
	assert(correct_setup_event(&e) == -1 && !memcmp(&e, &once, sizeof(e)));
	e = before; memcpy(e.attrs + 8, stale, 8); e.attrs_len = 16; once = e;
	assert(correct_setup_event(&e) == -1 && !memcmp(&e, &once, sizeof(e)));
	e = before; e.attrs_len = 64;
	e.attrs[8] = 99; e.attrs[9] = 53; e.attrs[10] = 0; once = e;
	assert(correct_setup_event(&e) == -1 && !memcmp(&e, &once, sizeof(e)));
	e = before; e.attrs_len = 65; once = e;
	assert(correct_setup_event(&e) == -1 && !memcmp(&e, &once, sizeof(e)));
	printf("Auth2 setup attribute repair and unchanged verification tests passed\n");
	printf("SAE setup classification: positive, %zu truncations and verification/malformed negatives passed\n", n);
	return 0;
}
