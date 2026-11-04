/* Exercise retransmission through the real event handlers, with no radio I/O. */
#include <assert.h>
#define nl_send_auto test_nl_send_auto
#define nl_wait_for_ack test_nl_wait_for_ack
#define main pasn_live_main
#include "../whc_host_linux/app/wifi_nan_utility/pasn_probe/pasn_live.c"
#undef main

static u8 expected_auth2[30];
static unsigned int transmissions;

int test_nl_send_auto(struct nl_sock *sock, struct nl_msg *msg)
{
	struct nlattr *attrs[NL80211_ATTR_MAX + 1];
	(void)sock;
	assert(genlmsg_hdr(nlmsg_hdr(msg))->cmd == NL80211_CMD_FRAME);
	assert(!genlmsg_parse(nlmsg_hdr(msg), 0, attrs, NL80211_ATTR_MAX, NULL));
	assert(attrs[NL80211_ATTR_FRAME]);
	assert(nla_len(attrs[NL80211_ATTR_FRAME]) == sizeof(expected_auth2));
	assert(!memcmp(nla_data(attrs[NL80211_ATTR_FRAME]), expected_auth2,
		       sizeof(expected_auth2)));
	transmissions++;
	return 1;
}

int test_nl_wait_for_ack(struct nl_sock *sock)
{
	(void)sock;
	return 0;
}

static void event_line(char *line, const void *event, size_t len)
{
	const u8 *bytes = event;
	line += sprintf(line, "hexdump(len=%zu): ", len);
	for (size_t i = 0; i < len; i++)
		line += sprintf(line, "%02x ", bytes[i]);
}

int main(void)
{
	struct bridge b = {0};
	struct pasn_start_event start = {0}, changed;
	struct pasn_rx_event rx = {0};
	char line[3 * PASN_START_LEN + 64];
	struct pasn_data *original;
	start.role = 2; start.pairing_type = PAIRING_SETUP;
	start.auth_method = 1; start.pass_len = 6;
	memcpy(start.pass, "123456", 6);
	start.frame_len = 32;
	start.frame[0] = 0xb0; start.frame[4] = 2; start.frame[10] = 4;
	start.frame[16] = 6; start.frame[24] = 7; start.frame[26] = 1;
	memcpy(start.peer, start.frame + 10, 6);
	memcpy(start.bssid, start.frame + 16, 6);
	memcpy(b.own, start.frame + 4, 6);
	memcpy(b.peer, start.peer, 6);
	memcpy(b.bssid, start.bssid, 6);
	b.pasn = original = pasn_data_init(); assert(original);
	b.pairing_type = PAIRING_SETUP;
	b.auth1_len = start.frame_len;
	memcpy(b.auth1_frame, start.frame, start.frame_len);
	assert(!clock_gettime(CLOCK_MONOTONIC, &b.auth1_started));
	b.auth2_len = sizeof(expected_auth2); b.auth2_sent = 1;
	expected_auth2[0] = 0xb0; expected_auth2[24] = 7; expected_auth2[26] = 2;
	memcpy(expected_auth2 + 4, b.peer, 6);
	memcpy(expected_auth2 + 10, b.own, 6);
	memcpy(b.auth2_frame, expected_auth2, sizeof(expected_auth2));

	/* Retry/sequence/duration may differ; the cryptographic transcript may not. */
	for (int i = 0; i < 3; i++) {
		start.frame[1] ^= 8; start.frame[2]++; start.frame[22] += 16;
		event_line(line, &start, sizeof(start));
		assert(!on_start(&b, line));
		assert(b.pasn == original && !b.keys_installed);
	}
	assert(transmissions == 3 && b.auth2_sent == 4);
	changed = start; changed.frame[31]++;
	assert(!auth1_is_retry(&b, &changed));
	changed = start; changed.frame[10]++;
	assert(!auth1_is_retry(&b, &changed));
	changed = start; changed.pairing_type = PAIRING_VERIFICATION;
	assert(!auth1_is_retry(&b, &changed));
	changed = start; changed.frame_len--;
	assert(!auth1_is_retry(&b, &changed));
	b.auth1_started.tv_sec -= 10;
	assert(!auth1_is_retry(&b, &start));
	assert(!clock_gettime(CLOCK_MONOTONIC, &b.auth1_started));

	/* Completed retries cannot send another Auth2 or reinstall/reset key PNs. */
	b.keys_installed = true;
	event_line(line, &start, sizeof(start));
	assert(!on_start(&b, line) && transmissions == 3 && b.pasn == original);
	rx.seq = 3; rx.frame_len = start.frame_len;
	memcpy(rx.frame, start.frame, rx.frame_len); rx.frame[26] = 3;
	event_line(line, &rx, sizeof(rx));
	assert(!on_rx(&b, line) && transmissions == 3 && b.keys_installed);
	rx.frame[10]++;
	event_line(line, &rx, sizeof(rx));
	assert(on_rx(&b, line) == -1 && transmissions == 3);
	reset_session(&b);
	assert(!b.pasn && !b.auth1_len && !b.auth2_len && !b.keys_installed);
	puts("PASN retries: Auth2 preserved across 3 Auth1 retries; completed keys not reinstalled; new transcript/peer/expiry rejected");
	return 0;
}
