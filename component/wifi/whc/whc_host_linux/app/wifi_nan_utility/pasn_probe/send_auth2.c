/* Send one generated PASN Auth2 management frame through nl80211.
 * This tool deliberately accepts only a successful PASN Auth2 frame.
 */
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

int main(int argc, char **argv)
{
	struct nl_sock *sock = NULL;
	struct nl_msg *msg = NULL;
	uint8_t frame[1024];
	unsigned int ifindex;
	unsigned long freq;
	size_t len;
	int family, ret = 1;
	FILE *f;
	char *end;

	if (argc != 4) {
		fprintf(stderr, "usage: %s IFACE FREQ_MHZ AUTH2.bin\n", argv[0]);
		return 2;
	}
	ifindex = if_nametoindex(argv[1]);
	freq = strtoul(argv[2], &end, 10);
	if (!ifindex || *end || freq < 2400 || freq > 7125) {
		fprintf(stderr, "invalid interface or frequency\n");
		return 2;
	}
	f = fopen(argv[3], "rb");
	if (!f) {
		perror("open Auth2");
		return 1;
	}
	len = fread(frame, 1, sizeof(frame), f);
	if (ferror(f) || !feof(f) || fclose(f) || len < 30 ||
	    frame[0] != 0xb0 || frame[1] != 0 ||
	    frame[24] != 7 || frame[25] != 0 ||
	    frame[26] != 2 || frame[27] != 0 ||
	    frame[28] != 0 || frame[29] != 0) {
		fprintf(stderr, "input is not a successful PASN Auth2 frame\n");
		return 1;
	}
	sock = nl_socket_alloc();
	if (!sock || genl_connect(sock) < 0) {
		fprintf(stderr, "could not connect to generic netlink\n");
		goto done;
	}
	family = genl_ctrl_resolve(sock, "nl80211");
	if (family < 0) {
		fprintf(stderr, "nl80211 family not available\n");
		goto done;
	}
	msg = nlmsg_alloc();
	if (!msg || !genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
				 NL80211_CMD_FRAME, 0) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, (uint32_t) freq) ||
	    nla_put(msg, NL80211_ATTR_FRAME, len, frame)) {
		fprintf(stderr, "could not construct nl80211 FRAME request\n");
		goto done;
	}
	ret = nl_send_auto(sock, msg);
	if (ret < 0) {
		fprintf(stderr, "send failed: %s\n", nl_geterror(ret));
		ret = 1;
		goto done;
	}
	ret = nl_wait_for_ack(sock);
	if (ret < 0) {
		fprintf(stderr, "frame rejected: %s\n", nl_geterror(ret));
		ret = 1;
		goto done;
	}
	printf("Auth2 accepted by nl80211: %zu bytes on %s at %lu MHz\n",
	       len, argv[1], freq);
	ret = 0;
done:
	nlmsg_free(msg);
	nl_socket_free(sock);
	memset(frame, 0, sizeof(frame));
	return ret;
}
