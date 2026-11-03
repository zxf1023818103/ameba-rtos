/* Feed Realtek PASN events directly to pasn_live without changing NAN mode.
 * Output contains authentication material: pipe it directly to pasn_live;
 * do not send it to a terminal or journal. No keys are printed on stderr.
 */
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

struct context {
	unsigned int ifindex;
};

static int on_event(struct nl_msg *msg, void *arg)
{
	struct context *ctx = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *genl = nlmsg_data(hdr);
	struct nlattr *attrs[NL80211_ATTR_MAX + 1];
	unsigned int subcmd, size, wiphy;
	const unsigned char *bytes;
	if (genl->cmd != NL80211_CMD_VENDOR ||
	    genlmsg_parse(hdr, 0, attrs, NL80211_ATTR_MAX, NULL) < 0)
		return NL_SKIP;
	if (!attrs[NL80211_ATTR_VENDOR_ID] ||
	    nla_len(attrs[NL80211_ATTR_VENDOR_ID]) != 4 ||
	    nla_get_u32(attrs[NL80211_ATTR_VENDOR_ID]) != 0xe04c ||
	    !attrs[NL80211_ATTR_VENDOR_SUBCMD] ||
	    nla_len(attrs[NL80211_ATTR_VENDOR_SUBCMD]) != 4 ||
	    !attrs[NL80211_ATTR_IFINDEX] ||
	    nla_len(attrs[NL80211_ATTR_IFINDEX]) != 4 ||
	    nla_get_u32(attrs[NL80211_ATTR_IFINDEX]) != ctx->ifindex ||
	    !attrs[NL80211_ATTR_VENDOR_DATA])
		return NL_SKIP;
	subcmd = nla_get_u32(attrs[NL80211_ATTR_VENDOR_SUBCMD]);
	size = nla_len(attrs[NL80211_ATTR_VENDOR_DATA]);
	if (!((subcmd == 29 && size == 645) ||
	      (subcmd == 30 && size == 598)))
		return NL_SKIP;
	wiphy = attrs[NL80211_ATTR_WIPHY] &&
		nla_len(attrs[NL80211_ATTR_WIPHY]) == 4 ?
		nla_get_u32(attrs[NL80211_ATTR_WIPHY]) : 0;
	bytes = nla_data(attrs[NL80211_ATTR_VENDOR_DATA]);
	printf("Vendor event: wiphy=%u vendor_id=0xe04c subcmd=%u\n",
	       wiphy, subcmd);
	printf("PASN vendor data - hexdump(len=%u):", size);
	for (unsigned int i = 0; i < size; i++)
		printf(" %02x", bytes[i]);
	putchar('\n');
	if (fflush(stdout) == EOF)
		exit(1);
	fprintf(stderr, "PASN event %u forwarded (%u bytes)\n", subcmd, size);
	return NL_OK;
}

int main(int argc, char **argv)
{
	struct context ctx;
	struct nl_sock *sock;
	int group, ret;
	if (argc != 2 || !(ctx.ifindex = if_nametoindex(argv[1]))) {
		fprintf(stderr, "usage: %s NAN_INTERFACE\n", argv[0]);
		return 2;
	}
	sock = nl_socket_alloc();
	if (!sock || genl_connect(sock) < 0) {
		fprintf(stderr, "cannot open generic netlink\n");
		if (sock)
			nl_socket_free(sock);
		return 1;
	}
	group = genl_ctrl_resolve_grp(sock, "nl80211", "vendor");
	if (group < 0 || nl_socket_add_membership(sock, group) < 0) {
		fprintf(stderr, "cannot subscribe to nl80211 vendor events\n");
		nl_socket_free(sock);
		return 1;
	}
	nl_socket_disable_seq_check(sock);
	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, on_event, &ctx);
	fprintf(stderr, "Listening for PASN vendor events on ifindex %u\n", ctx.ifindex);
	while ((ret = nl_recvmsgs_default(sock)) >= 0 || ret == -NLE_INTR)
		;
	fprintf(stderr, "netlink receive failed: %s\n", nl_geterror(ret));
	nl_socket_free(sock);
	return 1;
}
