/* Offline publisher state regression; no radio commands or pairing keys. */
#include <assert.h>
#include <errno.h>
#define main rtw_aware_main
#include "../whc_host_linux/app/wifi_nan_utility/rtw_aware/rtw_aware.c"
#undef main

static unsigned int completions;
static const uint8_t peer[ETH_ALEN] = {2, 0, 0, 0, 0, 1};

RTW_RET_STATUS dns_datapath_end(uint8_t id)
{
	(void)id;
	return RTW_RET_STATUS_SUCCESS;
}

void dns_local_pasn_result(const uint8_t *addr, uint8_t type)
{
	struct nan_data_mgnt *mgnt = &g_nan_service_mgnt[0].nan_mgnt;
	assert(!memcmp(addr, peer, ETH_ALEN));
	assert(type == NAN_PAIRING_TYPE_SETUP || type == NAN_PAIRING_TYPE_VERIFICATION);
	completions++;
	/* Model the normal callback's completed state. */
	mgnt->nan_status = NAN_STATUS_GET_PASN_RESULT;
	mgnt->service.pairing_info.pasn_type = type;
}

static void submit(const char *path, uint8_t type, bool other_peer, size_t len,
		   bool accepted)
{
	uint8_t data[1 + ETH_ALEN] = {type};
	unsigned int before = completions;
	FILE *fp = fopen(path, "wb");
	assert(fp);
	memcpy(data + 1, peer, ETH_ALEN);
	if (other_peer)
		data[ETH_ALEN]++;
	assert(fwrite(data, 1, len, fp) == len);
	assert(fclose(fp) == 0);
	check_local_pasn_result();
	assert(completions == before + accepted);
	assert(access(path, F_OK) != 0);
}

int main(void)
{
	char path[] = "/tmp/nan-completion-test-XXXXXX";
	int fd = mkstemp(path);
	struct nan_data_mgnt *mgnt = &g_nan_service_mgnt[0].nan_mgnt;
	struct pairing_info *pairing = &mgnt->service.pairing_info;
	assert(fd >= 0);
	close(fd);
	assert(setenv("GREEN2_PASN_RESULT_FILE", path, 1) == 0);
	g_num_service = 1;
	g_log_level = _AWARE_NONE_;
	pairing->role = PAIRING_ROLE_RESPONDER;
	memcpy(pairing->peer_nmi, peer, ETH_ALEN);

	/* Local result arrives first: complete setup once. */
	mgnt->nan_status = NAN_STATUS_PASN_START;
	pairing->pasn_type = NAN_PAIRING_TYPE_SETUP;
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 7, true);
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 7, false);

	/* Native stale verification arrives first: setup must still exchange NIK. */
	pairing->pasn_type = NAN_PAIRING_TYPE_VERIFICATION;
	submit(path, NAN_PAIRING_TYPE_SETUP, true, 7, false);
	submit(path, 255, false, 7, false);
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 6, false);
	submit(path, NAN_PAIRING_TYPE_VERIFICATION, false, 7, false);
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 7, true);
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 7, false);

	/* Do not overwrite an initiator, inactive session or active NDP. */
	pairing->pasn_type = NAN_PAIRING_TYPE_VERIFICATION;
	pairing->role = PAIRING_ROLE_INITIATOR;
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 7, false);
	pairing->role = PAIRING_ROLE_RESPONDER;
	mgnt->nan_status = NAN_STATUS_NONE;
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 7, false);
	mgnt->nan_status = NAN_STATUS_SEND_RSP;
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 7, false);
	mgnt->nan_status = NAN_STATUS_NDP_ESTABLISH;
	submit(path, NAN_PAIRING_TYPE_SETUP, false, 7, false);
	mgnt->nan_status = NAN_STATUS_PASN_START;
	submit(path, NAN_PAIRING_TYPE_VERIFICATION, false, 7, true);
	assert(completions == 3);
	/* Linux can allocate timer ID zero. It must still be deleted/replaced. */
	struct itimerspec timer_state;
	creat_timer();
	assert(timer_active);
	timer_t first = timerid;
	creat_timer();
	assert(timer_active && !timer_gettime(timerid, &timer_state));
	assert(timer_gettime(first, &timer_state) == -1 && errno == EINVAL);
	mgnt->nan_status = NAN_STATUS_PASN_START;
	pairing->role = PAIRING_ROLE_RESPONDER;
	pairing->pasn_type = NAN_PAIRING_TYPE_SETUP;
	mgnt->data_path_retry = 0;
	for (int i = 0; i < 23; i++) timer_handler(SIGUSR1);
	assert(timer_active && mgnt->nan_status == NAN_STATUS_PASN_START);
	timer_handler(SIGUSR1);
	assert(!timer_active && mgnt->nan_status == NAN_STATUS_NONE);
	creat_timer();
	mgnt->nan_status = NAN_STATUS_PASN_START;
	pairing->pasn_type = NAN_PAIRING_TYPE_VERIFICATION;
	mgnt->data_path_retry = 0;
	for (int i = 0; i < 4; i++) timer_handler(SIGUSR1);
	assert(!timer_active && mgnt->nan_status == NAN_STATUS_NONE);
	puts("Timer replacement and separate PIN/verification timeout limits passed");
	unsetenv("GREEN2_PASN_RESULT_FILE");
	puts("PASN completion: notification order, duplicate/peer/state/type/length guards passed");
	return 0;
}
