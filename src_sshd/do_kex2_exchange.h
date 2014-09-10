#ifndef KEX2_EXCHANGE_H
#define KEX2_EXCHANGE_H

struct p_state {
	u_int32_t seqnr;
	u_int32_t packets;
	u_int64_t blocks;
	u_int64_t bytes;
};

typedef struct _common_info {
	char	*client_version_string;
	char	*server_version_string;
	Kex	*kex;
	Newkeys	*send_keys;
	Newkeys	*recv_keys;
	int	sk_enable;
	int	rk_enable;
	CipherContext	send_cc;
	CipherContext	recv_cc;
	CipherContext	send_none_cc;
	CipherContext	recv_none_cc;
	struct p_state	p_send;
	struct p_state	p_read;
	int	compat20;
	int	last_cmd_type;
	int	after_authentication;
} common_info;

void do_kex2_exchange();

#endif
