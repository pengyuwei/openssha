/*
	do kex exchange step by step
*/
#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include "openbsd-compat/sys-tree.h"
#include "openbsd-compat/sys-queue.h"
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include "openbsd-compat/openssl-compat.h"

#include "packet.h"
#include "log.h"
#include "buffer.h"
#include "servconf.h"
//#include "uidswap.h"
#include "compat.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "dh.h"
#include "myproposal.h"
#include "xmalloc.h"
#include "ssh2.h"
#include "ssh.h"
#include "do_kex2_exchange.h"

#define KEX_COOKIE_LEN	16

extern struct {
	Key     *server_key;            /* ephemeral server key */
	Key     *ssh1_host_key;         /* ssh1 host key */
	Key     **host_keys;            /* all private host keys */
	int     have_ssh1_key;
	int     have_ssh2_key;
	u_char  ssh1_cookie[SSH_SESSION_KEY_LENGTH];
} sensitive_data;

extern ServerOptions options; 
extern char* client_version_string;
extern char* server_version_string;

common_info	g_data;

static char *
list_hostkey_types(void)
{
	Buffer b;
	const char *p;
	char *ret;
	int i;

	buffer_init(&b);
	for (i = 0; i < options.num_host_key_files; i++) {
		Key *key = sensitive_data.host_keys[i];
		if (key == NULL)
			continue;
		switch (key->type) {
			case KEY_RSA:
			case KEY_DSA:
				if (buffer_len(&b) > 0)
					buffer_append(&b, ",", 1);
				p = key_ssh_name(key);
				buffer_append(&b, p, strlen(p));
				break;
		}
	}
	buffer_append(&b, "\0", 1);
	ret = xstrdup(buffer_ptr(&b));
	buffer_free(&b);
	debug("list_hostkey_types: %s", ret);
	return ret;
}

Key *
get_hostkey_by_type(int type)
{
	int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		Key *key = sensitive_data.host_keys[i];
		if (key != NULL && key->type == type)
			return key;
	}
	return NULL;
}

Key *
get_hostkey_by_index(int ind)
{
	if (ind < 0 || ind >= options.num_host_key_files)
		return (NULL);
	return (sensitive_data.host_keys[ind]);
}

int
get_hostkey_index(Key *key)
{
	int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		if (key == sensitive_data.host_keys[i])
			return (i);
	}
	return (-1);
}

void kex_input_init(int type, u_int32_t seq, void *ctxt)
{
	char *ptr;
	u_int i, dlen;
	Kex *kex = (Kex *)ctxt;

	debug("SSH2_MSG_KEXINIT received");
	if (kex == NULL)
		fatal("kex_input_kexinit: no kex, cannot rekey");

	ptr = packet_get_raw(&dlen);
	buffer_append(&kex->peer, ptr, dlen);

	/* discard packet */
	for (i = 0; i < KEX_COOKIE_LEN; i++)
		packet_get_char();
	for (i = 0; i < PROPOSAL_MAX; i++)
		xfree(packet_get_string(NULL));
	(void) packet_get_char();
	(void) packet_get_int();
	packet_check_eom();

	//kex_kexinit_finish(kex);
}


void do_kex2_exchange()
{
	Kex *kex ;
	int seqnr;

	if (options.ciphers != NULL) {
		myproposal[PROPOSAL_ENC_ALGS_CTOS] =
			myproposal[PROPOSAL_ENC_ALGS_STOC] = options.ciphers;
	}
	myproposal[PROPOSAL_ENC_ALGS_CTOS] =
		compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_CTOS]);
	myproposal[PROPOSAL_ENC_ALGS_STOC] =
		compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC]);

	if (options.macs != NULL) {
		myproposal[PROPOSAL_MAC_ALGS_CTOS] =
			myproposal[PROPOSAL_MAC_ALGS_STOC] = options.macs;
	}
	if (options.compression == COMP_NONE) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
			myproposal[PROPOSAL_COMP_ALGS_STOC] = "none";
	} else if (options.compression == COMP_DELAYED) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
			myproposal[PROPOSAL_COMP_ALGS_STOC] = "none,zlib@openssh.com";
	}

	myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = list_hostkey_types();

	kex = xcalloc(1, sizeof(*kex));
	buffer_init(&kex->peer);
	buffer_init(&kex->my);
	kex_prop2buf(&kex->my, myproposal);
	kex->done = 0;
	kex->server = 1;
	kex->client_version_string=g_data.client_version_string;
	kex->server_version_string=g_data.server_version_string;
	kex->load_host_key=&get_hostkey_by_type;
	kex->host_key_index=&get_hostkey_index;

	kex_send_kexinit(kex);

	//packet_read_expect(SSH2_MSG_KEXINIT);
	if (SSH2_MSG_KEXINIT != packet_read_seqnr(&seqnr)) {
		goto err;
	}
	kex_input_init(0, seqnr, kex);

	kex_choose_conf(kex);

	switch (kex->kex_type) {
		case KEX_DH_GRP1_SHA1:
		case KEX_DH_GRP14_SHA1:
			kexdh_server(kex);
			break;
		case KEX_DH_GEX_SHA1:
		case KEX_DH_GEX_SHA256:
			kexgex_server(kex);
			break;
		default:
			goto err;
	}

	g_data.kex = kex;

err:
	return ;
}
