#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <libnet.h>
#include <utility>
#include <string.h>
#include <algorithm>

#define NUM 1'000'000
#define MOD1 1'000'000'007
#define MOD2 2'000'000'011
#define mul1 37
#define mul2 223

static char req[9][8]={"PATCH","TRACE","OPTIONS","CONNECT","DELETE","PUT","POST","HEAD","GET"};
static int reqsiz[9] = {5, 5, 7, 7, 6, 3, 4, 4, 3};
static std::pair<uint32_t, uint32_t> target[NUM + 5];
static int siz;

std::pair<uint32_t, uint32_t> myhash(char *s) {
	uint64_t x = 0, y = 0, p = 1, q = 1;
	for(int i = 0; s[i] != '\r' && s[i] != '\0'; i++) {
		x += p * s[i];
		y += q * s[i];
		x %= MOD1; y %= MOD2;
		p = p * mul1 % MOD1;
		q = q * mul2 % MOD2;
	}
	return std::make_pair((uint32_t)x, (uint32_t)y);
}

bool isAC(unsigned char *data, int len) {
	auto iphdr = (struct libnet_ipv4_hdr *) data;
	if(iphdr->ip_v != 4 || iphdr->ip_p != IPPROTO_TCP)
		return true;

	auto tcphdr = (struct libnet_tcp_hdr *) (data + iphdr->ip_hl * 4);
	char *payload = (char *)data + iphdr->ip_hl * 4 + tcphdr->th_off * 4;

	bool ret = true;
	for(int i=9; i--; )
		if(strncmp(payload, req[i], reqsiz[i]) == 0) {
			payload += reqsiz[i];
			ret = false;
			break;
		}
	if(ret)
		return true;

	for(int i=len - 6; i--;)
		if(strncmp(payload + i, "Host: ", 6) == 0) {
			if(strncmp(payload + i + 6, "www.", 4) == 0)
				ret |= std::binary_search(target, target+siz, myhash(payload + i + 10));
			else
				ret |= std::binary_search(target, target+siz, myhash(payload + i + 6));
		}
	return !ret;
}

/* returns packet id */
static std::pair<u_int32_t, bool> print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	bool ac;
	if (ret >= 0)
		ac = isAC(data, ret),
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return std::make_pair(id, ac);
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	auto id = print_pkt(nfa);
	printf("entering callback\n");
	if(!id.second) printf("=== Drop! ===\n");
	return nfq_set_verdict(qh, id.first, id.second ? NF_ACCEPT : NF_DROP, 0, NULL);
}

void usage() {
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
	exit(1);
}

void init(char *name) {
	FILE *in = fopen(name, "r");
	if(in == NULL) {
		printf("No such list file\n");
		exit(1);
	}
	char s[256];
	while(fscanf(in, "%s", s) != EOF) {
		for(int i = 0; s[i] != '\0'; i++)
			if(s[i] == ',') {
				target[siz++] = myhash(s + i + 1);
				break;
			}
	}
	fclose(in);
	std::sort(target, target + siz);
	for(int i=siz-1; i--;)
		if(target[i] == target[i + 1]) {
			printf("collision!!\n");
			exit(1);
		}
	printf("%d sites uploaded\n\n", siz);
}

int main(int argc, char **argv)
{
	if (argc != 2)
		usage();

	init(argv[1]);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
