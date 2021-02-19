#pragma once
#include <stdint.h>
#include <math.h>
#define DEV_NAME_LEN 20

// Link layer
typedef struct {
	u_char dest_mac[6];
	u_char src_mac[6];
	u_char etype[2];
}ETHHEADER;

// IP layer
typedef struct {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t total_len;
	uint16_t ident;
	uint16_t flags;
	uint8_t ttl;
	uint8_t proto;
	uint16_t checksum;
	u_char sourceIP[4];
	u_char destIP[4];
}IPHEADER;

// TCP layer
typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t data_offset; // 4 bits ; pos = data_offset * 4 bytes
	uint8_t flags;
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
}TCPHEADER;

// TCP option
typedef struct {
	uint8_t kind;
	uint8_t size;
}TCPOPTION;

// 
char *Proto[] = {
	"Reserved","ICMP","IGMP","GGP", "IP","ST","TCP"
};
// 17 = "UDP"
char *str_flags[] = {
	"[]", "[FIN]", "[SYN]", "[SYN, FIN]", "[RST]", "[RST, FIN]", "[RST, SYN]",
	"[RST, SYN, FIN]", "[PSH]", "[PSH, FIN]", "[PSH, SYN]",  "[PSH, SYN, FIN]",
	"[PSH, RST]", "[PSH, RST, FIN]", "[PSH, RST, SYN]", "[PSH, RST, SYN, FIN]",
	"[ACK]", "[ACK, FIN]", "[ACK, SYN]", "[ACK, SYN, FIN]", "[ACK, RST]",
	"[ACK, RST, FIN]", "[ACK, RST, SYN]", "[ACK, RST, SYN, FIN]", "[ACK, PSH]",
	"[ACK, PSH, FIN]", "[ACK, PSH, SYN]", "[ACK, PSH, SYN, FIN]",
	"[ACK, PSH, RST]", "[ACK, PSH, RST, FIN]", "[ACK, PSH, RST, SYN]",
	"[ACK, PSH, RST, SYN, FIN]"
};

int cmp_ip(char ip[4]) {
	static char sv_ip[4] = { 47, 100, 45, 27 };
	if ((ip[0] == sv_ip[0]) && (ip[1] == sv_ip[1]) && (ip[2] == sv_ip[2]) && (ip[3] == sv_ip[3]))
		return 1;
	return 0;
}

uint32_t cubic_root(uint64_t a) {
	return (uint32_t)(int)(pow((double)(long long)a, 1.0/3));
}
/*
uint32_t cubic_root(uint64_t a) {
	uint32_t x, b, shift;

	static const uint8_t v[] = {
		// 0x00//     0,   54,   54,   54,  118,  118,  118,  118,
		// 0x08//  123,  129,  134,  138,  143,  147,  151,  156,
		// 0x10   157,  161,  164,  168,  170,  173,  176,  179,
		// 0x18   181,  185,  187,  190,  192,  194,  197,  199,
		// 0x20   200,  202,  204,  206,  209,  211,  213,  215,
		// 0x28   217,  219,  221,  222,  224,  225,  227,  229,
		// 0x30   231,  232,  234,  236,  237,  239,  240,  242,
		// 0x38   244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		return ((uint32_t)v[(uint32_t)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));
	
	x = ((uint32_t)(((uint32_t)v[shift] + 10) << b)) >> 6;

		/*
		 * Newton-Raphson iteration
		 *                         2
		 * x    = ( 2 * x  +  a / x  ) / 3
		 *  k+1          k         k
		 */
/*
	x = (2 * x + (uint32_t)div64_u64(a, (uint64_t)x * (uint64_t)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

*/