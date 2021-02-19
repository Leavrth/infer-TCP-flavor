#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <WinSock2.h>
#include <pcap.h>
#include "utils.h"

int select_device_by_name(char *, char *);
/* select_packet
*		sender -> receiver
*/

void select_packet_cubic(struct timeval *now_ts, unsigned int len, uint32_t seq, uint32_t ack, uint32_t rwnd, int flag) {
	static uint32_t last_seq = 0; // the newest packet already seen
	static uint32_t ack_seq = 0; // the newest ack
	static uint32_t phase_start_seq = 0;
	static uint32_t Wmax = 0;
	static uint32_t last_max_cwnd = 0;
	static uint32_t origin_point = 0;
	static uint32_t K = 0;
	static double C = 0.04;
	static long first_dup_ack_tv = 0;
	static long phase_start_tv;
	static long phase_start_sec = 0;
	static int fal_num = 0;
	static int dupack_num = 0;
	static unsigned int ssthresh = 60000;	 // = beta * W_max
	unsigned int MSS = 1460;
	static unsigned int cwnd = 10;
	static unsigned int tcp_cwnd = 10;
	static unsigned int last_cwnd = 10;
	static unsigned int ack_cnt = 0;
	static unsigned int tcp_ack_cnt = 0;
	const static uint64_t cube_factor = 1ull << 40;
	static unsigned long last_delta_time = 10;
	static unsigned long last_time = 0;
	static unsigned long RTT_min = 1000000;

	unsigned long now_time = now_ts->tv_sec * 1000000 + now_ts->tv_usec;
	if (flag) {
		// the packet is from sender to receiver.
		// Assume TSO is closed, each packet's len <= MSS
		if (len < MSS) return; // not data packet
		if (seq < ack_seq) return;	// already ack'd
		// validate packet
		// init phase_start_seq
		if (phase_start_seq == 0) {
			phase_start_seq = seq;
			//phase_start_sec = now_ts->tv_sec;
			phase_start_tv = now_time;
			ack_seq = seq;
		}
		
		// 
		if (seq > last_seq) { 
			last_seq = seq; 
			/*
			unsigned int flight_size = (last_seq - ack_seq) / MSS + 1;


			printf("[cubic]\tflightsize: %d\tcwnd: %d\n", flight_size, cwnd);
			if (flight_size > cwnd) {
				++fal_num;
			}
			*/
			
			unsigned long delta_time = now_time - last_time + 10; // +10 to revise
			last_time = now_time;
			if (delta_time > 100 * last_delta_time) {
				// RTT time
				RTT_min = delta_time;
				last_delta_time = 10;
			} else {
				last_delta_time = delta_time;
			}

			return; 
		}
		if (seq == ack_seq && dupack_num > 3) {
			// Reransmission
			unsigned int flight_size = (last_seq - ack_seq) / MSS + 1;

			printf("[cubic]\tflightsize: %d\tcwnd: %d\n", flight_size, cwnd);
			if (flight_size > cwnd) {
				++fal_num;
			}
			// beta = 717/1024
			
			
			// Wmax is W_last_max, cwnd is new W_max
			if (cwnd < last_max_cwnd)
				last_max_cwnd = (uint32_t)((cwnd * 1741)/2048);
			else last_max_cwnd = cwnd;
			
			ssthresh = (unsigned int)(cwnd * 717 / 1024);
			ssthresh = max(ssthresh, 2);
			cwnd = ssthresh;
			
			tcp_cwnd = cwnd;
			if (last_max_cwnd <= cwnd) {
				K = 0;
				origin_point = cwnd;
			} else {
				// the unit of K is bictcp_HZ=2^10, not HZ
				K = cubic_root(cube_factor * (last_max_cwnd - cwnd));
				origin_point = last_max_cwnd;
			}
			
			
			//K = cubic_root()
			
			last_cwnd = cwnd;
			

		}
	}
	else {
		if (ack_seq > ack || ack < MSS) return; // dup packet, just ignore
		if (ack_seq == ack /* && */) { 
			if (dupack_num == 0) 

				first_dup_ack_tv = now_time;
			++dupack_num; 
			return; 
		}
		
		// else
		int acked = (ack - ack_seq) / MSS; /* the number of packets acked */
		if (dupack_num > 3) {
			phase_start_seq = ack;
			//phase_start_sec = now_ts->tv_sec;
			phase_start_tv = now_time;
			phase_start_tv = (phase_start_tv + first_dup_ack_tv) / 2;

			ack_cnt = 0;
			tcp_ack_cnt = 0;
		}
		dupack_num = 0;
		
		// new ack
		// slow-start at the beginning
		
		
		if (cwnd < ssthresh) { // after the first congetstion, cwnd always > ssthresh
			// use hybrid slow start
			/* hystart_ack_delta = 2ms */
			/* 1. firtly collect 8 ack sample 
			 * 2. then each ack test whether min rtt is less than 
			 *
			 */

			/* slow-start phase */
			int new_cwnd = min(cwnd + acked, ssthresh);
			acked -= new_cwnd - cwnd;
			last_cwnd = cwnd;
			cwnd = new_cwnd;
		}
		if (cwnd >= ssthresh && acked > 0){
			ack_cnt += acked;
			uint64_t t = now_time - phase_start_tv + RTT_min; // usec
			uint64_t offs;
			t <<= 10;	// unit turn to BICTCP_HZ * usec
			t /= 1000000;	// turn to BICTCP_HZ * sec
			if (t < K)
				offs = K - t;
			else 
				offs = t - K;

			/* c/rtt * (t-K)^3 */
			uint32_t delta = (offs * offs * offs) >> 40;
			uint32_t target;
			if (t < K)
				target = origin_point - delta;
			else
				target = origin_point + delta;

			uint32_t cnt;
			if (target > cwnd)
				cnt = cwnd / (target - cwnd);
			else
				cnt = 100 * cwnd;	/* increase slowly */

			if (last_max_cwnd == 0 && cnt > 20)
				cnt = 20;
	
			/* tcp_friendliness */
			
			// scale = 15 // = 8 * (1024 + 717) / 3 / (1024 - 717);
			delta = (cwnd * 15) >> 3;
			while (ack_cnt > delta) {
				ack_cnt -= delta;
				tcp_cwnd++;
			}

			if (tcp_cwnd > cwnd) {
				delta = tcp_cwnd - cwnd;
				uint32_t max_cnt = cwnd / delta;
				if (cnt > max_cnt)
					cnt = max_cnt;
			}

			cnt = max(cnt, 2U);

			/* standard tcp congestion avoidance */
			// w(cnt), acked

			if (tcp_ack_cnt >= cnt) {
				tcp_ack_cnt = 0;
				cwnd++;
			}
			tcp_ack_cnt += acked;
			if (tcp_ack_cnt >= cnt) {
				uint32_t delta = tcp_ack_cnt / cnt;

				tcp_ack_cnt -= delta * cnt;
				cwnd += delta;
			}
			
		}

		
		ack_seq = ack;
	}
}

void select_packet_reno(struct timeval *now_ts, unsigned int len, uint32_t seq, uint32_t ack, uint32_t rwnd, int flag) {
	static uint32_t last_seq = 0; // the newest packet already seen
	static uint32_t ack_seq = 0; // the newest ack
	static uint32_t phase_start_seq = 0;
	static uint32_t flight_size = 0;
	static int fal_num = 0;
	static int dupack_num = 0;
	static int ssthresh = 65536;
	unsigned int MSS = 1460;
	static int cwnd = 10;
	
	/* forecast RTT */
	/* I think no need to do */
	static int state_RTT = 2; /* 0 is DEFAULT; 1 is FROZEN; 2 is INIT */
	static uint32_t sample_RTT_seq = 0; // the first seq in next RTT
	static uint32_t start_RTT_seq = 0;
	static struct timeval start_RTT_ts;
	
	if (flag) {
		// the packet is from sender to receiver.
		// Assume TSO is closed, each packet's len <= MSS
		if (len < MSS) return; // not data packet
		if (seq < ack_seq) return;	// already ack'd
		// validate packet
		// init phase_start_seq
		if (phase_start_seq == 0)
			phase_start_seq = seq;
		// 
		if (seq > last_seq) { last_seq = seq; return; }
		if (seq == ack_seq && dupack_num > 3) {
			// Reransmission
			// 1. calculate new ocwnd (cwnd before it deflates)
			int acked = (ack_seq - phase_start_seq) / MSS; /* the number of packets acked */
			
			/* slow-start phase */
			int new_cwnd = min(cwnd + acked, ssthresh); 
			acked -= new_cwnd - cwnd;
			cwnd = new_cwnd;

			/* congestion avoidance phase */
			while (acked > cwnd) {
				acked -= cwnd;
				++cwnd;
			}
			// 2. calculate flightsize
			int flightsize = (last_seq - ack_seq) / MSS + 1;
			
			printf("[reno]\tflightsize: %d\tcwnd: %d\n", flightsize, cwnd);
			if (flightsize > cwnd)
				++fal_num;

			// 3. decrease cwnd
			cwnd = cwnd / 2;
			ssthresh = cwnd;
		}
		
		/* Decision process for the classification of out-of-sequence packets
		*              +---------------------+
		*              |packet already ack'd?|
		*              +---------------------+
		*                         |  yes
		*                         |-------> Unneeded Retransmission
		*                       no|
		*                         v
		*              +---------------------+
		*              | packet already seen |
		*              +---------------------+
		*                         |        +----------------------+
		*                         |   no   |   Time lag > RTO ?   |  no   +------------------+  no
		*                         |------->|         OR           |------>| Time lag < RTT ? |------> unknown
		*                         |        | Duplicate acks > 3 ? |       +------------------+
		*                      yes|        +----------------------+                |  yes
		*                         |                   |                            +-------> Reordering
		*                         v                   |yes
		*              +----------------------+       |
		*              |  IP ID different ?   |       |
		*              |          OR          | yes   v
		*              |   Time lag > RTO ?   |-----> Retransmission
		*              |          OR          |
		*              | Duplicate acks > 3 ? |
		*              +----------------------+
		*                         | no
		*                         +----> Network Duplicate
		*  Because of the monitor standing on receiver
		*   (If packet has already seen, ack for it also has been sent), 
		*  we only need to care
		*              +---------------------+
		*              |packet already ack'd?|
		*              +---------------------+
		*                         |  yes
		*                         |-------> Unneeded Retransmission
		*                       no|
		*                         v
		*              +----------------------+
		*              |   Time lag > RTO ?   | yes
		*              |          OR          |-----> Retransmission
		*              | Duplicate acks > 3 ? |
		*              +----------------------+
		*                         | no
		*                         +----> Otherwise
		*/
	}
	else {
		if (ack_seq > ack) return; // dup packet, just ignore
		if (ack_seq == ack /* && */) { ++dupack_num; return; }
		else {
			if (dupack_num > 3) {
				phase_start_seq = ack;
			}
			dupack_num = 0;
		}
		// new ack
		

		ack_seq = ack;

	}

}

void select_packet_tahoe(struct timeval *now_ts, unsigned int len, uint32_t seq, uint32_t ack, uint32_t rwnd, int flag) {
	static uint32_t last_seq = 0; // the newest packet already seen
	static uint32_t ack_seq = 0; // the newest ack
	static uint32_t phase_start_seq = 0;
	static uint32_t flight_size = 0;
	static int fal_num = 0;
	static int dupack_num = 0;
	static int ssthresh = 65536;
	unsigned int MSS = 1460;
	static int cwnd = 10;

	/* forecast RTT */
	/* I think no need to do */
	static int state_RTT = 2; /* 0 is DEFAULT; 1 is FROZEN; 2 is INIT */
	static uint32_t sample_RTT_seq = 0; // the first seq in next RTT
	static uint32_t start_RTT_seq = 0;
	static struct timeval start_RTT_ts;

	if (flag) {
		// the packet is from sender to receiver.
		// Assume TSO is closed, each packet's len <= MSS
		if (len < MSS) return; // not data packet
		if (seq < ack_seq) return;	// already ack'd
									// validate packet
									// init phase_start_seq
		if (phase_start_seq == 0)
			phase_start_seq = seq;
		// 
		if (seq > last_seq) { last_seq = seq; return; }
		if (seq == ack_seq && dupack_num > 3) {
			// Reransmission
			// 1. calculate new ocwnd (cwnd before it deflates)
			int acked = (ack_seq - phase_start_seq) / MSS; /* the number of packets acked */

														   /* slow-start phase */
			int new_cwnd = min(cwnd + acked, ssthresh);
			acked -= new_cwnd - cwnd;
			cwnd = new_cwnd;

			/* congestion avoidance phase */
			while (acked > cwnd) {
				acked -= cwnd;
				++cwnd;
			}
			// 2. calculate flightsize
			int flightsize = (last_seq - ack_seq) / MSS + 1;

			printf("[reno]\tflightsize: %d\tcwnd: %d\n", flightsize, cwnd);
			if (flightsize > cwnd)
				++fal_num;

			// 3. decrease cwnd
			ssthresh = cwnd / 2;
			cwnd = 1;
		}

		
	}
	else {
		if (ack_seq > ack) return; // dup packet, just ignore
		if (ack_seq == ack /* && */) { ++dupack_num; return; }
		else {
			if (dupack_num > 3) {
				phase_start_seq = ack;
			}
			dupack_num = 0;
		}
		// new ack


		ack_seq = ack;

	}

}

void select_packet_newreno(struct timeval *now_ts, unsigned int len, uint32_t seq, uint32_t ack, uint32_t rwnd, int flag) {
	static uint32_t last_seq = 0; // the newest packet already seen
	static uint32_t ack_seq = 0; // the newest ack
	static uint32_t isrecover = 0; // different from reno, newreno assume there might be a lot packets lost at the same time. 
	static uint32_t phase_start_seq = 0;
	static uint32_t flight_size = 0;
	static int fal_num = 0;
	static int dupack_num = 0;
	static int ssthresh = 65536;
	unsigned int MSS = 1460;
	static int cwnd = 10;

	/* forecast RTT */
	/* I think no need to do */
	static int state_RTT = 2; /* 0 is DEFAULT; 1 is FROZEN; 2 is INIT */
	static uint32_t sample_RTT_seq = 0; // the first seq in next RTT
	static uint32_t start_RTT_seq = 0;
	static struct timeval start_RTT_ts;

	if (flag) {
		// the packet is from sender to receiver.
		// Assume TSO is closed, each packet's len <= MSS
		if (len < MSS) return; // not data packet
		if (seq < ack_seq) return;	// already ack'd
									// validate packet
									// init phase_start_seq
		if (phase_start_seq == 0)
			phase_start_seq = seq;
		// 
		if (seq > last_seq) { last_seq = seq; return; }
		if (seq == ack_seq && dupack_num > 3) {
			// Reransmission
			int flightsize = 0;
			if (isrecover == 0) {
				// get into recover stage
				isrecover = 1; 
				// 1. calculate new ocwnd (cwnd before it deflates)
				int acked = (ack_seq - phase_start_seq) / MSS; /* the number of packets acked */

															   /* slow-start phase */
				int new_cwnd = min(cwnd + acked, ssthresh);
				acked -= new_cwnd - cwnd;
				cwnd = new_cwnd;

				/* congestion avoidance phase */
				while (acked > cwnd) {
					acked -= cwnd;
					++cwnd;
				}
				// 2. calculate flightsize
				flightsize = (last_seq - ack_seq) / MSS + 1;

				printf("[reno]\tflightsize: %d\tcwnd: %d\n", flightsize, cwnd);
				if (flightsize > cwnd)
					++fal_num;

				// 3. decrease cwnd
				cwnd = cwnd / 2;
				ssthresh = cwnd;
			} else {
				// still in recover stage
				// so this is the packet lost in the same time
				
				// we can ignore this
			}
			

			
		}

		
	}
	else {
		if (ack_seq > ack) return; // dup packet, just ignore
		if (ack_seq == ack /* && */) { ++dupack_num; return; }
		else {
			if (dupack_num > 3) {
				
				phase_start_seq = ack;
			}
			dupack_num = 0;
		}
		// new ack
		if (ack >= last_seq)
			isrecover = 0;

		ack_seq = ack;

	}

}



void pcap_handle(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	static struct timeval start_ts;
	static int ofd = -1;
	static char of_name[50];
	static uint32_t yf_seq, sv_seq; // yifan's seq, server's seq
	static uint8_t yf_scale = 0, sv_scale = 0; // yifan's window scale, server's window scale
	static uint16_t yf_mss = 1460, sv_mss = 1460;
	char of_buf[100];
	struct timeval now_ts;
	const unsigned long interval_usec = 2000; // 2ms
	ETHHEADER *eth_header = (ETHHEADER *)pkt_data;

	//printf("Packet length: %d \n", header->len);

	if (header->len >= 14 + 4) { // ether_header_len + ether_tailer_len
		IPHEADER *ip_header = (IPHEADER*)(pkt_data + 14);
		//解析协议类型
		if (ip_header->proto != 6) return;

		TCPHEADER *tcp_header = (TCPHEADER *)(pkt_data + 14 + ((ip_header->ver_ihl & 0x0F) << 2));
		unsigned int data_len = ntohs(ip_header->total_len) - ((ip_header->ver_ihl & 0xF) << 2) - (tcp_header->data_offset >> 2);
		int is_from_sender = cmp_ip(ip_header->sourceIP);
		// need to check RST? No!
		int syn = tcp_header->flags & SYN;
		int ack = tcp_header->flags & ACK;
		if (syn && !ack) {
			printf("begin to connecting\n");
			start_ts.tv_sec = header->ts.tv_sec;
			start_ts.tv_usec = header->ts.tv_usec;
			if (is_from_sender)
				sv_seq = ntohl(tcp_header->seq);
			else
				yf_seq = ntohl(tcp_header->seq);

			if (ofd != -1) _close(ofd);
			sprintf(of_name, "output_%4lx", header->ts.tv_usec & 0xFFFF);
			ofd = _open(of_name, O_WRONLY | O_CREAT, 0777);
		}
		else if (syn && ack) {
			if (cmp_ip(ip_header->sourceIP))
				sv_seq = ntohl(tcp_header->seq);
			else
				yf_seq = ntohl(tcp_header->seq);
		}

		if (start_ts.tv_usec > header->ts.tv_usec) {
			now_ts.tv_sec = header->ts.tv_sec - start_ts.tv_sec - 1;
			now_ts.tv_usec = header->ts.tv_usec + 1000000 - start_ts.tv_usec;
		}
		else {
			now_ts.tv_sec = header->ts.tv_sec - start_ts.tv_sec;
			now_ts.tv_usec = header->ts.tv_usec - start_ts.tv_usec;
		}

		if (is_from_sender) {
			tcp_header->seq = ntohl(tcp_header->seq) - sv_seq;
			tcp_header->ack = ntohl(tcp_header->ack) - yf_seq;
		}
		else {
			tcp_header->seq = ntohl(tcp_header->seq) - yf_seq;
			tcp_header->ack = ntohl(tcp_header->ack) - sv_seq;
		}


		//printf("%ld.%06ld : Source IP : %d.%d.%d.%d ==> ", now_ts.tv_sec, now_ts.tv_usec, ip_header->sourceIP[0], ip_header->sourceIP[1], ip_header->sourceIP[2], ip_header->sourceIP[3]);
		//printf("Dest   IP : %d.%d.%d.%d\n", ip_header->destIP[0], ip_header->destIP[1], ip_header->destIP[2], ip_header->destIP[3]);
		//printf("            seq %u , ack %u\n", tcp_header->seq, tcp_header->ack);
		//printf("            %s\n", str_flags[tcp_header->flags & 0x1F]);
		//printf("            window size: %d Bytes", tcp_header->window_size);
		
		
		{
			int header_length = (tcp_header->data_offset & 0xF0) >> 2;
			uint8_t *opt = (uint8_t *)tcp_header + 20;
			//printf("            header length : %d Bytes", header_length);
			header_length -= 20;
			while (header_length > 0) {
				TCPOPTION *opt_ = (TCPOPTION *)opt;
				if (opt_->kind == 0) break;
				if (opt_->kind == 1) { header_length -= 1; ++opt; continue;}
				switch (opt_->kind) {
				case 2:
					if (is_from_sender)
						sv_mss = ntohs(*(uint16_t *)(opt + 2));
					else
						yf_mss = ntohs(*(uint16_t *)(opt + 2));
					break;
				case 3:
					if (is_from_sender)
						sv_scale = *(opt + 2);
					else
						yf_scale = *(opt + 2);
					break;
				
				}
				
				header_length -= opt_->size;
				opt = opt + opt_->size;


			}

		}
		
		if (is_from_sender) {
			uint32_t rwnd = (ntohs(tcp_header->window_size) << sv_scale) / sv_mss;
			//select_packet_reno(&now_ts, data_len, tcp_header->seq, tcp_header->ack, rwnd, 1);
			select_packet_cubic(&now_ts, data_len, tcp_header->seq, tcp_header->ack, ntohs(tcp_header->window_size) << sv_scale, 1);
		}
		else {
			uint32_t rwnd = (ntohs(tcp_header->window_size) << yf_scale) / yf_mss;
			//select_packet_reno(&now_ts, data_len, tcp_header->seq, tcp_header->ack, rwnd, 0);
			select_packet_cubic(&now_ts, data_len, tcp_header->seq, tcp_header->ack, ntohs(tcp_header->window_size) << yf_scale, 0);
		}
		
		sprintf(of_buf, "%d,%ld.%06ld,%d.%d.%d.%d,%d.%d.%d.%d,%u,%u,%s,%d,%d\n", data_len,
			now_ts.tv_sec, now_ts.tv_usec, ip_header->sourceIP[0], ip_header->sourceIP[1],
			ip_header->sourceIP[2], ip_header->sourceIP[3], ip_header->destIP[0],
			ip_header->destIP[1], ip_header->destIP[2], ip_header->destIP[3],
			tcp_header->seq, tcp_header->ack, str_flags[tcp_header->flags & 0x1F],
			ntohs(tcp_header->window_size), is_from_sender? sv_mss:yf_mss);
		if (ofd != -1)
			_write(ofd, of_buf, strlen(of_buf));
		
	}

	//printf("\n\n");
}



int main(int argc, char **argv) {
	char device[DEV_NAME_LEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *phandle;
	struct bpf_program fcode;

	int r = select_device_by_name(device, errbuf);
	if (r == -1) {
		perror(errbuf);
		return 1;
	}

	phandle = pcap_open(device, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (phandle == NULL) {
		perror(errbuf);
		return 1;
	}

	pcap_compile(phandle, &fcode, "src host 47.100.45.27 or dst host 47.100.45.27", 1, 0);
	pcap_setfilter(phandle, &fcode);

	pcap_loop(phandle, -1, pcap_handle, NULL);

	return 0;

}

char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
int select_device_by_name(char *dev_name, char *errbuf) {
	pcap_if_t *it;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &it, errbuf) == -1)
		return -1;

	strcpy(dev_name, it->name);

	{
		const pcap_if_t *tmp = it;
		const pcap_addr_t *a = NULL;
		char ip6str[128];
		while (tmp) {
			printf(":%s\n", tmp->name);
			if (tmp->description)
				printf("\tDescription: (%s)\n", tmp->description);
			else
				printf("\tDescription: (No description available)\n");
			
			for (a = tmp->addresses; a; a = a->next) {
				printf("\tAddress Family: #%d\n", a->addr->sa_family);
				switch (a->addr->sa_family) {
				case AF_INET:
					printf("\tAddress Family Name: AF_INET\n");
					if (a->addr)
						printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
					if (a->netmask)
						printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
					if (a->broadaddr)
						printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
					if (a->dstaddr)
						printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
					break;

				case AF_INET6:
					printf("\tAddress Family Name: AF_INET6\n");
					if (a->addr)
						printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
					break;

				default:
					printf("\tAddress Family Name: Unknown\n");
					break;
				}
			}
			
			tmp = tmp->next;
		}
	}

	pcap_freealldevs(it);
	printf("select a device to watch([%s] default):", dev_name);

	{
		char c = getchar();
		int i = 0;
		while (c != '\n' /* only on linux*/ && i != DEV_NAME_LEN - 1) {
			dev_name[i++] = c;
			c = getchar();
		}
		if (i != 0) dev_name[i] = 0;
	}

	printf("you select device: [%s]\n", dev_name);
	return 0;
}

#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
