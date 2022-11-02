#ifndef GADGET_DNS_COMMON_H
#define GADGET_DNS_COMMON_H

// Max DNS name length: 255
// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
#define MAX_DNS_NAME 255

struct event_t {
	union {
		unsigned __int128 saddr_v6;
		__u32 saddr_v4;
	};
	union {
		unsigned __int128 daddr_v6;
		__u32 daddr_v4;
	};
	__u32 af; // AF_INET or AF_INET6

	__u16 id;

	// qr says if the dns message is a query (0), or a response (1)
	unsigned char qr;

	__u8 name[MAX_DNS_NAME];
	unsigned char pkt_type;
	unsigned short qtype;
};

#endif
