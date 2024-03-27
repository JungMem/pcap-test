#include <stdint.h>

#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define IPTYPE_TCP		0x06    /* TCP Protocol */

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];             /* destination ethernet address */
    u_int8_t  ether_shost[6];             /* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
    u_int8_t dum0[2];
    u_int16_t total_length;   /* total length */
    u_int8_t dum1[5];
    u_int8_t ip_p;            /* protocol */
    u_int8_t dum2[2];
    
    u_int8_t ip_src[4];	      /* src ip */
    u_int8_t ip_dst[4];         /* dst ip */
};

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    
    u_int8_t dum0[28];
};

struct payload
{
    u_int8_t pay[20];         /* payload */
};
