#ifndef PACKET_READING_H
#define PACKET_READING_H

int read_cfg(char *);
void read_pcap_global_header(int);
void create_att_pkt(int);
void read_ip(unsigned char *);
void read_arp(unsigned char *);
void read_tcp(unsigned int, unsigned char *);
void read_udp(unsigned int, unsigned char *);
void read_icmp(unsigned int, unsigned char *);

#endif
