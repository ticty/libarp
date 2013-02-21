/*
 * arp.h
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#ifndef ARP_H_
#define ARP_H_

#include <net/if_arp.h>
#include "eth.h"
#include "interface.h"
#include "network.h"
#include "misc.h"
#include "list.h"

/*
 * ARP decription from rfc826
 *
 Packet format:
 --------------

 Ethernet transmission layer
 ...
 
 Ethernet packet data:
 16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
 Packet Radio Net.)
 16.bit: (ar$pro) Protocol address space.  For Ethernet
 hardware, this is from the set of type
 fields ether_typ$<protocol>.
 8.bit: (ar$hln) byte length of each hardware address
 8.bit: (ar$pln) byte length of each protocol address
 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
 nbytes: (ar$sha) Hardware address of sender of this
 packet, n from the ar$hln field.
 mbytes: (ar$spa) Protocol address of sender of this
 packet, m from the ar$pln field.
 nbytes: (ar$tha) Hardware address of target of this
 packet (if known).
 mbytes: (ar$tpa) Protocol address of target.
 *
 */

#define PROTOCOL_ARP		0x0806
#define ARP_OP_REQUEST	ARPOP_REQUEST
#define ARP_OP_REPLY		ARPOP_REPLY

#define MAX_ARP_PACKET_LEN	128
#define MIN_ARP_PACKET_LEN	D_ARP_FIXED_HEAD_LEN

#define D_SEND_SINGLE	0x01
#define D_SEND_PAD		0x02

#define D_ARP_FIXED_HEAD_LEN	( sizeof(eth_header) + 8 )
//#define D_ARP_FIXED_HEAD_LEN	( (int)&((dynamic_arp_packet *)0)->src_hw_addr )
#define d_arp_packet_len( ptr_d_packet )	( D_ARP_FIXED_HEAD_LEN + \
		(ptr_d_packet)->protocol_addr_len + (ptr_d_packet)->hw_addr_len + \
		(ptr_d_packet)->protocol_addr_len + (ptr_d_packet)->hw_addr_len )

/*
 * ARP packet
 * Ethernet packet data
 */
typedef struct
{
	/* Ethernet transmission layer data header */
	eth_header eth_header;

	unsigned short hw_addr_space;
	unsigned short protocol_addr_space;
	unsigned char hw_addr_len;
	unsigned char protocol_addr_len;

	unsigned short operate_code;

	/* for list connector */
	struct list connector;

	/**/
	const if_desc *interface;

	/* dynamic allocate */
	unsigned char *src_hw_addr;
	unsigned char *src_protocol_addr;
	unsigned char *dest_hw_addr;
	unsigned char *dest_protocol_addr;

} dynamic_arp_packet;

/* arp_builder */
#define init_dynamic_arp_packet( ptr_d_packet ) do \
	{ \
		memset( ptr_d_packet, 0, sizeof(dynamic_arp_packet) ); \
	}while(0)

void reset_dynamic_arp ( dynamic_arp_packet *d_packet );
void reset_dynamic_arp_eth ( dynamic_arp_packet *d_packet );
void free_dynamic_arp ( dynamic_arp_packet *d_packet );

/* eth layer setting function */
int dynamic_arp_copy_eth ( dynamic_arp_packet *d_packet,
						   const eth_header *eth_header );

int dynamic_arp_set_eth_dest_addr_str ( dynamic_arp_packet *d_packet,
										const char *str );
int dynamic_arp_set_eth_dest_addr_bin (
		dynamic_arp_packet *d_packet,
		const unsigned char dest_addr[ETH_ADDR_LEN] );

int dynamic_arp_set_eth_src_addr_str ( dynamic_arp_packet *d_packet,
									   const char *str );
int dynamic_arp_set_eth_src_addr_bin (
		dynamic_arp_packet *d_packet,
		const unsigned char src_addr[ETH_ADDR_LEN] );

int dynamic_arp_set_eth_pro ( dynamic_arp_packet *d_packet,
							  unsigned short protocol_type );

/* arp packet setting function */
int dynamic_arp_cppy_all ( dynamic_arp_packet *to,
						   const dynamic_arp_packet *from );
int dynamic_arp_cppy_except_eth ( dynamic_arp_packet *to,
								  const dynamic_arp_packet *from );

int dynamic_arp_set_hw_fmt ( dynamic_arp_packet *d_packet,
							 unsigned short hw_fmt );
int dynamic_arp_set_pro_fmt ( dynamic_arp_packet *d_packet,
							  unsigned short pro_fmt );

int dynamic_arp_set_hw_len ( dynamic_arp_packet *d_packet,
							 unsigned char hw_len );
int dynamic_arp_set_pro_len ( dynamic_arp_packet *d_packet,
							  unsigned char pro_len );

int dynamic_arp_set_op_code ( dynamic_arp_packet *d_packet,
							  unsigned short op_code );

int dynamic_arp_set_src_hw_addr_str ( dynamic_arp_packet *d_packet,
									  const char *str, int is_update_len );
int dynamic_arp_set_src_hw_addr_bin ( dynamic_arp_packet *d_packet,
									  const void *addr );

int dynamic_arp_set_src_pro_addr_str ( dynamic_arp_packet *d_packet,
									   const char *str, int is_update_len );
int dynamic_arp_set_src_pro_addr_bin ( dynamic_arp_packet *d_packet,
									   const void *addr );

int dynamic_arp_set_dest_hw_addr_str ( dynamic_arp_packet *d_packet,
									   const char *str, int is_update_len );
int dynamic_arp_set_dest_hw_addr_bin ( dynamic_arp_packet *d_packet,
									   const void *addr );

int dynamic_arp_set_dest_pro_addr_str ( dynamic_arp_packet *d_packet,
										const char *str, int is_update_len );
int dynamic_arp_set_dest_pro_addr_bin ( dynamic_arp_packet *d_packet,
										const void *addr );

int build_dynamic_arp ( dynamic_arp_packet *d_packet, const if_desc *if_info,
						int is_reply, const char *src_eth_hw,
						const char *dest_eth_hw, const char *src_ip_addr,
						const char *src_hw_addr, const char *dest_ip_addr,
						const char *dest_hw_addr );

/* arp_extract */
char *dynamic_arp_get_eth_dest_addr_str ( const dynamic_arp_packet *d_packet,
										  void *buf, int size );
int dynamic_arp_get_eth_dest_addr_bin ( const dynamic_arp_packet *d_packet,
										void *buf, int size );

char *dynamic_arp_get_eth_src_addr_str ( const dynamic_arp_packet *d_packet,
										 void *buf, int size );
int dynamic_arp_get_eth_src_addr_bin ( const dynamic_arp_packet *d_packet,
									   void *buf, int size );

unsigned short dynamic_arp_get_eth_pro ( const dynamic_arp_packet *d_packet );

unsigned short dynamic_arp_get_hw_fmt ( const dynamic_arp_packet *d_packet );
unsigned short dynamic_arp_get_pro_fmt ( const dynamic_arp_packet *d_packet );

unsigned char dynamic_arp_get_hw_len ( const dynamic_arp_packet *d_packet );
unsigned char dynamic_arp_get_pro_len ( const dynamic_arp_packet *d_packet );

unsigned short dynamic_arp_get_op_code ( const dynamic_arp_packet *d_packet );

char *dynamic_arp_get_src_hw_addr_str ( const dynamic_arp_packet *d_packet,
										void *buf, int size );
int dynamic_arp_get_src_hw_addr_bin ( const dynamic_arp_packet *d_packet,
									  void *buf, int size );

char *dynamic_arp_get_src_pro_addr_str ( const dynamic_arp_packet *d_packet,
										 void *buf, int size );
int dynamic_arp_get_src_pro_addr_bin ( const dynamic_arp_packet *d_packet,
									   void *buf, int size );

char *dynamic_arp_get_dest_hw_addr_str ( const dynamic_arp_packet *d_packet,
										 void *buf, int size );
int dynamic_arp_get_dest_hw_addr_bin ( const dynamic_arp_packet *d_packet,
									   void *buf, int size );

char *dynamic_arp_get_dest_pro_addr_str ( const dynamic_arp_packet *d_packet,
										  void *buf, int size );
int dynamic_arp_get_dest_pro_addr_bin ( const dynamic_arp_packet *d_packet,
										void *buf, int size );

int is_dynamic_request_arp ( const dynamic_arp_packet *d_packet );
int is_dynamic_reply_arp ( const dynamic_arp_packet *d_packet );

ssize_t extract_arp ( const if_desc *if_ptr, const unsigned char *buf,
					  ssize_t len, void *data );

void print_arp ( const dynamic_arp_packet *d_packet );

/* arp_sniffer */
int open_arp_interface ( const char *interface, if_desc *if_info );
void close_arp_interface ( if_desc *if_info );

int listen_arp_interface ( if_desc *if_info, dynamic_arp_packet *d_packet,
						   time_t deadline );

/* network related */
int send_dynamic_arp ( const if_desc *if_info,
					   const dynamic_arp_packet *d_packet, unsigned char flags );

/* debug related */
void print_dynamic_arp ( const dynamic_arp_packet *d_packet );

#endif /* ARP_H_ */
