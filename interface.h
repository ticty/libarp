/*
 * interface.h
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#ifndef INTERFACE_H_
#define INTERFACE_H_

//#include <sys/socket.h>
//#include <linux/if_packet.h>
//#include <linux/if_ether.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/netdevice.h>

#include "list.h"

#define MAX_INTERFACE_LEN	32
#define MAX_IP_ADDR_LEN		15
#define MAX_HW_ADDR_LEN		MAX_ADDR_LEN
#define IPV4_BIN_ADDR_LEN	sizeof( struct in_addr )

/* struct f_desc flags to describe a interface */
//#define TO_SET_PROMISC	0x01
//#define ORIGINAL_PROMISC	0x02
typedef struct
{
	int sockfd;
	unsigned char hw_len;

	/* used on every send */
	int protocol;
	int index;

	/* used in every send without bind */
	int family;

	/* only used when open or close a socket */
	int socket_type;
	short request_flags;
	short if_flags;

	/* list connector */
	struct list connector;

	/* every send */
	unsigned char hw_addr[MAX_HW_ADDR_LEN];
	unsigned char ip_addr_bin[IPV4_BIN_ADDR_LEN];

	/* only used on every non-dest-specialled send */
	unsigned char bc_ip_addr_bin[IPV4_BIN_ADDR_LEN];

	/* only used when open interface and print debug info */
	char if_name[MAX_INTERFACE_LEN];

	/* at least value-assigned */
	char ip_addr[MAX_IP_ADDR_LEN];
	char bc_ip_addr[MAX_IP_ADDR_LEN];

} if_desc;

#define init_if_desc( ptr_if_info )	do \
	{ \
		memset( (ptr_if_info), 0, sizeof( if_desc ) ); \
		(ptr_if_info)->sockfd = -1; \
		init_list( &(ptr_if_info)->connector ); \
	}while(0)

#define copy_if_info( to_ptr, from_ptr ) do{ \
	memcpy( to_ptr, from_ptr, sizeof( if_desc ) );\
	}while(0)

int get_interface_list ( struct ifconf *ifc );
void destroy_interface_list ( struct ifconf *ifc );
int get_interface_name ( const char *ori_name, if_desc *if_info );

int exist_interface ( const if_desc *if_list, const char *name );

#endif	/* INTERFACE_H_ */
