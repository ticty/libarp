/*
 * arp.c
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "arp.h"
#include "eth.h"
#include "network.h"
#include "interface.h"
#include "misc.h"

/* eth layer setting function */
int dynamic_arp_copy_eth ( dynamic_arp_packet *d_packet,
						   const eth_header *eth_header )
{
	if ( d_packet == NULL || eth_header == NULL )
	{
		return -1;
	}

	return eth_copy ( &d_packet->eth_header, eth_header );
}

int dynamic_arp_set_eth_dest_addr_str ( dynamic_arp_packet *d_packet,
										const char *str )
{
	if ( d_packet == NULL || str == NULL )
	{
		return -1;
	}

	return eth_set_dest_hwaddr_str ( &d_packet->eth_header, str );
}

int dynamic_arp_set_eth_dest_addr_bin (
		dynamic_arp_packet *d_packet,
		const unsigned char dest_addr[ETH_ADDR_LEN] )
{
	if ( d_packet == NULL || dest_addr == NULL )
	{
		return -1;
	}

	return eth_set_dest_hwaddr_bin ( &d_packet->eth_header, dest_addr );
}

int dynamic_arp_set_eth_src_addr_str ( dynamic_arp_packet *d_packet,
									   const char *str )
{
	if ( d_packet == NULL || str == NULL )
	{
		return -1;
	}

	return eth_set_src_hwaddr_str ( &d_packet->eth_header, str );
}

int dynamic_arp_set_eth_src_addr_bin (
		dynamic_arp_packet *d_packet,
		const unsigned char src_addr[ETH_ADDR_LEN] )
{
	if ( d_packet == NULL || src_addr == NULL )
	{
		return -1;
	}

	return eth_set_src_hwaddr_bin ( &d_packet->eth_header, src_addr );
}

int dynamic_arp_set_eth_pro ( dynamic_arp_packet *d_packet,
							  unsigned short protocol_type )
{
	if ( d_packet == NULL )
	{
		return -1;
	}

	return eth_set_pro_type ( &d_packet->eth_header, protocol_type );
}

/* arp packet setting function */
int dynamic_arp_cppy_all ( dynamic_arp_packet *to,
						   const dynamic_arp_packet *from )
{
	if ( to == NULL || from == NULL )
	{
		return -1;
	}

	memcpy ( to, from, sizeof(dynamic_arp_packet) );
	return 0;
}

int dynamic_arp_cppy_except_eth ( dynamic_arp_packet *to,
								  const dynamic_arp_packet *from )
{
	if ( to == NULL || from == NULL )
	{
		return -1;
	}

	memcpy ( (char *) to + sizeof(eth_header),
			 (char *) from + sizeof(eth_header),
			 sizeof(dynamic_arp_packet) - sizeof(eth_header) );
	return 0;
}

int dynamic_arp_set_hw_fmt ( dynamic_arp_packet *d_packet,
							 unsigned short hw_fmt )
{
	if ( d_packet == NULL )
	{
		return -1;
	}

	d_packet->hw_addr_space = hw_fmt;
	return 0;
}

int dynamic_arp_set_pro_fmt ( dynamic_arp_packet *d_packet,
							  unsigned short pro_fmt )
{
	if ( d_packet == NULL )
	{
		return -1;
	}

	d_packet->protocol_addr_space = pro_fmt;
	return 0;
}

int dynamic_arp_set_hw_len ( dynamic_arp_packet *d_packet,
							 unsigned char hw_len )
{
	if ( d_packet == NULL )
	{
		return -1;
	}

	d_packet->hw_addr_len = hw_len;
	return 0;
}

int dynamic_arp_set_pro_len ( dynamic_arp_packet *d_packet,
							  unsigned char pro_len )
{
	if ( d_packet == NULL )
	{
		return -1;
	}

	d_packet->protocol_addr_len = pro_len;
	return 0;
}

int dynamic_arp_set_op_code ( dynamic_arp_packet *d_packet,
							  unsigned short op_code )
{
	if ( d_packet == NULL )
	{
		return -1;
	}

	d_packet->operate_code = op_code;
	return 0;
}

/* todo: be careful the diff len of dest_hw and src_hw */
int dynamic_arp_set_src_hw_addr_str ( dynamic_arp_packet *d_packet,
									  const char *str, int is_update_len )
{
	unsigned char ret;
	unsigned char mac[MAX_HW_ADDR_LEN];

	if ( d_packet == NULL || str == NULL )
	{
		return -1;
	}

	ret = str2mac ( str, mac, ETH_ADDR_LEN );

	if ( ret <= 0 )
	{
		return -1;
	}

	if ( d_packet->hw_addr_len > 0 && d_packet->src_hw_addr )
	{
		free ( d_packet->src_hw_addr );
	}

	d_packet->src_hw_addr = malloc ( ret );
	if ( d_packet->src_hw_addr == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	if ( is_update_len )
	{
		d_packet->hw_addr_len = ret;
	}
	else if ( d_packet->hw_addr_len != ret )
	{
		free ( d_packet->src_hw_addr );
		d_packet->src_hw_addr = NULL;
		return -1;
	}

	memcpy ( d_packet->src_hw_addr, mac, ret );
	return 0;
}
int dynamic_arp_set_src_hw_addr_bin ( dynamic_arp_packet *d_packet,
									  const void *addr )
{
	if ( d_packet == NULL || addr == NULL )
	{
		return -1;
	}

	if ( d_packet->hw_addr_len > 0 && d_packet->src_hw_addr )
	{
		free ( d_packet->src_hw_addr );
	}

	d_packet->src_hw_addr = malloc ( d_packet->hw_addr_len );
	if ( d_packet->src_hw_addr == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	memcpy ( d_packet->src_hw_addr, addr, d_packet->hw_addr_len );
	return 0;
}

int dynamic_arp_set_src_pro_addr_str ( dynamic_arp_packet *d_packet,
									   const char *str, int is_update_len )
{
	unsigned char len;
	unsigned char buf[IPV4_BIN_ADDR_LEN];

	if ( d_packet == NULL || str == NULL )
	{
		return -1;
	}

	if ( inet_pton ( AF_INET, str, buf ) == 1 )
	{
		len = IPV4_BIN_ADDR_LEN;
	}
	else
	{
		return -1;
	}

	if ( d_packet->protocol_addr_len > 0 && d_packet->src_protocol_addr )
	{
		free ( d_packet->src_protocol_addr );
	}

	d_packet->src_protocol_addr = malloc ( len );
	if ( d_packet->src_protocol_addr == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	if ( is_update_len )
	{
		d_packet->protocol_addr_len = len;
	}
	else if ( d_packet->protocol_addr_len != len )
	{
		free ( d_packet->src_protocol_addr );
		d_packet->src_protocol_addr = NULL;
		return -1;
	}

	//*(uint32_t *) buf = htonl(*(uint32_t *) buf);

	memcpy ( d_packet->src_protocol_addr, buf, len );
	return 0;
}
int dynamic_arp_set_src_pro_addr_bin ( dynamic_arp_packet *d_packet,
									   const void *addr )
{
	if ( d_packet == NULL || addr == NULL )
	{
		return -1;
	}

	if ( d_packet->protocol_addr_len > 0 && d_packet->src_protocol_addr )
	{
		free ( d_packet->src_protocol_addr );
	}

	d_packet->src_protocol_addr = malloc ( d_packet->protocol_addr_len );
	if ( d_packet->src_protocol_addr == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	memcpy ( d_packet->src_protocol_addr, addr, d_packet->protocol_addr_len );
	return 0;
}

int dynamic_arp_set_dest_hw_addr_str ( dynamic_arp_packet *d_packet,
									   const char *str, int is_update_len )
{
	unsigned char ret;
	unsigned char mac[MAX_HW_ADDR_LEN];

	if ( d_packet == NULL || str == NULL )
	{
		return -1;
	}

	ret = str2mac ( str, mac, ETH_ADDR_LEN );

	if ( ret <= 0 )
	{
		return -1;
	}

	if ( d_packet->hw_addr_len > 0 && d_packet->dest_hw_addr )
	{
		free ( d_packet->dest_hw_addr );
	}

	d_packet->dest_hw_addr = malloc ( ret );
	if ( d_packet->dest_hw_addr == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	if ( is_update_len )
	{
		d_packet->hw_addr_len = ret;
	}
	else if ( d_packet->hw_addr_len != ret )
	{
		free ( d_packet->dest_hw_addr );
		d_packet->dest_hw_addr = NULL;
		return -1;
	}

	memcpy ( d_packet->dest_hw_addr, mac, ret );
	return 0;
}
int dynamic_arp_set_dest_hw_addr_bin ( dynamic_arp_packet *d_packet,
									   const void *addr )
{
	if ( d_packet == NULL || addr == NULL )
	{
		return -1;
	}

	if ( d_packet->hw_addr_len > 0 && d_packet->dest_hw_addr )
	{
		free ( d_packet->dest_hw_addr );
	}

	d_packet->dest_hw_addr = malloc ( d_packet->hw_addr_len );
	if ( d_packet->dest_hw_addr == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	memcpy ( d_packet->dest_hw_addr, addr, d_packet->hw_addr_len );
	return 0;
}

/* todo: be careful the diff between src_ip and dest_ip len */
int dynamic_arp_set_dest_pro_addr_str ( dynamic_arp_packet *d_packet,
										const char *str, int is_update_len )
{
	unsigned char len;
	unsigned char buf[IPV4_BIN_ADDR_LEN];

	if ( d_packet == NULL || str == NULL )
	{
		return -1;
	}

	if ( inet_pton ( AF_INET, str, buf ) == 1 )
	{
		len = IPV4_BIN_ADDR_LEN;
	}
	else
	{
		return -1;
	}

	if ( d_packet->protocol_addr_len > 0 && d_packet->dest_protocol_addr )
	{
		free ( d_packet->dest_protocol_addr );
	}

	d_packet->dest_protocol_addr = malloc ( len );
	if ( d_packet->dest_protocol_addr == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	if ( is_update_len )
	{
		d_packet->protocol_addr_len = len;
	}
	else if ( d_packet->protocol_addr_len != len )
	{
		free ( d_packet->dest_protocol_addr );
		d_packet->dest_protocol_addr = NULL;
		return -1;
	}

	//*(uint32_t *) buf = htonl(*(uint32_t *) buf);

	memcpy ( d_packet->dest_protocol_addr, buf, len );
	return 0;
}
int dynamic_arp_set_dest_pro_addr_bin ( dynamic_arp_packet *d_packet,
										const void *addr )
{
	if ( d_packet == NULL || addr == NULL )
	{
		return -1;
	}

	if ( d_packet->protocol_addr_len > 0 && d_packet->dest_protocol_addr )
	{
		free ( d_packet->dest_protocol_addr );
	}

	d_packet->dest_protocol_addr = malloc ( d_packet->protocol_addr_len );
	if ( d_packet->dest_protocol_addr == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	memcpy ( d_packet->dest_protocol_addr, addr, d_packet->protocol_addr_len );
	return 0;
}

/*
 * build a dynamic ARP packet base on the data given
 * NULL Defalut value:
 * src_eth_hw		--	same as src_hw_addr
 * dest_eth_hw	--	same as dest_hw_addr
 * 	src_ip_addr	--	outgoing interface ip addr
 * 	src_hw_addr	--	outgoing interface hw addr
 * 	dest_ip_addr	--	broadcast addr of the outgoing interface
 * 	dest_hw_addr	--	"ff:ff:ff:ff" for req and "00:00:00:00:00:00" for rep
 */
int build_dynamic_arp ( dynamic_arp_packet *d_packet, const if_desc *if_info,
						int is_reply, const char *src_eth_hw,
						const char *dest_eth_hw, const char *src_ip_addr,
						const char *src_hw_addr, const char *dest_ip_addr,
						const char *dest_hw_addr )
{
	int ret;
	unsigned char buf_ip_src[IPV4_BIN_ADDR_LEN];
	unsigned char buf_ip_dest[IPV4_BIN_ADDR_LEN];
	unsigned char buf_hw_src[MAX_HW_ADDR_LEN];
	unsigned char buf_hw_dest[MAX_HW_ADDR_LEN];

	if ( d_packet == NULL )
	{
		return -1;
	}

	/* todo: maybe src and dest ip len is not equal */
	/* todo: distinct the receiver mac and request mac field */

	/* todo: only search AF_INET interface */
	/* set value */
	if ( src_ip_addr == NULL )
	{
		d_packet->protocol_addr_len = IPV4_BIN_ADDR_LEN;
		//*(uint32_t *) buf_ip_src = htonl(*(uint32_t *)if_info->ip_addr_bin);
		//*(uint32_t *) buf_ip_src = *(uint32_t *)if_info->ip_addr_bin;
				memcpy( buf_ip_src, if_info->ip_addr_bin, IPV4_BIN_ADDR_LEN );
			}
			else
			{
				if (inet_pton(AF_INET, src_ip_addr, buf_ip_src) == 1)
				{
					//*(uint32_t *) buf_ip_src = htonl(*(uint32_t *) buf_ip_src);
					d_packet->protocol_addr_len = IPV4_BIN_ADDR_LEN;
				}
				else
				{
					msg_log(LEVEL_ERR, "%s: wrong src ip format.\n", __func__);
					return -1;
				}
			}

	if ( dest_ip_addr == NULL )
	{
		d_packet->protocol_addr_len = IPV4_BIN_ADDR_LEN;
		//*(uint32_t *) buf_ip_dest = htonl(*(uint32_t *) if_info->bc_ip_addr_bin);
		//*(uint32_t *) buf_ip_dest = *(uint32_t *) if_info->bc_ip_addr_bin;
				memcpy( buf_ip_dest, if_info->bc_ip_addr_bin, IPV4_BIN_ADDR_LEN );
			}
			else
			{
				if (inet_pton(AF_INET, dest_ip_addr, buf_ip_dest) == 1)
				{
					//*(uint32_t *) buf_ip_dest = htonl(*(uint32_t *) buf_ip_dest);
					d_packet->protocol_addr_len = IPV4_BIN_ADDR_LEN;
				}
				else
				{
					msg_log(LEVEL_ERR, "%s: wrong dest ip format.\n", __func__);
					return -1;
				}
			}

	if ( src_hw_addr == NULL )
	{
		d_packet->hw_addr_len = if_info->hw_len;
		memcpy ( buf_hw_src, if_info->hw_addr, if_info->hw_len );
	}
	else
	{
		if ( (ret = str2mac ( src_hw_addr, buf_hw_src, MAX_HW_ADDR_LEN )) < 0 )
		{
			msg_log ( LEVEL_ERR, "%s: wrong src hw format.\n", __func__ );
			return -1;
		}

		d_packet->hw_addr_len = ret;
	}

	if ( dest_hw_addr == NULL )
	{
		if ( is_reply )
		{
			if ( (ret = str2mac ( "ff:ff:ff:ff:ff:ff", buf_hw_dest,
								  MAX_HW_ADDR_LEN ))
				 < 0 )
			{
				msg_log ( LEVEL_ERR, "%s: wrong dest hw format.\n", __func__ );
				return -1;
			}
		}
		else
		{
			if ( (ret = str2mac ( "00:00:00:00:00:00", buf_hw_dest,
								  MAX_HW_ADDR_LEN ))
				 < 0 )
			{
				msg_log ( LEVEL_ERR, "%s: wrong dest hw format.\n", __func__ );
				return -1;
			}
		}
	}
	else
	{
		if ( (ret = str2mac ( dest_hw_addr, buf_hw_dest, MAX_HW_ADDR_LEN )) < 0 )
		{
			msg_log ( LEVEL_ERR, "%s: wrong dest hw format.\n", __func__ );
			return -1;
		}
	}

	if ( d_packet->hw_addr_len != ret )
	{
		msg_log ( LEVEL_ERR,
				  "%s: src hw addr and dest hw addr should be in same len!\n",
				  __func__ );
		return -1;
	}

	if ( src_eth_hw == NULL )
	{
		if ( if_info->hw_len == ETH_ADDR_LEN )
		{
			memcpy ( d_packet->eth_header.src_eth_addr, buf_hw_src,
					 ETH_ADDR_LEN );
		}
		else
		{
			msg_log ( LEVEL_ERR, "%s: you must special eth src addr!\n",
					  __func__ );
			return -1;
		}
	}
	else
	{
		if ( (ret = str2mac ( src_eth_hw, d_packet->eth_header.src_eth_addr,
							  ETH_ADDR_LEN ))
			 < 0 )
		{
			msg_log ( LEVEL_ERR, "%s: wrong src eth hw format.\n", __func__ );
			return -1;
		}
		if ( ret != ETH_ADDR_LEN )
		{
			msg_log ( LEVEL_ERR, "%s: wrong src eth hw format.\n", __func__ );
			return -1;
		}
	}

	if ( dest_eth_hw == NULL )
	{
		if ( is_reply == 0 && dest_hw_addr == NULL )
		{
			if ( (ret = str2mac ( "ff:ff:ff:ff:ff:ff",
								  d_packet->eth_header.dest_eth_addr,
								  ETH_ADDR_LEN ))
				 < 0 )
			{
				msg_log ( LEVEL_ERR, "%s: wrong dest eth hw format.\n",
						  __func__ );
				return -1;
			}
			if ( ret != ETH_ADDR_LEN )
			{
				msg_log ( LEVEL_ERR, "%s: wrong dest eth hw format.\n",
						  __func__ );
				return -1;
			}
		}
		else
		{
			if ( d_packet->hw_addr_len == ETH_ADDR_LEN )
			{
				memcpy ( d_packet->eth_header.dest_eth_addr, buf_hw_dest,
						 ETH_ADDR_LEN );
			}
			else
			{
				msg_log ( LEVEL_ERR, "%s: you must special eth dest addr!\n",
						  __func__ );
				return -1;
			}
		}
	}
	else
	{
		if ( (ret = str2mac ( dest_eth_hw, d_packet->eth_header.dest_eth_addr,
							  ETH_ADDR_LEN ))
			 < 0 )
		{
			msg_log ( LEVEL_ERR, "%s: wrong dest eth hw format.\n", __func__ );
			return -1;
		}
		if ( ret != ETH_ADDR_LEN )
		{
			msg_log ( LEVEL_ERR, "%s: wrong dest eth hw format.\n", __func__ );
			return -1;
		}
	}

	/* alloc memory */
	if ( (d_packet->src_protocol_addr = malloc ( d_packet->protocol_addr_len )) == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory\n", __func__ );
		return -1;
	}

	if ( (d_packet->src_hw_addr = malloc ( d_packet->hw_addr_len )) == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory\n", __func__ );
		free ( d_packet->src_protocol_addr );
		d_packet->src_protocol_addr = NULL;
		return -1;
	}

	if ( (d_packet->dest_protocol_addr = malloc ( d_packet->protocol_addr_len )) == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory\n", __func__ );
		free ( d_packet->src_protocol_addr );
		d_packet->src_protocol_addr = NULL;
		free ( d_packet->src_hw_addr );
		d_packet->src_hw_addr = NULL;
		return -1;
	}

	if ( (d_packet->dest_hw_addr = malloc ( d_packet->hw_addr_len )) == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory\n", __func__ );
		free ( d_packet->src_protocol_addr );
		d_packet->src_protocol_addr = NULL;
		free ( d_packet->src_hw_addr );
		d_packet->src_hw_addr = NULL;
		free ( d_packet->dest_protocol_addr );
		d_packet->dest_protocol_addr = NULL;
		return -1;
	}

	/* copy data */
	memcpy ( d_packet->src_protocol_addr, buf_ip_src,
			 d_packet->protocol_addr_len );
	memcpy ( d_packet->dest_protocol_addr, buf_ip_dest,
			 d_packet->protocol_addr_len );
	memcpy ( d_packet->src_hw_addr, buf_hw_src, d_packet->hw_addr_len );
	memcpy ( d_packet->dest_hw_addr, buf_hw_dest, d_packet->hw_addr_len );

	/* set other value */
	d_packet->eth_header.protocol_type = PROTOCOL_ARP;

	d_packet->protocol_addr_space = IP_PROTOCOL_TYPE;
	d_packet->hw_addr_space = ETH_HW_TYPE;

	if ( is_reply )
	{
		d_packet->operate_code = ARP_OP_REPLY;
	}
	else
	{
		d_packet->operate_code = ARP_OP_REQUEST;
	}

	//dump_d_packet( d_packet );

	return 0;
}

void reset_dynamic_arp ( dynamic_arp_packet *d_packet )
{
	dynamic_arp_packet *ptr;

	for ( ; d_packet != NULL ; )
	{
		if ( d_packet->src_hw_addr != NULL )
		{
			free ( d_packet->src_hw_addr );
		}

		if ( d_packet->src_protocol_addr != NULL )
		{
			free ( d_packet->src_protocol_addr );
		}

		if ( d_packet->dest_hw_addr != NULL )
		{
			free ( d_packet->dest_hw_addr );
		}

		if ( d_packet->dest_protocol_addr != NULL )
		{
			free ( d_packet->dest_protocol_addr );
		}

		if ( list_is_usr( &d_packet->connector ))
		{
			init_dynamic_arp_packet( d_packet );
			d_packet =
					next_container( &d_packet->connector, connector, dynamic_arp_packet );
			continue;
		}

		ptr = next_container( &d_packet->connector, connector, dynamic_arp_packet );
		delete_same_list( &d_packet->connector );
		free ( d_packet );
		d_packet = ptr;
	}
}

void reset_dynamic_arp_eth ( dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		return;
	}

	eth_reset ( &d_packet->eth_header );
}

void free_dynamic_arp ( dynamic_arp_packet *d_packet )
{
	dynamic_arp_packet *ptr;

	for ( ; d_packet != NULL ; )
	{
		if ( d_packet->src_hw_addr != NULL )
		{
			free ( d_packet->src_hw_addr );
			d_packet->src_hw_addr = NULL;
		}

		if ( d_packet->src_protocol_addr != NULL )
		{
			free ( d_packet->src_protocol_addr );
			d_packet->src_protocol_addr = NULL;
		}

		if ( d_packet->dest_hw_addr != NULL )
		{
			free ( d_packet->dest_hw_addr );
			d_packet->dest_hw_addr = NULL;
		}

		if ( d_packet->dest_protocol_addr != NULL )
		{
			free ( d_packet->dest_protocol_addr );
			d_packet->dest_protocol_addr = NULL;
		}

		if ( list_is_usr( &d_packet->connector ))
		{
			list_set_unused( &d_packet->connector );
			d_packet =
					next_container( &d_packet->connector, connector, dynamic_arp_packet );
			continue;
		}

		ptr = next_container( &d_packet->connector, connector, dynamic_arp_packet );
		delete_same_list( &d_packet->connector );
		free ( d_packet );
		d_packet = ptr;
	}
}

char *dynamic_arp_get_eth_dest_addr_str ( const dynamic_arp_packet *d_packet,
										  void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return NULL ;
	}

	return eth_get_dest_hwaddr_str ( &d_packet->eth_header, buf, size );
}
int dynamic_arp_get_eth_dest_addr_bin ( const dynamic_arp_packet *d_packet,
										void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return -1;
	}

	return eth_get_dest_hwaddr_bin ( &d_packet->eth_header, buf, size );
}

char *dynamic_arp_get_eth_src_addr_str ( const dynamic_arp_packet *d_packet,
										 void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return NULL ;
	}

	return eth_get_src_hwaddr_str ( &d_packet->eth_header, buf, size );
}

int dynamic_arp_get_eth_src_addr_bin ( const dynamic_arp_packet *d_packet,
									   void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return -1;
	}

	return eth_get_src_hwaddr_bin ( &d_packet->eth_header, buf, size );
}

unsigned short dynamic_arp_get_eth_pro ( const dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		/* todo: unsigned return value */
		return 0;
	}

	return eth_get_pro_type ( &d_packet->eth_header );
}

unsigned short dynamic_arp_get_hw_fmt ( const dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		return 0;
	}

	return d_packet->hw_addr_space;
}
unsigned short dynamic_arp_get_pro_fmt ( const dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		return 0;
	}

	return d_packet->protocol_addr_space;
}

unsigned char dynamic_arp_get_hw_len ( const dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		return 0;
	}

	return d_packet->hw_addr_len;
}
unsigned char dynamic_arp_get_pro_len ( const dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		return 0;
	}

	return d_packet->protocol_addr_len;
}

unsigned short dynamic_arp_get_op_code ( const dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		return 0;
	}

	return d_packet->operate_code;
}

char *dynamic_arp_get_src_hw_addr_str ( const dynamic_arp_packet *d_packet,
										void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return NULL ;
	}

	return mac2str ( d_packet->src_hw_addr, d_packet->hw_addr_len, buf, size );
}

int dynamic_arp_get_src_hw_addr_bin ( const dynamic_arp_packet *d_packet,
									  void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return -1;
	}

	if ( size < d_packet->hw_addr_len )
	{
		return -1;
	}

	memcpy ( buf, d_packet->src_hw_addr, d_packet->hw_addr_len );
	return d_packet->hw_addr_len;
}

char *dynamic_arp_get_src_pro_addr_str ( const dynamic_arp_packet *d_packet,
										 void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return NULL ;
	}

	/* must be IPv4 len */
	if ( d_packet->protocol_addr_len != IPV4_BIN_ADDR_LEN)
	{
		return NULL ;
	}

	if ( inet_ntop ( AF_INET, d_packet->src_protocol_addr, buf, size ) == NULL )
	{
		return NULL ;
	}

	return buf;
}
int dynamic_arp_get_src_pro_addr_bin ( const dynamic_arp_packet *d_packet,
									   void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return -1;
	}

	if ( size < d_packet->protocol_addr_len )
	{
		return -1;
	}

	memcpy ( buf, d_packet->src_protocol_addr, d_packet->protocol_addr_len );
	return d_packet->protocol_addr_len;
}

char *dynamic_arp_get_dest_hw_addr_str ( const dynamic_arp_packet *d_packet,
										 void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return NULL ;
	}

	return mac2str ( d_packet->dest_hw_addr, d_packet->hw_addr_len, buf, size );
}
int dynamic_arp_get_dest_hw_addr_bin ( const dynamic_arp_packet *d_packet,
									   void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return -1;
	}

	if ( size < d_packet->hw_addr_len )
	{
		return -1;
	}

	memcpy ( buf, d_packet->dest_hw_addr, d_packet->hw_addr_len );
	return d_packet->hw_addr_len;
}

char *dynamic_arp_get_dest_pro_addr_str ( const dynamic_arp_packet *d_packet,
										  void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return NULL ;
	}

	/* must be IPv4 len */
	if ( d_packet->protocol_addr_len != IPV4_BIN_ADDR_LEN)
	{
		return NULL ;
	}

	if ( inet_ntop ( AF_INET, d_packet->dest_protocol_addr, buf, size ) == NULL )
	{
		return NULL ;
	}

	return buf;
}
int dynamic_arp_get_dest_pro_addr_bin ( const dynamic_arp_packet *d_packet,
										void *buf, int size )
{
	if ( d_packet == NULL || buf == NULL || size < 0 )
	{
		return -1;
	}

	if ( size < d_packet->protocol_addr_len )
	{
		return -1;
	}

	memcpy ( buf, d_packet->dest_protocol_addr, d_packet->protocol_addr_len );
	return d_packet->protocol_addr_len;
}

ssize_t extract_arp ( const if_desc *if_ptr, const unsigned char *buf,
					  ssize_t len, void *data )
{
	int rest;
	dynamic_arp_packet *d_packet = (dynamic_arp_packet *) data;

	if ( buf == NULL )
	{
		return -1;
	}

	/* check if is a ARP packet */
	if ( ntohs ( *(unsigned short *) (buf + ETH_ADDR_LEN + ETH_ADDR_LEN) ) != PROTOCOL_ARP )
	{
		return -1;
	}

	/* alloc a list node if no one available to use */
	while ( list_is_used(&d_packet->connector) && d_packet->connector.next
			!= NULL )
	{
		d_packet =
				next_container( &d_packet->connector, connector, dynamic_arp_packet );
	}

	if ( d_packet->connector.next == NULL && list_is_used(&d_packet->connector))
	{
		dynamic_arp_packet *ptr = malloc ( sizeof(dynamic_arp_packet) );
		if ( ptr == NULL )
		{
			msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
			return -1;
		}

		init_dynamic_arp_packet( ptr );
		list_set_sys( &ptr->connector );
		insert_list_nonptr( d_packet->connector, ptr->connector );

		d_packet = ptr;
	}

	memcpy ( &d_packet->eth_header, buf, ETH_ADDR_LEN + ETH_ADDR_LEN );
	d_packet->eth_header.protocol_type = PROTOCOL_ARP;
	buf += ETH_ADDR_LEN + ETH_ADDR_LEN + 2;
	len -= ETH_ADDR_LEN + ETH_ADDR_LEN + 2;

	d_packet->hw_addr_space = ntohs ( *(unsigned short *) buf );
	d_packet->protocol_addr_space = ntohs ( *(unsigned short *) (buf + 2) );
	buf += 4;
	len -= 4;

	d_packet->hw_addr_len = *buf;
	d_packet->protocol_addr_len = *(buf + 1);
	buf += 2;
	len -= 2;

	/* cale the size requair */
	rest = 2 + d_packet->protocol_addr_len + d_packet->hw_addr_len
		   + d_packet->protocol_addr_len + d_packet->hw_addr_len;

	/* how if len bigger rest ??? */
	if ( len < rest )
	{
		msg_log ( LEVEL_INFO, "%s: expect %d but only %d left\n", __func__,
				  rest, len );
		return -1;
	}

	d_packet->operate_code = ntohs ( *(unsigned short *) buf );
	buf += 2;

	/* alloc memory as need */
	/* src_hw_addr */
	if ( (d_packet->src_hw_addr = malloc ( d_packet->hw_addr_len )) == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: memory out!", __func__ );
		return -1;
	}
	memcpy ( d_packet->src_hw_addr, buf, d_packet->hw_addr_len );
	buf += d_packet->hw_addr_len;

	/* src_protocol_addr */
	if ( (d_packet->src_protocol_addr = malloc ( d_packet->protocol_addr_len )) == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: memory out!", __func__ );
		free ( d_packet->src_hw_addr );
		d_packet->src_hw_addr = NULL;
		return -1;
	}
	memcpy ( d_packet->src_protocol_addr, buf, d_packet->protocol_addr_len );
	buf += d_packet->protocol_addr_len;

	/* dest_hw_addr */
	if ( (d_packet->dest_hw_addr = malloc ( d_packet->hw_addr_len )) == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: memory out!", __func__ );
		free ( d_packet->src_hw_addr );
		d_packet->src_hw_addr = NULL;
		free ( d_packet->src_protocol_addr );
		d_packet->src_protocol_addr = NULL;
		return -1;
	}
	memcpy ( d_packet->dest_hw_addr, buf, d_packet->hw_addr_len );
	buf += d_packet->hw_addr_len;

	/* dest_protocol_addr */
	if ( (d_packet->dest_protocol_addr = malloc ( d_packet->protocol_addr_len )) == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: memory out!", __func__ );
		free ( d_packet->src_hw_addr );
		d_packet->src_hw_addr = NULL;
		free ( d_packet->src_protocol_addr );
		d_packet->src_protocol_addr = NULL;
		free ( d_packet->dest_hw_addr );
		d_packet->dest_hw_addr = NULL;
		return -1;
	}
	memcpy ( d_packet->dest_protocol_addr, buf, d_packet->protocol_addr_len );
	//buf += d_packet->protocol_addr_len;

	d_packet->interface = if_ptr;

	list_set_used( &d_packet->connector );

	return 0;
}

int is_dynamic_request_arp ( const dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		return 0;
	}

	if ( dynamic_arp_get_op_code ( d_packet ) == ARPOP_REQUEST )
	{
		return 1;
	}

	return 0;
}

int is_dynamic_reply_arp ( const dynamic_arp_packet *d_packet )
{
	if ( d_packet == NULL )
	{
		return 0;
	}

	if ( dynamic_arp_get_op_code ( d_packet ) == ARPOP_REPLY )
	{
		return 1;
	}

	return 0;
}

void print_arp ( const dynamic_arp_packet *d_packet )
{
	int i;
	static unsigned long count = 0;
	static char ip[MAX_IP_ADDR_LEN];

	if ( d_packet == NULL )
	{
		return;
	}

	foreach_list( d_packet, &d_packet->connector, connector, dynamic_arp_packet )
	{
		if ( list_is_unused(&d_packet->connector))
		{
			continue;
		}

		msg_log ( LEVEL_INFO, "\n#%ld: ", ++count );

		switch ( d_packet->operate_code )
		{
			case ARP_OP_REQUEST:
			{
				msg_log ( LEVEL_INFO, "REQUEST\n" );
			}
			break;

			case ARP_OP_REPLY:
			{
				msg_log ( LEVEL_INFO, "REPLY\n" );
			}
			break;

			default:
			{
				msg_log ( LEVEL_INFO, "UNKNOWN\n" );
			}
			break;

		}

		msg_log ( LEVEL_INFO, "%-8s\t", "Eth:" );

		for ( i = 0; i < ETH_ADDR_LEN; i++ )
		{
			msg_log ( LEVEL_INFO, "%02x:",
					  *(d_packet->eth_header.src_eth_addr + i) );
		}
		msg_log ( LEVEL_INFO, "\b " );
		msg_log ( LEVEL_INFO, "--> " );
		for ( i = 0; i < ETH_ADDR_LEN; i++ )
		{
			msg_log ( LEVEL_INFO, "%02x:",
					  *(d_packet->eth_header.dest_eth_addr + i) );
		}
		msg_log ( LEVEL_INFO, "\b \n" );

		msg_log ( LEVEL_INFO, "%-8s\t", "Sender:" );

		if ( d_packet->protocol_addr_len == IPV4_BIN_ADDR_LEN)
		{
			if ( inet_ntop ( AF_INET, d_packet->src_protocol_addr, ip,
							 MAX_IP_ADDR_LEN )
				 != NULL )
			{
				msg_log ( LEVEL_INFO, "%16s (", ip );
			}
			else
			{
				msg_log ( LEVEL_INFO, "%16s (", "unknown" );
			}

			for ( i = 0; i < d_packet->hw_addr_len; i++ )
			{
				msg_log ( LEVEL_INFO, "%02x:", *(d_packet->src_hw_addr + i) );
			}
			msg_log ( LEVEL_INFO, "\b)\n" );

			msg_log ( LEVEL_INFO, "%-8s\t", "Recever:" );

			if ( inet_ntop ( AF_INET, d_packet->dest_protocol_addr, ip,
							 MAX_IP_ADDR_LEN )
				 != NULL )
			{
				msg_log ( LEVEL_INFO, "%16s (", ip );
			}
			else
			{
				msg_log ( LEVEL_INFO, "%16s (", "unknown" );
			}

			for ( i = 0; i < d_packet->hw_addr_len; i++ )
			{
				msg_log ( LEVEL_INFO, "%02x:", *(d_packet->dest_hw_addr + i) );
			}
			msg_log ( LEVEL_INFO, "\b)\n" );
		}
		else
		{
			msg_log ( LEVEL_INFO, "%16s( ", "unknown" );

			for ( i = 0; i < d_packet->hw_addr_len; i++ )
			{
				msg_log ( LEVEL_INFO, "%02x:", *(d_packet->src_hw_addr + i) );
			}
			msg_log ( LEVEL_INFO, "\b)\n" );

			msg_log ( LEVEL_INFO, "%-8s\t", "Recever:" );

			msg_log ( LEVEL_INFO, "%16s( ", "unknown" );

			for ( i = 0; i < d_packet->hw_addr_len; i++ )
			{
				msg_log ( LEVEL_INFO, "%02x:", *(d_packet->dest_hw_addr + i) );
			}
			msg_log ( LEVEL_INFO, "\b)\n" );
		}
	}
}

int open_arp_interface ( const char *interface, if_desc *if_info )
{
	if ( if_info == NULL )
	{
		return -1;
	}

	if_info->family = PF_PACKET;
	if_info->socket_type = SOCK_RAW;
	if_info->protocol = ETH_P_ARP;

	return open_interface ( interface, if_info );
}

void close_arp_interface ( if_desc *if_info )
{
	foreach_list( if_info, &if_info->connector, connector, if_desc )
	{
		if ( list_is_used(&if_info->connector))
		{
			close_interface ( if_info );
		}
	}
}

/*
 * return the packet received
 */
int listen_arp_interface ( if_desc *if_info, dynamic_arp_packet *d_packet,
						   time_t deadline )
{
	return listen_interface ( if_info, extract_arp, d_packet, deadline );
}

int send_dynamic_arp ( const if_desc *if_info,
					   const dynamic_arp_packet *d_packet, unsigned char flags )
{
	int ret;
	int len;
	int effective = 0;
	unsigned char *buf, *ptr;
	dynamic_arp_packet *d;
	//struct sockaddr_ll out;	/* see man PF_PACKET */

	if ( if_info == NULL || if_info->sockfd < 0 )
	{
		return -1;
	}

	/* cale the packet total size */
	len = d_arp_packet_len(d_packet);
	if ( (flags & D_SEND_PAD) && len < ETH_PADDED_LEN )
	{
		len = ETH_PADDED_LEN;
	}

	buf = malloc ( len );
	if ( buf == NULL )
	{
		msg_log ( LEVEL_ERR, "%s: out of memory!\n", __func__ );
		return -1;
	}

	ptr = buf;
	d = (dynamic_arp_packet *) buf;

	memcpy ( ptr, d_packet, D_ARP_FIXED_HEAD_LEN);
	ptr += D_ARP_FIXED_HEAD_LEN;

	/* do some hton[sl] convert, be careful */
	d->eth_header.protocol_type = htons ( d->eth_header.protocol_type );
	d->hw_addr_space = htons ( d->hw_addr_space );
	d->protocol_addr_space = htons ( d->protocol_addr_space );
	d->operate_code = htons ( d->operate_code );

	memcpy ( ptr, d_packet->src_hw_addr, d_packet->hw_addr_len );
	ptr += d_packet->hw_addr_len;

	memcpy ( ptr, d_packet->src_protocol_addr, d_packet->protocol_addr_len );
	ptr += d_packet->protocol_addr_len;

	memcpy ( ptr, d_packet->dest_hw_addr, d_packet->hw_addr_len );
	ptr += d_packet->hw_addr_len;

	memcpy ( ptr, d_packet->dest_protocol_addr, d_packet->protocol_addr_len );
	ptr += d_packet->protocol_addr_len;

	//dump_packet(buf, len);
	//msg_log(LEVEL_INFO, "\n");

	/* see man PF_PACKET */
	//memset( &out, 0, sizeof( struct sockaddr_ll ) );
	//out.sll_family = if_info->family;		/*  */
	//out.sll_ifindex = if_info->index;	/*  */
	//out.sll_halen = ETH_ALEN;
	//memcpy(out.sll_addr, d_packet->eth_header.src_eth_addr, ETH_ALEN);
	//ret = send_packet(if_info->sockfd, buf, len, 0, &out,
	//		sizeof(struct sockaddr_ll));
	if ( flags & D_SEND_SINGLE )
	{
		ret = send_packet ( if_info->sockfd, buf, len, 0, NULL, 0 );

		if ( ret == -1 )
		{
			msg_log ( LEVEL_ERR, "%s(%s): send fail, %s\n", __func__,
					  if_info->if_name, strerror ( errno) );
		}
		else if ( ret != len )
		{
			/* what should I do here */
			msg_log ( LEVEL_ERR, "%s(%s): request %d, but send %d\n", __func__,
					  if_info->if_name, len, ret );
		}
		else
		{
			effective = 1;
		}

		msg_log (
				LEVEL_INFO, "%s: send an ARP %s (%d bytes) via \'%s\'\n",
				__func__,
				d_packet->operate_code == ARP_OP_REQUEST ? "Request" : "Reply",
				ret, if_info->if_name );
	}
	else
	{
		foreach_list( if_info, &if_info->connector, connector, const if_desc )
		{
			ret = send_packet ( if_info->sockfd, buf, len, 0, NULL, 0 );

			if ( ret == -1 )
			{
				msg_log ( LEVEL_ERR, "%s(%s): send fail, %s\n", __func__,
						  if_info->if_name, strerror ( errno) );
				continue;
			}
			else if ( ret != len )
			{
				/* what should I do here */
				msg_log ( LEVEL_ERR, "%s(%s): request %d, but send %d\n",
						  __func__, if_info->if_name, len, ret );
				continue;
			}

			effective = 1;

			msg_log (
					LEVEL_INFO,
					"%s: send an ARP %s (%d bytes) via \'%s\'\n",
					__func__,
					d_packet->operate_code == ARP_OP_REQUEST ?
							"Request" : "Reply",
					ret, if_info->if_name );
		}
	}

	free ( buf );
	buf = NULL;

	if ( effective )
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

void print_dynamic_arp ( const dynamic_arp_packet *d_packet )
{
	print_bin2hex ( (unsigned char *) d_packet, D_ARP_FIXED_HEAD_LEN);
	print_bin2hex ( (unsigned char *) d_packet->src_hw_addr,
					d_packet->hw_addr_len );
	print_bin2hex ( (unsigned char *) d_packet->src_protocol_addr,
					d_packet->protocol_addr_len );
	print_bin2hex ( (unsigned char *) d_packet->dest_hw_addr,
					d_packet->hw_addr_len );
	print_bin2hex ( (unsigned char *) d_packet->dest_protocol_addr,
					d_packet->protocol_addr_len );
	msg_log ( LEVEL_INFO, "\n\n" );
}
