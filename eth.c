/*
 * eth.c
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#include <string.h>
#include <arpa/inet.h>

#include "eth.h"
#include "misc.h"

void eth_reset ( eth_header *header )
{
	if ( header == NULL )
	{
		return;
	}

	memset ( header, 0, ETH_HEADER_SIZE);
}

int eth_copy ( eth_header *to, const eth_header *from )
{
	if ( to == NULL || from == NULL )
	{
		return -1;
	}

	memcpy ( to, from, ETH_ADDR_LEN );
	return 0;
}

int eth_set_dest_hwaddr_bin ( eth_header *header,
							  const unsigned char data[ETH_ADDR_LEN] )
{
	if ( header == NULL || data == NULL )
	{
		return -1;
	}

	memcpy ( header->dest_eth_addr, data, ETH_ADDR_LEN );
	return 0;
}

int eth_set_dest_hwaddr_str ( eth_header *header, const char *str )
{
	int ret;
	unsigned char mac[ETH_ADDR_LEN];

	if ( header == NULL || str == NULL )
	{
		return -1;
	}

	ret = str2mac ( str, mac, ETH_ADDR_LEN );

	if ( ret != ETH_ADDR_LEN )
	{
		return -1;
	}

	memcpy ( header->dest_eth_addr, mac, ETH_ADDR_LEN );
	return 0;
}

int eth_set_src_hwaddr_bin ( eth_header *header,
							 const unsigned char data[ETH_ADDR_LEN] )
{
	if ( header == NULL || data == NULL )
	{
		return -1;
	}

	memcpy ( header->src_eth_addr, data, ETH_ADDR_LEN );
	return 0;
}

int eth_set_src_hwaddr_str ( eth_header *header, const char *str )
{
	int ret;
	unsigned char mac[ETH_ADDR_LEN];

	if ( header == NULL || str == NULL )
	{
		return -1;
	}

	ret = str2mac ( str, mac, ETH_ADDR_LEN );

	if ( ret != ETH_ADDR_LEN )
	{
		return -1;
	}

	memcpy ( header->src_eth_addr, mac, ETH_ADDR_LEN );
	return 0;
}

int eth_set_pro_type ( eth_header *header, unsigned short type )
{
	if ( header == NULL )
	{
		return -1;
	}

	header->protocol_type = type;
	return 0;
}

int eth_get_dest_hwaddr_bin ( const eth_header *header, void *buf, int size )
{
	if ( header == NULL || buf == NULL || size < ETH_ADDR_LEN )
	{
		return -1;
	}

	memcpy ( buf, header->dest_eth_addr, ETH_ADDR_LEN );
	return ETH_ADDR_LEN;
}

char *eth_get_dest_hwaddr_str ( const eth_header *header, void *buf, int size )
{
	if ( header == NULL || buf == NULL || size < 0 )
	{
		return NULL ;
	}

	return mac2str ( header->dest_eth_addr, ETH_ADDR_LEN, buf, size );
}

int eth_get_src_hwaddr_bin ( const eth_header *header, void *buf, int size )
{
	if ( header == NULL || buf == NULL || size < ETH_ADDR_LEN )
	{
		return -1;
	}

	memcpy ( buf, header->src_eth_addr, ETH_ADDR_LEN );
	return ETH_ADDR_LEN;
}

char *eth_get_src_hwaddr_str ( const eth_header *header, void *buf, int size )
{
	if ( header == NULL || buf == NULL || size < 0 )
	{
		return NULL ;
	}

	return mac2str ( header->src_eth_addr, ETH_ADDR_LEN, buf, size );
}

unsigned short eth_get_pro_type ( const eth_header *header )
{
	if ( header == NULL )
	{
		/* todo: the return value */
		return 0;
	}

	return header->protocol_type;
}
