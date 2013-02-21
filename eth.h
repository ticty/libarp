/*
 * eth.h
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#ifndef ETH_H_
#define ETH_H_

/*
 * Ethernet transmission layer data header
 *
 Packet format:
 --------------

 Ethernet transmission layer (not necessarily accessible to
 the user):
 48.bit: Ethernet address of destination
 48.bit: Ethernet address of sender
 16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION
 
 Upper layer
 ...
 *
 */

#define ETH_ADDR_LEN	6
#define ETH_HEADER_SIZE	sizeof(eth_header)

/* Ethernet transmission layer data header */
typedef struct
{
	unsigned char dest_eth_addr[ETH_ADDR_LEN];
	unsigned char src_eth_addr[ETH_ADDR_LEN];
	unsigned short protocol_type;

} eth_header;

/* SET */
void eth_reset ( eth_header *header );
int eth_copy ( eth_header *to, const eth_header *from );

int eth_set_dest_hwaddr_bin ( eth_header *header,
							  const unsigned char data[ETH_ADDR_LEN] );
int eth_set_dest_hwaddr_str ( eth_header *header, const char *str );

int eth_set_src_hwaddr_bin ( eth_header *header,
							 const unsigned char data[ETH_ADDR_LEN] );
int eth_set_src_hwaddr_str ( eth_header *header, const char *str );

int eth_set_pro_type ( eth_header *header, unsigned short type );

/* GET */
int eth_get_dest_hwaddr_bin ( const eth_header *header, void *buf, int size );
char *eth_get_dest_hwaddr_str ( const eth_header *header, void *buf, int size );

int eth_get_src_hwaddr_bin ( const eth_header *header, void *buf, int size );
char *eth_get_src_hwaddr_str ( const eth_header *header, void *buf, int size );

unsigned short eth_get_pro_type ( const eth_header *header );

#endif	/* ETH_H_ */
