/*
 * network.h
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#ifndef NETWORK_H_
#define NETWORK_H_

#include <netinet/in.h>
#include "arp.h"
#include "interface.h"

#define ETH_PADDED_LEN	60
#define ETH_HW_TYPE		0x0001
#define IP_PROTOCOL_TYPE	0x0800

int open_interface ( const char *interface, if_desc *if_info );
void close_interface ( if_desc *if_info );

int listen_interface (
		if_desc *if_info,
		ssize_t (*data_factory) ( const if_desc *, const unsigned char *,
								  ssize_t, void * ),
		void *arg, time_t deadline );

int open_socket ( if_desc *if_info );
int close_socket ( if_desc *if_info );

ssize_t send_packet ( int sockfd, const void *data, size_t size, int flags,
					  const void *addr, socklen_t addrlen );

#endif  /* NETWORK_H_ */
