/*
 * network.c
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <ctype.h>

#include "arp.h"
#include "network.h"
#include "misc.h"
#include "list.h"

int open_socket ( if_desc *if_info )
{
	int sockfd;
	struct ifconf ifc;
	struct ifreq *ifr;
	struct sockaddr_ll out;

	//sockfd = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP));
	sockfd = socket ( if_info->family, if_info->socket_type,
					  htons ( if_info->protocol ) );
	if ( sockfd < 0 )
	{
		msg_log ( LEVEL_ERR, "%s(%s): socket error, %s\n", __func__,
				  if_info->if_name, strerror ( errno) );
		return -1;
	}

	/* bind to interface */
	memset ( &out, 0, sizeof(struct sockaddr_ll) );
	out.sll_family = if_info->family;
	out.sll_protocol = htons ( (unsigned short) if_info->protocol );
	out.sll_ifindex = if_info->index;
	//out.sll_halen = ETH_ALEN;
	//memcpy(out.sll_addr, if_info->hw_addr, ETH_ALEN);

	if ( bind ( sockfd, (struct sockaddr *) &out, sizeof(struct sockaddr_ll) ) == -1 )
	{
		msg_log ( LEVEL_ERR, "%s(%s): bind error, %s\n", __func__,
				  if_info->if_name, strerror ( errno) );
		close ( sockfd );
		return -1;
	}

	/*
	 if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, if_info->if_name,
	 strlen(if_info->if_name) + 1) == -1)
	 {
	 msg_log(LEVEL_ERR, "%s: setsockopt(SO_BINDTODEVICE) fail, %s\n",
	 __func__, strerror(errno));

	 close(sockfd);
	 return -1;
	 }
	 */

	if ( if_info->request_flags & IFF_PROMISC )
	{
		if ( if_info->if_flags & IFF_PROMISC )
		{
			if_info->if_flags |= if_info->request_flags;
			if_info->request_flags = 0;
		}
		else
		{
			if_info->if_flags |= if_info->request_flags;
			if_info->request_flags = IFF_PROMISC;
		}
	}
	else
	{
		if_info->if_flags |= if_info->request_flags;
	}

	/* fetch system interface list */
	if ( get_interface_list ( &ifc ) == -1 )
	{
		close ( sockfd );
		return -1;
	}

	for ( ifr = (struct ifreq *) ifc.ifc_buf;
			(char *) ifr < ifc.ifc_buf + ifc.ifc_len; ifr++ )
	{
		if ( strcasecmp ( if_info->if_name, ifr->ifr_name ) == 0 )
		{
			break;
		}
	}

	if ( (char *) ifr >= ifc.ifc_buf + ifc.ifc_len )
	{
		msg_log ( LEVEL_ERR, "%s: can find interface %s\n", __func__,
				  if_info->if_name );
		destroy_interface_list ( &ifc );
		close ( sockfd );
		return -1;
	}

	/* fetch flags */
	if ( ioctl ( sockfd, SIOCGIFFLAGS, ifr ) != 0 )
	{
		msg_log ( LEVEL_ERR, "%s(%s): ioctl error, %s\n", __func__,
				  if_info->if_name, strerror ( errno) );
		destroy_interface_list ( &ifc );
		close ( sockfd );
		return -1;
	}

	if ( (if_info->request_flags & IFF_PROMISC) && (ifr->ifr_flags & IFF_PROMISC) )
	{
		if_info->request_flags = 0;
	}

	ifr->ifr_flags = if_info->if_flags;

	/* set flags */
	if ( ioctl ( sockfd, SIOCSIFFLAGS, ifr ) != 0 )
	{
		msg_log ( LEVEL_ERR, "%s(%s): ioctl error, %s\n", __func__,
				  if_info->if_name, strerror ( errno) );
		destroy_interface_list ( &ifc );
		close ( sockfd );
		return -1;
	}

	destroy_interface_list ( &ifc );

	msg_log ( LEVEL_INFO, "add interface \"%s\"\n", if_info->if_name );

	return sockfd;
}

int close_socket ( if_desc *if_info )
{
	int all_finished = 1;
	struct ifconf ifc;
	struct ifreq *ifr;

	if ( if_info->sockfd < 0 )
	{
		return -1;
	}

	if ( if_info->request_flags & IFF_PROMISC )
	{
		/* fetch system interface list */
		if ( get_interface_list ( &ifc ) == -1 )
		{
			close ( if_info->sockfd );
			return -1;
		}

		for ( ifr = (struct ifreq *) ifc.ifc_buf;
				(char *) ifr < ifc.ifc_buf + ifc.ifc_len; ifr++ )
		{
			if ( strcasecmp ( if_info->if_name, ifr->ifr_name ) == 0 )
			{
				break;
			}
		}

		if ( (char *) ifr >= ifc.ifc_buf + ifc.ifc_len )
		{
			msg_log ( LEVEL_ERR, "%s: can find interface %s\n", __func__,
					  if_info->if_name );
			destroy_interface_list ( &ifc );
			all_finished = 0;
			goto close_socket_end;
		}

		/* fetch flags */
		if ( ioctl ( if_info->sockfd, SIOCGIFFLAGS, ifr ) != 0 )
		{
			msg_log ( LEVEL_ERR, "%s: ioctl error, %s\n", __func__,
					  strerror ( errno) );
			destroy_interface_list ( &ifc );
			all_finished = 0;
			goto close_socket_end;
		}

		if ( (ifr->ifr_flags & IFF_PROMISC) == 0 )
		{
			destroy_interface_list ( &ifc );
			goto close_socket_end;
		}

		ifr->ifr_flags &= ~IFF_PROMISC;

		/* set flags */
		if ( ioctl ( if_info->sockfd, SIOCSIFFLAGS, ifr ) != 0 )
		{
			msg_log ( LEVEL_ERR, "%s: ioctl error, %s\n", __func__,
					  strerror ( errno) );
			destroy_interface_list ( &ifc );
			all_finished = 0;
			goto close_socket_end;
		}

		destroy_interface_list ( &ifc );
	}

	close_socket_end:

	close ( if_info->sockfd );
	if_info->sockfd = -1;

	if ( all_finished )
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

int open_interface ( const char *interface, if_desc *if_info )
{
	int exist = 0;
	char *if_buf = NULL;
	if_desc *ptr;

	if ( if_info == NULL )
	{
		return -1;
	}

	if ( interface != NULL )
	{
		size_t len = strlen ( interface );
		if_buf = malloc ( len + 1 );

		if ( if_buf == NULL )
		{
			msg_log ( LEVEL_ERR, "%s: strdup error, %s\n", __func__,
					  strerror ( errno) );
			return -1;
		}

		if ( format_entry_str ( interface, if_buf, len + 1 ) == -1 )
		{
			msg_log ( LEVEL_ERR, "%s: format_entry_str fail\n", __func__ );
			return -1;
		}

		interface = if_buf;
	}

	if ( get_interface_name ( interface, if_info ) == -1 )
	{
		if ( if_buf != NULL )
		{
			free ( if_buf );
		}
		return -1;
	}

	if ( if_buf != NULL )
	{
		free ( if_buf );
	}

	for ( ; if_info != NULL ; )
	{
		if_info->sockfd = open_socket ( if_info );

		ptr = next_container( &if_info->connector, connector, if_desc );

		if ( if_info->sockfd < 0 )
		{
			if ( list_is_sys( &if_info->connector ))
			{
				free ( if_info );
			}
		}
		else
		{
			exist = 1;
		}

		delete_same_list( &if_info->connector );

		if_info = ptr;
	}

	/*
	 foreach_list(if_info, &if_info->connector, connector, if_desc)
	 {
	 if_info->sockfd = open_socket(if_info);

	 if (if_info->sockfd < 0)
	 {
	 if (have_next( &if_info->connector ))
	 {
	 if (count != 0)
	 {
	 ptr =
	 prev_container( &if_info->connector, connector, if_desc );
	 delete_same_list( &if_info->connector);
	 free(if_info);
	 if_info = ptr;
	 }

	 continue;
	 }
	 else
	 {
	 if (count == 0)
	 {
	 return -1;
	 }
	 else
	 {
	 ptr =
	 prev_container( &if_info->connector, connector, if_desc );
	 delete_same_list( &if_info->connector);
	 free(if_info);
	 return 0;
	 }
	 }
	 }

	 count++;
	 }
	 */

	return !exist;
}

void close_interface ( if_desc *if_info )
{
	close_socket ( if_info );
}

/*
 * return packet number received
 */
int listen_interface (
		if_desc *if_info,
		ssize_t (*data_factory) ( const if_desc *, const unsigned char *,
								  ssize_t, void * ),
		void *arg, time_t deadline )
{
	int ret;
	int max_fd;
	int count;
	ssize_t len;
	if_desc *if_ptr;
	fd_set rfds;
	struct timeval timeout;
	static unsigned char buffer[MAX_ARP_PACKET_LEN];

	if ( data_factory == NULL || if_info == NULL )
	{
		return -1;
	}

	timeout.tv_sec = deadline;
	timeout.tv_usec = 0;

	FD_ZERO( &rfds );
	count = 0;
	max_fd = -1;

	if_ptr = if_info;

	foreach_list( if_ptr, &if_ptr->connector, connector, if_desc )
	{
		if ( if_ptr->sockfd >= 0 )
		{
			FD_SET( if_ptr->sockfd, &rfds );

			if ( if_ptr->sockfd > max_fd )
			{
				max_fd = if_ptr->sockfd;
			}
		}
	}

	max_fd += 1;
	//fds_bak = rfds;

	for ( ;; )
	{
		//rfds = fds_bak;

		if ( deadline < 0 )
		{
			ret = select ( max_fd, &rfds, NULL, NULL, NULL );
		}
		else
		{
			ret = select ( max_fd, &rfds, NULL, NULL, &timeout );
		}

		if ( ret < 0 )
		{
			if ( errno == EINTR )
			{
				continue;
			}

			msg_log ( LEVEL_ERR, "%s: select error, %s\n", __func__,
					  strerror ( errno) );
			return -1;
		}
		else if ( ret == 0 )
		{
			continue;
		}

		if_ptr = if_info;

		foreach_list( if_ptr, &if_ptr->connector, connector, if_desc )
		{
			if ( if_ptr->sockfd >= 0 && FD_ISSET( if_ptr->sockfd, &rfds ))
			{
				ret--;

				readmsg:

				/* has something to read */
				len = recv ( if_ptr->sockfd, buffer, MAX_ARP_PACKET_LEN, 0 );

				if ( len < 0 )
				{
					if ( errno == EINTR )
					{
						goto readmsg;
					}

					msg_log ( LEVEL_ERR, "%s(%s): recv error, %s\n", __func__,
							  if_ptr->if_name, strerror ( errno) );

					//close( if_ptr->sockfd );
					//if_ptr->sockfd = -1;
				}
				else if ( len == 0 )
				{
					//continue;
				}
				else
				{
					//msg_log( LEVEL_INFO, "recv %d\n", len );

					if ( data_factory ( if_ptr, buffer, len, arg ) >= 0 )
					{
						count++;
					}
				}
			}

			if ( ret == 0 )
			{
				break;
			}
		}

		break;
	}

	return count;
}

ssize_t send_packet ( int sockfd, const void *data, size_t size, int flags,
					  const void *addr, socklen_t addrlen )
{
	ssize_t ret;

	if ( sockfd < 0 || data == NULL )
	{
		return -1;
	}

	sendmsg:

	if ( addr == NULL )
	{
		ret = send ( sockfd, data, size, flags );
	}
	else
	{
		ret = sendto ( sockfd, data, size, flags, (struct sockaddr *) addr,
					   addrlen );

	}

	if ( ret < 0 )
	{
		if ( errno == EINTR )
		{
			goto sendmsg;
		}

		msg_log ( LEVEL_ERR, "%s: send error, %s\n", __func__,
				  strerror ( errno) );
		return -1;
	}

	return ret;
}
