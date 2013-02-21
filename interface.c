/*
 * interface.c
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#include "interface.h"
#include "eth.h"
#include "misc.h"

/*
 * fetch system interface list,
 * user should remember to free the memory after successfully call this func
 */
int get_interface_list ( struct ifconf *ifc )
{
	int temp_sockfd;

	char *buf;
	int size;
	const int inc_step = 5;
	int count = inc_step;

	if ( ifc == NULL )
	{
		return -1;
	}

	temp_sockfd = socket ( AF_INET, SOCK_DGRAM, 0 );
	if ( temp_sockfd < 0 )
	{
		msg_log ( LEVEL_ERR, "%s: socket error, %s\n", __func__,
				  strerror ( errno) );
		return -1;
	}

	for ( ;; )
	{
		buf = (char *) calloc ( count, sizeof(struct ifreq) );

		if ( buf == NULL )
		{
			msg_log ( LEVEL_ERR, "%s: out of memory\n", __func__ );
			close ( temp_sockfd );
			return -1;
		}

		size = count * sizeof(struct ifreq);
		ifc->ifc_len = size;
		ifc->ifc_buf = buf;

		/* get interface list */
		if ( ioctl ( temp_sockfd, SIOCGIFCONF, ifc ) != 0 )
		{
			if ( errno != EINVAL )
			{
				msg_log ( LEVEL_ERR, "%s: ioctl fail, %s\n", __func__,
						  strerror ( errno) );
				free ( buf );
				buf = NULL;
				close ( temp_sockfd );
				return -1;
			}
			else
			{
				free ( buf );
				buf = NULL;
				count += inc_step;
				continue;
			}
		}

		/*
		 * if giving memory is enough,
		 * then ifc.ifc_len should <= giving size.
		 * but in order to ensure all interfaces fetched,
		 * if ifc.ifc_len should == giving size,
		 * try again with a larger memory
		 */
		if ( ifc->ifc_len < size )
		{
			break;
		}

		free ( buf );
		buf = NULL;
		count += inc_step;
	}

	close ( temp_sockfd );
	return 0;
}

void destroy_interface_list ( struct ifconf *ifc )
{
	if ( ifc == NULL )
	{
		return;
	}

	if ( ifc->ifc_buf )
	{
		free ( ifc->ifc_buf );
		ifc->ifc_buf = NULL;
	}
}

/*
 * Based on user specialled original interface name or its ip,
 * get the systen-sandard interface name and store it in fixed_buffer.
 * If original interface name is null, then random get one.
 */
int get_interface_name ( const char *ori_name, if_desc *o_if_info )
{
	int temp_sockfd;
	int wildcard;
	if_desc *if_info;
	struct ifconf ifc;
	struct ifreq *ifr, ifr_test;
	struct in_addr addr;

	/*
	 * Condition flag
	 * AF_UNSPEC for invalid string, AF_INET for ipv4
	 */
	int ip_string_type;
	/* if has finished */
	//int finished = 0;
	if ( o_if_info == NULL )
	{
		return -1;
	}

	if_info = o_if_info;

	/* ori_name is a valid ipv4 format string  */
	if ( ori_name != NULL && inet_pton ( AF_INET, ori_name, &addr ) == 1 )
	{
		ip_string_type = AF_INET;
	}
	else
	{
		ip_string_type = AF_UNSPEC;
	}

	wildcard = is_wildcard_str ( ori_name );

	/* fetch system interface list */
	if ( get_interface_list ( &ifc ) == -1 )
	{
		return -1;
	}

	temp_sockfd = socket ( AF_INET, SOCK_DGRAM, 0 );
	if ( temp_sockfd < 0 )
	{
		msg_log ( LEVEL_ERR, "%s: socket error, %s\n", __func__,
				  strerror ( errno) );
		destroy_interface_list ( &ifc );
		return -1;
	}

	/*
	 * always think that first node given is available
	 *
	 if (wildcard)
	 {
	 if_info = malloc(sizeof(if_desc));

	 if (if_info == NULL )
	 {
	 msg_log(LEVEL_ERR,
	 "%s, create new interface fail, out of memory!\n",
	 __func__);
	 destroy_interface_list(&ifc);
	 close(temp_sockfd);
	 return -1;
	 }

	 copy_if_info( if_info, o_if_info);
	 list_set_sys( &if_info->connector);
	 list_set_unused( &if_info->connector);
	 insert_list( &o_if_info->connector, &if_info->connector);
	 }
	 else
	 {
	 if_info = o_if_info;
	 }
	 */

	/* reset current avaiable node */
	list_set_unused( &if_info->connector );

	for ( ifr = (struct ifreq *) ifc.ifc_buf;
			(char *) ifr < ifc.ifc_buf + ifc.ifc_len; ifr++ )
	{
		//if (wildcard && finished == 2)
		//{
		//	finished = 3;
		//}

		/* check socket family */
		/*
		 if (if_info->family != AF_UNSPEC
		 && if_info->family != ifr->ifr_addr.sa_family)
		 {
		 continue;
		 }
		 */
		if ( ifr->ifr_addr.sa_family != AF_INET )
		{
			continue;
		}

		/* if ori_name not null, check it */
		if ( ori_name != NULL )
		{
			if ( wildcard )
			{
				if ( fit_case_wildcard ( ori_name, ifr->ifr_name ) != 1 )
				{
					continue;
				}
			}
			else
			{
				if ( strcasecmp ( ori_name, ifr->ifr_name ) != 0 )
				{
					continue;
				}
			}
		}

		/* if ori_name is a valid ip string, chenk addr */
		if ( ip_string_type != AF_UNSPEC )
		{
			if ( ip_string_type == AF_INET )
			{
				if ( memcmp (
						&addr,
						&((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr,
						sizeof(struct in_addr) )
					 != 0 )
				{
					continue;
				}
			}
		}

		ifr_test = *ifr;

		/* fetch flags */
		if ( ioctl ( temp_sockfd, SIOCGIFFLAGS, &ifr_test ) != 0 )
		{
			msg_log ( LEVEL_ERR, "%s: ioctl error, %s\n", __func__,
					  strerror ( errno) );
			//break;
			/* whether is it a system-related problem or just interface-related problem ? */
			/* quit or just try another interface ? */
			continue;
		}

		/* not up */
		if ( (ifr_test.ifr_flags & IFF_UP) == 0 )
		{
			if ( ip_string_type != AF_UNSPEC )
			{
				msg_log ( LEVEL_ERR, "%s: specialled interface %s(%s) not up\n",
						  __func__, ifr->ifr_name, ori_name );
				break;
			}
			else if ( ori_name != NULL && *ori_name != '\0' && !wildcard )
			{
				msg_log ( LEVEL_ERR, "%s: specialled interface %s not up\n",
						  __func__, ori_name );
				break;
			}
			else
			{
				continue;
			}
		}

		/* is a loopback if */
		if ( ifr_test.ifr_flags & IFF_LOOPBACK )
		{
			if ( ip_string_type != AF_UNSPEC )
			{
				msg_log (
						LEVEL_ERR,
						"%s: specialled interface %s(%s) is a loopback device\n",
						__func__, ifr->ifr_name, ori_name );
				break;
			}
			else if ( ori_name != NULL && *ori_name != '\0' && !wildcard )
			{
				msg_log ( LEVEL_ERR,
						  "%s: specialled interface %s is a loopback device\n",
						  __func__, ori_name );
				break;
			}
			else
			{
				continue;
			}
		}

		if_info->if_flags = ifr_test.ifr_flags;

		ifr_test = *ifr;

		/* fetch index */
		if ( ioctl ( temp_sockfd, SIOCGIFINDEX, &ifr_test ) != 0 )
		{
			msg_log ( LEVEL_ERR, "%s: ioctl error, %s\n", __func__,
					  strerror ( errno) );
			//break;
			/* whether is it a system-related problem or just interface-related problem ? */
			/* quit or just try another interface ? */
			continue;
		}

		if_info->index = ifr_test.ifr_ifindex;

		ifr_test = *ifr;

		/* fetch MAC */
		if ( ioctl ( temp_sockfd, SIOCGIFHWADDR, &ifr_test ) != 0 )
		{
			msg_log ( LEVEL_ERR, "%s: ioctl error, %s\n", __func__,
					  strerror ( errno) );
			//break;
			/* whether is it a system-related problem or just interface-related problem ? */
			/* quit or just try another interface ? */
			continue;
		}
		/* todo, the mac length */
		if_info->hw_len = ETH_ADDR_LEN;
		memcpy ( if_info->hw_addr, ifr_test.ifr_hwaddr.sa_data, ETH_ADDR_LEN );

		ifr_test = *ifr;

		/* fetch broadcast address */
		if ( ioctl ( temp_sockfd, SIOCGIFBRDADDR, &ifr_test ) != 0 )
		{
			msg_log ( LEVEL_ERR, "%s: ioctl error, %s\n", __func__,
					  strerror ( errno) );
			//break;
			/* whether is it a system-related problem or just interface-related problem ? */
			/* quit or just try another interface ? */
			continue;
		}
		memcpy ( if_info->bc_ip_addr_bin,
				 &((struct sockaddr_in *) &ifr_test.ifr_broadaddr)->sin_addr,
				 IPV4_BIN_ADDR_LEN);
		if ( inet_ntop ( AF_INET, if_info->bc_ip_addr_bin, if_info->bc_ip_addr,
						 MAX_IP_ADDR_LEN )
			 == NULL )
		{
			msg_log ( LEVEL_ERR, "%s: inet_ntop error, %s\n", __func__,
					  strerror ( errno) );
			continue;
		}

		/* set info */
		strncpy ( if_info->if_name, ifr->ifr_name, sizeof(if_info->if_name) );

		if ( ifr->ifr_addr.sa_family == AF_INET )
		{
			memcpy ( if_info->ip_addr_bin,
					 &((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr,
					 sizeof(struct in_addr) );
		}
		else
		{
			msg_log ( LEVEL_ERR, "%s: get unsupport socket family addr\n",
					  __func__ );
			if ( wildcard )
			{
				continue;
			}
			else
			{
				break;
			}
		}

		if ( ip_string_type != AF_UNSPEC )
		{
			strncpy ( if_info->ip_addr, ori_name, sizeof(if_info->ip_addr) );
		}
		else
		{
			if ( inet_ntop ( ifr->ifr_addr.sa_family, if_info->ip_addr_bin,
							 if_info->ip_addr, sizeof(if_info->ip_addr) )
				 == NULL )
			{
				msg_log ( LEVEL_ERR, "%s: inet_ntop error, %s\n", __func__,
						  strerror ( errno) );
				break;
			}
		}

		/*
		 if (ori_name == NULL )
		 {
		 msg_log(LEVEL_INFO, "%s: default to use interface \"%s\"\n\n",
		 __func__, if_info->if_name);
		 }
		 else
		 {
		 msg_log(LEVEL_INFO, "%s: prepare to use interface \"%s\"\n\n",
		 __func__, if_info->if_name);
		 }
		 */

		list_set_used( &if_info->connector );

		if ( wildcard )
		{
			if_desc *new_if = malloc ( sizeof(if_desc) );

			if ( new_if == NULL )
			{
				msg_log ( LEVEL_ERR,
						  "%s, create new interface fail, out of memory!\n",
						  __func__ );
				//finished = 4;
				break;
			}

			copy_if_info( new_if, if_info );
			list_set_unused( &new_if->connector );
			list_set_sys( &new_if->connector );
			insert_list_nonptr( if_info->connector, new_if->connector );
			if_info = new_if;

			continue;
		}

		break;
	}

	destroy_interface_list ( &ifc );
	close ( temp_sockfd );

	/* no interface found, print some info */
	if ( list_is_unused(&o_if_info->connector))
	{
		if ( wildcard || ori_name == NULL )
		{
			msg_log ( LEVEL_ERR, "%s: no proper interface found!\n", __func__ );
		}
		else
		{
			msg_log ( LEVEL_ERR, "%s: no interface(\"%s\") found!\n", __func__,
					  ori_name );
		}

		return -1;
	}

	if ( list_is_unused(&if_info->connector))
	{
		delete_same_list( &if_info->connector );
		free ( if_info );
	}

	/*	if (finished == 0)
	 {

	 * below condition goes here:
	 * 	1. not wildcard, not find any proper interface
	 * 	2. wildcard, first round fail find any proper interface


	 if (wildcard)
	 {
	 free(if_info);
	 init_list( &o_if_info->connector);
	 //if_info = o_if_info;
	 }

	 if ((char *) ifr >= ifc.ifc_buf + ifc.ifc_len)
	 {
	 if (ori_name == NULL )
	 {
	 msg_log(LEVEL_ERR, "%s: no proper interface found!\n",
	 __func__);
	 }
	 else
	 {
	 msg_log(LEVEL_ERR, "%s: no interface(\"%s\") found!\n",
	 __func__, ori_name);
	 }
	 return -1;
	 }
	 else
	 {
	 return -1;
	 }
	 }
	 else if (finished == 2 || finished == 3)
	 {
	 below condition goes here:
	 * 	1. wildcard, after some success search rounds,
	 * 	   and new if_info created,
	 * 	   but break cause 'for' contidion ( finished == 2 )
	 *	2. wildcard, after some success search rounds,
	 *	   but error break in a round ( finished == 3 )


	 if_desc *ptr = prev_container(&if_info->connector, connector, if_desc);

	 copy_if_info( o_if_info, ptr);
	 delete_same_list( &ptr->connector);
	 free(ptr);
	 free(if_info);
	 }
	 else if (finished == 4)
	 {
	 below condition goes here:
	 * 	1. wildcard, after some success search rounds,
	 * 	    but fail to create new in_info


	 copy_if_info( o_if_info, if_info);
	 delete_same_list( &if_info->connector);
	 free(if_info);
	 }*/

	return 0;
}

int exist_interface ( const if_desc *if_list, const char *name )
{
	if ( if_list == NULL || name == NULL )
	{
		return 0;
	}

	foreach_list( if_list, &if_list->connector, connector, const if_desc )
	{
		if ( list_is_used(&if_list->connector))
		{
			if ( if_list->if_name && strcmp ( if_list->if_name, name ) == 0 )
			{
				return 1;
			}
		}
	}

	return 0;
}
