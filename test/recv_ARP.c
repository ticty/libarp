/*
 * recv_ARP.c
 * receive ARP packet and extract it
 *
 *  Created on: 2012-9-10
	"  Author: guofeng
 *
 *  args:
	"interface/-I	interface to use, the name or ip address
	"timeout/-t		set deadline, example 10s, 5m, 1h; 0 means forever
	"promisc/-p		set the interface in promisc mode
	"help/-h			get help infomation
 */

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <arp/arp.h>

void usage ();
time_t str2time ( char *str );

int main ( int argc, char *argv[] )
{
	int ret;
	time_t deadline = -1;
	char *interface = NULL;

	if_desc if_info;
	dynamic_arp_packet arp_packet;

	const char short_opt[] = ":I:t:hp";
	struct option long_opt[] =
	{
	{ "interface", 1, NULL, 'I' },
	  { "timeout", 1, NULL, 't' },
	  { "promisc", 0, NULL, 'p' },
	  { "help", 0, NULL, 'h' },
	  { NULL, 0, NULL, 0 } };

	init_if_desc( &if_info );
	init_dynamic_arp_packet( &arp_packet );

	/* analyse optarg here */
	while ( (ret = getopt_long ( argc, argv, short_opt, long_opt, NULL )) > 0 )
	{
		switch ( ret )
		{
			case 'I':
			{
				if ( interface != NULL )
				{
					fprintf (
							stderr,
							"please special interface in one single string\n" );
					return -1;
				}

				interface = optarg;
			}
			break;

			case 't':
			{
				deadline = str2time ( optarg );
				if ( deadline < 0 )
				{
					fprintf ( stderr, "err value for option \'%s\'",
							  argv[optind - 1] );
					exit ( 1 );
				}
			}
			break;

			case 'h':
			{
				usage ();
				exit ( 0 );
			}
			break;

			case 'p':
			{
				if_info.request_flags |= IFF_PROMISC;
			}
			break;

			case ':':
			{
				fprintf ( stderr, "missing arg for option \'%s\'\n",
						  argv[optind - 1] );
				exit ( 1 );
			}
			break;

			case '?':
			{
				fprintf ( stderr, "unknown option \'%s\'\n", argv[optind - 1] );
				exit ( 1 );
			}
			break;

			default:
			{
				fprintf ( stderr, "unknown error with option \'%s\'\n",
						  argv[optind - 1] );
				exit ( 1 );
			}

		}
	}

	ret = open_arp_interface ( interface, &if_info );
	if ( ret < 0 )
	{
		exit ( 1 );
	}

	while ( (ret = listen_arp_interface ( &if_info, &arp_packet, deadline )) > 0 )
	{
		print_arp ( &arp_packet );
		reset_dynamic_arp ( &arp_packet );
	}

	close_arp_interface ( &if_info );
	exit ( 0 );
}


time_t str2time ( char *str )
{
	time_t timeout;
	long len;
	int unit;

	if ( str == NULL || (len = strlen ( str )) == 0 )
	{
		return -1;
	}

	unit = *(str + len - 1);

	switch ( unit )
	{

		case 's':
		case 'S':
		{
			unit = 1;
			*(str + len - 1) = '\0';
		}
		break;

		case 'm':
		case 'M':
		{
			unit = 60;
			*(str + len - 1) = '\0';
		}
		break;

		case 'h':
		case 'H':
		{
			unit = 3600;
			*(str + len - 1) = '\0';
		}
		break;

		default:
		{
			if ( unit >= '0' && unit <= '9' )
			{
				unit = 1;
			}
			else
			{
				return -1;
			}
		}
		break;

	}

	/* here not check the valid format of the string */
	len = atol ( str );
	timeout = len * unit;

	return timeout;
}



void usage ()
{
	const char *info = 
	"\n"
	"args:\n"
	"interface/-I	interface to use, the name or ip address\n"
	"timeout/-t		set deadline, example 10s, 5m, 1h; 0 means forever\n"
	"promisc/-p		set the interface in promisc mode\n"
	"help/-h			get help infomation\n";
	
	fprintf ( stdout, "%s\n", info );
}


