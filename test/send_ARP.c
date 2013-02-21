/*
 * send_ARP.c
 * send a arp reply packet to a target host
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 *
 * args:
	"request		send a request APR other than reply
	"pad			pad for eth
	"count		send times
	"interval		send interval
	"interface	outgoing interface
	"fromhw		source mac addr in eth
	"tohw			dest mac addr in eth
 * 	--senderip		sender ip address
 * 	--senderhw		sender hardware address
 * 	--recvip		receiver ip address
 * 	--recvhw		receiver hardware address
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <arp/arp.h>

void usage ();

int main ( int argc, char *argv[] )
{
	int ret;

	long count = 1;
	long interval = 1;
	int reply_type = 1;
	unsigned char to_pad = 0;

	void *fromhw = NULL;
	void *tohw = NULL;
	void *senderip = NULL;
	void *senderhw = NULL;
	void *recvip = NULL;
	void *recvhw = NULL;

	char *interface = NULL;

	if_desc if_info;
	dynamic_arp_packet arp_packet;

	const char short_opt[] = ":i:I:f:t:s:S:r:R:Qhpc:";
	struct option long_opt[] =
	{
	{ "interface", 1, NULL, 'I' },
	  { "fromhw", 1, NULL, 'f' },
	  { "tohw", 1, NULL, 't' },
	  { "senderip", 1, NULL, 's' },
	  { "count", 1, NULL, 'c' },
	  { "senderhw", 1, NULL, 'S' },
	  { "interval", 1, NULL, 'i' },
	  { "recvip", 1, NULL, 'r' },
	  { "recvhw", 1, NULL, 'R' },
	  { "request", 0, NULL, 'Q' },
	  { "pad", 0, NULL, 'p' },
	  { "help", 0, NULL, 'h' },
	  { NULL, 0, NULL, 0 } };

	/* analyse optarg here */
	while ( (ret = getopt_long ( argc, argv, short_opt, long_opt, NULL )) > 0 )
	{
		switch ( ret )
		{

			case 'i':
			{
				ret = str2long ( optarg, &interval, 10 );
				if ( ret == -1 || interval < 0 )
				{
					fprintf ( stderr, "invalid interval value \'%s\'\n",
							  argv[optind - 1] );
					return -1;
				}

				if ( interval == 0 )
				{
					/* give some warnning or confirm to FLOOD-SEND-ARP*/
					char buf[4];

					fprintf ( stderr, "You are going to do flood-arp send"
							  "\nInput \"Yes\" to continue: " );

					if ( fgets ( buf, 3, stdin ) == NULL )
					{
						exit ( 1 );
					}

					buf[3] = '\0';

					if ( strcmp ( buf, "Yes" ) != 0 )
					{
						exit ( 0 );
					}
					else
					{
						fputc ( '\n', stdout );
					}
				}
			}
			break;

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

			case 'c':
			{
				ret = str2long ( optarg, &count, 10 );
				if ( ret == -1 )
				{
					fprintf ( stderr, "invalid value for \'%s\'\n",
							  argv[optind - 1] );
					return -1;
				}
			}
			break;

			case 'f':
			{
				fromhw = optarg;
			}
			break;

			case 't':
			{
				tohw = optarg;
			}
			break;

			case 's':
			{
				senderip = optarg;
			}
			break;

			case 'S':
			{
				senderhw = optarg;
			}
			break;

			case 'r':
			{
				recvip = optarg;
			}
			break;

			case 'R':
			{
				recvhw = optarg;
			}
			break;

			case 'Q':
			{
				reply_type = 0;
			}
			break;

			case 'p':
			{
				to_pad = D_SEND_PAD;
			}
			break;

			case 'h':
			{
				usage ();
				exit ( 0 );
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

	init_if_desc( &if_info );

	ret = open_arp_interface ( interface, &if_info );
	if ( ret == -1 )
	{
		exit ( 1 );
	}

	init_dynamic_arp_packet( &arp_packet );

	/* send forever when count < 0 */
	while ( count < 0 || count-- != 0 )
	{
		ret = build_dynamic_arp ( &arp_packet, &if_info, reply_type, fromhw,
								  tohw, senderip, senderhw, recvip, recvhw );
		if ( ret != 0 )
		{
			close_arp_interface ( &if_info );
			exit ( 1 );
		}

		if ( send_dynamic_arp ( &if_info, &arp_packet, to_pad ) != 0 )
		{
			close_arp_interface ( &if_info );
			free_dynamic_arp ( &arp_packet );
			exit ( 1 );
		}

		reset_dynamic_arp ( &arp_packet );

		if ( interval != 0 && count != 0 )
		{
			sleep ( interval );
		}
	}

	close_arp_interface ( &if_info );
	free_dynamic_arp ( &arp_packet );
	exit ( 0 );
}

void usage ()
{
	const char *info = 
	"\n"
	"args:\n"
	"request		send a request APR other than reply\n"
	"pad		pad for eth\n"
	"count		send times\n"
	"interval	send interval\n"
	"interface	outgoing interface\n"
	"fromhw		source mac addr in eth\n"
	"tohw		dest mac addr in eth\n"
	"senderip	sender ip address\n"
	"senderhw	sender hardware address\n"
	"recvip		receiver ip address\n"
	"recvhw		receiver hardware address\n";

	fprintf ( stdout, "%s\n", info );
}

