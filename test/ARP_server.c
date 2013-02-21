/*
 * send_ARP.c
 * receive ARP and update or reply 
 * base on known arp map( can import from file and system ARP table)
 *
 *  Created on: 2012-9-10
	"  Author: guofeng
 *
 *  args:
	"--interface/-I	interface to use, the name or ip address
	"--file/-f		import arp initial table from file
	"--kernel/-k		import arp table from system kernel arp table
	"--update/-u		update the arp table while recv a arp reply
	"--nomodify/-n	when update, only add new and never modify olds
	"--ignreply/-R	not update arp via reply"
	"--add/-a		add a arp entry from cmdline ( not support yet )
	"--promisc/-p	set the interface in promisc mode
	"--senderip/-s		sender ip address	(( not support any more ))
	"--senderhw/-S		sender hardware address
	"--quiet/-q		do not print some message
	"--help/-h		get help infomation
 *
 */

#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <arp/arp.h>
#include <arp/list.h>

#define SYS_ARP_FILE "/proc/net/arp"
#define DFL_COMMENT_CHAR	'#'
#define ARP_GLOBLE_IF	"*"

typedef struct
{
	struct list connector;
	struct list if_connector; /* for interface index */

	unsigned char ip[sizeof(struct in_addr)];
	unsigned char hw[ETH_ADDR_LEN];
	char *dev;

} arp_entry;

/* init */
#define init_arp_entry( ptr ) do{ \
	memset( ptr, 0, sizeof(arp_entry) ); \
	}while(0)

typedef struct
{
	struct list connector; /* for 'arp_table_if_index' self */
	struct list *entry; /* for entries belong to it */

	char *dev;
} arp_table_if_index;

/* init */
#define init_arp_table_if_index( ptr ) do{ \
	memset( ptr, 0, sizeof(arp_table_if_index) ); \
	}while(0)

if_desc if_list;
arp_entry arp_table;
arp_table_if_index arp_if_index;
dynamic_arp_packet arp_packet;

/* AF_INET addr is acceptable */
//struct in_addr *senderip;
unsigned char *senderhw; /* ETH_ADDR_LEN */

int update;
int nomodify;
int ignreply;
int quiet;

static int init ( int, char ** );

static int add_arp_entry ( const char *, const char *, const char * );
static int add_arp_entry_bin ( const void *, const void *, const char * );

int import_sys_arp ();
int import_file_arp ( const char * );

int do_reply_arp ( const dynamic_arp_packet * );
int do_update_arp ( const dynamic_arp_packet * );
int packet_fatory ( const dynamic_arp_packet * );

arp_table_if_index *add_arp_if_index ( const char * );

void show_arp_table ();

void set_signal_handler ();
void set_exit_handler ();

void signal_hadler ( int );

void destroy_if_index ();
void destroy_arp_entry ();

char *ip2str ( const void * );
char *hw2str ( const void * );
void usage ();
void quit ();

int main ( int argc, char *argv[] )
{
	int ret;

	if ( init ( argc, argv ) == -1 )
	{
		exit ( 1 );
	}

	while ( (ret = listen_arp_interface ( &if_list, &arp_packet, -1 )) > 0 )
	{
		packet_fatory ( &arp_packet );
		reset_dynamic_arp ( &arp_packet );
	}

	return 0;
}

static int init ( int argc, char *argv[] )
{
	int ret;

	int import_sys = 0;
	char *interface = NULL;
	char *arp_file = NULL;
	unsigned char hw_buf[ETH_ADDR_LEN];

	const char short_opt[] = ":I:f:phS:Runkq";
	struct option long_opt[] =
	{
	{ "interface", 1, NULL, 'I' },
	  { "file", 1, NULL, 'f' },
	  { "promisc", 0, NULL, 'p' },
	  { "system", 0, NULL, 'k' },
	  { "update", 0, NULL, 'u' },
	  { "senderhw", 1, NULL, 'S' },
	  { "nomodify", 0, NULL, 'n' },
	  { "ignreply", 0, NULL, 'R' },
	  { "quiet", 0, NULL, 'q' },
	  { "help", 0, NULL, 'h' },
	  { NULL, 0, NULL, 0 } };

	update = 0;
	nomodify = 0;
	ignreply = 0;
	quiet = 0;
	senderhw = NULL;

	init_if_desc( &if_list );
	init_arp_entry( &arp_table );
	init_dynamic_arp_packet( &arp_packet );
	init_arp_table_if_index( &arp_if_index );

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

			case 'f':
			{
				if ( arp_file != NULL )
				{
					fprintf (
							stderr,
							"please special import files in one single string\n" );
					return -1;
				}

				arp_file = optarg;
			}
			break;

			case 'p':
			{
				if_list.request_flags |= IFF_PROMISC;
			}
			break;

			case 'S':
			{
				if ( senderhw != NULL )
				{
					fprintf ( stderr, "you can only special senderhw once!\n" );
					return -1;
				}

				if ( str2mac ( optarg, hw_buf, ETH_ADDR_LEN ) != ETH_ADDR_LEN )
				{
					fprintf ( stderr, "wrong senderhw string!\n" );
					return -1;
				}

				senderhw = hw_buf;
			}
			break;

			case 'k':
			{
				import_sys = 1;
			}
			break;

			case 'u':
			{
				update = 1;
			}
			break;

			case 'n':
			{
				nomodify = 1;
			}
			break;
			
			case 'R':
			{
				ignreply = 1;
			}
			break;

			case 'h':
			{
				usage ();
				exit ( 0 );
			}
			break;

			case 'q':
			{
				quiet = 1;
			}
			break;

			case ':':
			{
				fprintf ( stderr, "missing arg for option \'%s\'\n",
						  argv[optind - 1] );
				return -1;
			}
			break;

			case '?':
			{
				fprintf ( stderr, "unknown option \'%s\'\n", argv[optind - 1] );
				return -1;
			}
			break;

			default:
			{
				fprintf ( stderr, "unknown error with option \'%s\'\n",
						  argv[optind - 1] );
				return -1;
			}
			break;
		}
	}

	set_signal_handler ();
	set_exit_handler ();

	if ( senderhw != NULL )
	{
		void *ptr = malloc ( ETH_ADDR_LEN );
		if ( ptr == NULL )
		{
			return -1;
		}

		memcpy ( ptr, senderhw, ETH_ADDR_LEN );
		senderhw = ptr;
	}

	/* open arp interface */
	ret = open_arp_interface ( interface, &if_list );
	if ( ret < 0 )
	{
		return -1;
	}

	/* initial arp map */
	if ( import_sys != 0 )
	{
		import_sys_arp ();
	}

	if ( arp_file != NULL )
	{
		import_file_arp ( arp_file );
	}

	/**/
	if ( update == 0 && list_is_unused(&arp_table.connector))
	{
		fprintf ( stderr, "no arp entry found, and would not update!\n" );
		return -1;
	}

	return 0;
}

static int add_arp_entry ( const char *ip, const char *hw, const char *dev )
{
	arp_entry *entry;
	arp_table_if_index *index_ptr;
	unsigned char hw_buf[ETH_ADDR_LEN];
	unsigned char ip_buf[sizeof(struct in_addr)];

	if ( ip == NULL || hw == NULL )
	{
		return -1;
	}

	if ( dev == NULL )
	{
		dev = ARP_GLOBLE_IF;
	}

	/* mac format check */
	if ( str2mac ( hw, hw_buf, ETH_ADDR_LEN ) != ETH_ADDR_LEN )
	{
		return -1;
	}

	/* ip format check */
	if ( inet_pton ( AF_INET, ip, ip_buf ) != 1 )
	{
		return -1;
	}

	/* unique check */foreach_list( index_ptr, &arp_if_index.connector, connector, arp_table_if_index )
	{
		if ( list_is_used( &index_ptr->connector ) && strcmp (
															   index_ptr->dev,
															   dev )
														  == 0 )
		{
			foreach_list( entry, index_ptr->entry, if_connector, arp_entry )
			{
				if ( list_is_used(&entry->connector) && memcmp (
						entry->ip, ip_buf, sizeof(struct in_addr) )
														== 0 )
				{
					/* found a prev added entry, anyway, update it if needed */
					if ( memcmp ( entry->hw, hw_buf, ETH_ADDR_LEN ) != 0 )
					{
						memcpy ( entry->hw, hw_buf, ETH_ADDR_LEN );
					}

					return 0;
				}
			}
		}
	}

	if ( index_ptr == NULL )
	{
		index_ptr = add_arp_if_index ( dev );
		if ( index_ptr == NULL )
		{
			fprintf ( stderr, "%s: not found \"%s\" group\n", __func__, dev );
			return -1;
		}
	}

	if ( list_is_used( &arp_table.connector ))
	{
		entry = malloc ( sizeof(arp_entry) );
		if ( entry == NULL )
		{
			return -1;
		}

		init_arp_entry( entry );
		memcpy ( entry->ip, ip_buf, sizeof(struct in_addr) );
		memcpy ( entry->hw, hw_buf, ETH_ADDR_LEN );

		entry->dev = strdup ( dev );
		if ( entry->dev == NULL )
		{
			free ( entry );
			return -1;
		}

		list_set_sys( &entry->connector );
		list_set_used( &entry->connector );
		insert_list_nonptr( arp_table.connector, entry->connector );
		insert_list( index_ptr->entry, &entry->if_connector );
	}
	else
	{
		memcpy ( arp_table.ip, ip_buf, sizeof(struct in_addr) );
		memcpy ( arp_table.hw, hw_buf, ETH_ADDR_LEN );

		arp_table.dev = strdup ( dev );
		if ( arp_table.dev == NULL )
		{
			return -1;
		}

		list_set_used( &arp_table.connector );
		insert_list( index_ptr->entry, &arp_table.if_connector );
	}

	if ( !quiet )
	{
		fprintf ( stdout, "\n%s: add %-16s%-16s  %s\n", __func__, ip, hw, dev );
	}

	return 0;
}

static int add_arp_entry_bin ( const void *ip, const void *hw, const char *dev )
{
	arp_entry *entry;
	arp_table_if_index *index_ptr;

	if ( ip == NULL || hw == NULL )
	{
		return -1;
	}

	if ( dev == NULL )
	{
		dev = ARP_GLOBLE_IF;
	}

	/* index ptr search */foreach_list( index_ptr, &arp_if_index.connector, connector, arp_table_if_index )
	{
		if ( list_is_used( &index_ptr->connector ) && (strcmp ( index_ptr->dev,
																ARP_GLOBLE_IF )
													   || strcmp (
															   index_ptr->dev,
															   dev )
														  == 0) )
		{
			foreach_list( entry, index_ptr->entry, if_connector, arp_entry )
			{
				if ( list_is_used(&entry->connector) && memcmp (
						entry->ip, ip, sizeof(struct in_addr) )
														== 0 )
				{
					if ( memcmp ( entry->hw, hw, ETH_ADDR_LEN ) != 0 )
					{
						memcpy ( entry->hw, hw, ETH_ADDR_LEN );
					}

					return 0;
				}
			}
		}
	}

	if ( index_ptr == NULL )
	{
		index_ptr = add_arp_if_index ( dev );

		if ( index_ptr == NULL )
		{
			fprintf ( stderr, "%s: not found \"%s\" group\n", __func__, dev );
			return -1;
		}
	}

	if ( list_is_used( &arp_table.connector ))
	{
		entry = malloc ( sizeof(arp_entry) );
		if ( entry == NULL )
		{
			return -1;
		}

		init_arp_entry( entry );
		memcpy ( entry->ip, ip, sizeof(struct in_addr) );
		memcpy ( entry->hw, hw, ETH_ADDR_LEN );

		entry->dev = strdup ( dev );
		if ( entry->dev == NULL )
		{
			free ( entry );
			return -1;
		}

		list_set_sys( &entry->connector );
		list_set_used( &entry->connector );
		insert_list_nonptr( arp_table.connector, entry->connector );
		insert_list( index_ptr->entry, &entry->if_connector );
	}
	else
	{
		memcpy ( arp_table.ip, ip, sizeof(struct in_addr) );
		memcpy ( arp_table.hw, hw, ETH_ADDR_LEN );

		arp_table.dev = strdup ( dev );
		if ( arp_table.dev == NULL )
		{
			return -1;
		}

		list_set_used( &arp_table.connector );
		insert_list( index_ptr->entry, &arp_table.if_connector );
	}

	if ( !quiet )
	{
		fprintf ( stdout, "\n%s: add    %-16s%-16s  %s\n", __func__,
				  ip2str ( ip ), hw2str ( hw ), dev );
	}

	return 0;
}

int import_sys_arp ()
{
	int ret;
	FILE *fp;
	char ip[20], hw[20], dev[20];
	char flags_str[10];
	long flags;

	fp = fopen ( SYS_ARP_FILE, "r" );
	if ( fp == NULL )
	{
		fprintf ( stderr, "%s(%s): %s\n", __func__, SYS_ARP_FILE,
				  strerror ( errno) );
		return -1;
	}

	ret = fs_next_line ( fp );

	if ( ret == -1 )
	{
		/* read error */
		return -1;
	}
	else if ( ret == 1 )
	{
		/* file end */
		return 0;
	}

	while ( (ret = fscanf ( fp, "%s%*s%s%s%*s%s", ip, flags_str, hw, dev )) == 4 )
	{
		if ( str2long ( flags_str, &flags, 16 ) != -1 && flags != 0 )
		{
			add_arp_entry ( ip, hw, dev );
		}
	}

	fclose ( fp );

	return 0;
}

int import_file_arp ( const char *file )
{
	int ret;
	FILE *fp;
	char *begin, *end;
	char *ptr1, *ptr2;
	char buf[1024];
	int linenumber = 0;
	char ip[20], hw[20], dev[20];

	if ( file == NULL )
	{
		return -1;
	}

	fp = fopen ( file, "r" );
	if ( fp == NULL )
	{
		fprintf ( stderr, "%s(%s): %s\n", __func__, SYS_ARP_FILE,
				  strerror ( errno) );
		return -1;
	}

	/*
	 * Micro DFL_COMMENT_CHAR defines comment char
	 * a comment char is effective only if the char before is a blank ' ',
	 * or it is the first readable char of a line
	 * string after a comment char in same line is consider as comments
	 * to use the char itself after a blank ' ', please use '\' before it
	 */
	while ( feof ( fp ) == 0 )
	{
		if ( fgets ( buf, sizeof(buf), fp ) == NULL )
		{
			break;
		}

		linenumber++;
		begin = buf;

		/*
		 * char little than 32 in ASCII is non-readable
		 * char 32 of ACCII is ' '
		 * below is to trim begin non-readable char
		 */
		while ( *begin && *begin <= 32 )
		{
			begin++;
		}

		/* to find comment */
		for ( end = begin;; )
		{
			end = strchr ( end, DFL_COMMENT_CHAR );

			/* no comment char */
			if ( end == NULL )
			{
				break;
			}
			/* first readable char is comment char, ignore this line */
			else if ( end == begin )
			{
				/* to continue next line */
				*begin = '\0';
				break;
			}
			/* find a effecial comment char */
			else if ( *(end - 1) == ' ' )
			{
				*--end = '\0';
				break;
			}
		}

		if ( *begin == '\0' )
		{
			continue;
		}

		if ( end == NULL )
		{
			end = begin + strlen ( begin );
		}

		/* below is to trim end non-readable char */
		while ( end > begin && *end <= 32 )
		{
			end--;
		}

		if ( *end != '\0' )
		{
			*++end = '\0';
		}

		/*
		 * if exist "\DFL_COMMENT_CHAR" string,
		 * replace it with a single DFL_COMMENT_CHAR
		 */
		/* should this step put behind ? */
		for ( ptr1 = end - 1; ptr1 > begin; ptr1-- )
		{
			if ( *ptr1 == DFL_COMMENT_CHAR )
			{
				if ( *(ptr1 - 1) == '\\' )
				{
					ptr2 = ptr1;

					for ( ; ptr1 <= end; ptr1++ )
					{
						*(ptr1 - 1) = *ptr1;
					}

					end--;
					ptr1 = ptr2;
				}
			}
		}

		/* string have parse to [begin,end] */
		if ( (ret = sscanf ( begin, "%s%s%s", ip, hw, dev )) == 3 )
		{
			add_arp_entry ( ip, hw, dev );
		}
	}

	fclose ( fp );

	return 0;
}

int packet_fatory ( const dynamic_arp_packet *pkt_list )
{
	if ( pkt_list == NULL )
	{
		return -1;
	}

	foreach_list( pkt_list, &pkt_list->connector, connector, const dynamic_arp_packet )
	{
		if ( list_is_unused( &pkt_list->connector ))
		{
			continue;
		}

		if ( is_dynamic_request_arp ( pkt_list ) )
		{
			do_reply_arp ( pkt_list );

			if ( update )
			{
				do_update_arp ( pkt_list );
			}
		}
		else if ( is_dynamic_reply_arp ( pkt_list ) )
		{
			if ( update && !ignreply )
			{
				do_update_arp ( pkt_list );
			}
		}
	}

	return 0;
}

int do_reply_arp ( const dynamic_arp_packet *pkt )
{
	arp_entry *entry = NULL;
	arp_table_if_index *index_ptr;
	dynamic_arp_packet arp_packet;

	if ( pkt == NULL )
	{
		return -1;
	}

	foreach_list( index_ptr, &arp_if_index.connector, connector, arp_table_if_index )
	{
		if ( list_is_unused( &index_ptr->connector ) || (strcmp (
				index_ptr->dev, ARP_GLOBLE_IF )
														 != 0
														 && strcmp (
																 pkt->interface->if_name,
																 index_ptr->dev )
															!= 0) )
		{
			continue;
		}

		foreach_list( entry, index_ptr->entry, if_connector, arp_entry )
		{
			if ( list_is_used(&entry->connector) && memcmp (
					entry->ip, pkt->dest_protocol_addr, sizeof(struct in_addr) )
													  == 0 )
			{
				/* find */
				goto outloops;
			}
		}

		//if ( strcmp ( index_ptr->dev, ARP_GLOBLE_IF ) != 0 )
		//{
		//	break;
		//}
	}

	outloops:

	if ( index_ptr == NULL || entry == NULL )
	{
		if ( !quiet )
		{
			fprintf ( stdout, "\n%s: reply fail, arp info not found\n",
					  __func__ );
			fprintf ( stdout, "asker: %-16s%16s\n",
					  ip2str ( pkt->src_protocol_addr ),
					  hw2str ( pkt->src_hw_addr ) );
			fprintf ( stdout, "quest: %-16s\n\n",
					  ip2str ( pkt->dest_protocol_addr ) );
		}

		return -1;
	}

	init_dynamic_arp_packet( &arp_packet );

	/* data link layer */
	if ( senderhw != NULL )
	{
		dynamic_arp_set_eth_src_addr_bin ( &arp_packet, senderhw );
	}
	else
	{
		dynamic_arp_set_eth_src_addr_bin ( &arp_packet,
										   pkt->interface->hw_addr );
	}

	dynamic_arp_set_eth_dest_addr_bin ( &arp_packet, pkt->src_hw_addr );
	dynamic_arp_set_eth_pro ( &arp_packet, PROTOCOL_ARP );

	/* network layer*/
	dynamic_arp_set_hw_fmt ( &arp_packet, ETH_HW_TYPE );
	dynamic_arp_set_pro_fmt ( &arp_packet, IP_PROTOCOL_TYPE );

	dynamic_arp_set_hw_len ( &arp_packet, ETH_ADDR_LEN );
	dynamic_arp_set_pro_len ( &arp_packet, sizeof(struct in_addr) );

	dynamic_arp_set_op_code ( &arp_packet, ARP_OP_REPLY );

	dynamic_arp_set_src_hw_addr_bin ( &arp_packet, entry->hw );
	dynamic_arp_set_src_pro_addr_bin ( &arp_packet, entry->ip );
	dynamic_arp_set_dest_hw_addr_bin ( &arp_packet, pkt->src_hw_addr );
	dynamic_arp_set_dest_pro_addr_bin ( &arp_packet, pkt->src_protocol_addr );

	if ( !quiet )
	{
		fprintf ( stdout, "\n%s: reply success\n", __func__ );
		fprintf ( stdout, "asker:  %-16s%16s\n",
				  ip2str ( pkt->src_protocol_addr ),
				  hw2str ( pkt->src_hw_addr ) );
		fprintf ( stdout, "result: %-16s --> %s\n\n",
				  ip2str ( pkt->dest_protocol_addr ), hw2str( entry->hw ) );
	}

	return send_dynamic_arp ( pkt->interface, &arp_packet,
							  D_SEND_SINGLE | D_SEND_PAD );
}

int do_update_arp ( const dynamic_arp_packet *pkt )
{
	arp_entry *entry;
	arp_table_if_index *index_ptr;

	if ( pkt == NULL )
	{
		return -1;
	}

	foreach_list( index_ptr, &arp_if_index.connector, connector, arp_table_if_index )
	{
		if ( list_is_unused( &index_ptr->connector ) || (strcmp (
				index_ptr->dev, ARP_GLOBLE_IF )
														 != 0
														 && strcmp (
																 pkt->interface->if_name,
																 index_ptr->dev )
															!= 0) )
		{
			continue;
		}

		foreach_list( entry, index_ptr->entry, if_connector, arp_entry )
		{
                        if ( list_is_used(&entry->connector) && memcmp (
					entry->ip, pkt->src_protocol_addr, sizeof(struct in_addr) )
													  == 0 )
			{
				/* find */
				if ( nomodify )
				{
					return 0;
				}

				if ( memcmp ( entry->hw, pkt->src_hw_addr, ETH_ADDR_LEN ) != 0 )
				{
					if ( !quiet )
					{
						fprintf ( stdout, "\n%s: update\n", __func__ );
						fprintf ( stdout, "%s: %s --> ",
								  ip2str ( entry->ip ), hw2str ( entry->hw ) );
						fprintf( stdout, "%s\n\n", hw2str ( pkt->src_hw_addr ) );
					}

					memcpy ( entry->hw, pkt->src_hw_addr, ETH_ADDR_LEN );
				}

				return 0;
			}
		}

		//if ( strcmp ( index_ptr->dev, ARP_GLOBLE_IF ) != 0 )
		//{
		//	break;
		//}
	}

	/* not found */
	return add_arp_entry_bin ( pkt->src_protocol_addr, pkt->src_hw_addr,
							   pkt->interface->if_name );
}

arp_table_if_index *add_arp_if_index ( const char *dev )
{
	arp_table_if_index *ptr;

	if ( dev == NULL )
	{
		dev = ARP_GLOBLE_IF;
	}

	foreach_list( ptr, &arp_if_index.connector, connector, arp_table_if_index )
	{
		if ( list_is_used( &ptr->connector ) && strcmp ( dev, ptr->dev ) == 0 )
		{
			return ptr;
		}
	}

	if ( list_is_unused( &arp_if_index.connector ))
	{
		arp_if_index.dev = strdup ( dev );
		if ( arp_if_index.dev == NULL )
		{
			return NULL ;
		}

		arp_if_index.entry = NULL;
		list_set_used( &arp_if_index.connector );

		if ( !quiet )
		{
			fprintf ( stdout, "%s: add \"%s\" index group\n", __func__, dev );
		}

		return &arp_if_index;
	}
	else
	{
		ptr = malloc ( sizeof(arp_table_if_index) );
		if ( ptr == NULL )
		{
			return NULL ;
		}

		ptr->dev = strdup ( dev );
		if ( ptr->dev == NULL )
		{
			free ( ptr );
			return NULL ;
		}

		ptr->entry = NULL;
		list_set_used( &ptr->connector );
		list_set_sys( &ptr->connector );
		insert_list_nonptr( arp_if_index.connector, ptr->connector );

		if ( !quiet )
		{
			fprintf ( stdout, "\n%s: add \"%s\" index group\n\n", __func__,
					  dev );
		}

		return ptr;
	}

	return NULL ;
}

void show_arp_table ()
{
	long count = 0;
	arp_table_if_index *index_ptr;
	arp_entry *entry;

	if ( quiet )
	{
		return;
	}

	fprintf ( stdout, "\narp table:\n" );

	foreach_list( index_ptr, &arp_if_index.connector, connector, arp_table_if_index )
	{
		if ( list_is_used( &index_ptr->connector ))
		{
			foreach_list( entry, index_ptr->entry, if_connector, arp_entry )
			{
				if ( list_is_used( &entry->connector ))
				{
					fprintf ( stdout, "#%-5ld  %-16s %-17s %s\n", ++count,
							  ip2str ( entry->ip ), hw2str ( entry->hw ),
							  entry->dev );
				}
			}
		}
	}
}

void destroy_if_index ( arp_table_if_index *if_index )
{
	arp_table_if_index *ptr;

	for ( ; if_index != NULL ; )
	{
		if ( if_index->dev != NULL )
		{
			free ( if_index->dev );
		}

		if ( list_is_usr( &if_index->connector ))
		{
			if_index =
					next_container( &if_index->connector, connector, arp_table_if_index );
		}
		else
		{
			ptr = next_container( &if_index->connector, connector, arp_table_if_index );
			free ( if_index );
			if_index = ptr;
		}
	}
}

void destroy_arp_entry ( arp_entry *entry )
{
	arp_entry *ptr;

	for ( ; entry != NULL ; )
	{
		if ( entry->dev != NULL )
		{
			free ( entry->dev );
		}

		if ( list_is_usr( &entry->connector ))
		{
			entry = next_container( &entry->connector, connector, arp_entry );
		}
		else
		{
			ptr = next_container( &entry->connector, connector, arp_entry );
			free ( entry );
			entry = ptr;
		}
	}
}

void set_signal_handler ()
{
	struct sigaction sig_act;

	sig_act.sa_handler = signal_hadler;
    sig_act.sa_flags |= SA_RESTART;
    sigemptyset( &sig_act.sa_mask );

	if ( sigaction ( SIGINT, &sig_act, NULL ) == -1 
		 || sigaction ( SIGHUP, &sig_act, NULL ) == -1
		 || sigaction ( SIGQUIT, &sig_act, NULL ) == -1
		 || sigaction ( SIGTERM, &sig_act, NULL ) == -1 )
	{
		fprintf ( stderr, "%s: sigaction fail, %s\n", __func__,
				  strerror ( errno) );
		return;
	}
}

void set_exit_handler ()
{
	if ( atexit ( quit ) != 0 )
	{
		fprintf ( stderr, "%s: atexit fail\n", __func__ );
		return;
	}
}

void signal_hadler ( int signo )
{
	static int exit_count = 0;
	
	switch ( signo )
	{
		case SIGINT:
		case SIGHUP:
		case SIGTERM:
		{
			if( ++exit_count > 3 )
			{
				_Exit ( 0 );
			}
			
			exit(0);
		}
		break;
		
		case SIGSEGV:
		{
			if( ++exit_count > 3 )
			{
				_Exit ( 1 );
			}
			
			exit(1);
		}
		break;

		case SIGQUIT:
		{
			show_arp_table ();
		}
		break;

		default:
		{
		}
		break;
	}
}

void quit ()
{
	if ( senderhw != NULL )
	{
		free ( senderhw );
	}

	close_arp_interface ( &if_list );
	destroy_if_index ( &arp_if_index );
	destroy_arp_entry ( &arp_table );
}

char *ip2str ( const void *ip )
{
	static char buf[20];

	if ( ip == NULL )
	{
		strcpy ( buf, "null ip" );
	}
	else
	{
		if ( inet_ntop ( AF_INET, ip, buf, 20 ) == NULL )
		{
			strcpy ( buf, "unknown ip" );
		}
	}

	return buf;
}

char *hw2str ( const void *hw )
{
	static char buf[20];

	if ( hw == NULL )
	{
		strcpy ( buf, "null hw" );
	}
	else
	{
		if ( mac2str ( hw, ETH_ADDR_LEN, buf, 20 ) == NULL )
		{
			strcpy ( buf, "unknown hw" );
		}
	}

	return buf;
}



void usage ()
{
	const char *info = 
	"\n"
	"args:\n"
	"--interface/-I		interface to use, the name or ip address\n"
	"--file/-f		import arp initial table from file\n"
	"--kernel/-k		import arp table from system kernel arp table\n"
	"--update/-u		update the arp table while recv a arp reply\n"
	"--nomodify/-n		when update, only add new and never modify olds\n"
	"--ignreply/-R		not update arp via reply\n"
	"--add/-a		add a arp entry from cmdline ( not support yet )\n"
	"--promisc/-p		set the interface in promisc mode\n"
	"--senderip		sender ip address ( not support any more )\n"
	"--senderhw		sender hardware address\n"
	"--quiet/-q		do not print some message\n"
	"--help/-h		get help infomation\n";
	
	fprintf ( stdout, "%s\n", info );
}
