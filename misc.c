/*
 * logger.c
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>

#include "misc.h"

int msg_log ( int level, const char *format, ... )
{
	char buf[MAX_STRLEN_LEN];
	va_list args;

	UNUSED_ARGUMENT( level );

	va_start( args, format );
	vsnprintf ( buf, sizeof(buf), format, args );
	va_end( args );

	/* process diff based on level */
	fprintf ( stderr, "%s", buf );

	return 0;
}

inline char up2low ( char ch )
{
	if ( ch >= 'A' && ch <= 'Z' )
	{
		ch += 'a' - 'A';
	}

	return ch;
}

inline int xtoi ( char ch )
{
	ch = up2low ( ch );
	return ch >= 'a' ? ch - 'a' + 10 : ch - '0';
}

inline char itox ( int i )
{
	return i > 9 ? 'a' + i - 10 : '0' + i;
}

int str2mac ( const char *str, unsigned char *buf, int buf_size )
{
	int bytes;
	int cur;
	char temp[3];
	const char *ptr;

	for ( ptr = str, cur = 0, bytes = 0; *ptr != '\0' && bytes < buf_size;
			ptr++, cur++ )
	{
		if ( *ptr < '0' || (*ptr > ':' && *ptr < 'A')
			 || (*ptr > 'F' && *ptr < 'a') || *ptr > 'f' )
		{
			/* invalid char */
			return -1;
		}

		if ( *ptr == ':' )
		{
			switch ( cur )
			{
				case 2:
				{
					*buf++ = xtoi ( temp[1] ) + xtoi ( temp[0] ) * 16;
				}
				break;

				case 1:
				{
					*buf++ = xtoi ( temp[0] );
				}
				break;

				case 0:
				{
					*buf++ = 0;
				}
				break;

				default:
				{
					return -1;
				}
				break;
			}

			bytes++;
			cur = -1;
			continue;
		}

		if ( cur == 2 )
		{
			/* a field only can contain two num */
			return -1;
		}

		temp[cur] = *ptr;
	}

	if ( *ptr == '\0' )
	{
		if ( bytes >= buf_size )
		{
			return -1;
		}

		switch ( cur )
		{
			case 2:
			{
				*buf++ = xtoi ( temp[1] ) + xtoi ( temp[0] ) * 16;
			}
			break;

			case 1:
			{
				*buf++ = xtoi ( temp[0] );
			}
			break;

			case 0:
			{
				*buf++ = 0;
			}
			break;

			default:
			{
				return -1;
			}
			break;
		}

		bytes++;
	}
	else if ( bytes >= buf_size )
	{
		return -1;
	}

	return bytes;
}

char *mac2str ( const unsigned char *data, int len, char *buf, int size )
{
	char *ptr = buf;
	const unsigned char *end = data + len;

	if ( data == NULL || buf == NULL || len < 0 )
	{
		return NULL ;
	}

	if ( size < len + len - 1 )
	{
		/* buf size is not enough */
		return NULL ;
	}

	while ( data < end )
	{
		*ptr++ = itox ( *data >> 4 );
		*ptr++ = itox ( *data & 0x0f );
		*ptr++ = MAC_DELIMIT;
		data++;
	}

	*--ptr = '\0';

	return buf;
}

void print_bin2hex ( const unsigned char *buf, int len )
{
	const unsigned char *end;

	if ( buf == NULL || len <= 0 )
	{
		return;
	}

	end = buf + len;

	/* hex */
	while ( buf < end )
	{
		msg_log ( LEVEL_INFO, "%.2x ", *buf++ );
	}
}

inline int is_wildcard_char ( char ch )
{
	const char *wildcast_chars = WILDCARD_CHAR;

	while ( *wildcast_chars != '\0' )
	{
		if ( ch == *wildcast_chars )
		{
			return 1;
		}

		wildcast_chars++;
	}

	return 0;
}

int is_wildcard_str ( const char *str )
{
	if ( str == NULL )
	{
		return 0;
	}

	while ( *str != '\0' )
	{
		if ( is_wildcard_char ( *str++ ) )
		{
			return 1;
		}
	}

	return 0;
}

/*
 * return:
 * 	-1	--	error
 * 	0	--	patten fixed len
 * 	1	--	patten infinited
 */
/*int get_condition(const char *tpl, char **patten, int *pat_pos, int *pat_chars)
 {
 int len;
 int infinite;

 if (tpl == NULL || *patten == NULL || pat_pos == NULL || pat_chars == NULL )
 {
 return -1;
 }

 len = 0;
 infinite = 0;
 *pat_chars = 0;

 if (is_wildcard_char(*tpl))
 {
 *pat_pos = -1;

 do
 {
 switch (*tpl)
 {
 case '*':
 {
 infinite = 1;
 }
 break;

 case '?':
 {
 if (infinite)
 {
 *pat_chars -= 1;
 }
 else
 {
 *pat_chars += 1;
 }
 }
 break;

 default:
 {
 not a defined wildcard char
 return -1;
 }
 break;

 }

 } while (is_wildcard_char(*++tpl));

 *patten = tpl;

 while (*tpl != '\0' && !is_wildcard_char(*tpl++))
 ;
 {
 len++;
 }

 if (len > 0)
 {
 *patten = strndup(*patten, len);
 if (*patten == NULL )
 {
 return -1;
 }
 }
 else
 {
 *patten = NULL;
 }
 }
 else
 {
 *pat_pos = 1;
 *patten = tpl;

 while (*tpl != '\0' && !is_wildcard_char(*tpl++))
 ;
 {
 len++;
 }

 if (len > 0)
 {
 *patten = strndup(*patten, len);
 if (*patten == NULL )
 {
 return -1;
 }
 }
 else
 {
 *patten = NULL;
 }

 while (*tpl != '\0' && !is_wildcard_char(*tpl))
 {
 switch (*tpl)
 {
 case '*':
 {
 infinite = 1;
 }
 break;

 case '?':
 {
 if (infinite)
 {
 *pat_chars -= 1;
 }
 else
 {
 *pat_chars += 1;
 }
 }
 break;

 default:
 {
 not a defined wildcard char
 return -1;
 }
 break;

 }
 }
 }

 return infinite;
 }




 int strwildcasecmp( const char *str1, const char *str2 )
 {
 int n;
 int ret;
 const char *tpl = NULL;
 const char *str = NULL;
 const char *cur_str, *ptr;

 char *patten;
 int pat_pos;
 int pat_chars;


 if( is_wildcard_str( str1 ) )
 {
 tpl = str1;
 }
 else
 {
 str = str1;
 }

 if( is_wildcard_str( str2 ) )
 {
 if( tpl == NULL )
 {
 tpl = str2;
 }
 else
 {
 can not both are wildcard string
 return -1;
 }
 }
 else
 {
 if( str == NULL )
 {
 str = str2;
 }
 else
 {
 return strcasecmp( str1, str2 );
 }
 }

 cur_str = str;


 while( get_condition( tpl, &patten, &pat_pos, &pat_chars ) != -1 )
 {
 if( pat_pos == -1 )
 {
 n = strlen( patten );
 if( (ret = strncacecmp( patten, cur_str, n )) != 0 )
 {
 if(  )
 return ret;
 }
 }
 else
 {

 }
 }

 return 1;
 }



 int strwildcmp( const char *str1, const char *str2 )
 {
 return 1;
 }*/

int fit_case_wildcard ( const char *str1, const char *str2 )
{
	return fit_wildcard ( str1, str2, 0 );
}

int fit_wildcard ( const char *str1, const char *str2, int case_sen )
{
	FILE *fp;
	int ret;
	int len = 0;
	int step = 1024;
	char *buf;
	const char *tpl = NULL, *str = NULL, *cmd;
	const char *cmd_fmt = "echo -n \"%s\" | grep -iE \"%s\"";
	const char *cmd_case_fmt = "echo -n \"%s\" | grep -E \"%s\"";

	if ( is_wildcard_str ( str1 ) )
	{
		tpl = str1;
	}
	else
	{
		str = str1;
	}

	if ( is_wildcard_str ( str2 ) )
	{
		if ( tpl == NULL )
		{
			tpl = str2;
		}
		else
		{
			/* can not both are wildcard string */
			return -1;
		}
	}
	else
	{
		if ( str == NULL )
		{
			str = str2;
		}
		else
		{
			return !strcasecmp ( str1, str2 );
		}
	}

	if ( case_sen )
	{
		cmd = cmd_case_fmt;
	}
	else
	{
		cmd = cmd_fmt;
	}

	size_up:

	len += step;
	buf = malloc ( len );
	if ( buf == NULL )
	{
		/* todo: ..... */
		return -1;
	}

	ret = sprintf ( buf, cmd, str, tpl );
	if ( ret == len )
	{
		free ( buf );
		goto size_up;
	}

	fp = popen ( buf, "r" );
	if ( fp == NULL )
	{
		free ( buf );
		return -1;
	}

	ret = fscanf ( fp, "%s", buf );

	if ( ret <= 0 )
	{
		pclose ( fp );
		free ( buf );
		return ret;
	}

	ret = strcmp ( str, buf );

	pclose ( fp );
	free ( buf );

	return !ret;
}

inline int str2long ( const char *str, long *result, int base )
{
	char *error;
	long ret;

	if ( str == NULL )
	{
		return -1;
	}

	errno = 0;
	ret = strtol ( str, &error, base );

	if ( (errno == ERANGE && (ret == LONG_MAX || ret == LONG_MIN))
	|| (errno != 0 && ret == 0)
	|| error == str ){
	return -1;
}

	*result = ret;
	return 0;
}

inline int is_entry_delimit_char ( char ch )
{
	const char *ptr;

	for ( ptr = ENTRY_DELIMIT; *ptr != '\0'; ptr++ )
	{
		if ( ch == *ptr )
		{
			return 1;
		}
	}

	return 0;
}

inline int is_readable_char ( char ch )
{
	return ch >= MIN_READABLE_CHAR ? 1 : 0;
}

/*
 *
 */
int format_entry_str ( const char *src, char *buf, int size )
{
	char *endline;
	const char *ptr;

	if ( src == NULL || buf == NULL || size <= 0 )
	{
		return -1;
	}

	endline = buf + size;
	ptr = src;

	mainloop:

	/* trim begin */
	while ( *ptr != '\0' )
	{
		if ( is_readable_char ( *ptr ) && !is_entry_delimit_char ( *ptr ) )
		{
			break;
		}

		ptr++;
	}

	/* no chars found */
	if ( ptr == '\0' )
	{
		*buf = '\0';
		return 0;
	}

	/* record something until see a delimit again */
	for ( ; *ptr != '\0'; ptr++ )
	{
		if ( is_entry_delimit_char ( *ptr ) )
		{
			*buf++ = STD_ENTRY_DELIMIT_CHAR;
			if ( buf >= endline )
			{
				return -1;
			}

			ptr++;
			goto mainloop;
		}

		if ( !is_readable_char ( *ptr ) )
		{
			continue;
		}

		*buf++ = *ptr;

		if ( buf >= endline )
		{
			return -1;
		}
	}

	if ( *(buf - 1) == STD_ENTRY_DELIMIT_CHAR )
	{
		buf--;
	}

	*buf = '\0';
	return 0;
}

int fs_next_line ( FILE *fp )
{
	int ch;

	if ( fp == NULL )
	{
		return -1;
	}

	/*
	 * use fgetc other than fgets, b
	 * cause the buf size of fgets cann't easy measure
	 */

	while ( (ch = fgetc ( fp )) != '\n' || ch == EOF)
		;

	if ( ch == '\n' )
	{
		return 0;
	}

	return 1;
}
