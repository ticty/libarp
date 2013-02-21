/*
 * misc.h
 *
 *  Created on: 2012-9-10
 *      Author: guofeng
 */

#ifndef MISC_H_
#define MISC_H_

#include <stdio.h>

#define ATTR(x)	__attribute__((x))
#define UNUSED_ARGUMENT(x) (void)x;

#define MAX_STRLEN_LEN 8196

#define MAC_DELIMIT	':'

#define WILDCARD_CHAR	"*?|"

#define ENTRY_DELIMIT	", |"

#define STD_ENTRY_DELIMIT_CHAR	'|'

/* chars whose SASCII little than '!'(32) are not human readable */
#define MIN_READABLE_CHAR	' '

/* log level */
#define LEVEL_DEBUG	1
#define LEVEL_INFO	2
#define LEVEL_WARN	3
#define LEVEL_ERR		4

int msg_log ( int, const char *, ... ) ATTR(format(printf, 2, 3));
int str2mac ( const char *str, unsigned char *buf, int buf_size );
char *mac2str ( const unsigned char *data, int len, char *buf, int size );

int str2long ( const char *str, long *result, int base );

void print_bin2hex ( const unsigned char *buf, int len );

int is_wildcard_str ( const char *str );

int fit_case_wildcard ( const char *str1, const char *str2 );

int fit_wildcard ( const char *str1, const char *str2, int case_sen );

int format_entry_str ( const char *src, char *buf, int size );

int fs_next_line ( FILE *fp );

#endif /* MISC_H_ */
