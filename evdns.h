/* This software is Public Domain. To view a copy of the public domain dedication,
 * visit http://creativecommons.org/licenses/publicdomain/ or send a letter to
 * Creative Commons, 559 Nathan Abbott Way, Stanford, California 94305, USA.
 *
 * I ask and expect, but do not require, that all derivative works contain an
 * attribution similar to:
 * 	Parts developed by Adam Langley <agl@imperialviolet.org>
 *
 * You may wish to replace the word "Parts" with something else depending on
 * the amount of original code.
 *
 * (Derivative works does not include programs which link against, run or include
 * the source verbatim in their source distributions)
 */

#ifndef EVENTDNS_H
#define EVENTDNS_H

/* Error codes 0-5 are as described in RFC 1035. */
#define DNS_ERR_NONE 0
/* The name server was unable to interpret the query */
#define DNS_ERR_FORMAT 1
/* The name server was unable to process this query due to a problem with the
 * name server */
#define DNS_ERR_SERVERFAILED 2
/* The domain name does not exist */
#define DNS_ERR_NOTEXIST 3
/* The name server does not support the requested kind of query */
#define DNS_ERR_NOTIMPL 4
/* The name server refuses to reform the specified operation for policy
 * reasons */
#define DNS_ERR_REFUSED 5
/* The reply was truncated or ill-formated */
#define DNS_ERR_TRUNCATED 65
/* An unknown error occurred */
#define DNS_ERR_UNKNOWN 66
/* Communication with the server timed out */
#define DNS_ERR_TIMEOUT 67

#define DNS_IPv4_A 1

#define DNS_QUERY_NO_SEARCH 1

#define DNS_OPTION_SEARCH 1
#define DNS_OPTION_NAMESERVERS 2
#define DNS_OPTION_MISC 4
#define DNS_OPTIONS_ALL 7

typedef void (*eventdns_callback_type) (int result, char type, int count, int ttl, void *addresses, void *arg);

int eventdns_nameserver_add(unsigned long int address);
int eventdns_count_nameservers(void);
int eventdns_clear_nameservers_and_suspend(void);
int eventdns_resume(void);
int eventdns_nameserver_ip_add(const char *ip_as_string);
int eventdns_resolve(const char *name, int flags, eventdns_callback_type callback, void *ptr);
int eventdns_resolv_conf_parse(int flags, const char *);
#ifdef MS_WINDOWS
int eventdns_config_windows_nameservers(void);
#endif
void eventdns_search_clear(void);
void eventdns_search_add(const char *domain);
void eventdns_search_ndots_set(const int ndots);

typedef void (*eventdns_debug_log_fn_type)(const char *msg);
void eventdns_set_log_fn(eventdns_debug_log_fn_type fn);

#define DNS_NO_SEARCH 1

#endif  // !EVENTDNS_H
