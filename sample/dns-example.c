/*
  This example code shows how to use the high-level, low-level, and
  server-level interfaces of evdns.

  XXX It's pretty ugly and should probably be cleaned up.
 */

#include <event2/event-config.h>

/* Compatibility for possible missing IPv6 declarations */
#include "../ipv6-internal.h"

#include <sys/types.h>

#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <getopt.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>

#ifdef EVENT__HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define u32 ev_uint32_t
#define u8 ev_uint8_t

static const char *
debug_ntoa(u32 address)
{
	static char buf[32];
	u32 a = ntohl(address);
	evutil_snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
					(int)(u8)((a>>24)&0xff),
					(int)(u8)((a>>16)&0xff),
					(int)(u8)((a>>8 )&0xff),
					(int)(u8)((a	)&0xff));
	return buf;
}

static void
main_callback(int result, char type, int count, int ttl,
			  void *addrs, void *orig) {
	char *n = (char*)orig;
	int i;

	if (type == DNS_CNAME) {
		printf("%s: %s (CNAME)\n", n, (char*)addrs);
	}

	for (i = 0; i < count; ++i) {
		if (type == DNS_IPv4_A) {
			printf("%s: %s\n", n, debug_ntoa(((u32*)addrs)[i]));
		} else if (type == DNS_NS) {
			struct evdns_reply_ns *ns = addrs;
			printf("NS %s: %s ttl=%d\n", n, ns[i].name, ns[i].ttl);
		} else if (type == DNS_CNAME) {
			printf("CNAME %s: %s ttl=%d\n", n, (char*)addrs, ttl);
		} else if (type == DNS_SOA) {
			struct evdns_reply_soa *soa = addrs;
			printf("SOA %s: %s %s sn=%u ttl=%d\n", n, soa[i].nsname,
				soa[i].email, soa[i].serial, ttl);
		} else if (type == DNS_PTR) {
			printf("%s: %s\n", n, ((char**)addrs)[i]);
		} else if (type == DNS_MX) {
			struct evdns_reply_mx *mx = addrs;
			printf("MX %s: %s pref=%u ttl=%d\n", n, mx[i].name,
				mx[i].pref, ttl);
		} else if (type == DNS_TXT) {
			struct evdns_reply_txt *txt = addrs;
			printf("TXT %s: %s parts=%u ttl=%d\n", n,
				txt[i].parts == 1 ? txt[i].text : "",
				txt[i].parts, ttl);
			if (txt[i].parts > 1) {
				char *part = txt[i].text;
				for (int j = 0; j < txt[i].parts; ++j) {
					printf("\tpart=%d \"%s\"\n", j, part);
					part += strlen(part) + 1; // skip '/0'
				}
			}
		} else if (type == DNS_SRV) {
			struct evdns_reply_srv *srv = addrs;
			printf("SRV %s: %s priority=%u weight=%u port=%u ttl=%d\n",
				n, srv[i].name, srv[i].priority, srv[i].weight,
				srv[i].port, ttl);
		} else {
			printf("Unknown type: %d\n", type);
		}
	}
	if (!count) {
		printf("%s: No answer (%d)\n", n, result);
	}
	fflush(stdout);
}

static void
gai_callback(int err, struct evutil_addrinfo *ai, void *arg)
{
	const char *name = arg;
	int i;
	struct evutil_addrinfo *first_ai = ai;

	if (err) {
		printf("%s: %s\n", name, evutil_gai_strerror(err));
	}
	if (ai && ai->ai_canonname)
		printf("    %s ==> %s\n", name, ai->ai_canonname);
	for (i=0; ai; ai = ai->ai_next, ++i) {
		char buf[128];
		if (ai->ai_family == PF_INET) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in*)ai->ai_addr;
			evutil_inet_ntop(AF_INET, &sin->sin_addr, buf,
			    sizeof(buf));
			printf("[%d] %s: %s\n",i,name,buf);
		} else {
			struct sockaddr_in6 *sin6 =
			    (struct sockaddr_in6*)ai->ai_addr;
			evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, buf,
			    sizeof(buf));
			printf("[%d] %s: %s\n",i,name,buf);
		}
	}

	if (first_ai)
		evutil_freeaddrinfo(first_ai);
}

static void
evdns_server_callback(struct evdns_server_request *req, void *data)
{
	int i, r;
	char label1[EVDNS_NAME_MAX + 1];
	char label2[EVDNS_NAME_MAX + 1];
	(void)data;
	for (i = 0; i < req->nquestions; ++i) {
		if (req->questions[i]->type == EVDNS_TYPE_A &&
		    req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {
		/* give 192.168.11.11 as an answer for all A questions */
			u32 ans = htonl(0xc0a80b0bUL);
			printf(" -- replying for %s (A)\n", req->questions[i]->name);
			r = evdns_server_request_add_a_reply(req, req->questions[i]->name,
										  1, &ans, 10);
			if (r<0)
				printf("eeep, A didn't work.\n");
		} else if (req->questions[i]->type == EVDNS_TYPE_NS &&
		    req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {
		/* give ns1.example.com and ns2.example.com as an answer for all NS questions */
			printf(" -- replying for %s (NS)\n", req->questions[i]->name);
			r = evdns_server_request_add_ns_reply(req, req->questions[i]->name,
				"ns1.example.com", 100);
			if (r<0) printf("eeep, NS1 didn't work.\n");
			r = evdns_server_request_add_ns_reply(req, req->questions[i]->name,
				"ns2.example.com", 200);
			if (r<0) printf("eeep, NS2 didn't work.\n");
		} else if (req->questions[i]->type == EVDNS_TYPE_CNAME &&
		    req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {
		/* give example.com as an answer for www.example.com CNAME questions */
			if (!strncasecmp(req->questions[i]->name, "www.", 4)) {
				printf(" -- replying for %s (CNAME)\n", req->questions[i]->name);
				r = evdns_server_request_add_cname_reply(req, req->questions[i]->name,
					req->questions[i]->name + 4, 300);
				if (r<0) printf("eeep, CNAME didn't work.\n");
			}
		} else if (req->questions[i]->type == EVDNS_TYPE_SOA &&
		    req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {
		/* give ns1.example.com and admin@example.com as an answer for all SOA questions */
			struct evdns_reply_soa soa = {
				.nsname = label1,
				.email = label2,
				.serial = 2024120233,
				.refresh = 7200, // 2h
				.retry = 3600, // 1h
				.expire = 1209600 , // 14d
				.minimum = 3600, // 1h
			};
			snprintf(label1, EVDNS_NAME_MAX, "%s", "ns1.example.com");
			snprintf(label2, EVDNS_NAME_MAX, "%s", "admin.example.com");
			printf(" -- replying for %s (SOA)\n", req->questions[i]->name);
			r = evdns_server_request_add_soa_reply(req, req->questions[i]->name,
				&soa, 0, soa.minimum);
			if (r<0) printf("eeep, SOA didn't work.\n");
		} else if (req->questions[i]->type == EVDNS_TYPE_PTR &&
		    req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {
		/* give foo.bar.example.com as an answer for all PTR questions. */
			printf(" -- replying for %s (PTR)\n", req->questions[i]->name);
			r = evdns_server_request_add_ptr_reply(req, NULL, req->questions[i]->name,
											"foo.bar.example.com", 10);
			if (r<0)
				printf("ugh, no luck");
		} else if (req->questions[i]->type == EVDNS_TYPE_MX &&
		    req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {
		/* give mx1.example.com and mx2.example.com as an answer for all MX questions */
			struct evdns_reply_mx mx1 = {.name = label1,.pref = 10};
			struct evdns_reply_mx mx2 = {.name = label2,.pref = 20};
			snprintf(label1, EVDNS_NAME_MAX, "%s", "mx1.example.com");
			snprintf(label2, EVDNS_NAME_MAX, "%s", "mx2.example.com");
			printf(" -- replying for %s (MX)\n", req->questions[i]->name);
			r = evdns_server_request_add_mx_reply(req, req->questions[i]->name, &mx1, 600);
			if (r<0) printf("eeep, MX1 didn't work.\n");
			r = evdns_server_request_add_mx_reply(req, req->questions[i]->name, &mx2, 1200);
			if (r<0) printf("eeep, MX2 didn't work.\n");
		} else if (req->questions[i]->type == EVDNS_TYPE_TXT &&
		    req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {
		/* give spf and two parts text as an answer for all TXT questions */
			struct evdns_reply_txt txt1 = {.parts = 1, .text = label1 };
			struct evdns_reply_txt txt2 = {.parts = 2, .text = label2 };
			snprintf(label1, EVDNS_NAME_MAX, "%s", "v=spf1 +a +mx -all");
			snprintf(label2, EVDNS_NAME_MAX, "%s%c%s", "part1=hello world",
				'\0',"part2=second part");
			printf(" -- replying for %s (TXT)\n", req->questions[i]->name);
			r = evdns_server_request_add_txt_reply(req, req->questions[i]->name, &txt1, 600);
			if (r<0) printf("eeep, TXT1 didn't work.\n");
			r = evdns_server_request_add_txt_reply(req, req->questions[i]->name, &txt2, 1200);
			if (r<0) printf("eeep, TXT2 didn't work.\n");
		} else if (req->questions[i]->type == EVDNS_TYPE_SRV &&
		    req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {
		/* give 5 0 .example.com and mx2.example.com as an answer for all MX questions */
			struct evdns_reply_srv srv = { .name = label1 };
			if (!strcmp(req->questions[i]->name,"_ldap._tcp.example.com")) {
				srv.priority = 1; srv.weight = 0; srv.port = 389;
				snprintf(label1, EVDNS_NAME_MAX, "%s", "ldap.example.com");
			} else if (!strcmp(req->questions[i]->name,"_rsync._tcp.example.com")) {
				srv.priority = 5; srv.weight = 10; srv.port = 873;
				snprintf(label1, EVDNS_NAME_MAX, "%s", "storage.example.com");
			} else continue;
			printf(" -- replying for %s (SRV)\n", req->questions[i]->name);
			r = evdns_server_request_add_srv_reply(req, req->questions[i]->name, &srv, 600);
			if (r<0) printf("eeep, SRV didn't work.\n");
		} else {
			printf(" -- skipping %s [%d %d]\n", req->questions[i]->name,
				   req->questions[i]->type, req->questions[i]->dns_question_class);
		}
	}

	r = evdns_server_request_respond(req, 0);
	if (r<0)
		printf("eeek, couldn't send reply.\n");
}

static int verbose = 0;

static void
logfn(int is_warn, const char *msg) {
	if (!is_warn && !verbose)
		return;
	fprintf(stderr, "%s: %s\n", is_warn?"WARN":"INFO", msg);
}

int
main(int c, char **v) {
	struct options {
		int reverse;
		int use_getaddrinfo;
		int servertest;
		const char *resolv_conf;
		const char *ns;
		int resolve_type;
	};
	struct options o;
	int opt;
	struct event_base *event_base = NULL;
	struct evdns_base *evdns_base = NULL;

	memset(&o, 0, sizeof(o));

	if (c < 2) {
		fprintf(stderr, "syntax: %s [-x] [-v] [-c resolv.conf] [-s ns] [-t type] hostname\n", v[0]);
		fprintf(stderr, "syntax: %s [-T]\n", v[0]);
		return 1;
	}

	while ((opt = getopt(c, v, "xvc:Ts:t:g")) != -1) {
		switch (opt) {
			case 'x': o.reverse = 1; break;
			case 'v': ++verbose; break;
			case 'g': o.use_getaddrinfo = 1; break;
			case 'T': o.servertest = 1; break;
			case 'c': o.resolv_conf = optarg; break;
			case 's': o.ns = optarg; break;
			case 't':
				if (!strcasecmp(optarg, "A")) o.resolve_type = DNS_IPv4_A;
				// else if (!strcasecmp(optarg, "AAAA")) o.resolve_type = DNS_IPv6_AAAA;
				else if (!strcasecmp(optarg, "NS")) o.resolve_type = DNS_NS;
				else if (!strcasecmp(optarg, "CNAME")) o.resolve_type = DNS_CNAME;
				else if (!strcasecmp(optarg, "SOA")) o.resolve_type = DNS_SOA;
				else if (!strcasecmp(optarg, "MX")) o.resolve_type = DNS_MX;
				else if (!strcasecmp(optarg, "TXT")) o.resolve_type = DNS_TXT;
				else if (!strcasecmp(optarg, "SRV")) o.resolve_type = DNS_SRV;
				else fprintf(stderr, "Unknown -%c value %s\n", opt, optarg);
				break;
			default : fprintf(stderr, "Unknown option %c\n", opt); break;
		}
	}

#ifdef _WIN32
	{
		WSADATA WSAData;
		WSAStartup(0x101, &WSAData);
	}
#endif

	event_base = event_base_new();
	if (event_base == NULL) {
		fprintf(stderr, "Couldn't create new event_base\n");
		return 1;
	}
	evdns_base = evdns_base_new(event_base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
	if (evdns_base == NULL) {
		event_base_free(event_base);
		fprintf(stderr, "Couldn't create new evdns_base\n");
		return 1;
	}
	
	evdns_set_log_fn(logfn);

	if (o.servertest) {
		evutil_socket_t sock;
		struct sockaddr_in my_addr;
		sock = socket(PF_INET, SOCK_DGRAM, 0);
		if (sock == -1) {
			perror("socket");
			exit(1);
		}
		evutil_make_socket_nonblocking(sock);
		my_addr.sin_family = AF_INET;
		my_addr.sin_port = htons(10053);
		my_addr.sin_addr.s_addr = INADDR_ANY;
		if (bind(sock, (struct sockaddr*)&my_addr, sizeof(my_addr))<0) {
			perror("bind");
			exit(1);
		}
		evdns_add_server_port_with_base(event_base, sock, 0, evdns_server_callback, NULL);
	}
	if (optind < c) {
		int res;
#ifdef _WIN32
		if (o.resolv_conf == NULL && !o.ns)
			res = evdns_base_config_windows_nameservers(evdns_base);
		else
#endif
		if (o.ns)
			res = evdns_base_nameserver_ip_add(evdns_base, o.ns);
		else
			res = evdns_base_resolv_conf_parse(evdns_base,
			    DNS_OPTION_NAMESERVERS, o.resolv_conf);

		if (res) {
			fprintf(stderr, "Couldn't configure nameservers\n");
			return 1;
		}
	}

	printf("EVUTIL_AI_CANONNAME in example = %d\n", EVUTIL_AI_CANONNAME);
	for (; optind < c; ++optind) {
		if (o.reverse) {
			struct in_addr addr;
			if (evutil_inet_pton(AF_INET, v[optind], &addr)!=1) {
				fprintf(stderr, "Skipping non-IP %s\n", v[optind]);
				continue;
			}
			fprintf(stderr, "resolving %s...\n",v[optind]);
			evdns_base_resolve_reverse(evdns_base, &addr, 0, main_callback, v[optind]);
		} else if (o.use_getaddrinfo) {
			struct evutil_addrinfo hints;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = PF_UNSPEC;
			hints.ai_protocol = IPPROTO_TCP;
			hints.ai_flags = EVUTIL_AI_CANONNAME;
			fprintf(stderr, "resolving (fwd) %s...\n",v[optind]);
			evdns_getaddrinfo(evdns_base, v[optind], NULL, &hints,
			    gai_callback, v[optind]);
		} else if (o.resolve_type != 0) {
			switch(o.resolve_type) {
			case DNS_IPv4_A:
				fprintf(stderr, "resolving (fwd) %s...\n",v[optind]);
				evdns_base_resolve_ipv4(evdns_base, v[optind], DNS_CNAME_CALLBACK, main_callback, v[optind]);
				break;
			case DNS_NS:
				fprintf(stderr, "resolving NS (fwd) %s...\n",v[optind]);
				evdns_base_resolve_ns(evdns_base, v[optind], 0, main_callback, v[optind]);
				break;
			case DNS_CNAME:
				fprintf(stderr, "resolving CNAME (fwd) %s...\n",v[optind]);
				evdns_base_resolve_cname(evdns_base, v[optind], 0, main_callback, v[optind]);
				break;
			case DNS_SOA:
				fprintf(stderr, "resolving SOA (fwd) %s...\n",v[optind]);
				evdns_base_resolve_soa(evdns_base, v[optind], 0, main_callback, v[optind]);
				break;
			case DNS_MX:
				fprintf(stderr, "resolving MX (fwd) %s...\n",v[optind]);
				evdns_base_resolve_mx(evdns_base, v[optind], 0, main_callback, v[optind]);
				break;
			case DNS_TXT:
				fprintf(stderr, "resolving TXT (fwd) %s...\n",v[optind]);
				evdns_base_resolve_txt(evdns_base, v[optind], 0, main_callback, v[optind]);
				break;
			case DNS_SRV:
				fprintf(stderr, "resolving SRV (fwd) %s...\n",v[optind]);
				evdns_base_resolve_srv(evdns_base, v[optind], 0, main_callback, v[optind]);
				break;
			default: fprintf(stderr, "Unknown resolve type %d\n", o.resolve_type);
			}
		} else {
			fprintf(stderr, "resolving (fwd) %s...\n",v[optind]);
			evdns_base_resolve_ipv4(evdns_base, v[optind], DNS_CNAME_CALLBACK, main_callback, v[optind]);
		}
	}
	fflush(stdout);
	event_base_dispatch(event_base);
	evdns_base_free(evdns_base, 1);
	event_base_free(event_base);
	return 0;
}

