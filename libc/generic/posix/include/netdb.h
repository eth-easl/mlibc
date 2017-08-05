#ifndef _NETDB_H
#define _NETDB_H

#include <stdint.h>
#include <mlibc/in_port_t.h>
#include <mlibc/in_addr_t.h>
#include <mlibc/socklen_t.h>

#define AI_PASSIVE 0x01
#define AI_CANONNAME 0x02
#define AI_NUMERICHOST 0x04
#define AI_V4MAPPED 0x08
#define AI_ALL 0x10
#define AI_ADDRCONFIG 0x20

#define NI_NOFQDN 0x01
#define NI_NUMERICHOST 0x02
#define NI_NAMEREQD 0x04
#define NI_NUMERICSCOPE 0x08
#define NI_DGRAM 0x10

#define EAI_AGAIN 1
#define EAI_BADFLAGS 2
#define EAI_FAIL 3
#define EAI_FAMILY 4
#define EAI_MEMORY 5
#define EAI_NONAME 6
#define EAI_SERVICE 7
#define EAI_SOCKTYPE 8
#define EAI_SYSTEM 9
#define EAI_OVERFLOW 10

#ifdef __cplusplus
extern "C" {
#endif

struct hostent {
	char *h_name;
	char **h_aliases;
	int h_addrtype;
	int h_length;
	char **h_addr_list;
};

struct netent {
	char *n_name;
	char **n_alises;
	int n_addrtype;
	uint32_t n_net;
};

struct protoent {
	char *p_name;
	char **p_aliases;
	int p_proto;
};

struct servent {
	char *s_name;
	char **s_aliases;
	int s_port;
	char *s_proto;
};

struct addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	socklen_t ai_addrlen;
	struct sockaddr *ai_addr;
	char *ai_canonname;
	struct addrinfo *ai_next;
};

void endhostent(void);
void endnetent(void);
void endprotoent(void);
void endservent(void);
void freeaddrinfo(struct addrinfo *);
const char *gai_strerror(int);
int getaddrinfo(const char *__restrict, const char *__restrict,
		const struct addrinfo *__restrict, struct addrinfo **__restrict);
struct hostent *gethostent(void);
int getnameinfo(const struct sockaddr *__restrict, socklen_t,
		char *__restrict, socklen_t, char *__restrict, socklen_t, int);
struct netent *getnetbyaddr(uint32_t, int);
struct netent *getnetbyname(const char *);
struct netent *getnetent(void);
struct protoent *getprotobyname(const char *);
struct protoent *getprotobynumber(int);
struct protoent *getprotoent(void);
struct servent *getservbyname(const char *, const char *);
struct servent *getservbyport(int, const char *);
struct servent *getservent(void);
void sethostent(int);
void setnetent(int);
void setprotoent(int);

#ifdef __cplusplus
}
#endif

#endif // _NETDB_H