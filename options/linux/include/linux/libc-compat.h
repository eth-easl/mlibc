#ifndef _LINUX_LIBC_COMPAT_H
#define _LINUX_LIBC_COMPAT_H

#if defined(_NET_IF_H)

#define __UAPI_DEF_IF_IFCONF 0
#define __UAPI_DEF_IF_IFMAP 0
#define __UAPI_DEF_IF_IFNAMSIZ 0
#define __UAPI_DEF_IF_IFREQ 0
#define __UAPI_DEF_IF_NET_DEVICE_FLAGS 0

#else // _NET_IF_H

#define __UAPI_DEF_IF_IFCONF 1
#define __UAPI_DEF_IF_IFMAP 1
#define __UAPI_DEF_IF_IFNAMSIZ 1
#define __UAPI_DEF_IF_IFREQ 1
#define __UAPI_DEF_IF_NET_DEVICE_FLAGS 1
#define __UAPI_DEF_IF_NET_DEVICE_FLAGS_LOWER_UP_DORMANT_ECHO 0

#endif //_NET_IF_H

#if defined(_NETINET_IN_H)

#define __UAPI_DEF_IN_ADDR 0
#define __UAPI_DEF_IN_CLASS 0
#define __UAPI_DEF_IN_IPPROTO 0
#define __UAPI_DEF_IN_PKTINFO 0
#define __UAPI_DEF_IP_MREQ 0
#define __UAPI_DEF_SOCKADDR_IN 0

#define __UAPI_DEF_IN6_ADDR 0
#define __UAPI_DEF_IN6_ADDR_ALT 1
#define __UAPI_DEF_IN6_PKTINFO 0
#define __UAPI_DEF_IP6_MTUINFO 0
#define __UAPI_DEF_IPPROTO_V6 0
#define __UAPI_DEF_IPV6_MREQ 0
#define __UAPI_DEF_IPV6_OPTIONS 0
#define __UAPI_DEF_SOCKADDR_IN6 0

#else

#define __UAPI_DEF_IN_ADDR 1
#define __UAPI_DEF_IN_CLASS 1
#define __UAPI_DEF_IN_IPPROTO 1
#define __UAPI_DEF_IN_PKTINFO 1
#define __UAPI_DEF_IP_MREQ 1
#define __UAPI_DEF_SOCKADDR_IN 1

#define __UAPI_DEF_IN6_ADDR 1
#define __UAPI_DEF_IN6_ADDR_ALT 1
#define __UAPI_DEF_IN6_PKTINFO 1
#define __UAPI_DEF_IP6_MTUINFO 1
#define __UAPI_DEF_IPPROTO_V6 1
#define __UAPI_DEF_IPV6_MREQ 1
#define __UAPI_DEF_IPV6_OPTIONS 1
#define __UAPI_DEF_SOCKADDR_IN6 1

#endif /* _NETINET_IN_H */

#endif // _LINUX_LIBC_COMPAT_H
