/*
 * ng_sample.c
 */

/*-
 * Copyright (c) 1996-1999 Whistle Communications, Inc.
 * All rights reserved.
 *
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 *
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Julian Elischer <julian@freebsd.org>
 *
 * $FreeBSD: release/10.0.0/sys/netgraph/ng_sample.c 227293 2011-11-07 06:44:47Z ed $
 * $Whistle: ng_sample.c,v 1.13 1999/11/01 09:24:52 julian Exp $
 */

/* temporary for debug */
//#define NETGRAPH_DEBUG 1

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/ctype.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <machine/atomic.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/radix.h>
#include <net/ethernet.h>
#include <vm/uma.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_sample.h>
#include <netgraph/netgraph.h>
#include "ng_route.h"

/* If you do complicated mallocs you may want to do this */
/* and use it for your mallocs */
#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(M_NETGRAPH_ROUTE, "netgraph_route", "netgraph route node");
#else
#define M_NETGRAPH_ROUTE M_NETGRAPH
#endif

/* zone for storing ngpl_hdr-s */
static uma_zone_t ngr_zone;

#define NG_ROUTE_MAX_UPLINKS 1048576 /* It results in 8-megabyte (x86_64) array
				      * in node's private info. That's many,
				      * maybe we shold move it to hashtable. */

/* Next 8 #defines was fully copied from ip_fw_table.c */
#define KEY_LEN(v)      *((uint8_t *)&(v))
#define KEY_OFS         (8*offsetof(struct sockaddr_in, sin_addr))
/*
 * Do not require radix to compare more than actual IPv4/IPv6 address
 */
#define KEY_LEN_INET    (offsetof(struct sockaddr_in, sin_addr) + sizeof(in_addr_t))
#define KEY_LEN_INET6   (offsetof(struct sockaddr_in6, sin6_addr) + sizeof(struct in6_addr))
#define KEY_LEN_IFACE   (offsetof(struct xaddr_iface, ifname))

#define OFF_LEN_INET    (8 * offsetof(struct sockaddr_in, sin_addr))
#define OFF_LEN_INET6   (8 * offsetof(struct sockaddr_in6, sin6_addr))
#define OFF_LEN_IFACE   (8 * offsetof(struct xaddr_iface, ifname))

/*
 * Netgraph methods.
 */
static ng_constructor_t	ng_route_constructor;
static ng_rcvmsg_t	ng_route_rcvmsg;
static ng_shutdown_t	ng_route_shutdown;
static ng_newhook_t	ng_route_newhook;
static ng_connect_t	ng_route_connect;
static ng_rcvdata_t	ng_route_rcvdata;
static ng_disconnect_t	ng_route_disconnect;
static ng_findhook_t    ng_route_findhook;
static int ng_route_modevent(module_t, int, void *);

/*
 * Internal methods
 */
static inline struct ng_route_hookinfo *
ng_route_findhookinfo(node_p node, const char *name);
static int
ng_table_lookup(struct radix_node_head *rnh, void *addrp, int type, u_int32_t *val);
static int
ng_table_flush(struct radix_node_head *rnh);
static int
ng_table_del_entry(struct radix_node_head *rnh, void *entry, int type);
static int
ng_table_add_entry(struct radix_node_head *rnh, void *entry, int type);

/* Parse types */
// IPv4 tuple subtype and supertype
struct ng_parse_struct_field ng_route_tuple4_fields[] = {
	{ "addr",	&ng_parse_ipaddr_type   },
	{ "mask",	&ng_parse_ipaddr_type   },
	{ "value",	&ng_parse_int32_type    },
	{ NULL }
};
static const struct ng_parse_type ng_route_tuple4_type = {
	&ng_parse_struct_type,
	&ng_route_tuple4_fields
};

// Anything for IPv6 tuple
static int
ng_route_tuple6_getLength(const struct ng_parse_type *type,
			  const u_char *start, const u_char *buf)
{
	return 16;
}
static const struct ng_parse_type ng_route_ip6addr_type = {
	&ng_parse_bytearray_type,
	&ng_route_tuple6_getLength
};
struct ng_parse_struct_field ng_route_tuple6_fields[] = {
	{ "addr",	&ng_route_ip6addr_type },
	{ "mask",	&ng_route_ip6addr_type },
	{ "value",	&ng_parse_int32_type   },
	{ NULL }
};
static const struct ng_parse_type ng_route_tuple6_type = {
	&ng_parse_struct_type,
	&ng_route_tuple6_fields
};

/* Type for flags structure
 */
struct ng_parse_struct_field ng_route_flags_fields[] = {
	/* indicating matching direction: source (1) or destination (0) address */
	{ "direct",	&ng_parse_int8_type },
	{ "verbose",	&ng_parse_int8_type },
	{ "debug",	&ng_parse_int8_type },
	{ NULL }
};
static const struct ng_parse_type ng_route_flags_type = {
	&ng_parse_struct_type,
	&ng_route_flags_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_route_cmdlist[] = {
	{
		NGM_ROUTE_COOKIE,
		NGM_ROUTE_ADD4,
		"add4",
		&ng_route_tuple4_type,
		NULL,
	},
	{
		NGM_ROUTE_COOKIE,
		NGM_ROUTE_ADD6,
		"add6",
		&ng_route_tuple6_type,
		NULL
	},
	{
		NGM_ROUTE_COOKIE,
		NGM_ROUTE_DEL4,
		"del4",
		&ng_route_tuple4_type,
		NULL,
	},
	{
		NGM_ROUTE_COOKIE,
		NGM_ROUTE_DEL6,
		"del6",
		&ng_route_tuple6_type,
		NULL
	},
	{
		NGM_ROUTE_COOKIE,
		NGM_ROUTE_FLUSH,
		"flush",
		NULL,
		NULL,
	},
	{
		NGM_ROUTE_COOKIE,
		NGM_ROUTE_SETFLAGS,
		"setflags",
		&ng_route_flags_type,
		NULL
	},
	{
		NGM_ROUTE_COOKIE,
		NGM_ROUTE_GETFLAGS,
		"getflags",
		NULL,
		&ng_route_flags_type
	},
	{ 0 }
};

/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =	NG_ROUTE_NODE_TYPE,
	.mod_event =	ng_route_modevent,
	.constructor =	ng_route_constructor,
	.rcvmsg =	ng_route_rcvmsg,
	.shutdown =	ng_route_shutdown,
	.newhook =	ng_route_newhook,
	.findhook =	ng_route_findhook,
	.connect =	ng_route_connect,
	.rcvdata =	ng_route_rcvdata,
	.disconnect =	ng_route_disconnect,
	.cmdlist =	ng_route_cmdlist,
};
NETGRAPH_INIT(route, &typestruct);

/*
 * Information we store for each hook on each node
 * We don't really need it now, but there may be some stats in future
 */
struct ng_route_hookinfo {
	hook_p	hook;
	struct ng_route_hookstat stats;
};

/* Information we store for each node */
struct ng_route {
	struct  ng_route_hookinfo up[NG_ROUTE_MAX_UPLINKS];
	struct  ng_route_hookinfo down;
	struct	ng_route_hookinfo notmatch;
	node_p	node;		/* back pointer to node */
	struct	ng_route_flags flags;
	struct	radix_node_head *table4;
	struct	radix_node_head *table6;
};
typedef struct ng_route *ng_route_p;

/*
 * Allocate the private data structure. The generic node has already
 * been created. Link them together. We arrive with a reference to the node
 * i.e. the reference count is incremented for us already.
 *
 * If this were a device node than this work would be done in the attach()
 * routine and the constructor would return EINVAL as you should not be able
 * to creatednodes that depend on hardware (unless you can add the hardware :)
 */
static int
ng_route_constructor(node_p node)
{
	ng_route_p privdata;
	
	/* Initialize private descriptors */
	privdata = malloc(sizeof(*privdata), M_NETGRAPH_ROUTE, M_WAITOK | M_ZERO);
	if (privdata == NULL) goto init_error;
	
	/* Init tables */
	if (!rn_inithead((void **)&privdata->table4, OFF_LEN_INET) ||
		!rn_inithead((void **)&privdata->table6, OFF_LEN_INET6))
			goto init_error;
	/* Link structs together; this counts as our one reference to *nodep */
	NG_NODE_SET_PRIVATE(node, privdata);
	privdata->node = node;
	return (0);
	
init_error:
	if (privdata->table4 != NULL)
		rn_detachhead((void **)&privdata->table4);
	if (privdata->table6 != NULL)
		rn_detachhead((void **)&privdata->table6);
	if (privdata != NULL)
		free(privdata,M_NETGRAPH_ROUTE);
	printf("ng_route: failed to init node!\n");
	return (ENOMEM);
}

static int
ng_route_newhook(node_p node, hook_p hook, const char *name)
{
	/* Find address of hookinfo struct in node's private data */
	struct ng_route_hookinfo *hinfo = 
		ng_route_findhookinfo(node, name);

	/* Completely invalid hookname (all valid names will be always found). */
	if (!hinfo)
		return (EINVAL);
	
	hinfo->hook = hook;
	NG_HOOK_SET_PRIVATE(hook, hinfo);
	
	return(0);
}

static int
ng_route_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const ng_route_p ng_routep = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;
	struct ng_mesg *msg;
	
	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_ROUTE_COOKIE:
		switch (msg->header.cmd) {
		case NGM_ROUTE_ADD4:
			error = ng_table_add_entry(ng_routep->table4, msg->data, 4);
			break;
		case NGM_ROUTE_ADD6:
			error = ng_table_add_entry(ng_routep->table6, msg->data, 6);
			break;
		case NGM_ROUTE_DEL4:
			error = ng_table_del_entry(ng_routep->table4, msg->data, 4);
			break;
		case NGM_ROUTE_DEL6:
			error = ng_table_del_entry(ng_routep->table6, msg->data, 6);
			break;
		case NGM_ROUTE_FLUSH:
			if ((error = ng_table_flush(ng_routep->table4))) break;
			error = ng_table_flush(ng_routep->table6);
			break;
		case NGM_ROUTE_SETFLAGS:
			ng_routep->flags = *((struct ng_route_flags*) msg->data);
			break;
		case NGM_ROUTE_GETFLAGS:
			//if (ng_routep->flags.verbose)
			NG_MKRESPONSE(resp, msg, sizeof(struct ng_route_flags), M_NOWAIT);
			*((struct ng_route_flags*) resp->data) = ng_routep->flags;
			break;
		default:
			error = EINVAL;		/* unknown command */
			break;
		}
		break;
	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}
	
	/* Take care of synchronous response, if any */
	NG_RESPOND_MSG(error, node, item, resp);
	/* Free the message and return */
	NG_FREE_MSG(msg);
	return(error);
}


static int
ng_route_rcvdata(hook_p hook, item_p item )
{
  /* Node private data */
  const ng_route_p ng_routep = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
  /* Name of incoming hook */
  char *hook_name = NG_HOOK_NAME(hook);
  /* For outgoing hook */
  hook_p out_hook;

  int error = 0;
  struct mbuf *m;
  struct ether_header *eh;
  struct ip      *ip4hdr;
  struct ip6_hdr *ip6hdr;
  void  *ipaddr;
  u_int32_t num;

  NGI_GET_M(item, m);

  /* Update input hook's statistics */
  atomic_add_64(
	  &((struct ng_route_hookinfo *) NG_HOOK_PRIVATE(hook))->stats.in_packets,
		1);
  atomic_add_64(
	  &((struct ng_route_hookinfo *) NG_HOOK_PRIVATE(hook))->stats.in_octets,
		m->m_pkthdr.len);

  if (strncmp(hook_name, NG_ROUTE_HOOK_UP, strlen(NG_ROUTE_HOOK_UP)) == 0 ||
      strncmp(hook_name, NG_ROUTE_HOOK_NOTMATCH,
              strlen(NG_ROUTE_HOOK_NOTMATCH)) == 0 ) {
    /* Item coming from one of uplink nodes. Just forward it to downlink */
    out_hook = ng_routep->down.hook;
  } else if (hook == ng_routep->down.hook) {
    /* Item came from downlink. We need to lookup table to find next hook */
    if ( m->m_len < sizeof(struct ether_header) &&
        (m = m_pullup(m, sizeof(struct ether_header))) == NULL) {
          error=ENOBUFS;
          goto bad;
    }
    eh = mtod(m, struct ether_header *);

    /* Determine IP version and lookup corresponding table.
     * Fallback to notmatch hook if not found in any table or not IP at all. */
    switch (ntohs(eh->ether_type)) {
      case ETHERTYPE_IP:
        if ( m->m_len < sizeof(struct ether_header)+sizeof(struct ip) &&
           (m = m_pullup(m, sizeof(struct ether_header)+sizeof(struct ip)))
              == NULL) {
          error=ENOBUFS;
          goto bad;
        }
        ip4hdr = mtodo(m, ETHER_HDR_LEN);
	log(LOG_DEBUG, "ng_route: searching direct %u\n",
	      ng_routep->flags.direct);
        ipaddr = (ng_routep->flags.direct)
                      ?(&ip4hdr->ip_src.s_addr):(&ip4hdr->ip_dst.s_addr);

        //log(LOG_DEBUG, "ng_route: looking up address %s\n",inet_ntoa(*(struct in_addr*)ipaddr));
        /* Lookup */
        if (ng_table_lookup(ng_routep->table4, ipaddr, 4, &num)) {
          //log(LOG_DEBUG, "ng_route: found hook number %u\n",num);
          out_hook = ng_routep->up[num].hook;
        } else {
          out_hook = ng_routep->notmatch.hook;
        }
        break;
      case ETHERTYPE_IPV6:
        if ( m->m_len < sizeof(struct ether_header)+sizeof(struct ip6_hdr) &&
           (m = m_pullup(m, sizeof(struct ether_header)+sizeof(struct ip6_hdr)))
              == NULL) {
          error=ENOBUFS;
          goto bad;
        }
        ip6hdr = mtodo(m, ETHER_HDR_LEN);
        ipaddr = (ng_routep->flags.direct)?(&ip6hdr->ip6_src):(&ip6hdr->ip6_dst);
        if (ng_table_lookup(ng_routep->table6, ipaddr, 6, &num)) {
          out_hook = ng_routep->up[num].hook;
        } else {
          out_hook = ng_routep->notmatch.hook;
        }
        break;
      default:
        //log(LOG_DEBUG, "ng_route: forwarding ethertype 0x%x\n",ntohs(eh->ether_type));
        /* Not IP or IPv6, send to special hook */
        out_hook = ng_routep->notmatch.hook;
    }
    /* Check that output hook exists */
    if (out_hook == NULL)
      goto bad;

    NG_FWD_NEW_DATA(error, item, out_hook, m);

    /* Update output hook statistics */
    if (!error) {
	atomic_add_64(
		&((struct ng_route_hookinfo *) NG_HOOK_PRIVATE(out_hook))->stats.out_packets,
		1);
	atomic_add_64(
		&((struct ng_route_hookinfo *) NG_HOOK_PRIVATE(out_hook))->stats.out_octets,
		m->m_pkthdr.len);
    }

    return error; /* On error peer should take care of freeing things */
  } else {
    return (EINVAL);    /* not a hook we know about */
  }

bad:
  NG_FREE_ITEM(item);
  NG_FREE_M(m);
  return error;
}

static inline struct ng_route_hookinfo *
ng_route_findhookinfo(node_p node, const char *name)
{
	const ng_route_p ng_routep = NG_NODE_PRIVATE(node);
	struct ng_route_hookinfo *hinfo;
	const char *cp;
	int link = 0;
	
	if (strncmp(name, NG_ROUTE_HOOK_UP, strlen(NG_ROUTE_HOOK_UP)) == 0) {
		char *eptr;
		
		cp = name + strlen(NG_ROUTE_HOOK_UP);
		if (!isdigit(*cp))
			return (NULL);
		link = (int)strtoul(cp, &eptr, 10);
		if (*eptr != '\0' || link < 0 || link >= NG_ROUTE_MAX_UPLINKS)
			return (NULL);
		
		hinfo = &ng_routep->up[link];
	} else if (strcmp(name, NG_ROUTE_HOOK_DOWN) == 0) {
		hinfo = &ng_routep->down;
	} else if (strcmp(name, NG_ROUTE_HOOK_NOTMATCH) == 0) {
		hinfo = &ng_routep->notmatch;
	} else
		return(NULL);    /* not a hook we know about */
	return(hinfo);
}

static hook_p
ng_route_findhook(node_p node, const char *name)
{
	struct ng_route_hookinfo *hinfo = 
		ng_route_findhookinfo(node, name);

	if (hinfo) {
		return hinfo->hook;
	} else {
		return NULL;
	}
}
static int
ng_route_shutdown(node_p node)
{
  const ng_route_p privdata = NG_NODE_PRIVATE(node);
  NG_NODE_SET_PRIVATE(node, NULL);
  NG_NODE_UNREF(node);
  ng_table_flush(privdata->table4);
  rn_detachhead((void **)&privdata->table4);
  ng_table_flush(privdata->table6);
  rn_detachhead((void **)&privdata->table6);
  free(privdata, M_NETGRAPH_ROUTE);
  return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_route_connect(hook_p hook)
{
  return (0);
}

/*
 * Hook disconnection
 *
 * For this type, removal of the last link destroys the node
 */
static int
ng_route_disconnect(hook_p hook)
{
  /* Remove pointer from node's private data */
  (* (struct ng_route_hookinfo*) NG_HOOK_PRIVATE(hook)).hook = NULL;

  if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
      && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) /* already shutting down? */
    ng_rmnode_self(NG_HOOK_NODE(hook));
  return (0);
}

/*
 * Here begins routing table utility functions.
 */

/* Add entry */
static int
ng_table_add_entry(struct radix_node_head *rnh, void *entry, int type)
{
  struct ng_route_entry *ent = uma_zalloc(ngr_zone, M_WAITOK | M_ZERO);
  struct radix_node *rn;
  struct sockaddr *addr_ptr, *mask_ptr;

  switch (type) {
    case 4:
      KEY_LEN(ent->a.addr4) = KEY_LEN_INET;
      KEY_LEN(ent->m.mask4) = KEY_LEN_INET;
      struct ng_route_tuple4 *newent = entry;
      ent->a.addr4.sin_addr = newent->addr;
      ent->m.mask4.sin_addr = newent->mask;
      /*log(LOG_DEBUG, "Adding address %s ", inet_ntoa(ent->a.addr4.sin_addr));
      log(LOG_DEBUG, "mask %s\n",          inet_ntoa(ent->m.mask4.sin_addr));*/
      ent->value = newent->value;
      addr_ptr = (struct sockaddr *) &ent->a.addr4;
      mask_ptr = (struct sockaddr *) &ent->m.mask4;
      break;

    case 6:
      KEY_LEN(ent->a.addr6) = KEY_LEN_INET6;
      KEY_LEN(ent->m.mask6) = KEY_LEN_INET6;
      struct ng_route_tuple6 *newent6 = entry;
      ent->a.addr6.sin6_addr = newent6->addr;
      ent->m.mask6.sin6_addr = newent6->mask;
      ent->value = newent6->value;
      addr_ptr = (struct sockaddr *) &ent->a.addr6;
      mask_ptr = (struct sockaddr *) &ent->m.mask6;
      break;

    default:
      return (EINVAL);
  }

  rn = rnh->rnh_addaddr(addr_ptr, mask_ptr, rnh, (void *) ent);
  if (rn == NULL) {
    uma_zfree(ngr_zone, ent);
    return (EEXIST);
  }
  return (0);
}

/* Delete entry */
static int
ng_table_del_entry(struct radix_node_head *rnh, void *entry, int type)
{
  struct ng_route_entry *ent;
  struct sockaddr_in    addr4, mask4;
  struct sockaddr_in6   addr6, mask6;
  struct ng_route_tuple4 *newent;
  struct ng_route_tuple6 *newent6;
  struct sockaddr *addr_ptr, *mask_ptr;

  switch (type) {
    case 4:
      KEY_LEN(addr4) = KEY_LEN_INET;
      KEY_LEN(mask4) = KEY_LEN_INET;
      newent = entry;
      addr4.sin_addr = newent->addr;
      mask4.sin_addr = newent->mask;
      addr_ptr = (struct sockaddr *) &addr4;
      mask_ptr = (struct sockaddr *) &mask4;
      break;

    case 6:
      KEY_LEN(addr6) = KEY_LEN_INET6;
      KEY_LEN(mask6) = KEY_LEN_INET6;
      newent6 = entry;
      addr6.sin6_addr = newent6->addr;
      mask6.sin6_addr = newent6->mask;
      addr_ptr = (struct sockaddr *) &addr6;
      mask_ptr = (struct sockaddr *) &mask6;
      break;

    default:
      return (EINVAL);
  }

  ent = (struct ng_route_entry *)rnh->rnh_deladdr(addr_ptr, mask_ptr, rnh);

  if (ent == NULL)
    return (ESRCH);

  uma_zfree(ngr_zone, ent);
  return (0);

}

static int
flush_table_entry(struct radix_node *rn, void *arg)
{
        struct radix_node_head * const rnh = arg;
        struct table_entry *ent;

        ent = (struct table_entry *)
            rnh->rnh_deladdr(rn->rn_key, rn->rn_mask, rnh);
        if (ent != NULL)
                uma_zfree(ngr_zone, ent);
        return (0);
}

static inline int
ng_table_flush(struct radix_node_head *rnh)
{
        if (rnh != NULL) {
                rnh->rnh_walktree(rnh, flush_table_entry, rnh);
        }

        return (0);
}

/* Table lookup */
static int
ng_table_lookup(struct radix_node_head *rnh, void *addrp, int type, u_int32_t *val)
{
  struct ng_route_entry *ent;
  struct sockaddr_in    addr4;
  struct sockaddr_in6   addr6;
  struct sockaddr *addr_ptr;

  switch (type) {
    case 4:
      KEY_LEN(addr4) = KEY_LEN_INET;
      addr4.sin_addr = *((struct  in_addr*) addrp);
      addr_ptr = (struct sockaddr *) &addr4;
      break;

    case 6:
      KEY_LEN(addr6) = KEY_LEN_INET6;
      memcpy(&addr6.sin6_addr, addrp, sizeof(addr6.sin6_addr));
      addr_ptr = (struct sockaddr *) &addr6;
      break;

    default:
      return (EINVAL);
  }
  ent = (struct ng_route_entry *)(rnh->rnh_matchaddr(addr_ptr, rnh));

  if (ent != NULL) {
    *val = ent->value;
    return (1);
  }
  return (0);
}

static int
ng_route_modevent(module_t mod, int type, void *unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		ngr_zone = uma_zcreate("ng_route", sizeof(struct ng_route_entry),
				       NULL, NULL, NULL, NULL,
		    UMA_ALIGN_PTR, 0);
		if (ngr_zone == NULL)
			panic("ng_route: couldn't allocate table zone");
		break;
	case MOD_UNLOAD:
		uma_zdestroy(ngr_zone);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}
