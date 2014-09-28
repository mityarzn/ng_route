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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/ctype.h>
#include <sys/errno.h>
#include <sys/syslog.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_sample.h>
#include <netgraph/netgraph.h>

/* If you do complicated mallocs you may want to do this */
/* and use it for your mallocs */
#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(M_NETGRAPH_ROUTE, "netgraph_route", "netgraph route node");
#else
#define M_NETGRAPH_ROUTE M_NETGRAPH
#endif

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
 * This section contains the netgraph method declarations for the
 * sample node. These methods define the netgraph 'type'.
 */

static ng_constructor_t	ng_route_constructor;
static ng_rcvmsg_t	ng_route_rcvmsg;
static ng_shutdown_t	ng_route_shutdown;
static ng_newhook_t	ng_route_newhook;
static ng_connect_t	ng_route_connect;
static ng_rcvdata_t	ng_route_rcvdata;
static ng_disconnect_t	ng_route_disconnect;

/* Parse types */
// IPv4 tuple subtype and supertype
struct ng_parse_struct_info ng_route_tuple4_fields = {
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
struct ng_parse_struct_info ng_route_tuple6_fields = {
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
struct ng_parse_struct_info ng_route_flags_fields = {
  /* indicating matching direction: source (1) or destination (0) address */
  { "direct",	&ng_parse_int8_type },
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
    NGM_ROUTE_PRINT,
    "print",
    NULL
    NULL, /* TODO: make struct of 2 arrays (for v4 and v6) here */
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
  { 0 }
};

/* Netgraph node type descriptor */
static struct ng_type typestruct = {
  .version =	NG_ABI_VERSION,
  .name =		NG_ROUTE_NODE_TYPE,
  .constructor =	ng_route_constructor,
  .rcvmsg =	ng_route_rcvmsg,
  .shutdown =	ng_route_shutdown,
  .newhook =	ng_route_newhook,
  /*	.findhook =	ng_route_findhook, 	*/
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
};

/* Information we store for each node */
struct ng_route {
  struct 	 ng_route_hookinfo up[NG_ROUTE_MAX_UPLINKS];
  struct 	 ng_route_hookinfo down;
  node_p	 node;		/* back pointer to node */
  ng_route_flags flags;
  struct radix_node_head *table4;
  struct radix_node_head *table6;
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
  int i;
  
  /* Initialize private descriptors */
  privdata = malloc(sizeof(*privdata), M_NETGRAPH_ROUTE, M_WAITOK | M_ZERO);
  if (privdata == NULL) goto init_error;
  table4 = malloc(sizeof(*table4), M_NETGRAPH_ROUTE, M_WAITOK | M_ZERO);
  if (table4 == NULL) goto init_error;
  table6 = malloc(sizeof(*table6), M_NETGRAPH_ROUTE, M_WAITOK | M_ZERO);
  if (table6 == NULL) goto init_error;

  /* Init tables */
  if (!rn_inithead((void **)&table4, OFF_LEN_INET4) || 
      !rn_inithead((void **)&table6, OFF_LEN_INET6)) 
	goto init_error;
  /* Link structs together; this counts as our one reference to *nodep */
  NG_NODE_SET_PRIVATE(node, privdata);
  privdata->node = node;
  return (0);
  
init_error:
  if (privdata != NULL)
    free(privdata,M_NETGRAPH_ROUTE);
  if (table4 != NULL)
    free(table4,M_NETGRAPH_ROUTE);
  if (table6 != NULL)
    free(table6,M_NETGRAPH_ROUTE);
  return (ENOMEM);
}

/*
 * Give our ok for a hook to be added...
 * If we are not running this might kick a device into life.
 * Possibly decode information out of the hook name.
 * Add the hook's private info to the hook structure.
 * (if we had some).
 */
static int
ng_route_newhook(node_p node, hook_p hook, const char *name)
{
  const ng_route_p ng_routep = NG_NODE_PRIVATE(node);
  const char *cp;
  int link = 0;
  
  if (strncmp(name, NG_ROUTE_HOOK_UP, strlen(NG_ROUTE_HOOK_UP)) == 0) {
    char *eptr;
  
    cp = name + strlen(NG_ROUTE_HOOK_UP);
    if (!isdigit(*cp))
      return (EINVAL);
    link = (int)strtoul(cp, &eptr, 10);
    if (*eptr != '\0' || link < 0 || link >= NG_ROUTE_MAX_UPLINKS)
      return (EINVAL);

    ng_routep->up[link].hook = hook;
    NG_HOOK_SET_PRIVATE(hook, ng_routep->up + link);
    return (0);
  } else if (strcmp(name, NG_ROUTE_HOOK_DOWN) == 0) {
    /* Example of simple predefined hooks. */
    /* do something specific to the downstream connection */
    ng_routep->down.hook = hook;
    NG_HOOK_SET_PRIVATE(hook, &ng_routep->down);
  } else
    return (EINVAL);	/* not a hook we know about */
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
	{
	  ng_table_add_entry(ng_routep->table4, msg->data, 4);
	}
	case NGM_ROUTE_ADD6:
	{
	  ng_table_add_entry(ng_routep->table6, msg->data, 6);
	}
	case NGM_ROUTE_GET_STATUS:
	{
	  struct ngxxxstat *stats;
	  
	  NG_MKRESPONSE(resp, msg, sizeof(*stats), M_NOWAIT);
	  if (!resp) {
	    error = ENOMEM;
	    break;
	  }
	  stats = (struct ngxxxstat *) resp->data;
	  stats->packets_in = ng_routep->packets_in;
	  stats->packets_out = ng_routep->packets_out;
	  break;
	}
	case NGM_ROUTE_SET_FLAG:
	  if (msg->header.arglen != sizeof(u_int32_t)) {
	    error = EINVAL;
	    break;
	  }
	  ng_routep->flags = *((u_int32_t *) msg->data);
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

/*
 * Receive data, and do something with it.
 * Actually we receive a queue item which holds the data.
 * If we free the item it will also free the data unless we have
 * previously disassociated it using the NGI_GET_M() macro.
 * Possibly send it out on another link after processing.
 * Possibly do something different if it comes from different
 * hooks. The caller will never free m, so if we use up this data or
 * abort we must free it.
 *
 * If we want, we may decide to force this data to be queued and reprocessed
 * at the netgraph NETISR time.
 * We would do that by setting the HK_QUEUE flag on our hook. We would do that
 * in the connect() method.
 */
static int
ng_route_rcvdata(hook_p hook, item_p item )
{
  const ng_route_p ng_routep = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
  int chan = -2;
  int dlci = -2;
  int error;
  struct mbuf *m;
  
  NGI_GET_M(item, m);
  if (NG_HOOK_PRIVATE(hook)) {
    dlci = ((struct XXX_hookinfo *) NG_HOOK_PRIVATE(hook))->dlci;
    chan = ((struct XXX_hookinfo *) NG_HOOK_PRIVATE(hook))->channel;
    if (dlci != -1) {
      /* If received on a DLCI hook process for this
       * channel and pass it to the downstream module.
       * Normally one would add a multiplexing header at
       * the front here */
      /* M_PREPEND(....)	; */
      /* mtod(m, xxxxxx)->dlci = dlci; */
      NG_FWD_NEW_DATA(error, item,
		      ng_routep->downstream_hook.hook, m);
      ng_routep->packets_out++;
    } else {
      /* data came from the multiplexed link */
      dlci = 1;	/* get dlci from header */
      /* madjust(....) *//* chop off header */
      for (chan = 0; chan < XXX_NUM_DLCIS; chan++)
	if (ng_routep->channel[chan].dlci == dlci)
	  break;
	if (chan == XXX_NUM_DLCIS) {
	  NG_FREE_ITEM(item);
	  NG_FREE_M(m);
	  return (ENETUNREACH);
	}
	/* If we were called at splnet, use the following:
	 * NG_SEND_DATA_ONLY(error, otherhook, m); if this
	 * node is running at some SPL other than SPLNET
	 * then you should use instead: error =
	 * ng_queueit(otherhook, m, NULL); m = NULL;
	 * This queues the data using the standard NETISR
	 * system and schedules the data to be picked
	 * up again once the system has moved to SPLNET and
	 * the processing of the data can continue. After
	 * these are run 'm' should be considered
	 * as invalid and NG_SEND_DATA actually zaps them. */
	NG_FWD_NEW_DATA(error, item,
			ng_routep->channel[chan].hook, m);
	ng_routep->packets_in++;
    }
  } else {
    /* It's the debug hook, throw it away.. */
    if (hook == ng_routep->downstream_hook.hook) {
      NG_FREE_ITEM(item);
      NG_FREE_M(m);
    }
  }
  return 0;
}


/*
 * Do local shutdown processing..
 * All our links and the name have already been removed.
 * If we are a persistant device, we might refuse to go away.
 * In the case of a persistant node we signal the framework that we
 * are still in business by clearing the NGF_INVALID bit. However
 * If we find the NGF_REALLY_DIE bit set, this means that
 * we REALLY need to die (e.g. hardware removed).
 * This would have been set using the NG_NODE_REALLY_DIE(node)
 * macro in some device dependent function (not shown here) before
 * calling ng_rmnode_self().
 */
static int
ng_route_shutdown(node_p node)
{
  const ng_route_p privdata = NG_NODE_PRIVATE(node);
  
  #ifndef PERSISTANT_NODE
  NG_NODE_SET_PRIVATE(node, NULL);
  NG_NODE_UNREF(node);
  free(privdata, M_NETGRAPH);
  #else
  if (node->nd_flags & NGF_REALLY_DIE) {
    /*
     * WE came here because the widget card is being unloaded,
     * so stop being persistant.
     * Actually undo all the things we did on creation.
     */
    NG_NODE_SET_PRIVATE(node, NULL);
    NG_NODE_UNREF(privdata->node);
    free(privdata, M_NETGRAPH);
    return (0);
  }
  NG_NODE_REVIVE(node);		/* tell ng_rmnode() we will persist */
  #endif /* PERSISTANT_NODE */
  return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_route_connect(hook_p hook)
{
  #if 0
  /*
   * If we were a driver running at other than splnet then
   * we should set the QUEUE bit on the edge so that we
   * will deliver by queing.
   */
  if /*it is the upstream hook */
    NG_HOOK_FORCE_QUEUE(NG_HOOK_PEER(hook));
  #endif
  #if 0
  /*
   * If for some reason we want incoming date to be queued
   * by the NETISR system and delivered later we can set the same bit on
   * OUR hook. (maybe to allow unwinding of the stack)
   */
  
  if (NG_HOOK_PRIVATE(hook)) {
  int dlci;
  /*
   * If it's dlci 1023, requeue it so that it's handled
   * at a lower priority. This is how a node decides to
   * defer a data message.
   */
  dlci = ((struct XXX_hookinfo *) NG_HOOK_PRIVATE(hook))->dlci;
  if (dlci == 1023) {
  NG_HOOK_FORCE_QUEUE(hook);
  }
  #endif
  /* otherwise be really amiable and just say "YUP that's OK by me! " */
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
  if (NG_HOOK_PRIVATE(hook))
    ((struct XXX_hookinfo *) (NG_HOOK_PRIVATE(hook)))->hook = NULL;
  if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
    && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) /* already shutting down? */
  ng_rmnode_self(NG_HOOK_NODE(hook));
  return (0);
}

/*
 * Here begins routing table utility functions.
 */

/* Aadd entry */
int
ng_table_add_entry(radix_node_head *rnh, void *entry, int type)
{
  struct ng_route_entry *ent = malloc(sizeof(*ent), M_IPFW_TBL, M_WAITOK | M_ZERO);
  struct radix_node *rn;
  struct sockaddr *addr_ptr, *mask_ptr;
  char c;
  
  switch (type) {
    case 4:
      KEY_LEN(ent->a.addr4) = KEY_LEN_INET;
      KEY_LEN(ent->m.mask4) = KEY_LEN_INET;
      struct ng_route_tuple4 * newent = entry;
      ent->a.addr4.sin_addr = newent->addr.sin_addr;
      ent->m.mask4.sin_addr = newent->mask.sin_addr;
      ent->value = newent->value;
      addr_ptr = &ent->a.addr4;
      mask_ptr = &ent->m.mask4;
      break;
      
    case 6:
      KEY_LEN(ent->a.addr6) = KEY_LEN_INET6;
      KEY_LEN(ent->m.mask6) = KEY_LEN_INET6;
      struct ng_route_tuple6 * newent = entry;
      memcpy(&ent->a.addr6.sin6_addr, &newent->addr6.sin6_addr,
	     sizeof(newent->addr6));
      memcpy(&ent->m.mask6.sin6_addr, &newent->mask6.sin6_addr, 
	     sizeof(newent->mask6));
      ent->value = newent->value;
      addr_ptr = &ent->a.addr6;
      mask_ptr = &ent->m.mask6;
      break;
      
    default:
      return (EINVAL);
  }
  
  rn = rnh->rnh_addaddr(addr_ptr, mask_ptr, rnh, (void *) ent);
  if (rn == NULL) {
    free(ent_ptr, M_IPFW_TBL);
    return (EEXIST);
  }
  return (0);
}



