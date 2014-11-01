/*-
 * Copyright (c) 2004-2010 University of Zagreb
 * Copyright (c) 2007-2008 FreeBSD Foundation
 *
 * This software was developed by the University of Zagreb and the
 * FreeBSD Foundation under sponsorship by the Stichting NLnet and the
 * FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: release/10.0.0/sys/netgraph/ng_pipe.c 222257 2011-05-24 14:36:32Z zec $
 */

/*
 * This node permits simple traffic shaping by emulating bandwidth
 * and delay, as well as random packet losses.
 * The node has two hooks, upper and lower. Traffic flowing from upper to
 * lower hook is referenced as downstream, and vice versa. Parameters for
 * both directions can be set separately, except for delay.
 */


#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/time.h>

#include <vm/uma.h>

#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_pipe.h>

static MALLOC_DEFINE(M_NG_PIPE, "ng_pipe", "ng_pipe");

/* Packet header struct */
struct ngpl_hdr {
	TAILQ_ENTRY(ngpl_hdr)	ngpl_link;	/* next pkt in queue */
	struct mbuf		*m;		/* ptr to the packet data */
};
TAILQ_HEAD(p_head, ngpl_hdr);

/* FIFO queue struct */
struct ngpl_fifo {
	TAILQ_ENTRY(ngpl_fifo)	fifo_le;	/* list of active queues only */
	struct p_head		packet_head;	/* FIFO queue head */
	u_int32_t		hash;		/* flow signature */
	struct timeval		vtime;		/* virtual time, for WFQ */
	u_int32_t		rr_deficit;	/* for DRR */
	u_int32_t		packets;	/* # of packets in this queue */
};

/* Per hook info */
struct hookinfo {
	hook_p			hook;
	int			noqueue;	/* bypass any processing */
	TAILQ_HEAD(, ngpl_fifo)	fifo_head;	/* FIFO queues */
	TAILQ_HEAD(, ngpl_hdr)	qout_head;	/* delay queue head */
	struct timeval		qin_utime;
	struct ng_pipe_hookcfg	cfg;
	struct ng_pipe_hookrun	run;
	struct ng_pipe_hookstat	stats;
	struct timeval          last_refill;    /* time of last refill */
};

/* Per node info */
struct node_priv {
	u_int64_t		delay;
	u_int32_t		overhead;
	u_int32_t		header_offset;
	struct hookinfo		lower;
	struct hookinfo		upper;
	struct callout		timer;
	int			timer_scheduled;
};
typedef struct node_priv *priv_p;

/* Macro for calculating the virtual time for packet dequeueing in WFQ */
#define FIFO_VTIME_SORT(plen)						\
	if (hinfo->cfg.wfq && hinfo->cfg.bandwidth) {			\
		ngpl_f->vtime.tv_usec = now->tv_usec + ((uint64_t) (plen) \
			+ priv->overhead ) * hinfo->run.fifo_queues *	\
			8000000 / hinfo->cfg.bandwidth;			\
		ngpl_f->vtime.tv_sec = now->tv_sec +			\
			ngpl_f->vtime.tv_usec / 1000000;			\
		ngpl_f->vtime.tv_usec = ngpl_f->vtime.tv_usec % 1000000;	\
		TAILQ_FOREACH(ngpl_f1, &hinfo->fifo_head, fifo_le)	\
			if (ngpl_f1->vtime.tv_sec > ngpl_f->vtime.tv_sec || \
			    (ngpl_f1->vtime.tv_sec == ngpl_f->vtime.tv_sec && \
			    ngpl_f1->vtime.tv_usec > ngpl_f->vtime.tv_usec)) \
				break;					\
		if (ngpl_f1 == NULL)					\
			TAILQ_INSERT_TAIL(&hinfo->fifo_head, ngpl_f, fifo_le); \
		else							\
			TAILQ_INSERT_BEFORE(ngpl_f1, ngpl_f, fifo_le);	\
	} else								\
		TAILQ_INSERT_TAIL(&hinfo->fifo_head, ngpl_f, fifo_le);	\


static void	parse_cfg(struct ng_pipe_hookcfg *, struct ng_pipe_hookcfg *,
			struct hookinfo *, priv_p);
static void	pipe_dequeue(struct hookinfo *, struct timeval *);
static void	ngpl_callout(node_p, hook_p, void *, int);
static int	ngpl_modevent(module_t, int, void *);

/* zone for storing ngpl_hdr-s */
static uma_zone_t ngpl_zone;

/* Netgraph methods */
static ng_constructor_t	ngpl_constructor;
static ng_rcvmsg_t	ngpl_rcvmsg;
static ng_shutdown_t	ngpl_shutdown;
static ng_newhook_t	ngpl_newhook;
static ng_rcvdata_t	ngpl_rcvdata;
static ng_disconnect_t	ngpl_disconnect;

/* Parse type for struct ng_pipe_hookstat */
static const struct ng_parse_struct_field
	ng_pipe_hookstat_type_fields[] = NG_PIPE_HOOKSTAT_INFO;
static const struct ng_parse_type ng_pipe_hookstat_type = {
	&ng_parse_struct_type,
	&ng_pipe_hookstat_type_fields
};

/* Parse type for struct ng_pipe_stats */
static const struct ng_parse_struct_field ng_pipe_stats_type_fields[] =
	NG_PIPE_STATS_INFO(&ng_pipe_hookstat_type);
static const struct ng_parse_type ng_pipe_stats_type = {
	&ng_parse_struct_type,
	&ng_pipe_stats_type_fields
};

/* Parse type for struct ng_pipe_hookrun */
static const struct ng_parse_struct_field
	ng_pipe_hookrun_type_fields[] = NG_PIPE_HOOKRUN_INFO;
static const struct ng_parse_type ng_pipe_hookrun_type = {
	&ng_parse_struct_type,
	&ng_pipe_hookrun_type_fields
};

/* Parse type for struct ng_pipe_run */
static const struct ng_parse_struct_field
	ng_pipe_run_type_fields[] = NG_PIPE_RUN_INFO(&ng_pipe_hookrun_type);
static const struct ng_parse_type ng_pipe_run_type = {
	&ng_parse_struct_type,
	&ng_pipe_run_type_fields
};

/* Parse type for struct ng_pipe_hookcfg */
static const struct ng_parse_struct_field
	ng_pipe_hookcfg_type_fields[] = NG_PIPE_HOOKCFG_INFO;
static const struct ng_parse_type ng_pipe_hookcfg_type = {
	&ng_parse_struct_type,
	&ng_pipe_hookcfg_type_fields
};

/* Parse type for struct ng_pipe_cfg */
static const struct ng_parse_struct_field
	ng_pipe_cfg_type_fields[] = NG_PIPE_CFG_INFO(&ng_pipe_hookcfg_type);
static const struct ng_parse_type ng_pipe_cfg_type = {
	&ng_parse_struct_type,
	&ng_pipe_cfg_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ngpl_cmds[] = {
	{
		.cookie =	NGM_PIPE_COOKIE,
		.cmd =		NGM_PIPE_GET_STATS,
		.name = 	"getstats",
		.respType =	 &ng_pipe_stats_type
	},
	{
		.cookie =	NGM_PIPE_COOKIE,
		.cmd =		NGM_PIPE_CLR_STATS,
		.name =		"clrstats"
	},
	{
		.cookie =	NGM_PIPE_COOKIE,
		.cmd =		NGM_PIPE_GETCLR_STATS,
		.name =		"getclrstats",
		.respType =	&ng_pipe_stats_type
	},
	{
		.cookie =	NGM_PIPE_COOKIE,
		.cmd =		NGM_PIPE_GET_RUN,
		.name =		"getrun",
		.respType =	&ng_pipe_run_type
	},
	{
		.cookie =	NGM_PIPE_COOKIE,
		.cmd =		NGM_PIPE_GET_CFG,
		.name =		"getcfg",
		.respType =	&ng_pipe_cfg_type
	},
	{
		.cookie =	NGM_PIPE_COOKIE,
		.cmd =		NGM_PIPE_SET_CFG,
		.name =		"setcfg",
		.mesgType =	&ng_pipe_cfg_type,
	},
	{ 0 }
};

/* Netgraph type descriptor */
static struct ng_type ng_pipe_typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_PIPE_NODE_TYPE,
	.mod_event =	ngpl_modevent,
	.constructor =	ngpl_constructor,
	.shutdown =	ngpl_shutdown,
	.rcvmsg =	ngpl_rcvmsg,
	.newhook =	ngpl_newhook,
	.rcvdata =	ngpl_rcvdata,
	.disconnect =	ngpl_disconnect,
	.cmdlist =	ngpl_cmds
};
NETGRAPH_INIT(pipe, &ng_pipe_typestruct);

/* Node constructor */
static int
ngpl_constructor(node_p node)
{
	priv_p priv;

	priv = malloc(sizeof(*priv), M_NG_PIPE, M_ZERO | M_WAITOK);
	NG_NODE_SET_PRIVATE(node, priv);

	/* Mark node as single-threaded */
	NG_NODE_FORCE_WRITER(node);

	ng_callout_init(&priv->timer);

	return (0);
}

/* Add a hook */
static int
ngpl_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct hookinfo *hinfo;

	if (strcmp(name, NG_PIPE_HOOK_UPPER) == 0) {
		bzero(&priv->upper, sizeof(priv->upper));
		priv->upper.hook = hook;
		NG_HOOK_SET_PRIVATE(hook, &priv->upper);
	} else if (strcmp(name, NG_PIPE_HOOK_LOWER) == 0) {
		bzero(&priv->lower, sizeof(priv->lower));
		priv->lower.hook = hook;
		NG_HOOK_SET_PRIVATE(hook, &priv->lower);
	} else
		return (EINVAL);

	/* Load non-zero initial cfg values */
	hinfo = NG_HOOK_PRIVATE(hook);
	hinfo->cfg.qin_size_limit = 50;
	hinfo->cfg.fifo = 1;
	hinfo->cfg.droptail = 1;
	TAILQ_INIT(&hinfo->fifo_head);
	TAILQ_INIT(&hinfo->qout_head);
	return (0);
}

/* Receive a control message */
static int
ngpl_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	struct ng_mesg *msg, *flow_msg;
	struct ng_pipe_stats *stats;
	struct ng_pipe_run *run;
	struct ng_pipe_cfg *cfg;
	int error = 0;
	int prev_down, now_down, cmd;

	NGI_GET_MSG(item, msg);
	switch (msg->header.typecookie) {
	case NGM_PIPE_COOKIE:
		switch (msg->header.cmd) {
		case NGM_PIPE_GET_STATS:
		case NGM_PIPE_CLR_STATS:
		case NGM_PIPE_GETCLR_STATS:
			if (msg->header.cmd != NGM_PIPE_CLR_STATS) {
				NG_MKRESPONSE(resp, msg,
				    sizeof(*stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				stats = (struct ng_pipe_stats *) resp->data;
				bcopy(&priv->upper.stats, &stats->downstream,
				    sizeof(stats->downstream));
				bcopy(&priv->lower.stats, &stats->upstream,
				    sizeof(stats->upstream));
			}
			if (msg->header.cmd != NGM_PIPE_GET_STATS) {
				bzero(&priv->upper.stats,
				    sizeof(priv->upper.stats));
				bzero(&priv->lower.stats,
				    sizeof(priv->lower.stats));
			}
			break;
		case NGM_PIPE_GET_RUN:
			NG_MKRESPONSE(resp, msg, sizeof(*run), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			run = (struct ng_pipe_run *) resp->data;
			bcopy(&priv->upper.run, &run->downstream,
				sizeof(run->downstream));
			bcopy(&priv->lower.run, &run->upstream,
				sizeof(run->upstream));
			break;
		case NGM_PIPE_GET_CFG:
			NG_MKRESPONSE(resp, msg, sizeof(*cfg), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			cfg = (struct ng_pipe_cfg *) resp->data;
			bcopy(&priv->upper.cfg, &cfg->downstream,
				sizeof(cfg->downstream));
			bcopy(&priv->lower.cfg, &cfg->upstream,
				sizeof(cfg->upstream));
			cfg->overhead = priv->overhead;
			if (cfg->upstream.bandwidth ==
			    cfg->downstream.bandwidth) {
				cfg->bandwidth = cfg->upstream.bandwidth;
				cfg->upstream.bandwidth = 0;
				cfg->downstream.bandwidth = 0;
			} else
				cfg->bandwidth = 0;
			break;
		case NGM_PIPE_SET_CFG:
			cfg = (struct ng_pipe_cfg *) msg->data;
			if (msg->header.arglen != sizeof(*cfg)) {
				error = EINVAL;
				break;
			}

			if (cfg->bandwidth == -1) {
				priv->upper.cfg.bandwidth = 0;
				priv->lower.cfg.bandwidth = 0;
				priv->overhead = 0;
			} else if (cfg->bandwidth >= 100 &&
			    cfg->bandwidth <= 1000000000) {
				priv->upper.cfg.bandwidth = cfg->bandwidth;
				priv->lower.cfg.bandwidth = cfg->bandwidth;
				if (cfg->bandwidth >= 10000000)
					priv->overhead = 8+4+12; /* Ethernet */
				else
					priv->overhead = 10; /* HDLC */
			}

			if (cfg->overhead == -1)
				priv->overhead = 0;
			else if (cfg->overhead > 0 &&
			    cfg->overhead < MAX_OHSIZE)
				priv->overhead = cfg->overhead;

			parse_cfg(&priv->upper.cfg, &cfg->downstream,
			    &priv->upper, priv);
			parse_cfg(&priv->lower.cfg, &cfg->upstream,
			    &priv->lower, priv);

                        break;
		default:
			error = EINVAL;
			break;
		}
		break;
	default:
		error = EINVAL;
		break;
	}
	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);

	return (error);
}

static void
parse_cfg(struct ng_pipe_hookcfg *current, struct ng_pipe_hookcfg *new,
	struct hookinfo *hinfo, priv_p priv)
{

	if (new->qin_size_limit == -1)
		current->qin_size_limit = 0;
	else if (new->qin_size_limit >= 5)
		current->qin_size_limit = new->qin_size_limit;

	if (new->fifo) {
		current->fifo = 1;
		current->wfq = 0;
		current->drr = 0;
	}

	if (new->wfq) {
		current->fifo = 0;
		current->wfq = 1;
		current->drr = 0;
	}

	if (new->drr) {
		current->fifo = 0;
		current->wfq = 0;
		/* DRR quantum */
		if (new->drr >= 32)
			current->drr = new->drr;
		else
			current->drr = 2048;		/* default quantum */
	}

	if (new->droptail) {
		current->droptail = 1;
	}

	if (new->bandwidth == -1) {
		current->bandwidth = 0;
		current->fifo = 1;
		current->wfq = 0;
		current->drr = 0;
	} else if (new->bandwidth >= 100 && new->bandwidth <= 1000000000)
		current->bandwidth = new->bandwidth;

	if (current->bandwidth)
		hinfo->noqueue = 0;
	else
		hinfo->noqueue = 1;
}

/*
 * TODO: Add IPv6 support.
 * Compute a hash signature for a packet. This function suffers from the
 * NIH sindrome, so probably it would be wise to look around what other
 * folks have found out to be a good and efficient IP hash function...
 */
static int
ip_hash(struct mbuf *m, int offset)
{
	u_int64_t i;
	struct ip *ip = (struct ip *)(mtod(m, u_char *) + offset);

	if (m->m_len < sizeof(struct ip) + offset ||
	    ip->ip_v != 4 || ip->ip_hl << 2 != sizeof(struct ip))
		return 0;

	i = ((u_int64_t) ip->ip_src.s_addr ^
	    ((u_int64_t) ip->ip_src.s_addr << 13) ^
	    ((u_int64_t) ip->ip_dst.s_addr << 7) ^
	    ((u_int64_t) ip->ip_dst.s_addr << 19));
	return (i ^ (i >> 32));
}

/*
 * Receive data on a hook - both in upstream and downstream direction.
 * We put the frame on the inbound queue, and try to initiate dequeuing
 * sequence immediately. If inbound queue is full, discard one frame
 * depending on dropping policy (from the head or from the tail of the
 * queue).
 */
static int
ngpl_rcvdata(hook_p hook, item_p item)
{
	struct hookinfo *const hinfo = NG_HOOK_PRIVATE(hook);
	const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct timeval uuptime;
	struct timeval *now = &uuptime;
	struct ngpl_fifo *ngpl_f = NULL, *ngpl_f1;
	struct ngpl_hdr *ngpl_h = NULL;
	struct mbuf *m;
	int hash, plen;
	int error = 0;

        getmicrouptime(now);

        /* Populate the packet header */
	ngpl_h = uma_zalloc(ngpl_zone, M_NOWAIT);
	KASSERT((ngpl_h != NULL), ("ngpl_h zalloc failed (1)"));
	NGI_GET_M(item, m);
	KASSERT(m != NULL, ("NGI_GET_M failed"));
	ngpl_h->m = m;
	NG_FREE_ITEM(item);

	if (hinfo->cfg.fifo)
		hash = 0;	/* all packets go into a single FIFO queue */
	else
		hash = ip_hash(m, priv->header_offset);

	/* Find the appropriate FIFO queue for the packet and enqueue it*/
	TAILQ_FOREACH(ngpl_f, &hinfo->fifo_head, fifo_le)
		if (hash == ngpl_f->hash)
			break;
	if (ngpl_f == NULL) {
		ngpl_f = uma_zalloc(ngpl_zone, M_NOWAIT);
		KASSERT(ngpl_h != NULL, ("ngpl_h zalloc failed (2)"));
		TAILQ_INIT(&ngpl_f->packet_head);
		ngpl_f->hash = hash;
		ngpl_f->packets = 1;
		ngpl_f->rr_deficit = hinfo->cfg.drr;	/* DRR quantum */
		hinfo->run.fifo_queues++;
		TAILQ_INSERT_TAIL(&ngpl_f->packet_head, ngpl_h, ngpl_link);
		FIFO_VTIME_SORT(m->m_pkthdr.len);
	} else {
		TAILQ_INSERT_TAIL(&ngpl_f->packet_head, ngpl_h, ngpl_link);
		ngpl_f->packets++;
	}
	hinfo->run.qin_frames++;
	hinfo->run.qin_octets += m->m_pkthdr.len;

	/* Discard a frame if inbound queue limit has been reached */
	if (hinfo->run.qin_frames > hinfo->cfg.qin_size_limit) {
		struct mbuf *m1;
		int longest = 0;

		/* Find the longest queue */
		TAILQ_FOREACH(ngpl_f1, &hinfo->fifo_head, fifo_le)
			if (ngpl_f1->packets > longest) {
				longest = ngpl_f1->packets;
				ngpl_f = ngpl_f1;
			}

		/* Drop a frame from the queue head/tail, depending on cfg */
		if (hinfo->cfg.drophead)
			ngpl_h = TAILQ_FIRST(&ngpl_f->packet_head);
		else
			ngpl_h = TAILQ_LAST(&ngpl_f->packet_head, p_head);
		TAILQ_REMOVE(&ngpl_f->packet_head, ngpl_h, ngpl_link);
		m1 = ngpl_h->m;
		uma_zfree(ngpl_zone, ngpl_h);
		hinfo->run.qin_octets -= m1->m_pkthdr.len;
		hinfo->stats.in_disc_octets += m1->m_pkthdr.len;
		m_freem(m1);
		if (--(ngpl_f->packets) == 0) {
			TAILQ_REMOVE(&hinfo->fifo_head, ngpl_f, fifo_le);
			uma_zfree(ngpl_zone, ngpl_f);
			hinfo->run.fifo_queues--;
		}
		hinfo->run.qin_frames--;
		hinfo->stats.in_disc_frames++;
	}

	/*
	 * Try to start the dequeuing process immediately.
	 */
	pipe_dequeue(hinfo, now);

	return (0);
}


/*
 * Dequeueing sequence - we basically do the following:
 *  1) Try to extract the frame from the inbound (bandwidth) queue;
 *  2) In accordance to BER specified, discard the frame randomly;
 *  3) If the frame survives BER, prepend it with delay info and move it
 *     to outbound (delay) queue;
 *  4) Loop to 2) until bandwidth quota for this timeslice is reached, or
 *     inbound queue is flushed completely;
 *  5) Dequeue frames from the outbound queue and send them downstream until
 *     outbound queue is flushed completely, or the next frame in the queue
 *     is not due to be dequeued yet
 */
static void
pipe_dequeue(struct hookinfo *hinfo, struct timeval *now) {
	static uint64_t rand, oldrand;
	const node_p node = NG_HOOK_NODE(hinfo->hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct hookinfo *dest;
	struct ngpl_fifo *ngpl_f, *ngpl_f1;
	struct ngpl_hdr *ngpl_h;
	struct timeval *when;
	struct mbuf *m;
	int plen, error = 0;

	/* Which one is the destination hook? */
	if (hinfo == &priv->lower)
		dest = &priv->upper;
	else
		dest = &priv->lower;

	/* Bandwidth queue processing */
	while ((ngpl_f = TAILQ_FIRST(&hinfo->fifo_head))) {
		when = &hinfo->qin_utime;
		if (when->tv_sec > now->tv_sec || (when->tv_sec == now->tv_sec
		    && when->tv_usec > now->tv_usec))
			break;

		ngpl_h = TAILQ_FIRST(&ngpl_f->packet_head);
		m = ngpl_h->m;

		/* Deficit Round Robin (DRR) processing */
		if (hinfo->cfg.drr) {
			if (ngpl_f->rr_deficit >= m->m_pkthdr.len) {
				ngpl_f->rr_deficit -= m->m_pkthdr.len;
			} else {
				ngpl_f->rr_deficit += hinfo->cfg.drr;
				TAILQ_REMOVE(&hinfo->fifo_head, ngpl_f, fifo_le);
				TAILQ_INSERT_TAIL(&hinfo->fifo_head,
				    ngpl_f, fifo_le);
				continue;
			}
		}

		/* Actually dequeue packet */
		TAILQ_REMOVE(&ngpl_f->packet_head, ngpl_h, ngpl_link);
		hinfo->run.qin_frames--;
		hinfo->run.qin_octets -= m->m_pkthdr.len;
		ngpl_f->packets--;

		/* Sort / rearrange inbound queues */
		if (ngpl_f->packets) {
			if (hinfo->cfg.wfq) {
				TAILQ_REMOVE(&hinfo->fifo_head, ngpl_f, fifo_le);
				FIFO_VTIME_SORT(TAILQ_FIRST(
				    &ngpl_f->packet_head)->m->m_pkthdr.len)
			}
		} else {
			TAILQ_REMOVE(&hinfo->fifo_head, ngpl_f, fifo_le);
			uma_zfree(ngpl_zone, ngpl_f);
			hinfo->run.fifo_queues--;
		}

                NG_SEND_DATA_ONLY(error, dest->hook, m);
                if (error) {
                        hinfo->stats.out_disc_frames++;
                        hinfo->stats.out_disc_octets += plen;
                } else {
                        hinfo->stats.fwd_frames++;
                        hinfo->stats.fwd_octets += plen;
                }

		hinfo->run.qout_frames++;
		hinfo->run.qout_octets += m->m_pkthdr.len;
	}

	if (hinfo->run.qin_frames != 0 &&
	    !priv->timer_scheduled) {
		ng_callout(&priv->timer, node, NULL, 1, ngpl_callout, NULL, 0);
		priv->timer_scheduled = 1;
	}
}

/*
 * This routine is called on every clock tick.  We poll connected hooks
 * for queued frames by calling pipe_dequeue().
 */
static void
ngpl_callout(node_p node, hook_p hook, void *arg1, int arg2)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct timeval now;

	priv->timer_scheduled = 0;
	getmicrouptime(&now);
	if (priv->upper.hook != NULL)
		pipe_dequeue(&priv->upper, &now);
	if (priv->lower.hook != NULL)
		pipe_dequeue(&priv->lower, &now);
}

/*
 * Shutdown processing
 *
 * This is tricky. If we have both a lower and upper hook, then we
 * probably want to extricate ourselves and leave the two peers
 * still linked to each other. Otherwise we should just shut down as
 * a normal node would.
 */
static int
ngpl_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	if (priv->timer_scheduled)
		ng_uncallout(&priv->timer, node);
	if (priv->lower.hook && priv->upper.hook)
		ng_bypass(priv->lower.hook, priv->upper.hook);
	else {
		if (priv->upper.hook != NULL)
			ng_rmhook_self(priv->upper.hook);
		if (priv->lower.hook != NULL)
			ng_rmhook_self(priv->lower.hook);
	}
	NG_NODE_UNREF(node);
	free(priv, M_NG_PIPE);
	return (0);
}


/*
 * Hook disconnection
 */
static int
ngpl_disconnect(hook_p hook)
{
	struct hookinfo *const hinfo = NG_HOOK_PRIVATE(hook);
	struct ngpl_fifo *ngpl_f;
	struct ngpl_hdr *ngpl_h;

	KASSERT(hinfo != NULL, ("%s: null info", __FUNCTION__));
	hinfo->hook = NULL;

	/* Flush all fifo queues associated with the hook */
	while ((ngpl_f = TAILQ_FIRST(&hinfo->fifo_head))) {
		while ((ngpl_h = TAILQ_FIRST(&ngpl_f->packet_head))) {
			TAILQ_REMOVE(&ngpl_f->packet_head, ngpl_h, ngpl_link);
			m_freem(ngpl_h->m);
			uma_zfree(ngpl_zone, ngpl_h);
		}
		TAILQ_REMOVE(&hinfo->fifo_head, ngpl_f, fifo_le);
		uma_zfree(ngpl_zone, ngpl_f);
	}

	/* Flush the delay queue */
	while ((ngpl_h = TAILQ_FIRST(&hinfo->qout_head))) {
		TAILQ_REMOVE(&hinfo->qout_head, ngpl_h, ngpl_link);
		m_freem(ngpl_h->m);
		uma_zfree(ngpl_zone, ngpl_h);
	}

	/* Release the packet loss probability table (BER) */
	if (hinfo->ber_p)
		free(hinfo->ber_p, M_NG_PIPE);

	return (0);
}

static int
ngpl_modevent(module_t mod, int type, void *unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		ngpl_zone = uma_zcreate("ng_pipe_lite", max(sizeof(struct ngpl_hdr),
		    sizeof (struct ngpl_fifo)), NULL, NULL, NULL, NULL,
		    UMA_ALIGN_PTR, 0);
		if (ngpl_zone == NULL)
			panic("ng_pipe: couldn't allocate descriptor zone");
		break;
	case MOD_UNLOAD:
		uma_zdestroy(ngpl_zone);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}
