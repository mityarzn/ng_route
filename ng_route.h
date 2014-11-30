/*
 * ng_sample.h
 */

/*-
 * Copyright (c) 2014 Dmitry Petuhov
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
 * Author: Dmitry Petuhov <mityapetuhov@gmail.com>
 */

#ifndef _NETGRAPH_NG_ROUTE_H_
#define _NETGRAPH_NG_ROUTE_H_

/* Node type name. This should be unique among all netgraph node types */
#define NG_ROUTE_NODE_TYPE	"route"

/* Node type cookie. Should also be unique. This value MUST change whenever
   an incompatible change is made to this header file, to insure consistency.
   The de facto method for generating cookies is to take the output of the
   date command: date -u +'%s' */
#define NGM_ROUTE_COOKIE		1411206309

/* Hook names */
#define NG_ROUTE_HOOK_UP	"up"
#define NG_ROUTE_HOOK_DOWN	"down"
#define NG_ROUTE_HOOK_NOTMATCH      "notmatch"

/* Netgraph commands understood by this node type */
enum {
  NGM_ROUTE_ADD4 = 1,
  NGM_ROUTE_ADD6,
  NGM_ROUTE_DEL4,
  NGM_ROUTE_DEL6,
  NGM_ROUTE_FLUSH,
  NGM_ROUTE_SETFLAGS,
  NGM_ROUTE_GETFLAGS,
};

/* Internal type for IPv4 routing table */
struct ng_route_tuple4 {
  struct in_addr 	addr;
  struct in_addr 	mask;
  u_int32_t	value;
};

/* Internal type for IPv6 routing table */
struct ng_route_tuple6 {
  struct in6_addr	addr;
  struct in6_addr	mask;
  uint32_t	value;
};

struct ng_route_flags {
  int8_t direct;
};

struct ng_route_entry {
  struct radix_node	rn[2];
  union {
    struct sockaddr_in	addr4;
    struct sockaddr_in6	addr6;
  } a;
    union {
    struct sockaddr_in	mask4;
    struct sockaddr_in6	mask6;
  } m;
  uint32_t	value;
};

/* No stats here
 */
#endif /* _NETGRAPH_NG_ROUTE_H_ */
