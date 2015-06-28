/* $Id$ */
/* Copyright (C) 2005 Nicholas Harbour
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* This file is part of
   Tcpxtract, a sniffer that extracts files based on headers
   by Nick Harbour
*/

#ifndef SESSIONLIST_H
#define SESSIONLIST_H

#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "extract.h"
#include "search.h"

typedef struct {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t eth_src[ETHER_ADDR_LEN];
    uint8_t eth_dst[ETHER_ADDR_LEN];
    uint16_t port_src;
    uint16_t port_dst;
} connection_t;

typedef struct slist_node {
    struct slist_node *prev;
    struct slist_node *next;    
    connection_t connection; 
    int last_seqnum;         /* the last sequence number recieved */
    time_t last_recvd;           /* the last time a packet was seen */
    int recording;               /* whether we are currently extracting data */
    srchptr_list_t *srchptr_list;   /* current search threads */
    extract_list_t *extract_list;   /* list of current files being extracted */
} slist_t;

extern slist_t *add_session(slist_t **, connection_t *);
extern slist_t *find_session(slist_t **, connection_t *);
extern void sweep_sessions(slist_t **);

/* for debugging */
extern int count_sessions(slist_t *);

#endif /* SESSIONLIST_H */
