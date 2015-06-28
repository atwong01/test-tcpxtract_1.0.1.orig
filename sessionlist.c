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
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "sessionlist.h"
#include "util.h"

slist_t *add_session(slist_t **slist, connection_t *conn)
{
    slist_t **last_slist;
    slist_t *slist_ptr = NULL;

    
    assert(slist != NULL);
    assert(conn != NULL);

    /* find where to append a new element (aka. the end) */
    if (*slist == NULL)
        last_slist = slist;
    else {
        for (slist_ptr = *slist; slist_ptr->next != NULL; slist_ptr = slist_ptr->next)
            ;
        last_slist = &slist_ptr->next;
    }

    *last_slist = (slist_t *) emalloc(sizeof (slist_t));

    memcpy(&(*last_slist)->connection, conn, sizeof (*conn));
    (*last_slist)->prev = slist_ptr;
    (*last_slist)->next = NULL;
    (*last_slist)->srchptr_list = NULL;
    return *last_slist;
}

slist_t *find_session(slist_t **slist, connection_t *conn)
{
    slist_t *slist_ptr;
    uint32_t ip_src;       /* keep this so we don't need to dereference conn each time */

    assert(slist != NULL);
    assert(conn != NULL);

    ip_src = conn->ip_src;
    
    for (slist_ptr = *slist; slist_ptr != NULL; slist_ptr = slist_ptr->next) {
        if (ip_src == slist_ptr->connection.ip_src
            && memcmp(conn, &slist_ptr->connection, sizeof (connection_t)) == 0)
        {
            /* we've found it */
            break;
        }
    }

    if (slist_ptr == NULL)
        return NULL;

    /* move the newly found session to the top of the list */
    
    if (slist_ptr->prev != NULL)
        slist_ptr->prev->next = slist_ptr->next;

    if (slist_ptr->next != NULL)
        slist_ptr->next->prev = slist_ptr->prev;

    slist_ptr->prev = NULL;
    if (*slist != slist_ptr)
        slist_ptr->next = *slist;
    
    if (slist_ptr->next != NULL)
        slist_ptr->next->prev = slist_ptr;

    *slist = slist_ptr;

    return slist_ptr;
}

/* This function cleans out any old sessions from the list */
void sweep_sessions(slist_t **slist)
{
    const int TIMETOKILL = 30;  /* remove session if stale for 30 seconds */
    time_t currtime = time(NULL);
    slist_t *slist_ptr, *slist_next;

    assert(slist != NULL);

    for (slist_ptr = *slist; slist_ptr != NULL; slist_ptr = slist_next) {
        slist_next = slist_ptr->next;
        if (currtime - slist_ptr->last_recvd >= TIMETOKILL) {
            if (slist_ptr->prev == NULL) {
                *slist = slist_ptr->next;
                if (slist_ptr->next != NULL)
                    slist_ptr->next->prev = NULL;
                free(slist_ptr);
            } else {
                slist_ptr->prev->next = slist_ptr->next;
                if (slist_ptr->next != NULL)
                    slist_ptr->next->prev = slist_ptr->prev;
                free(slist_ptr);
            }
        }
    }
}

int count_sessions(slist_t *slist)
{
    slist_t *ptr;
    int count = 0;

    for (ptr = slist; ptr != NULL; ptr = ptr->next)
        count++;

    return count;
}
