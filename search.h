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

#ifndef SEARCH_H
#define SEARCH_H

#include <sys/types.h>
#include <inttypes.h>

typedef enum {
    TABLE,
    COMPLETE
} srch_nodetype_t;

typedef enum {
    HEADER,
    FOOTER
} spectype_t;

typedef struct {
    int id;
    char *ext;
    unsigned long maxlen;
    size_t len;    /* the length of the header or footer */
} fileid_t;

/* srch_node_t objects represent the compiled form of a set of search keywords */
typedef struct srch_node {
    srch_nodetype_t nodetype;
    spectype_t spectype;
    union {
        struct srch_node *table[256];
        fileid_t fileid;
    } data;
} srch_node_t;

/* srchptr_list_t is for maintaining a list of concurrent search threads */
typedef struct srchptr_list {
    struct srchptr_list *next;
    struct srchptr_list *prev;
    srch_node_t *node;
} srchptr_list_t;

typedef struct srch_results {
    struct srch_results *next;
    struct srch_results *prev;
    fileid_t *fileid;
    spectype_t spectype;
    struct {
        int start;    /* for HEADERs */
        int end;      /* for FOOTERs */
    } offset;
} srch_results_t;

extern srch_node_t *srch_machine;

extern void compile_srch(srch_node_t **, int, char *, unsigned long, char *, spectype_t);
extern srch_results_t *search(srch_node_t *, srchptr_list_t **, uint8_t *, size_t);
extern void free_results_list(srch_results_t **);

#endif /* SEARCH_H */
