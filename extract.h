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

#ifndef EXTRACT_H
#define EXTRACT_H

#include <sys/types.h>
#include <inttypes.h>
#include "search.h"
//#include "sessionlist.h"

typedef struct extract_list {
    struct extract_list *next;
    struct extract_list *prev;
    fileid_t *fileid;        /* the data about the file type */
    int fd;                  /* the file descriptor for writing too */
    off_t nwritten;          /* The amount of data sofar written */
    struct {                 /* this struct defines the area to be written */
        int start;
        int end;
    } segment;
    int finish;             /* this mark is set when a footer is found */
} extract_list_t;

// Using slist_t in the prototype created a mutually recursive header situation
// that will not compile.
//extern void extract(extract_list_t **, srch_results_t *, slist_t *, const uint8_t *, size_t);
extern void extract();
extern int filenum;
extern char *output_prefix;

#ifndef FILENAME_BUFFER_SIZE
#define FILENAME_BUFFER_SIZE 4096
#endif /* FILENAME_BUFFER_SIZE */

#endif /* EXTRACT_H */
