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

#include <assert.h>
#include <sys/types.h>
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "extract.h"
#include "search.h"
#include "util.h"
#include "sessionlist.h"

int filenum;
char *output_prefix;

static void add_extract(extract_list_t **, fileid_t *, slist_t *, int, int);
static void set_segment_marks(extract_list_t *, size_t);
static void mark_footer(extract_list_t *, srch_results_t *);
static void extract_segment(extract_list_t *, const uint8_t *);
static void sweep_extract_list(extract_list_t **);
static int open_extract(char *);

/* called once for each packet, this funciton starts, updates, and closes
 * file extractions.  this is the one-stop-shop for all your file extraction needs */
void extract(extract_list_t **elist, srch_results_t *results, slist_t *session, const uint8_t *data, size_t size)
{
    srch_results_t *rptr;
    extract_list_t *eptr;

    assert(elist != NULL);

    /* set all existing segment values to what they would be with no search results */
    for (eptr = *elist; eptr != NULL; eptr = eptr->next)
        set_segment_marks(eptr, size);

    /* look for new headers in the results set */
    for (rptr = results; rptr != NULL; rptr = rptr->next)
        if (rptr->spectype == HEADER)
            add_extract(elist, rptr->fileid, session, rptr->offset.start, size);

    /* flip through any footers we found and close out those extracts */
    for (rptr = results; rptr != NULL; rptr = rptr->next)
        if (rptr->spectype == FOOTER)
            mark_footer(*elist, rptr);

    /* now lets do all the file writing and whatnot */
    for (eptr = *elist; eptr != NULL; eptr = eptr->next)
        extract_segment(eptr, data);

    /* remove any finished extractions from the list */
    sweep_extract_list(elist);
}

/* Add a new header match to the list of files being extracted */
static void add_extract(extract_list_t **elist, fileid_t *fileid, slist_t *session, int offset, int size)
{
    extract_list_t *eptr;

    assert(elist != NULL);
    assert(fileid != NULL);

    /* add a new entry to the list */
    eptr = ecalloc(1, sizeof *eptr);
    eptr->next = *elist;
    eptr->fileid = fileid;
    if (eptr->next != NULL)
        eptr->next->prev = eptr;

    report("Found file of type \"%s\" in session [", fileid->ext);
    printip(session->connection.ip_src);
    report(":%d -> ", session->connection.port_src);
    printip(session->connection.ip_dst);
    report(":%d], exporting to ", session->connection.port_dst);
    eptr->fd = open_extract(fileid->ext);
    eptr->segment.start = offset;
    if (fileid->maxlen <= size - offset)
        eptr->segment.end = offset + fileid->maxlen;
    else   
        eptr->segment.end = size;

    *elist = eptr;
}

/* open the next availible filename for writing */
static int open_extract(char *ext)
{
    int retval;
    char fname[FILENAME_BUFFER_SIZE] = {'\0'};      /* buffer to snprintf our filename to */
    
    do 
        snprintf(fname, FILENAME_BUFFER_SIZE, "%s%08d.%s", output_prefix == NULL ? "" : output_prefix, filenum++, ext);
    while ((retval = open(fname, O_WRONLY|O_CREAT|O_EXCL, S_IRWXU)) == -1);

    report("%s\n", fname);
    
    return retval;
}

/* set segment start and end values to the contraints of the data buffer or maxlen */
static void set_segment_marks(extract_list_t *elist, size_t size)
{
    extract_list_t *eptr;

    for (eptr = elist; eptr != NULL; eptr = eptr->next) {
        eptr->segment.start = 0;
        if (eptr->fileid->maxlen - eptr->nwritten < size) {
            eptr->segment.end = eptr->fileid->maxlen - eptr->nwritten;
            eptr->finish++;
        } else
            eptr->segment.end = size;
    }
}

/* adjust segment end values depending on footers found */
static void mark_footer(extract_list_t *elist, srch_results_t *footer)
{
    extract_list_t *eptr;

    /* this associates the first footer found with the last header found of a given type
     * this is to accommodate embedded document types.  Somebody may have differing needs
     * so this may want to be reworked later */
    for (eptr = elist; eptr != NULL; eptr = eptr->next) {
        if (footer->fileid->id == eptr->fileid->id && eptr->segment.start < footer->offset.start) {
            eptr->segment.end = footer->offset.end;  /* this could extend beyond maxlen */
            eptr->finish++;
            break;
        }
    }
}

/* write data to a specified extract file */
static void extract_segment(extract_list_t *elist, const uint8_t *data)
{
    size_t nbytes = elist->segment.end - elist->segment.start;

    if (nbytes != write(elist->fd, data + elist->segment.start, nbytes)) {
        perror("Error Writing File");
        error("Quiting.");
    }
    elist->nwritten += nbytes;
    sync();
}

/* remove all finished extracts from the list */
static void sweep_extract_list(extract_list_t **elist)
{
    extract_list_t *eptr, *nxt;

    assert(elist != NULL);

    for (eptr = *elist; eptr != NULL; eptr = nxt) {
        nxt = eptr->next;
        if (eptr->finish) {
            if (eptr->prev != NULL)
                eptr->prev->next = eptr->next;
            if (eptr->next != NULL)
                eptr->next->prev = eptr->prev;
            if (*elist == eptr)
                *elist = eptr->next;
            close(eptr->fd);
            free(eptr);
        }
    }
}

