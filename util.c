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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>

void error(char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(0);
}

void report(char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void printip(uint32_t ip)
{
    uint8_t addr[4];

    memcpy(addr, &ip, 4);
    report("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
}

void *emalloc(size_t size)
{
    void *retval = malloc(size);

    if (retval == NULL) {
        perror("Error in function emalloc()");
        exit(0);
    }

    return retval;
}

void *ecalloc(size_t nmemb, size_t size)
{
    void *retval = calloc(nmemb, size);

    if (retval == NULL) {
        perror("Error in function ecalloc()");
        exit(0);
    }

    return retval;
}
