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

#include "conf.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "search.h"

static int id;

void config_type(char *ext, char *maxlength, char *hspec, char *fspec)
{
    unsigned long maxlen;

    if (!sscanf(maxlength, "%lu", &maxlen))
        error("Invalid maximum length in file format specifier");

    compile_srch(&srch_machine, id, strdup(ext), maxlen, hspec, HEADER);
    if (fspec != NULL)
        compile_srch(&srch_machine, id, strdup(ext), maxlen, fspec, FOOTER);

    id++;
}

