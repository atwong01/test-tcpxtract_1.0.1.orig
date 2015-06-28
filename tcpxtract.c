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

#define _BSD_SOURCE 1

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <assert.h>
#include <strings.h>
#include <string.h>

#include "sessionlist.h"
#include "util.h"
#include "confy.h"
#include "search.h"

#ifndef DEFAULT_CONFIG_FILE
#define DEFAULT_CONFIG_FILE "/usr/local/etc/tcpxtract.conf"
#endif

extern FILE *yyin;     /* the lex/yacc input file */
static char *yyinfname = DEFAULT_CONFIG_FILE;

/*
 * remember, statically declared variables are
 * implicitly initialized to zero.
 */

static char *progname;    /* the name of this program; */

static void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

pcap_t *handle;                 /* Sniff handler */
void quit_signal(int);

slist_t *sessions;

static uintmax_t num_packets;    /* the running total of packets */

enum protos {
    TCP_PROTO = 6,
    UDP_PROTO = 17
    /* anything else that sits on top of ip (like icmp) will be dumped in full */
};

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* Source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        #if BYTE_ORDER == LITTLE_ENDIAN
                u_int   ip_hl:4,        /* header length */
                        ip_v:4;         /* version */
        #endif
        #if BYTE_ORDER == BIG_ENDIAN
                u_int   ip_v:4,         /* version */
                        ip_hl:4;        /* header length */
        #endif
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

/* TCP header */
struct sniff_tcp {
        u_short th_sport;                       /* source port */
        u_short th_dport;                       /* destination port */
        tcp_seq th_seq;                         /* sequence number */
        tcp_seq th_ack;                         /* acknowledgement number */
        #if BYTE_ORDER == LITTLE_ENDIAN
                u_int   th_x2:4,                /* (unused) */
                        th_off:4;               /* data offset */
        #endif
        #if BYTE_ORDER == BIG_ENDIAN
                u_int   th_off:4,               /* data offset */
                        th_x2:4;                /* (unused) */
        #endif
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                         /* window */
        u_short th_sum;                         /* checksum */
        u_short th_urp;                         /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short uh_sport;     /* source port */
    u_short uh_dport;     /* destination port */
    u_short uh_length;    /* message length */
    u_short uh_sum;       /* checksum */
};

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* Define pointers for packet's attributes */
    struct sniff_ethernet *ethernet;  /* The ethernet header */
    struct sniff_ip *ip;              /* The IP header */
    struct sniff_tcp *tcp;            /* The TCP header */
    struct sniff_udp *udp;            /* The UDP header */
    uint8_t *payload;           /* The data */
    
    /* And define the size of the structures we're using */
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip;
    int size_tcp;
    int size_udp = 8;  /* just trust me */
    
    size_t header_size, payload_size;
    slist_t *session = NULL;
    connection_t conn;
    srch_results_t *results;
    
    num_packets++;
    
    /* -- Define our packet's attributes -- */
    /* There is obviously a lot of unused potential here since we only want to dump */
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + size_ethernet);
    size_ip = ip->ip_hl << 2;
    tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
    size_tcp = tcp->th_off << 2;
    udp = (struct sniff_udp*)(packet + size_ethernet + size_ip);
        
    /* if it ain't IP, bail, hard */
    if (ethernet->ether_type != 0x08) /* I think 0x08 is IP, at least it looks that way */
        return;
    
    switch (ip->ip_p) {
    case TCP_PROTO:
        header_size = size_ethernet + size_ip + size_tcp;
        break;
    case UDP_PROTO:
        header_size = size_ethernet + size_ip + size_udp;
        break;
    default:
        return;          /* at this point, I only care about tcp and udp */
    }

    payload_size = header->len - header_size;
    if (payload_size <= 0)
        return;
    payload = (uint8_t *)(packet + header_size);
    
    conn.ip_src = ip->ip_src.s_addr;
    conn.ip_dst = ip->ip_dst.s_addr;
    memcpy(conn.eth_src, ethernet->ether_shost, ETHER_ADDR_LEN);
    memcpy(conn.eth_dst, ethernet->ether_dhost, ETHER_ADDR_LEN);
    conn.port_src = tcp->th_sport;
    conn.port_dst = tcp->th_dport;
    
    if (sessions != NULL) {
        session = find_session(&sessions, &conn);
    }

    if (session == NULL) {
        session = add_session(&sessions, &conn);
        assert(session);
    }
    
    session->last_seqnum = tcp->th_seq;
    session->last_recvd = time(NULL);

    results = search(srch_machine, &session->srchptr_list, payload, payload_size);

    extract(&session->extract_list, results, session, payload, payload_size);
    free_results_list(&results);
}

static void usage(void)
{
    printf("Usage: %s [OPTIONS] [[-d <DEVICE>] [-f <FILE>]]\n"
           "Valid options include:\n"
           "  --file, -f <FILE>         to specify an input capture file instead of a device\n"
           "  --device, -d <DEVICE>     to specify an input device (i.e. eth0)\n"
           "  --config, -c <FILE>       use FILE as the config file\n"
           "  --output, -o <DIRECTORY>  dump files to DIRECTORY instead of current directory\n"
           "  --version, -v             display the version number of this program\n"
           "  --help, -h                display this lovely screen\n", progname);
    exit(1);    
}

int main(int argc, char *argv[])
{
    int c;
    char *capfname = NULL;          /* Capture file for input */
    char *dev;                      /* Sniffing devise */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error buffer */
    
    struct bpf_program filter;          /* hold compiled program */
    bpf_u_int32 mask;              /* subnet mask */
    bpf_u_int32 net;               /* ip */
    char filter_app[] = "";

    progname = strdup(argv[0]);
    sessions = NULL;
    srch_machine = NULL;
    output_prefix = NULL;
    filenum = 0;

    if (argc == 1)
        usage();
    
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"file", 1, 0, 'f'},
            {"device", 1, 0, 'd'},
            {"config", 1, 0, 'c'},
            {"output", 1, 0, 'o'},
            {"version", 0, 0, 'v'},
            {"help", 0, 0, 'h'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "f:d:o:c:hv", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case 'f':
            capfname = strdup(optarg);
            break;
        case 'd':
            dev = strdup(optarg);
            break;
        case 'c':
            yyinfname = strdup(optarg);
            break;
        case 'o':
            if (optarg[strlen(optarg) - 1] != '/') {
                output_prefix = emalloc(strlen(optarg) + 1);
                strcpy(output_prefix, optarg);
                output_prefix[strlen(optarg)] = '/';
                output_prefix[strlen(optarg) + 1] = '\0';
            } else
                output_prefix = strdup(optarg);
            break;
        case 'h':
            usage();
            break;
        case 'v':
            printf("%s v%s\n", PACKAGE, VERSION);
            exit(1);
            break;
        default:
            printf("Barf: '%c'\n", c);
            exit(0);
        }
    }

    yyin = fopen(yyinfname, "r");
    if (yyin == NULL) {
        perror(yyinfname);
        exit(0);
    }
    
    yyparse();
        
    if (optind < argc) {
        if (!dev)
            dev = argv[optind];
    }

    if (!dev && !capfname)
        dev = pcap_lookupdev(errbuf);

    if (capfname) {
         handle = pcap_open_offline(capfname, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open file %s: %s\n", capfname, errbuf);
            return(2);
        }
    } else {
         if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        
         /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
        }
        
         /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
    }
    
    signal(SIGTERM, quit_signal);
    signal(SIGQUIT, quit_signal);
    signal(SIGINT, quit_signal);
    
    /* Compile and apply the filter */
    if (pcap_compile(handle, &filter, filter_app, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
       return(2);
    }

    for (;;) {
        int ncapd = pcap_dispatch(handle, 100, got_packet, NULL);
        sweep_sessions(&sessions);
        if (ncapd < 0)
            error(pcap_geterr(handle));
        else if (ncapd == 0 && capfname != NULL)
            break;
    }

    pcap_close(handle);

    return(0);
}

void quit_signal(int sig)
{
    pcap_close(handle);
    exit(1);
}
