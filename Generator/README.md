# Description
The attack tool used is a packet generating program called pacgen. This program takes as input a number
of header files which specify the parameters of the packet. The ethernet header file specifies the protocol
(tcp/udp) used and also the source and destination MAC ids of the packet. The ip header includes source
and destination ip among a number of other fields. The udp header includes the source and destination ports
to be used by the packet. The payload files contain the details of the payload sent by the packet and are to
be modified to form a packet of our desire. The program uses the libnet library to form and send the packet.
The main functions are to load the payload, ethernet header, udp header and ip header from the header files
into the program. Once these are loaded, the program generates a random hostname under the target domain
name to send as a DNS query. After this name is generated, it loads the previously mentioned headers and
values and uses libnet library to send the packet. Immediately after this packet is sent, the program loads a
new payload with the DNS answer and an additional answer containing a malicious IP for the nameserver.
The program also generates a random transaction ID for the payload between 1 and 65536 and uses the libnet
library to once again send this DNS answer. This second part of the program is done around 10,000 times
to simulate flooding the DNS server with DNS answer packets. The hostnames are added to the payload by
using the payload location variable and adding them from the 12th byte onward. The DNS answer payload
has the transaction ID as the first 2 bytes in addition.

# Efficiency
The attack tool required a number of tries before it successfully poisoned the cache. This is mostly due to the
fact that our packet has to reach the DNS server before the actual response reaches it. Also we only generate
10,000 answer packets for every query packet, This means that not only will our answer have to reach
the DNS server before the real response, the response that reaches the server must also have the matching
transaction ID. A straightforward way to improve the attack would be to generate all 65,536 packets with
every transaction ID for every query. These packets would then have to reach the DNS server first. This can
be done by either using advanced computing resources or by taking advantage of distributed computing. If
we can bombard the DNS server from multiple directions with packets containing every possible transaction
ID, then our chances of poisoning the cache would improve manifold. Another solution is to somehow delay
the arrival of the real DNS answer packets however this would prove to be more difficult than the former.
Using distributed computing, the attack will be very successful.

# To compile
gcc `libnet-config --cflags --defines` generator.c -o generator `libnet-config --libs` -g

# To execute
./generator -p payload -t udp_header_query -i ip_header_query -e eth_header_query

# Notes
Need to provide UDP, IP and Eth header files with corresponding data like souce address, destination address and port numbers.
Payload file must match the payload sent out by target DNS query response, with resolution address spoofed. 
A forwarding server was setup and targeted by the first DNS server to prevent the packets from escaping to
the internet. The conditional forwarder was setup to catch all packets trying to resolve the target hostname.
These packets would then be redirected to a second forwarding server where the appropriate zone for the
hostname was created thereby ensuring that the packets would not roam elsewhere. This is a necessary fail-safe just incase a host with 
the specified attack name does exist in the real world. 


