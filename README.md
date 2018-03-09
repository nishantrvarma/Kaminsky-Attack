# Kaminsky-Attack
The Kaminsky attack is an advanced DNS cache poisoning attack that takes advantage of the DNS structure.
It works on the basis that if you send a query for a random non-existent hostname within an existing domain,
then the server will always try to get an answer. This would not be a problem as the response would simply
be a negative response. However DNS messages also allow information to be carried over in additional
fields. This information could be data pertaining to an actual hostname in the domain. As the response
reaches the DNS server that sent the query it will update its cache to reflect the new value received from the
additional field thereby providing a mechanism for attackers to inject malicious IPs into the DNS cache.
#Process
The adversary first sends a query for a hostname that does not exist (xyz234.domainname.com) to the target
DNS server. This server would then try to get a response for this query by sending it further. During this time,
the adversary floods the DNS server with a large number of DNS answer packets trying a new combination
of the transaction ID in each packet. One of these packets would contain the matching transaction ID to
the query that was sent and if this packet reaches before the actual response reaches, then the DNS server
accepts it as the solution. Since the field size for the transaction ID is relatively small, the adversary can
simply try all possible combinations in a feasible amount of time. The adversary however also includes an
additional field carrying a malicious hostname-IP pair for the proper hostname (ns.domainname.com). This
will thus be cached in the DNS server and further queries for that hostname by any unsuspecting user would
be redirected to that IP.

#Work flow :-
1) DNS query packet for a random non-existent host is sent using a packet generator to the target DNS server.
2) DNS server forwards this packet to the forwarding server trying to resolve the query.
3) Packet generator is used to flood the DNS server with 10,000 DNS answer packets per execution, each packet with
a randomized transaction ID.
4) The forwarding server’s ports are delayed to ensure a better chance of our pacgen packets reaching the
DNS server first.
5) The DNS answer packets contain a payload which can have an additional field. In this additional field,
we add an incorrect resolution for the nameserver of the domain that was queried for.
6) If the generated packets reach the DNS server before the actual response reaches it, then our answer is
accepted by the server and cached. Along with the main answer, it also accepts the nameserver-IP pair in
the additional field and caches it.
7) Subsequent queries for this domain to the DNS server, is returned with the malicious IP thereby verifying
that the cache has been poisoned.

