
This is a starting point for Go solutions to the
["Build Your Own DNS server" Challenge](https://app.codecrafters.io/courses/dns-server/overview).

This challenge helped me to build build a DNS server that's capable of parsing and
creating DNS packets, responding to DNS queries, handling various record types
and doing recursive resolve. 
Along the way I learnt about the DNS protocol,
DNS packet format, root servers, authoritative servers, forwarding servers,
various record types (A, AAAA, CNAME, etc) and more.

## Improvement
Recursive Resolve - currently we just send the request from the client to resolver that is capable of recursion to go fetch the records
