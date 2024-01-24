# traceroute
traceroute utility pet project

## State:
the program is able to manipulate the ip header ttl field while constantly sending pings to server, and thus obtaining the path of routers.

The timeout for non-responding hosts is 10sec.

## Limitations to be fixed:
First of all, this only works on wireless interfaces.
It is not verified, as far as I'm aware of. There might be a possibility for someone to forge those packets and fool me.
There are a lot of space wasted, because I didn't put attention to it. So it's not as fast as it could be.
It is a messy code.

