# traceroute
traceroutev4 utility pet project

## State:
the program is able to manipulate the ip header ttl field while constantly sending pings to server, and thus obtaining the path of routers.

The timeout for non-responding hosts is 10sec.

## Limitations to be fixed:
It is not verified, as far as I'm aware of. There might be a possibility for someone to forge those packets and fool me.
There are a lot of space wasted, because I didn't put attention to it. So it's not as fast as it could be.
Only works with ipv4
maybe too much code.
.
