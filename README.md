# WithFallback.com

### **What is this?**
An IPv4 to IPv6 reverse proxy service similar to http://v4-frontend.netiter.com/

### **How do I report abuse?**
Email Jon@9072997.com

### **Why would I want this?**
The world is running out of IPv4 addresses, so NAT is commonly used to share a single public IPv4 address between multiple users. NAT has the side effect of blocking incoming connections. The best solution to this would be for everyone to get connected to the IPv6 internet, where NAT is not necessary. Unfortunately, [many users are not connected to the IPv6 internet](https://www.google.com/intl/en/ipv6/statistics.html). If you have a connection to the IPv6 internet, this service allows you to run many types of servers in a way that will allow IPv6 users to connect directly to you, while allowing IPv4 users to *fall back* to connecting through my IPv4-to-IPv6 reverse proxy.

### **Which services are supported?**
* **HTTP** on any port
* **HTTPS** on any port
* **TLS with SNI** on any port (this includes dozens of protocols that are built on TLS)
* Limited support for any TCP based protocol that includes the hostname as ASCII/UTF-8 in the first 4096 bytes (ex: Minecraft Java Edition)

### **How do I use this?**
* [Make sure you have IPv6 connectivity](https://ipv6-test.com/)
* Make sure you don't have a firewall blocking incoming connections to your IPv6 address. Once you have your server running, you can check [here](http://www.ipv6scanner.com/cgi-bin/main.py).
* Access your service at your-ipv6-address.withfallback.com. You must include all possible zeros in the IPv6 address and use a dash "-" rather than a colon as the seperator. For example, if your IPv6 address was `2001:db8::1:0:0:1` you would use `2001-0db8-0000-0000-0001-0000-0000-0001.withfallback.com`.
* NOTE: you can also use subdomains. They will point to the same address. Ex: `foo.2001-0db8-0000-0000-0001-0000-0000-0001.withfallback.com`

### **Can I use a custom DNS name?**
Yes, as long as you only need support for HTTP, HTTPS, and/or TLS. Just use a `CNAME` or `ALIAS` record to point to `2001-0db8-0000-0000-0001-0000-0000-0001.withfallback.com` (substitute in your own IPv6 address). If you cannot use a `CNAME`/`ALIAS` record, you can manually add an `A` record for `45.33.22.33` and an `AAAA` record for your IPv6 address, though this may break if I ever have to change the server's public IPv4 address.

### **How does this work?**
DNS queries for some-ipv6-address.withfallback.com always return an `AAAA` record for the given IP, and an `A` record for my reverse proxy. If the client supports IPv6, they can connect directly to the IPv6 address. If not, they will connect to the proxy. The proxy uses [name-based virtual hosting](https://en.wikipedia.org/wiki/Virtual_hosting#Name-based) to figure out which site the client was trying to connect to and proxies the connection for them. The source code for all this is available [here](https://github.com/9072997/uvhost), though it's not really packaged in a way that is designed for re-use.

### **How do I get the client's original IPv4 address?**
Connections from the reverse proxy always come from `2600:3c00:e000:03f5::/96` with the last 32 bytes of the IPv6 address being the client's IPv4 address. The source port is also preserved in case you care about that.

### **Does this support UDP-based protocols?**
It supports DNS, as long as you don't use vanity nameservers. Set your nameservers to something like `2001-0db8-0000-0000-0001-0000-0000-0001.withfallback.com` (substitute your DNS server's IPv6 address).

It also has very limited support for running your own DNS server for the `withfallback.com` domain itself. For now you can only set `A`, `AAAA`, `MX`, and `TXT` records, and everything is limited to a TTL of 5 minutes.

### **I don't have a public IPv6 address**
[Do you want one](http://wireguard.9072997.net/)? You will need to [install WireGuard](https://www.wireguard.com/install/).

### **I have a public IPv6 address, but I can't accept incoming connections**
If you control the firewall, change your firewall rules to allow incoming connections on the appropriate port. If not, see the above question.