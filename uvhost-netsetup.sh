#!/bin/sh

if [ ! -f /run/uvhost-netsetup.done ] ; then
	touch /run/uvhost-netsetup.done 

	nft add table ip uvhost

	nft add chain ip uvhost allports '{type filter hook input priority mangle;}'
	nft add rule  ip uvhost allports ip protocol tcp tproxy to 127.127.127.127:127

	nft add chain ip uvhost nov4out '{type filter hook output priority filter; policy drop;}'
	nft add rule  ip uvhost nov4out iif lo accept
	nft add rule  ip uvhost nov4out oif lo accept
	nft add rule  ip uvhost nov4out ct state established,related accept

	ip -6 route add local 2600:3c00:e000:03f5::/64 dev lo

	sysctl net.ipv6.ip_nonlocal_bind=1
fi