#!/usr/bin/env python3

"""
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

pdns.conf example:  passing command name, config file & log level

launch=pipe
pipe-command=/usr/sbin/pdns-dynamic-reverse-backend.py /etc/pdns/dynrev.yml 1
pipe-timeout=500

if you use other backends include them all in the one launch statement
e.g.
launch=gmysql,pipe

### LICENSE ###

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
Copyright (c) 2010 Stefan "ZaphodB" Schmidt
Copyright (c) 2011 Endre Szabo
Copyright (c) 2017 Technical University of Munich (Lukas Erlacher)
Copyright (c) 2019 David Beveridge (bevhost)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import sys, os
import re
import syslog
import time
import ipaddress
import netaddr
import radix
import yaml

LOGLEVEL = 2
CONFIG = 'dynrev.yml'

VERSION = 0.9
DIGITS = '0123456789bcdfghjklmnpqrstvwxyz'
SCRIPTNAME=os.path.basename(sys.argv[0])

#xrange() backwards compatibility for python3
try:
    xrange
except NameError:
    xrange = range
try:
    long
except NameError:
    long = int


class HierDict(dict):
    def __init__(self, parent=None, default=None):
        self._parent = parent
        if default != None:
            self.update(default)

    def __getitem__(self, name):
        try:
            return super(HierDict,self).__getitem__(name)
        except KeyError as e:
            if self._parent is None:
                raise
            return self._parent[name]

def base36encode(n):
    s = ''
    while True:
        n, r = divmod(n, len(DIGITS))
        s = DIGITS[r] + s
        if n == 0:
            break
    return s

def base36decode(s):
    n, s = 0, s[::-1]
    for i in xrange(0, len(s)):
        r = DIGITS.index(s[i])
        n += r * (len(DIGITS) ** i)
    return n

def get_reverse_pointer(ip_network):
    """Get reverse pointer for an IP network zone (not host-level)."""
    # Get the full reverse pointer for the network address
    full_pointer = str(ip_network.network_address.reverse_pointer)

    if ip_network.version == 4:
        # IPv4: reverse_pointer has octets separated by dots
        # For a /16, we need to keep only the last 2 octets (network bits / 8)
        # For a /24, we need to keep only the last 3 octets
        num_octets_to_keep = ip_network.prefixlen // 8
        labels = full_pointer.split('.')
        # labels = ['0', '0', '254', '169', 'in-addr', 'arpa']
        # For /16: keep last 2 octets before 'in-addr.arpa' = labels[2:4] + ['in-addr', 'arpa']
        network_labels = labels[4 - num_octets_to_keep:4] + labels[4:]
        return '.'.join(network_labels)
    else:
        # IPv6: reverse_pointer has nibbles separated by dots
        # For a /64, we need to keep 64 bits / 4 bits per nibble = 16 nibbles
        num_nibbles_to_keep = ip_network.prefixlen // 4
        labels = full_pointer.split('.')
        # Keep the last num_nibbles_to_keep labels before 'ip6.arpa'
        # labels has 32 nibbles + 2 = 34 elements for full IPv6
        network_labels = labels[32 - num_nibbles_to_keep:32] + labels[32:]
        return '.'.join(network_labels)

def get_reverse_names(ip_network):
    """Get reverse zone names for an IP network."""
    # For delegation purposes, return the main reverse zone(s)
    names = []
    # For small networks, return all possible reverse zones
    # This mimics IPy.reverseNames() behavior
    if ip_network.version == 4:
        # For IPv4, generate reverse zone names based on CIDR
        if ip_network.prefixlen % 8 == 0:
            # Byte-aligned networks have single reverse zones
            names.append(str(ip_network.network_address.reverse_pointer))
        else:
            # Non-byte-aligned networks need CNAME delegation
            # For simplicity, return the primary reverse zone
            names.append(str(ip_network.network_address.reverse_pointer))
    else:
        # For IPv6, similar logic
        names.append(str(ip_network.network_address.reverse_pointer))
    return names

def parse(prefixes, rtree, fd, out):
    def log(level=LOGLEVEL, message=None, **kwargs):
        if level<=LOGLEVEL:
            message="%s; %s" % (message, ", ".join(filter(None, map(lambda k: "%s=%s" % (k, repr(str(kwargs[k]))), kwargs.keys()))))
            #out.write("LOG\t%s\n" % message)
            syslog.syslog(message)
    def logd(level=LOGLEVEL, message=None, kwargs={}):
        if level<=LOGLEVEL:
            message="%s; %s" % (message, ", ".join(filter(None, map(lambda k: "%s=%s" % (k, repr(str(kwargs[k]))), kwargs.keys()))))
            #out.write("LOG\t%s\n" % message)
            syslog.syslog(message)
    log(0,"starting up")
    line = fd.readline().strip()
    if not line.startswith('HELO'):
        out.write("FAIL\n")
        out.flush()
        log(1,"unknown line received from powerdns, expected HELO", line=line)
        sys.exit(1)
    else:
        out.write("OK\t%s ready with %d prefixes configured\n" % (SCRIPTNAME, len(prefixes)))
        log(0,'powerdns HELO received, ready to process requests', prefixes_count=len(prefixes))
        out.flush()

    lastnet=0
    count=100000
    while count > 0:
        count -= 1
        line = fd.readline().strip()
        if not line:
            break

        #syslog.syslog('<<< %s' % (line,))
        log(4, "got input line from powerdns", line=line)

        request = line.split('\t')
        if request[0] == 'AXFR':
            if not lastnet == 0:
                out.write("DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600\n" % \
                        (lastnet['forward'], 'IN', lastnet['ttl'], qid, lastnet['dns'], lastnet['email'], time.strftime('%Y%m%d%H')))
                lastnet=lastnet
                for ns in lastnet['nameserver']:
                    out.write("DATA\t%s\t%s\tNS\t%d\t%s\t%s\n" % \
                            (lastnet['forward'], 'IN', lastnet['ttl'], qid, ns))
            out.write("END\n")
            out.flush()
            continue
        if len(request) < 6:
            out.write("LOG\tPowerDNS sent unparsable line\n")
            out.write("FAIL\n")
            out.flush()
            continue

        #q&d handling of different pdns pipe backend protocol versions
        try:
            kind, qname, qclass, qtype, qid, ip = request
        except ValueError:
            kind, qname, qclass, qtype, qid, ip, their_ip = request
        log(2, "parsed query", qname=qname, qtype=qtype, qclass=qclass, qid=qid, ip=ip)

        if qtype in ['AAAA', 'ANY']:
            for range in prefixes.keys():
                key=prefixes[range]
                if qname.endswith('%s.%s' % (key['postfix'], key['forward'],)) and key['version'] == 6 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        if key['replace']:
                            ipv6 = node.replace(key['replace'],':')
                        else:
                            node = base36decode(node)
                            # Clamp node offset so resulting IP stays within the prefix
                            base = int(getattr(range, 'network', range.value))
                            try:
                                broadcast = int(getattr(range, 'broadcast', range.value))
                            except Exception:
                                broadcast = base
                            max_offset = max(0, broadcast - base)
                            node_int = int(node)
                            if node_int < 0 or node_int > max_offset:
                                break
                            ipv6 = netaddr.IPAddress(base + node_int)
                        out.write("DATA\t%s\t%s\tAAAA\t%d\t%s\t%s\n" % \
                            (qname, qclass, key['ttl'], qid, ipv6))
                        break
                    except ValueError:
                        node = None

        if qtype in ['A', 'ANY']:
            for range in prefixes.keys():
                key=prefixes[range]
                if qname.endswith('%s.%s' % (key['postfix'], key['forward'],)) and key['version'] == 4 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        if key['replace']:
                            ipv4 = node.replace(key['replace'],'.')
                        else:
                            node = base36decode(node)
                            # Clamp node offset so resulting IP stays within the prefix
                            base = int(getattr(range, 'network', range.value))
                            try:
                                broadcast = int(getattr(range, 'broadcast', range.value))
                            except Exception:
                                broadcast = base
                            max_offset = max(0, broadcast - base)
                            node_int = int(node)
                            if node_int < 0 or node_int > max_offset:
                                break
                            ipv4 = netaddr.IPAddress(base + node_int)
                        out.write("DATA\t%s\t%s\tA\t%d\t%s\t%s\n" % \
                            (qname, qclass, key['ttl'], qid, ipv4))
                        break
                    except ValueError:
                        log(3,'failed to base36 decode host value',node=node)

        if qtype in ['PTR', 'ANY'] and qname.endswith('.ip6.arpa'):
            ptr = qname.split('.')[:-2][::-1]
            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in xrange(0, len(ptr), 4))
            try:
                ipv6 = netaddr.IPAddress(ipv6)
            except:
                ipv6 = netaddr.IPAddress('::')
            node=rtree.search_best(str(ipv6))
            if node:
                range, key = node.data['prefix'], prefixes[node.data['prefix']]
                if key['replace']:
                    node = str(ipv6).replace(':',key['replace'])
                else:
                    node = ipv6.value - range.value
                    node = base36encode(node)
                out.write("DATA\t%s\t%s\tPTR\t%d\t%s\t%s%s%s.%s\n" % \
                    (qname, qclass, key['ttl'], qid, key['prefix'], node, key['postfix'], key['forward']))
        if qtype in ['PTR', 'ANY'] and qname.endswith('.in-addr.arpa'):
            ptr = qname.split('.')[:-2][::-1]
            ipv4='.'.join(''.join(ptr[x:x+1]) for x in xrange(0, len(ptr), 1))
            try:
                ipv4 = netaddr.IPAddress(ipv4)
            except:
                ipv4 = netaddr.IPAddress('127.0.0.1')
            node=rtree.search_best(str(ipv4))
            if node:
                range, key = node.data['prefix'], prefixes[node.data['prefix']]
                if key['replace']:
                    node = str(ipv4).replace('.',key['replace'])
                else:
                    node = ipv4.value - range.value
                    node = base36encode(node)
                out.write("DATA\t%s\t%s\tPTR\t%d\t%s\t%s%s%s.%s\n" % \
                    (qname, qclass, key['ttl'], qid, key['prefix'], node, key['postfix'], key['forward']))
        if qtype in ['SOA', 'ANY', 'NS']:
            for range in prefixes.keys():
                key=prefixes[range]
                if qname == key['domain']:
                    if not qtype == 'NS':
                        out.write("DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600\n" % \
                                (key['domain'], qclass, key['ttl'], qid, key['dns'], key['email'], time.strftime('%Y%m%d%H')))
                        lastnet=key
                    if qtype in ['ANY', 'NS']:
                        for ns in key['nameserver']:
                            out.write("DATA\t%s\t%s\tNS\t%d\t%s\t%s\n" % \
                                    (key['domain'], qclass, key['ttl'], qid, ns))
                    break
                elif qname == key['forward']:
                    if not qtype == 'NS':
                        out.write("DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600\n" % \
                                (key['forward'], qclass, key['ttl'], qid, key['dns'], key['email'], time.strftime('%Y%m%d%H')))
                        lastnet=key
                    if qtype in ['ANY', 'NS']:
                        for ns in key['nameserver']:
                            out.write("DATA\t%s\t%s\tNS\t%d\t%s\t%s" % \
                                    (key['forward'], qclass, key['ttl'], qid, ns))
                    break

        out.write("END\n")
        out.flush()

    log(1, "terminating")
    return 0

def parse_config(config_path):
    with open(config_path) as config_file:
        config_dict = yaml.safe_load(config_file)

    defaults = config_dict.get('defaults', {})
    if not 'replace' in defaults:
        defaults['replace']=None
    prefixes = { netaddr.IPNetwork(prefix) : HierDict(defaults, info) for prefix, info in config_dict['prefixes'].items()}

    for zone in prefixes:
        ip_net = ipaddress.ip_network(zone.cidr, strict=False)
        prefixes[zone]['version']=ip_net.version
        if not 'domain' in prefixes[zone]:
            prefixes[zone]['domain']=get_reverse_pointer(ip_net)[:-1]

    rtree=radix.Radix()

    for prefix in prefixes.keys():
        node=rtree.add(str(prefix))
        node.data['prefix']=prefix

    return prefixes, rtree

if __name__ == '__main__':
    syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID)
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
        if len(sys.argv) > 2:
            LOGLEVEL = int(sys.argv[2])
    else:
        config_path = CONFIG

    prefixes, rtree = parse_config(config_path)
    sys.exit(parse(prefixes, rtree, sys.stdin, sys.stdout))
