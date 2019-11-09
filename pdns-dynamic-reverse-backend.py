#!/usr/bin/env python

"""
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

pdns.conf example:

launch=pipe
pipe-command=/usr/sbin/pdns-dynamic-reverse-backend.py /etc/pdns/dynrev.yml
pipe-timeout=500

### LICENSE ###

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
Copyright (c) 2010 Stefan "ZaphodB" Schmidt
Copyright (c) 2011 Endre Szabo
Copyright (c) 2017 Technical University of Munich (Lukas Erlacher)

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
import netaddr
import IPy
import radix
import yaml

LOGLEVEL = 2
CONFIG = '/etc/pdns/dynrev.yml'

VERSION = 0.9
DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz'
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

def parse(prefixes, rtree, fd, out):
    def log(level=LOGLEVEL, message=None, **kwargs):
        if level<=LOGLEVEL:
            message="%s; %s" % (message, ", ".join(filter(None, map(lambda k: "%s=%s" % (k, repr(str(kwargs[k]))), kwargs.keys()))))
            out.write("LOG\t%s\n" % message)
            syslog.syslog(message)
    def logd(level=LOGLEVEL, message=None, kwargs={}):
        if level<=LOGLEVEL:
            message="%s; %s" % (message, ", ".join(filter(None, map(lambda k: "%s=%s" % (k, repr(str(kwargs[k]))), kwargs.keys()))))
            out.write("LOG\t%s\n" % message)
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
    while True:
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
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 6 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        node = base36decode(node)
                        ipv6 = netaddr.IPAddress(long(range.value) + long(node))
                        out.write("DATA\t%s\t%s\tAAAA\t%d\t%s\t%s\n" % \
                            (qname, qclass, key['ttl'], qid, ipv6))
                        break
                    except ValueError:
                        node = None

        if qtype in ['A', 'ANY']:
            for range in prefixes.keys():
                key=prefixes[range]
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 4 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        node = base36decode(node)
                        ipv4 = netaddr.IPAddress(long(range.value) + long(node))
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
        config_dict = yaml.load(config_file)

    defaults = config_dict.get('defaults', {})
    prefixes = { netaddr.IPNetwork(prefix) : HierDict(defaults, info) for prefix, info in config_dict['prefixes'].items()}

    for zone in prefixes:
        if not 'domain' in prefixes[zone]:
            from IPy import IP
            prefixes[zone]['domain']=IP(str(zone.cidr)).reverseName()[:-1]

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
