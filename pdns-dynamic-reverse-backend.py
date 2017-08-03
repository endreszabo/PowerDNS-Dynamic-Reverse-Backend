#!/usr/bin/python
#
"""
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

pdns.conf example:

launch=pipe
pipe-command=/usr/local/sbin/pipe-local-ipv6-wrapper
pipe-timeout=500

### LICENSE ###

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
Copyright (c) 2010 Stefan "ZaphodB" Schmidt
Copyright (c) 2011 Endre Szabo


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

syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID)
syslog.syslog('starting up')

class HierDict(dict):
    def __init__(self, parent=None, default=None):
        self._parent = parent
        if default != None:
            self.update(default)

    def __getitem__(self, name):
        try:
            return super(HierDict,self).__getitem__(name)
        except KeyError, e:
            if self._parent is None:
                raise
            return self._parent[name]

DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz'
DEFAULTS = {                      # ranges we serve
        'email' : 'hostmaster.example.com',
        'dns' : 'ns0.example.com',
        'ttl' : 300,
        'version' : 6,
        'nameserver': [
            'ns0.example.com',
            'ns1.example.com',
        ],
}

PREFIXES = {
    #link local subnets:
    netaddr.IPNetwork('169.254.0.0/16'):          HierDict(DEFAULTS,{'prefix': 'u', 'postfix': '-l0', 'forward': 'y7.hu', 'version': 4}),
    netaddr.IPNetwork('fe80::/16'):               HierDict(DEFAULTS,{'prefix': 'u', 'postfix': '-l1', 'forward': 'y7.hu',}),

    #site local unallocated subnets:
    netaddr.IPNetwork('fd00::/8'):                HierDict(DEFAULTS,{'prefix': 'u', 'postfix': '-i1', 'forward': 'y7.hu',}),
    netaddr.IPNetwork('192.168.0.0/16'):          HierDict(DEFAULTS,{'prefix': 'u', 'postfix': '-i2', 'forward': 'y7.hu', 'version': 4}),
    netaddr.IPNetwork('172.16.0.0/12'):           HierDict(DEFAULTS,{'prefix': 'u', 'postfix': '-i3', 'forward': 'y7.hu', 'version': 4}),
    netaddr.IPNetwork('10.0.0.0/8'):              HierDict(DEFAULTS,{'prefix': 'u', 'postfix': '-i4', 'forward': 'y7.hu', 'version': 4}),

    #test networks:
    netaddr.IPNetwork('192.0.2.0/24'):            HierDict(DEFAULTS,{'prefix': 'u', 'postfix': '-r0', 'forward': 'y7.hu', 'version': 4}),
    netaddr.IPNetwork('44.128.0.0/16'):           HierDict(DEFAULTS,{'prefix': 'u', 'postfix': '-i0', 'forward': 'y7.hu', 'version': 4}),
    netaddr.IPNetwork('44.128.0.0/24'):           HierDict(DEFAULTS,{'prefix': 'h', 'postfix': '-s0i0', 'forward': 'y7.hu', 'version': 4}),
    netaddr.IPNetwork('44.128.1.0/24'):           HierDict(DEFAULTS,{'prefix': 'h', 'postfix': '-s1i0', 'forward': 'y7.hu', 'version': 4}),
}

rtree=radix.Radix()

for prefix in PREFIXES.keys():
    node=rtree.add(str(prefix))
    node.data['prefix']=prefix


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



def parse(fd, out):
    line = fd.readline().strip()
    if not line.startswith('HELO'):
        print >>out, 'FAIL'
        out.flush()
        syslog.syslog('received "%s", expected "HELO"' % (line,))
        sys.exit(1)
    else:
        print >>out, 'OK\t%s ready with %d prefixes configured' % (os.path.basename(sys.argv[0]),len(PREFIXES))
        out.flush()
        syslog.syslog('received HELO from PowerDNS')

    lastnet=0
    while True:
        line = fd.readline().strip()
        if not line:
            break

        #syslog.syslog('<<< %s' % (line,))
        #print >>out, 'LOG\tline: %s' % line

        request = line.split('\t')
        if request[0] == 'AXFR':
            if not lastnet == 0:
                print >>out, 'DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600' % \
                        (lastnet['forward'], 'IN', lastnet['ttl'], qid, lastnet['dns'], lastnet['email'], time.strftime('%Y%m%d%H'))
                lastnet=lastnet
                for ns in lastnet['nameserver']:
                    print >>out, 'DATA\t%s\t%s\tNS\t%d\t%s\t%s' % \
                            (lastnet['forward'], 'IN', lastnet['ttl'], qid, ns)
            print >>out, 'END'
            out.flush()
            continue
        if len(request) < 6:
            print >>out, 'LOG\tPowerDNS sent unparsable line'
            print >>out, 'FAIL'
            out.flush()
            continue


        try:
            kind, qname, qclass, qtype, qid, ip = request
        except:
            kind, qname, qclass, qtype, qid, ip, their_ip = request
        #debug
        #print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< qid>>%s<< ip>>%s<<' % (qname, qtype, qclass, qid, ip)

        if qtype in ['AAAA', 'ANY']:
            #print >>out, 'LOG\twe got a AAAA query'
            for range, key in PREFIXES.iteritems():
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 6 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        ipv6 = netaddr.IPAddress(long(range.value) + long(node))
                        print >>out, 'DATA\t%s\t%s\tAAAA\t%d\t%s\t%s' % \
                            (qname, qclass, key['ttl'], qid, ipv6)
                        break
        if qtype in ['A', 'ANY']:
            #print >>out, 'LOG\twe got a A query'
            for range, key in PREFIXES.iteritems():
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 4 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        ipv4 = netaddr.IPAddress(long(range.value) + long(node))
                        print >>out, 'DATA\t%s\t%s\tA\t%d\t%s\t%s' % \
                            (qname, qclass, key['ttl'], qid, ipv4)
                break

        if qtype in ['PTR', 'ANY'] and qname.endswith('.ip6.arpa'):
            #print >>out, 'LOG\twe got a PTR query'
            ptr = qname.split('.')[:-2][::-1]
            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in xrange(0, len(ptr), 4))
            try:
                ipv6 = netaddr.IPAddress(ipv6)
            except:
                ipv6 = netaddr.IPAddress('::')
            node=rtree.search_best(str(ipv6))
            if node:
                range, key = node.data['prefix'], PREFIXES[node.data['prefix']]
                node = ipv6.value - range.value
                node = base36encode(node)
                print >>out, 'DATA\t%s\t%s\tPTR\t%d\t%s\t%s%s%s.%s' % \
                    (qname, qclass, key['ttl'], qid, key['prefix'], node, key['postfix'], key['forward'])

        if qtype in ['PTR', 'ANY'] and qname.endswith('.in-addr.arpa'):
            #print >>out, 'LOG\twe got a PTR query'
            ptr = qname.split('.')[:-2][::-1]
            ipv4='.'.join(''.join(ptr[x:x+1]) for x in xrange(0, len(ptr), 1))
            try:
                ipv4 = netaddr.IPAddress(ipv4)
            except:
                ipv4 = netaddr.IPAddress('127.0.0.1')
            node=rtree.search_best(str(ipv4))
            if node:
                range, key = node.data['prefix'], PREFIXES[node.data['prefix']]
                node = ipv4.value - range.value
                node = base36encode(node)
                print >>out, 'DATA\t%s\t%s\tPTR\t%d\t%s\t%s%s%s.%s' % \
                    (qname, qclass, key['ttl'], qid, key['prefix'], node, key['postfix'], key['forward'])


        if qtype in ['SOA', 'ANY', 'NS']:
            for range, key in PREFIXES.iteritems():
                if qname == key['domain']:
                    if not qtype == 'NS':
                        print >>out, 'DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600' % \
                                (key['domain'], qclass, key['ttl'], qid, key['dns'], key['email'], time.strftime('%Y%m%d%H'))
                        lastnet=key
                    if qtype in ['ANY', 'NS']:
                        for ns in key['nameserver']:
                            print >>out, 'DATA\t%s\t%s\tNS\t%d\t%s\t%s' % \
                                    (key['domain'], qclass, key['ttl'], qid, ns)
                    break
                elif qname == key['forward']:
                    if not qtype == 'NS':
                        print >>out, 'DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600' % \
                                (key['forward'], qclass, key['ttl'], qid, key['dns'], key['email'], time.strftime('%Y%m%d%H'))
                        lastnet=key
                    if qtype in ['ANY', 'NS']:
                        for ns in key['nameserver']:
                            print >>out, 'DATA\t%s\t%s\tNS\t%d\t%s\t%s' % \
                                    (key['forward'], qclass, key['ttl'], qid, ns)
                    break

        print >>out, 'END'
        out.flush()

    syslog.syslog('terminating')
    return 0

for zone in PREFIXES:
    if not PREFIXES[zone].has_key('domain'):
        from IPy import IP
        PREFIXES[zone]['domain']=IP(str(zone.cidr)).reverseName()[:-1]

if __name__ == '__main__':
    import sys
    sys.exit(parse(sys.stdin, sys.stdout))
