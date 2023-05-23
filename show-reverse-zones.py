#!/usr/bin/env python

"""

This ia a utility to produce a list of reverse zones for the main pdns server
as found in the CIDR ranges in the config file which can be passed as the
first parameter or found in the current directory

# ./show-reverse-zones.py | while read ZONE ; do pdnsutil create-zone $ZONE; done

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
import netaddr
import IPy
import radix
import yaml

LOGLEVEL = 2
CONFIG = 'dynrev.yml'

VERSION = 0.9
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

def parse_config(config_path):
    with open(config_path) as config_file:
        config_dict = yaml.load(config_file)

    defaults = config_dict.get('defaults', {})
    if not 'replace' in defaults:
        defaults['replace']=None
    prefixes = { netaddr.IPNetwork(prefix) : HierDict(defaults, info) for prefix, info in config_dict['prefixes'].items()}

    for zone in prefixes:
        from IPy import IP
        if not 'domain' in prefixes[zone]:
            prefixes[zone]['domain']=IP(str(zone.cidr)).reverseName()[:-1]
            for name in IP(str(zone.cidr)).reverseNames():
		print(name[:-1])

    return 

if __name__ == '__main__':
    syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID)
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
        if len(sys.argv) > 2:
            LOGLEVEL = int(sys.argv[2])
    else:
        config_path = CONFIG

    parse_config(config_path)
    #sys.exit(parse(prefixes, rtree, sys.stdin, sys.stdout))
