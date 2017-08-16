# PowerDNS Dynamic Reverse Zone Backend

PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

## Prerequisites

* Python 2.7 or 3
* Python modules: `netaddr`, `py-radix`, `ipy`, `pyyaml`

## Setup

1. Copy script to e.g. `/usr/local/sbin/pipe-local-ipv6-wrapper`, make sure to chmod executable
2. Copy and edit `dynrev.yml` with your zones
3. Edit `pdns.conf`:

```
launch=pipe
pipe-command=/usr/local/sbin/pipe-local-ipv6-wrapper /etc/powerdns/dynrev.yml
pipe-timeout=500
```

# LICENSE

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
