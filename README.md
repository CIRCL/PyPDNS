[![Documentation Status](https://readthedocs.org/projects/pypdns/badge/?version=latest)](https://pypdns.readthedocs.io/en/latest/?badge=latest)

Client API for PDNS
===================

Client API to query any Passive DNS implementation following the Passive DNS - Common Output Format.

* https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/

## Installation

```bash
pip install pypdns
```

## Usage

### Command line

You can use the `pdns` command to trigger a request.

```bash
usage: pdns [-h] --username USERNAME --password PASSWORD --query QUERY [--rrtype RRTYPE]

Triggers a request againse CIRCL Passive DNS.

options:
  -h, --help           show this help message and exit
  --username USERNAME  The username of you account.
  --password PASSWORD  The password of you account.
  --query QUERY        The query, can be an IP. domain, hostname, TLD.
  --rrtype RRTYPE      Filter the request based on the RR Type.
```

### Library

See [API Reference](https://pypdns.readthedocs.io/en/latest/api_reference.html)


Example
=======

~~~~
import pypdns
import json
x = pypdns.PyPDNS(basic_auth=('username','yourpassword'))

for record in x.iter_query(q='circl.lu', filter_rrtype='A'):
    print(json.dumps(record.record, indent=2))
~~~~

Passive DNS Services
====================

* (default) [CIRCL Passive DNS](http://www.circl.lu/services/passive-dns/)


