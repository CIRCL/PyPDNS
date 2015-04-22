Client API for PDNS
===================

Client API to query any Passive DNS implementation following the Passive DNS - Common Output Format.

* https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/

Example
=======

~~~~
import pypdns
x = pypdns.PyPDNS(basic_auth=('username','yourpassword'))
print (x.query('www.microsoft.com')[0]['rdata'])
~~~~

Passive DNS Services
====================

* (default) [CIRCL Passive DNS](http://www.circl.lu/services/passive-dns/)


