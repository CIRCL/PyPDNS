.. PyLookyloo documentation master file, created by
   sphinx-quickstart on Tue Mar 23 12:28:17 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to PyPDNS's documentation!
==================================

This is the client API for `CIRCL passive DNS <https://www.circl.lu/services/passive-dns/>`_

Installation
------------

The package is available on PyPi, so you can install it with::

  pip install pypdns


Usage
-----

You can use `pdns` as a python script::

    $ pdns -h
    usage: pdns [-h] --username USERNAME --password PASSWORD --query QUERY [--rrtype RRTYPE]

    Triggers a request againse CIRCL Passive DNS.

    options:
      -h, --help           show this help message and exit
      --username USERNAME  The username of you account.
      --password PASSWORD  The password of you account.
      --query QUERY        The query, can be an IP. domain, hostname, TLD.
      --rrtype RRTYPE      Filter the request based on the RR Type.

Or as a library:

.. toctree::
   :glob:

   api_reference


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
