#!/usr/bin/env python

from __future__ import annotations


import os
import unittest

from pypdns import PyPDNS, UnauthorizedError


class TestBasic(unittest.TestCase):

    login = os.environ.get('LOGIN', '')
    password = os.environ.get('PASSWORD', '')

    def test_not_auth(self) -> None:
        x = PyPDNS(basic_auth=('username', 'yourpassword'))
        with self.assertRaises(UnauthorizedError):
            x.query('www.microsoft.com')

    def test_auth(self) -> None:
        x = PyPDNS(basic_auth=(self.login, self.password))
        for i in x.iter_query('circl.lu', filter_rrtype='A'):
            self.assertEqual(i.rrname, '185.194.93.14')
        for i in x.iter_query('circl.lu', filter_rrtype='AAAA'):
            self.assertIn(i.rrname, ['2a00:5980:93::67', '2a00:5980:93::14'])
        ns_records = [i for i in x.iter_query('circl.lu', filter_rrtype='NS')]
        self.assertEqual(len(ns_records), 8, ns_records)
        sorted_query = x.query('circl.lu', sort_by='rrname')
        self.assertEqual(sorted_query[0]['rrname'], '10 cppy.circl.lu')


if __name__ == '__main__':
    unittest.main()
