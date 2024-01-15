#!/usr/bin/env python

import unittest
from pypdns import PyPDNS, UnauthorizedError


class TestBasic(unittest.TestCase):

    def test_not_auth(self) -> None:
        x = PyPDNS(basic_auth=('username', 'yourpassword'))
        with self.assertRaises(UnauthorizedError):
            x.query('www.microsoft.com')


if __name__ == '__main__':
    unittest.main()
