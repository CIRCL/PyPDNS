#!/bin/python
# -*- coding: utf-8 -*-

import datetime
import json
import requests
import requests_cache
import logging
logger = logging

sort_choice = ['count', 'rdata', 'rrname', 'rrtype', 'time_first', 'time_last']


class PyPDNS(object):

    def __init__(self, url='https://www.circl.lu/pdns/query', basic_auth=None,
                 auth_token=None, enable_cache=False, cache_expire_after=604800, cache_file='/tmp/pdns.cache'):
        self.url = url
        self.enable_cache = enable_cache

        if enable_cache is True:
            requests_cache.install_cache()
            requests_cache.install_cache(cache_file, backend='sqlite', expire_after=cache_expire_after)
            self.session = requests_cache.CachedSession()
        else:
            self.session = requests.Session()
        if basic_auth is not None:
            # basic_auth has do be a tuple ('user_name', 'password')
            self.session.auth = basic_auth
        elif auth_token is not None:
            self.session.headers.update({'Authorization': auth_token})
        else:
            # No authentication defined.
            pass

    def query(self, q, sort_by='time_last'):
        logger.info("start query() q=[%s]", q)
        if sort_by not in sort_choice:
            raise Exception('You can only sort by ' + ', '.join(sort_choice))
        response = self.session.get('{}/{}' .format(self.url, q))
        if response.status_code != 200:
            raise Exception('HTTP error authentication incorrect?')
        to_return = []
        for l in response.text.split('\n'):
            if len(l) == 0:
                continue
            try:
                if self.enable_cache is True and response.from_cache is True:
                    logger.info("from cache query() q=[%s]", q)
                obj = json.loads(l)
            except:
                logger.exception("except query() q=[%s]", q)
                raise Exception('Unable to decode JSON object: ' + l)
            obj['time_first'] = datetime.datetime.fromtimestamp(obj['time_first'])
            obj['time_last'] = datetime.datetime.fromtimestamp(obj['time_last'])
            to_return.append(obj)
        to_return = sorted(to_return, key=lambda k: k[sort_by])
        return to_return
