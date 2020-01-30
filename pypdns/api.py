#!/bin/python
# -*- coding: utf-8 -*-

import datetime
import json
import requests
from typing import Optional, Tuple, List, Dict

from pypdns.errors import PDNSError, UnauthorizedError, ForbiddenError, RateLimitError, ServerError

try:
    import requests_cache  # type: ignore
    HAS_CACHE = True
except ImportError:
    HAS_CACHE = False
import logging
logger = logging

sort_choice = ['count', 'rdata', 'rrname', 'rrtype', 'time_first', 'time_last']


class PyPDNS(object):

    def __init__(self, url: str='https://www.circl.lu/pdns/query', basic_auth: Optional[Tuple[str, str]]=None,
                 auth_token: Optional[str]=None, enable_cache: bool=False, cache_expire_after: int=604800,
                 cache_file: str='/tmp/pdns.cache'):
        self.url = url
        if enable_cache and not HAS_CACHE:
            raise PDNSError('Please install requests_cache if you want to use the caching capabilities.')
        self.enable_cache = enable_cache

        if enable_cache is True:
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

    def query(self, q: str, sort_by: str='time_last') -> List[Dict]:
        logger.info("start query() q=[%s]", q)
        if sort_by not in sort_choice:
            raise PDNSError('You can only sort by ' + ', '.join(sort_choice))
        response = self.session.get('{}/{}' .format(self.url, q))
        if response.status_code != 200:
            self._handle_http_error(response)
        to_return = []
        for l in response.text.split('\n'):
            if len(l) == 0:
                continue
            try:
                if self.enable_cache is True and response.from_cache is True:
                    logger.info("from cache query() q=[%s]", q)
                obj = json.loads(l)
            except Exception:
                logger.exception("except query() q=[%s]", q)
                raise PDNSError('Unable to decode JSON object: ' + l)
            obj['time_first'] = datetime.datetime.fromtimestamp(obj['time_first'])
            obj['time_last'] = datetime.datetime.fromtimestamp(obj['time_last'])
            to_return.append(obj)
        to_return = sorted(to_return, key=lambda k: k[sort_by])
        return to_return

    @staticmethod
    def _handle_http_error(response: requests.Response):
        if response.status_code == 401:
            raise UnauthorizedError("Not authenticated: is authentication correct?")
        if response.status_code == 403:
            raise ForbiddenError("Not authorized to access resource")
        if response.status_code == 429:
            raise RateLimitError("Quota exhausted")
        if 500 <= response.status_code < 600:
            raise ServerError("Server error")
        raise PDNSError("Something went wrong")
