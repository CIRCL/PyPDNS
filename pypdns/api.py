#!/bin/python
# -*- coding: utf-8 -*-

import json
import logging

from datetime import datetime
from typing import Optional, Tuple, List, Dict, Union, Any

import requests
from requests import Session, Response
from dns.rdatatype import RdataType

from pypdns.errors import PDNSError, UnauthorizedError, ForbiddenError, RateLimitError, ServerError, PDNSRecordTypeError

try:
    import requests_cache
    from requests_cache import CachedSession, CachedResponse
    HAS_CACHE = True
except ImportError:
    HAS_CACHE = False

logger = logging.getLogger("pypdns")

sort_choice = ['count', 'rdata', 'rrname', 'rrtype', 'time_first', 'time_last']


class PDNSRecord:

    def __init__(self, record: Dict[str, Optional[Union[str, int, bool, List[str]]]]):
        self.record = record

    @property
    def raw(self) -> Dict[str, Optional[Union[str, int, bool, List[str]]]]:
        return self.record

    @property
    def rrname(self) -> str:
        if not isinstance(self.record['rrname'], str):
            raise PDNSRecordTypeError('rrname', 'str', self.record["rrname"])
        return self.record['rrname']

    @property
    def rrtype(self) -> str:
        if not isinstance(self.record['rrtype'], (str, int)):
            raise PDNSRecordTypeError('rrtype', 'str, int', self.record["rrtype"])
        if isinstance(self.record['rrtype'], int):
            return RdataType(self.record['rrtype']).name
        else:
            # Just to make sure the type is correct
            return RdataType[self.record['rrtype']].name

    @property
    def rdata(self) -> Union[str, List[str]]:
        if not isinstance(self.record['rdata'], (str, list)):
            raise PDNSRecordTypeError('rrdata', 'str, list of string', self.record["rrdata"])
        return self.record['rdata']

    @property
    def time_first(self) -> int:
        if not isinstance(self.record['time_first'], int):
            raise PDNSRecordTypeError('time_first', 'int', self.record["time_first"])
        return self.record['time_first']

    @property
    def time_last(self) -> int:
        if not isinstance(self.record['time_last'], int):
            raise PDNSRecordTypeError('time_last', 'int', self.record["time_last"])
        return self.record['time_last']

    def __repr__(self) -> str:
        return f'PDNSRecord(rrname="{self.rrname}", rrtype="{self.rrtype}", rdata="{self.rdata}", time_first={self.time_first}, time_last={self.time_last})'

    @property
    def time_first_datetime(self) -> datetime:
        return datetime.fromtimestamp(self.time_first)

    @property
    def time_last_datetime(self) -> datetime:
        return datetime.fromtimestamp(self.time_last)

    @property
    def count(self) -> Optional[int]:
        if 'count' not in self.record:
            return None
        if not isinstance(self.record['count'], int):
            raise PDNSRecordTypeError('count', 'int', self.record["count"])
        return self.record['count']

    @property
    def bailiwick(self) -> Optional[str]:
        if 'bailiwick' not in self.record:
            return None
        if not isinstance(self.record['bailiwick'], str):
            raise PDNSRecordTypeError('bailiwick', 'str', self.record["bailiwick"])
        return self.record['bailiwick']

    @property
    def sensor_id(self) -> Optional[str]:
        if 'sensor_id' not in self.record:
            return None
        if not isinstance(self.record['sensor_id'], str):
            raise PDNSRecordTypeError('sensor_id', 'str', self.record["sensor_id"])
        return self.record['sensor_id']

    @property
    def zone_time_first(self) -> Optional[int]:
        if 'zone_time_first' not in self.record:
            return None
        if not isinstance(self.record['zone_time_first'], int):
            raise PDNSRecordTypeError('zone_time_first', 'int', self.record["zone_time_first"])
        return self.record['zone_time_first']

    @property
    def zone_time_last(self) -> Optional[int]:
        if 'zone_time_last' not in self.record:
            return None
        if not isinstance(self.record['zone_time_last'], int):
            raise PDNSRecordTypeError('zone_time_last', 'int', self.record["zone_time_last"])
        return self.record['zone_time_last']

    @property
    def origin(self) -> Optional[str]:
        if 'origin' not in self.record:
            return None
        if not isinstance(self.record['origin'], str):
            raise PDNSRecordTypeError('origin', 'str', self.record["origin"])
        return self.record['origin']

    @property
    def time_first_ms(self) -> Optional[int]:
        if 'time_first_ms' not in self.record:
            return None
        if not isinstance(self.record['time_first_ms'], int):
            raise PDNSRecordTypeError('time_first_ms', 'int', self.record["time_first_ms"])
        return self.record['time_first_ms']

    @property
    def time_last_ms(self) -> Optional[int]:
        if 'time_last_ms' not in self.record:
            return None
        if not isinstance(self.record['time_last_ms'], int):
            raise PDNSRecordTypeError('time_last_ms', 'int', self.record["time_last_ms"])
        return self.record['time_last_ms']

    @property
    def time_first_rfc3339(self) -> Optional[str]:
        if 'time_first_rfc3339' not in self.record:
            return None
        if not isinstance(self.record['time_first_rfc3339'], str):
            raise PDNSRecordTypeError('time_first_rfc3339', 'str', self.record["time_first_rfc3339"])
        return self.record['time_first_rfc3339']

    @property
    def time_last_rfc3339(self) -> Optional[str]:
        if 'time_last_rfc3339' not in self.record:
            return None
        if not isinstance(self.record['time_last_rfc3339'], str):
            raise PDNSRecordTypeError('time_last_rfc3339', 'str', self.record["time_last_rfc3339"])
        return self.record['time_last_rfc3339']

    @property
    def meta(self) -> Optional[Dict[Any, Any]]:
        if 'meta' not in self.record:
            return None
        if not isinstance(self.record['meta'], dict):
            raise PDNSRecordTypeError('meta', 'dict', self.record["meta"])
        return self.record['meta']


class PyPDNS(object):

    def __init__(self, url: str='https://www.circl.lu/pdns/query', basic_auth: Optional[Tuple[str, str]]=None,
                 auth_token: Optional[str]=None, enable_cache: bool=False, cache_expire_after: int=604800,
                 cache_file: str='/tmp/pdns.cache', https_proxy_string: Optional[str]=None):
        self.session: Union[CachedSession, Session]
        self.url = url
        if enable_cache and not HAS_CACHE:
            raise PDNSError('Please install requests_cache if you want to use the caching capabilities.')

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

        if https_proxy_string is not None:
            proxy = {'https': https_proxy_string}
            self.session.proxies.update(proxy)

    def _query(self, q: str, sort_by: str = 'time_last', timeout: int = None) -> List[Dict[str, Optional[Union[str, int, bool, List[str]]]]]:
        logger.debug("start query() q=[%s]", q)
        if sort_by not in sort_choice:
            raise PDNSError(f'You can only sort by {", ".join(sort_choice)}')
        response: Union[Response, CachedResponse] = self.session.get(f'{self.url}/{q}', timeout=timeout if timeout else 30)
        if response.status_code != 200:
            self._handle_http_error(response)
        to_return = []
        for line in response.text.split('\n'):
            if len(line) == 0:
                continue
            try:
                if isinstance(response, CachedResponse) and response.from_cache is True:
                    logger.debug("from cache query() q=[%s]", q)
                obj = json.loads(line)
            except Exception:
                logger.exception("except query() q=[%s]", q)
                raise PDNSError(f'Unable to decode JSON object: {line}')
            to_return.append(obj)
        to_return = sorted(to_return, key=lambda k: k[sort_by])
        return to_return

    def rfc_query(self, q: str, /, *, sort_by: str = 'time_last', timeout: int = None) -> List[PDNSRecord]:
        return [PDNSRecord(record) for record in self._query(q, sort_by, timeout)]

    def query(self, q: str, sort_by: str = 'time_last', timeout: int = None) -> List[Dict]:
        # This method (almost) returns the response from the server but turns the times into python datetime.
        # It was a bad design decision hears ago. Use rfc_query instead for something saner.
        # This method will be deprecated.
        records = self._query(q, sort_by, timeout)
        for record in records:
            record['time_first'] = datetime.fromtimestamp(record['time_first'])  # type: ignore
            record['time_last'] = datetime.fromtimestamp(record['time_last'])  # type: ignore
        return records

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
