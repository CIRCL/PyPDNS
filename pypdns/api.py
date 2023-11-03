#!/bin/python
# -*- coding: utf-8 -*-

import json
import logging

from datetime import datetime
from functools import cached_property
from importlib.metadata import version
from typing import Optional, Tuple, List, Dict, Union, Any, TypedDict, overload, Literal, Generator
# from urllib.parse import urljoin, urlparse

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


class TypedPDNSRecord(TypedDict, total=False):
    '''A dict representing a Passive DNS record'''

    rrname: str
    rrtype: str
    rdata: Union[str, List[str]]
    time_first: int
    time_last: int
    count: Optional[int]
    bailiwick: Optional[str]
    sensor_id: Optional[str]
    zone_time_first: Optional[int]
    zone_time_last: Optional[int]
    origin: Optional[str]
    time_first_ms: Optional[int]
    time_last_ms: Optional[int]
    time_first_rfc3339: Optional[str]
    time_last_rfc3339: Optional[str]
    meta: Optional[Dict[Any, Any]]


class PDNSRecord:

    def __init__(self, record: Dict[str, Optional[Union[str, int, bool, List[str], Dict[Any, Any]]]]):
        '''A pythonesque Passive DNS record'''
        self._record = record

    @property
    def raw(self) -> Dict[str, Optional[Union[str, int, bool, List[str], Dict[Any, Any]]]]:
        '''The raw record'''
        return self._record

    @cached_property
    def record(self) -> TypedPDNSRecord:
        '''The record as a python dictionary'''
        if not isinstance(self._record['rrname'], str):
            raise PDNSRecordTypeError('rrname', 'str', self._record["rrname"])

        if not isinstance(self._record['rrtype'], (str, int)):
            raise PDNSRecordTypeError('rrtype', 'str, int', self._record["rrtype"])

        if isinstance(self._record['rrtype'], int):
            # Accordingly to the specs, the type can be a string OR an int. we normalize to str
            rrtype: str = RdataType(self._record['rrtype']).name
        else:
            rrtype = RdataType[self._record['rrtype']].name

        if not isinstance(self._record['rdata'], (str, list)):
            raise PDNSRecordTypeError('rdata', 'str, list of string', self._record["rdata"])

        if not isinstance(self._record['time_first'], int):
            raise PDNSRecordTypeError('time_first', 'int', self._record["time_first"])

        if not isinstance(self._record['time_last'], int):
            raise PDNSRecordTypeError('time_last', 'int', self._record["time_last"])

        to_return: TypedPDNSRecord = {'rrname': self._record['rrname'],
                                      'rrtype': rrtype,
                                      'rdata': self._record['rdata'],
                                      'time_first': self._record["time_first"],
                                      'time_last': self._record["time_last"]}
        if 'count' in self._record:
            if not isinstance(self._record['count'], int):
                raise PDNSRecordTypeError('count', 'int', self._record["count"])
            to_return['count'] = self._record["count"]

        if 'bailiwick' in self._record:
            if not isinstance(self._record['bailiwick'], str):
                raise PDNSRecordTypeError('bailiwick', 'str', self._record["bailiwick"])
            to_return['bailiwick'] = self._record['bailiwick']

        if 'sensor_id' in self._record:
            if not isinstance(self._record['sensor_id'], str):
                raise PDNSRecordTypeError('sensor_id', 'str', self._record["sensor_id"])
            to_return['sensor_id'] = self._record['sensor_id']

        if 'zone_time_first' in self._record:
            if not isinstance(self._record['zone_time_first'], int):
                raise PDNSRecordTypeError('zone_time_first', 'int', self._record["zone_time_first"])
            to_return['zone_time_first'] = self._record['zone_time_first']

        if 'zone_time_last' in self._record:
            if not isinstance(self._record['zone_time_last'], int):
                raise PDNSRecordTypeError('zone_time_last', 'int', self._record["zone_time_last"])
            to_return['zone_time_first'] = self._record["zone_time_last"]

        if 'origin' in self._record:
            if not isinstance(self._record['origin'], str):
                raise PDNSRecordTypeError('origin', 'str', self._record["origin"])
            to_return['origin'] = self._record["origin"]

        if 'time_first_ms' in self._record:
            if not isinstance(self._record['time_first_ms'], int):
                raise PDNSRecordTypeError('time_first_ms', 'int', self._record["time_first_ms"])
            to_return['time_first_ms'] = self._record["time_first_ms"]

        if 'time_last_ms' in self._record:
            if not isinstance(self._record['time_last_ms'], int):
                raise PDNSRecordTypeError('time_last_ms', 'int', self._record["time_last_ms"])
            to_return['time_last_ms'] = self._record['time_last_ms']

        if 'time_first_rfc3339' in self._record:
            if not isinstance(self._record['time_first_rfc3339'], str):
                raise PDNSRecordTypeError('time_first_rfc3339', 'str', self._record["time_first_rfc3339"])
            to_return['time_first_rfc3339'] = self._record['time_first_rfc3339']

        if 'time_last_rfc3339' in self._record:
            if not isinstance(self._record['time_last_rfc3339'], str):
                raise PDNSRecordTypeError('time_last_rfc3339', 'str', self._record["time_last_rfc3339"])
            to_return['time_last_rfc3339'] = self._record['time_last_rfc3339']

        if 'meta' in self._record:
            if not isinstance(self._record['meta'], dict):
                raise PDNSRecordTypeError('meta', 'dict', self._record["meta"])
            to_return['meta'] = self._record['meta']

        return to_return

    @property
    def rrname(self) -> str:
        return self.record['rrname']

    @property
    def rrtype(self) -> str:
        return self.record['rrtype']

    @property
    def rdata(self) -> Union[str, List[str]]:
        return self.record['rdata']

    @property
    def time_first(self) -> int:
        return self.record['time_first']

    @property
    def time_last(self) -> int:
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
        return self.record.get('count')

    @property
    def bailiwick(self) -> Optional[str]:
        return self.record.get('bailiwick')

    @property
    def sensor_id(self) -> Optional[str]:
        return self.record.get('sensor_id')

    @property
    def zone_time_first(self) -> Optional[int]:
        return self.record.get('zone_time_first')

    @property
    def zone_time_last(self) -> Optional[int]:
        return self.record.get('zone_time_last')

    @property
    def origin(self) -> Optional[str]:
        return self.record.get('origin')

    @property
    def time_first_ms(self) -> Optional[int]:
        return self.record.get('time_first_ms')

    @property
    def time_last_ms(self) -> Optional[int]:
        return self.record.get('time_last_ms')

    @property
    def time_first_rfc3339(self) -> Optional[str]:
        return self.record.get('time_first_rfc3339')

    @property
    def time_last_rfc3339(self) -> Optional[str]:
        return self.record.get('time_last_rfc3339')

    @property
    def meta(self) -> Optional[Dict[Any, Any]]:
        return self.record.get('meta')


class PyPDNS(object):

    def __init__(self, url: str='https://www.circl.lu/pdns/query',
                 basic_auth: Optional[Tuple[str, str]]=None,
                 auth_token: Optional[str]=None,
                 enable_cache: bool=False, cache_expire_after: int=604800,
                 cache_file: str='/tmp/pdns.cache',
                 https_proxy_string: Optional[str]=None,
                 useragent: Optional[str]=None,
                 disable_active_query: bool=False):
        '''Connector to Passive DNS

        :param url: The URL of the service
        :param basic_auth: HTTP basic auth to cnnect to the service: ("username", "password")
        :param auth_token: HTTP basic auth but the token
        :param enable_cache: Cache responses locally
        :param cache_file: The file to cache the responses to
        :param https_proxy_string: The HTTP proxy to connect to the service
        :param useragent: User Agent to submit to the server
        :param disable_active_query: THe passive DNS will attempt to resolve the request by default. Set to True if you don't want that.
        '''

        self.url = url

        if enable_cache and not HAS_CACHE:
            raise PDNSError('Please install requests_cache if you want to use the caching capabilities.')

        self.session: Union[CachedSession, Session]
        if enable_cache is True:
            requests_cache.install_cache(cache_file, backend='sqlite', expire_after=cache_expire_after)
            self.session = requests_cache.CachedSession()
        else:
            self.session = requests.Session()
        self.session.headers['user-agent'] = useragent if useragent else f'PyPDNS / {version("pypdns")}'

        if basic_auth is not None:
            # basic_auth has do be a tuple ('user_name', 'password')
            self.session.auth = basic_auth
        elif auth_token is not None:
            self.session.headers.update({'Authorization': auth_token})
        else:
            # No authentication defined.
            pass

        if disable_active_query:
            self.session.headers.update({'dribble-disable-active-query': '1'})

        if https_proxy_string is not None:
            proxy = {'https': https_proxy_string}
            self.session.proxies.update(proxy)

    def iter_query(self, q: str,
                   filter_rrtype: Optional[str]=None,
                   break_on_errors: bool=False) -> Generator[PDNSRecord, None, Optional[Dict[str, Union[str, int]]]]:
        '''Iterate over all the recording matching your request, useful if there are a lot.
        Note: the order is non-deterministic.

        :param q: The query
        :param filter_rrtype: The filter, must be a valid RR Type or the response will be enpty.
        :param break_on_errors: If there is an error, stop iterating and break immediately
        '''
        cursor = -1
        query_headers = {'dribble-paginate-count': '50'}
        if filter_rrtype:
            query_headers['dribble-filter-rrtype'] = filter_rrtype
        while True:
            if cursor > 0:
                query_headers['dribble-paginate-cursor'] = str(cursor)
            response: Union[Response, CachedResponse] = self.session.get(f'{self.url}/{q}',
                                                                         timeout=15,
                                                                         headers=query_headers)
            if response.status_code != 200:
                self._handle_http_error(response)
            if break_on_errors:
                if e := self._handle_dribble_errors(response):
                    return e

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
                yield PDNSRecord(obj)

            if 'x-dribble-cursor' in response.headers:
                cursor = int(response.headers['x-dribble-cursor'])
            else:
                return None

    def _query(self, q: str, sort_by: str = 'time_last',
               *,
               filter_rrtype: Optional[str]=None) -> Tuple[List[Dict[str, Optional[Union[str, int, bool, List[str], Dict[Any, Any]]]]],
                                                           Dict[str, Union[str, int]]]:
        '''Internal method running a non-paginated query, can be sorted.'''
        logger.debug("start query() q=[%s]", q)
        if sort_by not in sort_choice:
            raise PDNSError(f'You can only sort by {", ".join(sort_choice)}')
        query_headers = {}
        if filter_rrtype:
            query_headers['dribble-filter-rrtype'] = filter_rrtype
        response: Union[Response, CachedResponse] = self.session.get(f'{self.url}/{q}',
                                                                     timeout=15,
                                                                     headers=query_headers)
        if response.status_code != 200:
            self._handle_http_error(response)
        errors = self._handle_dribble_errors(response)
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
        return to_return, errors

    @overload
    def rfc_query(self, q: str, /,
                  *,
                  sort_by: str = 'time_last',
                  filter_rrtype: Optional[str]= None,
                  with_errors: Literal[True]) -> Tuple[List[PDNSRecord], Dict[str, Union[str, int]]]:
        pass

    @overload
    def rfc_query(self, q: str, /,
                  *,
                  sort_by: str = 'time_last',
                  filter_rrtype: Optional[str]= None,
                  with_errors: Literal[False]) -> List[PDNSRecord]:
        pass

    def rfc_query(self, q: str, /,
                  *,
                  sort_by: str = 'time_last',
                  filter_rrtype: Optional[str]= None,
                  with_errors: bool=False) -> Union[List[PDNSRecord], Tuple[List[PDNSRecord], Dict[str, Union[str, int]]]]:
        '''Triggers a non-paginated query, can be sorted but will raise an error if the response is too big.

        :param q: The query
        :param sort_by: The key to use to sort the records
        :param filter_rrtype: The filter, must be a valid RR Type or the response will be enpty.
        :param with_errors: Returns the errors (if any)
        '''
        records, errors = self._query(q, sort_by, filter_rrtype=filter_rrtype)
        to_return_records = [PDNSRecord(record) for record in records]
        if not with_errors:
            return to_return_records
        return to_return_records, errors

    def query(self, q: str, sort_by: str = 'time_last', timeout: Optional[int] = None) -> List[Dict]:
        '''This method (almost) returns the response from the server but turns the times into python datetime.
        It was a bad design decision hears ago. Use rfc_query instead for something saner.
        This method is deprecated.
        '''
        records, errors = self._query(q, sort_by)
        for record in records:
            record['time_first'] = datetime.fromtimestamp(record['time_first'])  # type: ignore
            record['time_last'] = datetime.fromtimestamp(record['time_last'])  # type: ignore
        return records

    def _handle_dribble_errors(self, response: requests.Response) -> Dict[str, Union[str, int]]:
        if 'x-dribble-errors' in response.headers:
            return json.loads(response.headers['x-dribble-errors'])
        return {}

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
