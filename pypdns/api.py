#!/usr/bin/env python3

from __future__ import annotations

import json
import logging

from datetime import datetime, timezone
from importlib.metadata import version
from typing import Any, TypedDict, overload, Literal, Generator

import requests
from requests import Session, Response
from dns.exception import DNSException
from dns.rdatatype import RdataType, to_text as rrtype_to_text

from pypdns.errors import PDNSError, UnauthorizedError, ForbiddenError, RateLimitError, ServerError, PDNSRecordTypeError

try:
    from requests_cache import CachedSession
    from requests_cache.models import CachedResponse  # type: ignore[attr-defined]
    HAS_CACHE = True
except ImportError:
    HAS_CACHE = False

logger = logging.getLogger("pypdns")

sort_choice = ['count', 'rdata', 'rrname', 'rrtype', 'time_first', 'time_last']

default_timeout = 15

# Optional fields of a COF record, and the python type each one must have.
_optional_fields: dict[str, type] = {
    'count': int,
    'bailiwick': str,
    'sensor_id': str,
    'zone_time_first': int,
    'zone_time_last': int,
    'origin': str,
    'time_first_ms': int,
    'time_last_ms': int,
    'time_first_rfc3339': str,
    'time_last_rfc3339': str,
    'meta': dict,
}


class TypedPDNSRecord(TypedDict, total=False):
    '''A dict representing a Passive DNS record'''

    rrname: str
    rrtype: str
    rdata: str | list[str]
    time_first: int
    time_last: int
    count: int | None
    bailiwick: str | None
    sensor_id: str | None
    zone_time_first: int | None
    zone_time_last: int | None
    origin: str | None
    time_first_ms: int | None
    time_last_ms: int | None
    time_first_rfc3339: str | None
    time_last_rfc3339: str | None
    meta: dict[Any, Any] | None


class PDNSRecord:
    '''A pythonesque Passive DNS record,
       see RFC for details: https://www.ietf.org/id/draft-dulaunoy-dnsop-passive-dns-cof-10.html
    '''
    __slots__ = ('_raw_record', '_typed_record')

    def __init__(self, record: dict[str, str | int | bool | list[str] | dict[Any, Any] | None]):
        self._raw_record = record
        self._typed_record = self.__init_typed_record()

    @property
    def raw(self) -> dict[str, str | int | bool | list[str] | dict[Any, Any] | None]:
        '''The raw record'''
        return self._raw_record

    @property
    def record(self) -> TypedPDNSRecord:
        return self._typed_record

    def __init_typed_record(self) -> TypedPDNSRecord:
        '''The record as a python dictionary'''
        raw = self._raw_record

        if not isinstance(raw['rrname'], str):
            raise PDNSRecordTypeError('rrname', 'str', raw['rrname'])

        rrtype_raw = raw['rrtype']
        if not isinstance(rrtype_raw, (str, int)):
            raise PDNSRecordTypeError('rrtype', 'str, int', rrtype_raw)

        try:
            # Accordingly to the specs, the type can be a string OR an int. we normalize to str.
            # make()/to_text() also cover the RFC 3597 "TYPE65535" spelling.
            rrtype = rrtype_to_text(RdataType.make(rrtype_raw))
        except (DNSException, ValueError):
            raise PDNSRecordTypeError('rrtype', 'valid RR type', rrtype_raw)

        if not isinstance(raw['rdata'], (str, list)):
            raise PDNSRecordTypeError('rdata', 'str, list of string', raw['rdata'])

        if not isinstance(raw['time_first'], int):
            raise PDNSRecordTypeError('time_first', 'int', raw['time_first'])

        if not isinstance(raw['time_last'], int):
            raise PDNSRecordTypeError('time_last', 'int', raw['time_last'])

        to_return: TypedPDNSRecord = {'rrname': raw['rrname'],
                                      'rrtype': rrtype,
                                      'rdata': raw['rdata'],
                                      'time_first': raw['time_first'],
                                      'time_last': raw['time_last']}

        for name, expected_type in _optional_fields.items():
            if name not in raw:
                continue
            value = raw[name]
            if not isinstance(value, expected_type):
                raise PDNSRecordTypeError(name, expected_type.__name__, value)
            to_return[name] = value  # type: ignore[literal-required]
        return to_return

    @property
    def rrname(self) -> str:
        '''The name of the queried resource'''
        return self.record['rrname']

    @property
    def rrtype(self) -> str:
        '''The resource record type as seen by the passive DNS'''
        return self.record['rrtype']

    @property
    def rdata(self) -> str | list[str]:
        '''The resource records of the queried resource'''
        return self.record['rdata']

    @property
    def time_first(self) -> int:
        '''The first time that the record / unique tuple (rrname, rrtype, rdata)
           has been seen by the passive DNS
        '''
        return self.record['time_first']

    @property
    def time_last(self) -> int:
        '''The last time that the record / unique tuple (rrname, rrtype, rdata)
           has been seen by the passive DNS
        '''
        return self.record['time_last']

    def __repr__(self) -> str:
        return f'PDNSRecord(rrname="{self.rrname}", rrtype="{self.rrtype}", rdata="{self.rdata}", time_first={self.time_first}, time_last={self.time_last})'

    @property
    def time_first_datetime(self) -> datetime:
        '''The first time that the record / unique tuple (rrname, rrtype, rdata)
           has been seen by the passive DNS, as a python datetime.
        '''
        return datetime.fromtimestamp(self.time_first, timezone.utc)

    @property
    def time_last_datetime(self) -> datetime:
        '''The last time that the record / unique tuple (rrname, rrtype, rdata)
           has been seen by the passive DNS, as a python datetime.
        '''
        return datetime.fromtimestamp(self.time_last, timezone.utc)

    @property
    def count(self) -> int | None:
        '''How many authoritative DNS answers were received at the Passive DNS Server's
           collectors with exactly the given set of values as answers
        '''
        return self.record.get('count')

    @property
    def bailiwick(self) -> str | None:
        '''The best estimate of the apex of the zone where this data is authoritative'''
        return self.record.get('bailiwick')

    @property
    def sensor_id(self) -> str | None:
        '''The sensor information where the record was seen.'''
        return self.record.get('sensor_id')

    @property
    def zone_time_first(self) -> int | None:
        '''The first time that the unique tuple (rrname, rrtype, rdata) record
           has been seen via master file import
        '''
        return self.record.get('zone_time_first')

    @property
    def zone_time_last(self) -> int | None:
        '''The last time that the unique tuple (rrname, rrtype, rdata) record
           has been seen via master file import
        '''
        return self.record.get('zone_time_last')

    @property
    def origin(self) -> str | None:
        '''The resource origin of the Passive DNS response'''
        return self.record.get('origin')

    @property
    def time_first_ms(self) -> int | None:
        '''The first time that the record / unique tuple (rrname, rrtype, rdata)
           has been seen by the passive DNS, in miliseconds since 1st of January 1970 (UTC).
        '''
        return self.record.get('time_first_ms')

    @property
    def time_last_ms(self) -> int | None:
        '''The first time that the record / unique tuple (rrname, rrtype, rdata)
           has been seen by the passive DNS, in miliseconds since 1st of January 1970 (UTC).
        '''
        return self.record.get('time_last_ms')

    @property
    def time_first_rfc3339(self) -> str | None:
        return self.record.get('time_first_rfc3339')

    @property
    def time_last_rfc3339(self) -> str | None:
        return self.record.get('time_last_rfc3339')

    @property
    def meta(self) -> dict[Any, Any] | None:
        return self.record.get('meta')


class PyPDNS:

    def __init__(self, url: str='https://www.circl.lu/pdns/query',
                 basic_auth: tuple[str, str] | None=None,
                 auth_token: str | None=None,
                 auth_header: tuple[str, str] | None=None,
                 enable_cache: bool=False, cache_expire_after: int=604800,
                 cache_file: str='/tmp/pdns.cache',
                 https_proxy_string: str | None=None,
                 useragent: str | None=None,
                 disable_active_query: bool=False,
                 *, proxies: dict[str, str] | None=None):
        '''Connector to Passive DNS

        :param url: The URL of the service
        :param basic_auth: HTTP basic auth to cnnect to the service: ("username", "password")
        :param auth_token: HTTP basic auth but the token
        :param auth_header: HTTP header to use for authentication: ("X-API-AUTH", "1234")
        :param enable_cache: Cache responses locally
        :param cache_file: The file to cache the responses to
        :param https_proxy_string: The HTTP proxy to connect to the service (deprecated, use proxies instead)
        :param useragent: User Agent to submit to the server
        :param disable_active_query: THe passive DNS will attempt to resolve the request by default. Set to True if you don't want that.
        :param proxies: The proxies to use to connect to Passive DNS - More details: https://requests.readthedocs.io/en/latest/user/advanced/#proxies
        '''

        self.url = url

        if enable_cache and not HAS_CACHE:
            raise PDNSError('Please install requests_cache if you want to use the caching capabilities.')

        self.session: CachedSession | Session
        if enable_cache is True:
            # NOT install_cache(): that one patches requests.Session for the whole process.
            self.session = CachedSession(cache_name=cache_file, backend='sqlite',
                                         expire_after=cache_expire_after)
        else:
            self.session = requests.Session()
        self.session.headers['user-agent'] = useragent if useragent else f'PyPDNS / {version("pypdns")}'

        if basic_auth is not None:
            # basic_auth has do be a tuple ('user_name', 'password')
            self.session.auth = basic_auth
        elif auth_token is not None:
            self.session.headers.update({'Authorization': auth_token})
        elif auth_header is not None:
            self.session.headers.update({auth_header[0]: auth_header[1]})
        else:
            # No authentication defined.
            pass

        if disable_active_query:
            self.session.headers.update({'dribble-disable-active-query': '1'})

        if https_proxy_string is not None:
            proxies = {'https': https_proxy_string}

        if proxies:
            self.session.proxies.update(proxies)

    def iter_query(self, q: str,
                   filter_rrtype: str | None=None,
                   break_on_errors: bool=False,
                   *, page_size: int=50,
                   timeout: int=default_timeout) -> Generator[PDNSRecord, None, dict[str, str | int] | None]:
        '''Iterate over all the recording matching your request, useful if there are a lot.
        Note: the order is non-deterministic.

        :param q: The query
        :param filter_rrtype: The filter, must be a valid RR Type or the response will be empty.
        :param break_on_errors: If there is an error, stop iterating and break immediately
        :param timeout: Timeout of each HTTP request, in seconds
        :param page_size: How many records to fetch per request. The pages are fetched
                          sequentially, so a bigger page means fewer round trips on a big
                          response, at the cost of more memory per response. The server
                          may cap it to a lower value.
        '''
        if page_size < 1:
            raise PDNSError('page_size must be a strictly positive integer.')
        cursor = -1
        query_headers = {'dribble-paginate-count': str(page_size)}
        if filter_rrtype:
            query_headers['dribble-filter-rrtype'] = filter_rrtype
        while True:
            if cursor > 0:
                query_headers['dribble-paginate-cursor'] = str(cursor)
            response: Response | CachedResponse = self.session.get(f'{self.url}/{q}', timeout=timeout, headers=query_headers)
            if response.status_code != 200:
                self._handle_http_error(response)
            if break_on_errors:
                if e := self._handle_dribble_errors(response):
                    return e

            if getattr(response, 'from_cache', False):
                logger.debug("from cache query() q=[%s]", q)

            for line in response.text.split('\n'):
                if len(line) == 0:
                    continue
                try:
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
               filter_rrtype: str | None=None,
               timeout: int=default_timeout) -> tuple[list[dict[str, str | int | bool | list[str] | dict[Any, Any] | None]],
                                                        dict[str, str | int]]:
        '''Internal method running a non-paginated query, can be sorted.'''
        logger.debug("start query() q=[%s]", q)
        if sort_by not in sort_choice:
            raise PDNSError(f'You can only sort by {", ".join(sort_choice)}')
        query_headers = {}
        if filter_rrtype:
            query_headers['dribble-filter-rrtype'] = filter_rrtype
        response: Response | CachedResponse = self.session.get(f'{self.url}/{q}', timeout=timeout, headers=query_headers)
        if response.status_code != 200:
            self._handle_http_error(response)
        errors = self._handle_dribble_errors(response)
        if getattr(response, 'from_cache', False):
            logger.debug("from cache query() q=[%s]", q)

        to_return = []
        for line in response.text.split('\n'):
            if len(line) == 0:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                logger.exception("except query() q=[%s]", q)
                raise PDNSError(f'Unable to decode JSON object: {line}')
            to_return.append(obj)
        try:
            to_return.sort(key=lambda k: k[sort_by])
        except KeyError:
            raise PDNSError(f'Unable to sort by "{sort_by}": some records do not have that key.')
        except TypeError:
            raise PDNSError(f'Unable to sort by "{sort_by}": records have mixed types for that key.')
        return to_return, errors

    @overload
    def rfc_query(self, q: str, /,
                  *,
                  sort_by: str = 'time_last',
                  filter_rrtype: str | None= None,
                  timeout: int=default_timeout,
                  with_errors: Literal[True]) -> tuple[list[PDNSRecord], dict[str, str | int]]:
        pass

    @overload
    def rfc_query(self, q: str, /,
                  *,
                  sort_by: str = 'time_last',
                  filter_rrtype: str | None= None,
                  timeout: int=default_timeout,
                  with_errors: Literal[False]) -> list[PDNSRecord]:
        pass

    def rfc_query(self, q: str, /,
                  *,
                  sort_by: str = 'time_last',
                  filter_rrtype: str | None= None,
                  timeout: int=default_timeout,
                  with_errors: bool=False) -> list[PDNSRecord] | tuple[list[PDNSRecord], dict[str, str | int]]:
        '''Triggers a non-paginated query, can be sorted but will raise an error if the response is too big.

        :param q: The query
        :param sort_by: The key to use to sort the records
        :param filter_rrtype: The filter, must be a valid RR Type or the response will be enpty.
        :param timeout: Timeout of the HTTP request, in seconds
        :param with_errors: Returns the errors (if any)
        '''
        records, errors = self._query(q, sort_by, filter_rrtype=filter_rrtype, timeout=timeout)
        to_return_records = [PDNSRecord(record) for record in records]
        if not with_errors:
            return to_return_records
        return to_return_records, errors

    def query(self, q: str, sort_by: str = 'time_last', timeout: int | None = None) -> list[dict[str, Any]]:
        '''This method (almost) returns the response from the server but turns the times into python datetime.
        It was a bad design decision years ago. Use rfc_query instead for something saner.
        This method is deprecated.
        '''
        records, errors = self._query(q, sort_by,
                                      timeout=timeout if timeout is not None else default_timeout)
        for record in records:
            record['time_first'] = datetime.fromtimestamp(record['time_first'], timezone.utc)  # type: ignore
            record['time_last'] = datetime.fromtimestamp(record['time_last'], timezone.utc)  # type: ignore
        return records

    def _handle_dribble_errors(self, response: requests.Response) -> dict[str, str | int]:
        if 'x-dribble-errors' in response.headers:
            return json.loads(response.headers['x-dribble-errors'])
        return {}

    @staticmethod
    def _handle_http_error(response: requests.Response) -> None:
        if response.status_code == 401:
            raise UnauthorizedError("Not authenticated: is authentication correct?")
        if response.status_code == 403:
            raise ForbiddenError("Not authorized to access resource")
        if response.status_code == 429:
            raise RateLimitError("Quota exhausted")
        if 500 <= response.status_code < 600:
            raise ServerError("Server error")
        raise PDNSError("Something went wrong")
