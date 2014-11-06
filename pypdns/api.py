#!/bin/python
# -*- coding: utf-8 -*-

import datetime
import json
import requests

url = 'https://www.circl.lu/pdns/query'

sort_choice = ['count', 'rdata', 'rrname', 'rrtype', 'time_first', 'time_last']


def prepare_session(basic_auth=None, auth_token=None):
    session = requests.Session()
    if basic_auth is not None:
        # basic_auth has do be a tuple ('user_name', 'password')
        session.auth = basic_auth
    elif auth_token is not None:
        session.headers.update({'Authorization': auth_token})
    else:
        # No authentication defined.
        pass
    return session


def query(session, q, sort_by='time_last'):
    if sort_by not in sort_choice:
        raise Exception('You can only sort by ' + ', '.join(sort_choice))
    response = session.get('{}/{}' .format(url, q))
    to_return = []
    for l in response.text.split('\n'):
        if len(l) == 0:
            continue
        try:
            obj = json.loads(l)
        except:
            raise Exception('Unable to decode JSON object: ' + l)
        obj['time_first'] = datetime.datetime.fromtimestamp(obj['time_first'])
        obj['time_last'] = datetime.datetime.fromtimestamp(obj['time_last'])
        to_return.append(obj)
    to_return = sorted(to_return, key=lambda k: k[sort_by])
    return to_return
