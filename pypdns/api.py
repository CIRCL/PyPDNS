#!/bin/python
# -*- coding: utf-8 -*-

from api_key import user, password

import datetime
import json
import requests
from requests.auth import HTTPBasicAuth

url = 'https://www.circl.lu/pdns/query'

sort_choice = ['count', 'rdata', 'rrname', 'rrtype', 'time_first', 'time_last']


def query(q, sort_by='time_last'):
    if sort_by not in sort_choice:
        raise Exception('You can only sort by ' + ', '.join(sort_choice))
    auth = HTTPBasicAuth(user, password)
    response = requests.get('{}/{}' .format(url, q), auth=auth, stream=True)
    to_return = []
    for l in response.text.split('\n'):
        if len(l) == 0:
            continue
        obj = json.loads(l)
        obj['time_first'] = datetime.datetime.fromtimestamp(obj['time_first'])
        obj['time_last'] = datetime.datetime.fromtimestamp(obj['time_last'])
        to_return.append(obj)
    to_return = sorted(to_return, key=lambda k: k[sort_by])
    return to_return
