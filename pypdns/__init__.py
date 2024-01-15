import argparse
import json

from .api import PyPDNS, PDNSRecord, TypedPDNSRecord  # noqa
from .errors import PDNSError, RateLimitError, UnauthorizedError, ForbiddenError, ServerError  # noqa

__all__ = ['PyPDNS', 'PDNSRecord', 'TypedPDNSRecord', 'PDNSError', 'RateLimitError', 'UnauthorizedError', 'ForbiddenError', 'ServerError']


def main() -> None:
    parser = argparse.ArgumentParser(description='Triggers a request againse CIRCL Passive DNS.')
    parser.add_argument('--username', required=True, help='The username of you account.')
    parser.add_argument('--password', required=True, help='The password of you account.')
    parser.add_argument('--query', required=True, help='The query, can be an IP. domain, hostname, TLD.')
    parser.add_argument('--rrtype', help='Filter the request based on the RR Type.')
    args = parser.parse_args()

    pdns = PyPDNS(basic_auth=(args.username, args.password))

    for record in pdns.iter_query(q=args.query, filter_rrtype=args.rrtype if args.rrtype else None):
        print(json.dumps(record.record, indent=2))
