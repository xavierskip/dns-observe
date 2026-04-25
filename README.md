[![publish](https://github.com/xavierskip/dns-observe/actions/workflows/publish-to-test-pypi.yml/badge.svg?event=push)](https://github.com/xavierskip/dns-observe/actions) [![PyPI version](https://badge.fury.io/py/dns-observe.svg?icon=si%3Apython)](https://badge.fury.io/py/dns-observe)

# dns-observe
a simple client to observe dns pollution network situation under The Great Firewall of China.

## Features

- Pure Python implementation with no third-party dependencies
- Uses raw UDP sockets and implements DNS protocol parsing per RFC 1035
- Listens continuously for a configurable time window to capture multiple responses
- Box-drawing character output for visually grouping multiple answers

## Supported Query Types

| Type  | Status | Description |
|-------|--------|-------------|
| A     | ✅ Supported  | IPv4 address records |
| AAAA  | ✅ Supported  | IPv6 address records |
| CNAME | ✅ Supported  | Canonical name records |
| TXT   | ✅ Supported  | Text records |
| HTTPS | 🚧 incomplete | HTTPS service binding records |
| NS    | ✅ Supported  | Name server records |
| MX    | ✅ Supported  | Mail exchange records |

## Installing
Install and update using [pip](https://pypi.org/project/dns-observe/):
`pip install dns-observe`

## usage
cli
```
> dns-observe -h
usage: dns-observe [-h] [-s DNS_SERVER] [-q {A,AAAA,CNAME,TXT,HTTPS,NS,MX}] [-t WAIT_TIME] [-id TRANSACTION_ID] [-v] domain

Observing DNS pollution

positional arguments:
  domain                query domain

options:
  -h, --help            show this help message and exit
  -s, --dns_server DNS_SERVER
                        DNS server (default: 1.1.1.1)
  -q, --query_type {A,AAAA,CNAME,TXT,HTTPS,NS,MX}
                        DNS record type (default: A)
  -t, --wait_time WAIT_TIME
                        socket reception duration in seconds (default: 5)
  -id, --transaction_id TRANSACTION_ID
                        DNS transaction ID (0=random, 1-65535=fixed), can use in wireshark display filter like `dns.id == 0x123` to track queries (default: 0)
  -v, --version         show program's version number and exit
```

python:

`> python -m dns_observe api.openai.com`

```python
from dns_observe import DNSQuery, RecordType
dns = DNSQuery('1.1.1.1')
dns.query('api.openai.com')
dns.query('claude.ai', RecordType.AAAA)
```

output:
```
- Time: 2024-11-22 11:18:16.977688, Name: api.openai.com, TTL: 153, A: 103.56.16.112
- Time: 2024-11-22 11:18:16.978715, Name: api.openai.com, TTL: 206, A: 192.133.77.145
┌ Time: 2024-11-22 11:18:17.140652, Name: api.openai.com, TTL: 46, A: 162.159.140.245
└ Time: 2024-11-22 11:18:17.140652, Name: api.openai.com, TTL: 46, A: 172.66.0.243
```

### How to Packaging Python Projects
https://packaging.python.org/en/latest/tutorials/packaging-projects/

```
python -m build

# testpypi
py -m twine upload --repository testpypi dist/*

# pypi
py -m twine upload dist/*
```

## dev

`> pip install -e .`

### test

`> python tests/test_run.py`