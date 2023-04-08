## dns-observe
a simple client to observe dns pollution network situation under The Great Firewall of China.

So far, only type A DNS queries have been implemented.

## Installing
Install and update using [pip](https://pypi.org/project/dns-observe/):
`pip install dns-observe`

## usage
cli
```
> dns-observe -h
usage: dns-observe [-h] [-s SERVER] [-w WAIT] [-v] domain

Observing DNS pollution

positional arguments:
  domain                query domain

options:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        DNS server (default: 1.1.1.1)
  -w WAIT, --wait WAIT  wait time (default: 3)
  -v, --version         show program's version number and exit
```


```python
from dns_observe import DNSQuery
dns = DNSQuery('1.1.1.1')
dns.query('api.openai.com')
```

output:
```
Time: 2023-04-08 23:16:19.217111, Name: api.openai.com, TTL: 280, Data: 199.96.61.1
Time: 2023-04-08 23:16:19.218111, Name: api.openai.com, TTL: 433, Data: 204.79.197.217
Time: 2023-04-08 23:16:19.358490, Name: api.openai.com, TTL: 7, Data: 104.18.7.192
Time: 2023-04-08 23:16:19.358490, Name: api.openai.com, TTL: 7, Data: 104.18.6.192
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
