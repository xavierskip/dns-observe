### 
a simple client to observe dns pollution network situation under The Great Firewall of China.


### usage
```
usage: dns.py [-h] [-s SERVER] [-w WAIT] domain

Observing DNS pollution

positional arguments:
  domain                query domain

options:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        DNS server (default: 1.1.1.1)
  -w WAIT, --wait WAIT  wait time (default: 3)
```

### Packaging Python Projects
https://packaging.python.org/en/latest/tutorials/packaging-projects/

```
python -m build

py -m twine upload --repository testpypi dist/*
```
