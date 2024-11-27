import unittest
from dns_observe import DNSQuery, RecordType, query_type, UnsupportTypeError
import os
from pathlib import Path

test_path = os.path.split(os.path.realpath(__file__))[0]

domains_file = Path(test_path, "./domain_list.txt")

class MyTest(unittest.TestCase):
    def test_query_type_argument(self):
        types = ["A","AAAA"]
        for t in types:
            print(f"=== query_type: {t} ===")
            query_type(t)
        unsupport = "CNAME", "NS", "MX", "TXT"
        for t in unsupport:
            try:
                query_type(t)
            except UnsupportTypeError:
                print(f"=== unsupport query_type: {t} ===")

    def test_run(self):
        with open(domains_file, 'r') as f:
            domains = f.readlines()
        for d in domains:
            d = d.strip()
            print(f"== {d} ==")
            dns = DNSQuery(listen_time=1, timeout=1)
            dns.query(d)
    
    def test_type_AAAA(self):
        dns = DNSQuery('223.5.5.5')
        domains = ['taobao.com', 'data.bilibili.com', 'www.qq.com']
        for d in domains:
            print(f"== {d} ==")
            dns.query(d, RecordType.AAAA)

if __name__ == '__main__':
    unittest.main()            