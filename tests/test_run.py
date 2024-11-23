import unittest
from dns_observe import DNSQuery
import os
from pathlib import Path

test_path = os.path.split(os.path.realpath(__file__))[0]

domains_file = Path(test_path, "./domain_list.txt")

class MyTest(unittest.TestCase):
    def test_run(self):
        with open(domains_file, 'r') as f:
            domains = f.readlines()
        for d in domains:
            d = d.strip()
            print(f"== {d} ==")
            dns = DNSQuery()
            dns.query(d)

if __name__ == '__main__':
    unittest.main()            