"""Test decompression_message function for DNS name decompression."""
import unittest
import sys
sys.path.insert(0, 'src')

# from dns_observe.utils import decompression_message1 as decompression
from dns_observe import decompression_message as decompression


class TestDecompressionMessage(unittest.TestCase):
    """Test decompression_message returns (domain, length) correctly."""

    def test_multi_compressed_pointer(self):
        """Test domain with multiple compressed pointers."""
        import base64
        data = b'\x0A\x68\x6F\x73\x74\x6D\x61\x73\x74\x65\x72\xC0\x38\x65\xf2\x8b\xbc\x00\x00\x07\x08\x00\x00\x03\x84\x00\x12\x75\x00\x00\x00\x01'
        buff = base64.b64decode('FGqBgwABAAAAAQAACG5vdGV4aXN0CWV4YW1wbGUxMQNjb20AAAEAAcAVAAYAAQAAASwAMANuczEIc3RhY2tkbnPAHwpob3N0bWFzdGVywDhl8ou8AAAHCAAAA4QAEnUAAAABLA==')

        domain, length = decompression(buff, data)

        self.assertEqual(domain, 'hostmaster.stackdns.com')
        self.assertEqual(length, 13)
        print(f"[OK] Multi compressed: '{domain}', length={length}")
        

    def test_simple_domain(self):
        """Test simple uncompressed domain."""
        # example.com = \x07example\x03com\x00
        data = b'\x07example\x03com\x00'
        buff = data  # 简单情况，buffer就是data本身

        domain, length = decompression(buff, data)

        self.assertEqual(domain, 'example.com')
        self.assertEqual(length, 13)  # 1+7 + 1+3 + 1 = 13
        print(f"[OK] Simple domain: '{domain}', length={length}")

    def test_single_label(self):
        """Test single label domain."""
        # localhost = \x09localhost\x00
        data = b'\x09localhost\x00'
        buff = data

        domain, length = decompression(buff, data)

        self.assertEqual(domain, 'localhost')
        self.assertEqual(length, 11)  # 1+9 + 1 = 11
        print(f"[OK] Single label: '{domain}', length={length}")

    def test_compressed_pointer_at_end(self):
        """Test domain ending with compression pointer."""
        # www.example.com where \xc0\x0c points to offset 12
        # data = \x03www\xc0\x0c
        # buff contains: ...\x07example\x03com\x00 at offset 12
        data = b'\x03www\xc0\x0c'  # 6 bytes: 1+3 + 2(pointer)
        buff = b'\x00' * 12 + b'\x07example\x03com\x00'  # padding + original domain

        domain, length = decompression(buff, data)

        self.assertEqual(domain, 'www.example.com')
        self.assertEqual(length, 6)  # only count bytes in 'data', not the pointed part
        print(f"[OK] Compressed pointer: '{domain}', length={length}")

    def test_compressed_in_middle(self):
        """Test domain with compression pointer in the middle."""
        # sub.domain.example.com
        # data = \x03sub\x06domain\xc0\x10
        # buff has example.com at offset 16
        data = b'\x03sub\x06domain\xc0\x10'  # 1+3 + 1+6 + 2 = 13 bytes
        buff = b'\x00' * 16 + b'\x07example\x03com\x00'

        domain, length = decompression(buff, data)

        self.assertEqual(domain, 'sub.domain.example.com')
        self.assertEqual(length, 13)
        print(f"[OK] Mid compression: '{domain}', length={length}")

    def test_root_domain(self):
        """Test root domain (just \x00)."""
        data = b'\x00'
        buff = data

        domain, length = decompression(buff, data)

        self.assertEqual(domain, '')  # root is empty string
        self.assertEqual(length, 1)  # just the null terminator
        print(f"[OK] Root domain: '{domain}', length={length}")

    def test_long_domain(self):
        """Test longer domain with multiple labels."""
        # a.b.c.example.com
        data = b'\x01a\x01b\x01c\x07example\x03com\x00'
        buff = data

        domain, length = decompression(buff, data)

        self.assertEqual(domain, 'a.b.c.example.com')
        self.assertEqual(length, 19)  # 1+1 + 1+1 + 1+1 + 1+7 + 1+3 + 1 = 19
        print(f"[OK] Long domain: '{domain}', length={length}")


class TestDecompressionInContext(unittest.TestCase):
    """Test decompression in realistic DNS response context."""

    def test_mx_record_data(self):
        """Test parsing MX record data (priority + domain)."""
        # MX data: 00 0a (priority=10) + \x08mxdomain\x02qq\xc0\x17
        # After priority, domain starts at offset 2
        # \xc0\x17 points to offset 23 in buff
        priority = b'\x00\x0a'  # 10
        domain_part = b'\x08mxdomain\x02qq\xc0\x17'  # 14 bytes: 1+8 + 1+2 + 2
        data = priority + domain_part

        # buff has example.com at offset 23
        buff = b'\x00' * 23 + b'\x07example\x03com\x00'

        # Parse domain part only (skip priority)
        domain, length = decompression(buff, domain_part)

        self.assertEqual(domain, 'mxdomain.qq.example.com')
        self.assertEqual(length, 14)  # 1+8 + 1+2 + 2(pointer)
        print(f"[OK] MX record: '{domain}', length={length}")

    def test_soa_record_mname_rname(self):
        """Test parsing SOA record with MNAME and RNAME."""
        # SOA: MNAME + RNAME + 5 integers
        # MNAME: \x06ns1-09\x09azure-dns\x04info\x00 (23 bytes)
        # RNAME: \x09mshtr-mx2\x09azure-dns\x04info\x00 (26 bytes)
        mname = b'\x06ns1-09\x09azure-dns\x04info\x00'  # 1+6 + 1+9 + 1+4 + 1 = 23
        rname = b'\x09mshtr-mx2\x09azure-dns\x04info\x00'  # 1+9 + 1+9 + 1+4 + 1 = 25
        serial_refresh_retry_expire_mininum = b'\x00\x00\x00\x01' * 5  # 20 bytes

        data = mname + rname + serial_refresh_retry_expire_mininum
        buff = data  # No compression in this example

        # Parse MNAME
        mname_domain, mname_len = decompression(buff, mname)
        self.assertEqual(mname_domain, 'ns1-09.azure-dns.info')
        self.assertEqual(mname_len, 23)

        # Parse RNAME (at offset 23 in data)
        rname_domain, rname_len = decompression(buff, rname)
        self.assertEqual(rname_domain, 'mshtr-mx2.azure-dns.info')
        self.assertEqual(rname_len, 26)

        print(f"[OK] SOA MNAME: '{mname_domain}', len={mname_len}")
        print(f"[OK] SOA RNAME: '{rname_domain}', len={rname_len}")


if __name__ == '__main__':
    unittest.main(verbosity=2)