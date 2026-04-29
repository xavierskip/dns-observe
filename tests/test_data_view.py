"""Test data_view functionality for DNS record types."""
import unittest
from dns_observe import DNSQuery, RecordType


class TestDataView(unittest.TestCase):
    """Test data_view property across different record types."""

    @classmethod
    def setUpClass(cls):
        """Set up shared DNSQuery instance."""
        cls.dns = DNSQuery('1.1.1.1', wait_time=3, timeout=2)

    def test_a_record_data_view(self):
        """Test A record returns IPv4 address in data_view."""
        responses = self.dns.query('example.com', RecordType.A)
        self.assertTrue(len(responses) > 0, "Should receive at least one response")

        for resp in responses:
            for ans in resp.answer_RRs:
                self.assertEqual(ans.type, RecordType.A)
                self.assertIsNotNone(ans.data_view)
                # IPv4 should contain dots
                self.assertIn('.', ans.data_view)
                print(f"A record: {ans.name} -> {ans.data_view}")

    def test_cname_record_data_view(self):
        """Test CNAME record returns canonical name in data_view."""
        # Use a domain known to have CNAME records
        responses = self.dns.query('www.github.com', RecordType.CNAME)

        for resp in responses:
            for ans in resp.answer_RRs:
                if ans.type == RecordType.CNAME:
                    self.assertIsNotNone(ans.data_view)
                    # CNAME should contain domain parts
                    self.assertIn('.', ans.data_view)
                    print(f"CNAME record: {ans.name} -> {ans.data_view}")

    def test_txt_record_data_view(self):
        """Test TXT record returns text content in data_view."""
        responses = self.dns.query('example.com', RecordType.TXT)

        for resp in responses:
            for ans in resp.answer_RRs:
                self.assertEqual(ans.type, RecordType.TXT)
                self.assertIsNotNone(ans.data_view)
                # TXT data_view should be a string
                self.assertIsInstance(ans.data_view, str)
                print(f"TXT record: {ans.name} -> {ans.data_view}")

    def test_aaaa_record_data_view(self):
        """Test AAAA record returns IPv6 address in data_view."""
        responses = self.dns.query('example.com', RecordType.AAAA)

        for resp in responses:
            for ans in resp.answer_RRs:
                self.assertEqual(ans.type, RecordType.AAAA)
                self.assertIsNotNone(ans.data_view)
                # IPv6 should contain colons
                self.assertIn(':', ans.data_view)
                print(f"AAAA record: {ans.name} -> {ans.data_view}")

    def test_unsupported_type_data_view(self):
        """Test unsupported types return hex data in data_view."""
        # HTTPS type may not be widely supported but we can test the fallback
        responses = self.dns.query('example.com', RecordType.SRV)

        for resp in responses:
            for ans in resp.answer_RRs:
                # HTTPS falls back to base class data_hex
                self.assertTrue(ans.data_view.startswith('0x'))
                print(f"HTTPS record: {ans.name} -> {ans.data_view}")

    def test_str_representation(self):
        """Test __str__ uses data_view correctly."""
        responses = self.dns.query('example.com', RecordType.A)

        for resp in responses:
            for ans in resp.answer_RRs:
                str_repr = str(ans)
                # Should contain data_view value
                self.assertIn(ans.data_view, str_repr)
                # Should follow expected format
                self.assertTrue(str_repr.startswith("Answer("))
                print(f"String repr: {str_repr}")


class TestDNSRecordConstructors(unittest.TestCase):
    """Test new constructor with response parameter."""

    def test_cname_constructor_with_response(self):
        """Test DNSRecordTypeCNAME accepts response in constructor."""
        from dns_observe.dns import DNSRecordTypeCNAME

        # Mock data - this is a simplified test
        # In real scenario, response would be full DNS packet
        record = DNSRecordTypeCNAME(
            name='www.example.com',
            type_=RecordType.CNAME,
            class_=1,
            ttl=300,
            data=b'\x07example\x03com\x00',
            response=b'\x00' * 100  # Mock response buffer
        )

        # Should have CNAME attribute set
        self.assertTrue(hasattr(record, 'CNAME'))

    def test_ns_constructor_with_response(self):
        """Test DNSRecordTypeNS accepts response in constructor."""
        from dns_observe.dns import DNSRecordTypeNS

        record = DNSRecordTypeNS(
            name='example.com',
            type_=RecordType.NS,
            class_=1,
            ttl=300,
            data=b'\x07example\x03com\x00',
            response=b'\x00' * 100  # Mock response buffer
        )

        # Should have NS attribute set
        self.assertTrue(hasattr(record, 'NS'))


if __name__ == '__main__':
    unittest.main()