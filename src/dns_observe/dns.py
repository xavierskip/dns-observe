import socket
import struct
import time
import datetime
import argparse

__version__ = "0.0.3"

# DNS query type  
class QueryType:
    A = 1   # IPv4
    AAAA = 28  # IPv6
    CNAME = 5 # 域名别名
    NS = 2   # DNS服务器地址
    PTR = 12 # 指针记录指向另一个名称
    MX = 15  # 邮件交换记录
    SOA = 6  # 开始授权记录
    TXT = 16 # 任意文本信息

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
DNS_RCODE = {
    0:  "No Error",
    1:  "Format Error",
    2:  "Server Failure",
    3:  "Non-Existent Domain",
    4:  "Not Implemented",
    5:  "Query Refused",
    6:  "Name Exists when it should not",
    7:  "RR Set Exists when it should not",
    8:  "RR Set that should exist does not",
    9:  "Server Not Authoritative for zone",
    9:  "Not Authorized",
    10: "Name not contained in zone",
    11: "DSO-TYPE Not Implemented	",
    16: "Bad OPT Version",
    16: "TSIG Signature Failure",
    17: "Key not recognized",
    18: "Signature out of time window",
    19: "Bad TKEY Mode",
    20: "Duplicate key name",
    21: "Algorithm not supported",
    22: "Bad Truncation",
    23: "Bad/missing Server Cookie"
}

class DNSQuery:
    def __init__(self, server, timeout=2):
        self._server = server
        self._TIMEOUT = timeout
        self.queries = []

    def query(self, qname, qtype=QueryType.A):
        """
        向指定 DNS 服务器查询 DNS 记录

        Parameters:
            - qname(str): 查询记录的域名
            - qtype(QueryType): 查询的记录类型，默认为 A 类型

        Returns:
            - DNSRecord: DNS 记录实例

        Raises:
            - RuntimeError: 当 DNS 请求失败时抛出运行时错误
        """
        qdata = self._build_request(qname, qtype)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._TIMEOUT)
            sock.sendto(qdata, (self._server, 53))
        except socket.error as err:
            raise RuntimeError('DNS request failed: %s' % err)
        
        start_time = time.time()
        listen_time = 5  # 设置持续监听的时间为5秒
        while time.time() - start_time < listen_time:
            try:
                buff, address = sock.recvfrom(1024)
                dns_record = self._parse_response(buff)
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                if len(dns_record.answers) == 0:
                    code = dns_record.flags & 0b1111
                    reply = DNS_RCODE.get(code, 'Unassigned')
                    print(f"Time: {now}, Reply code: {reply}({code})")
                for answer in dns_record.answers:
                    print(f"Time: {now}, Name: {answer.name}, TTL: {answer.ttl}, Data: {answer.ip_address}")
            except socket.timeout as err:
                # print('{} fail'.format(time))
                pass

        return self.queries
    


    def _build_request(self, qname, qtype):
        id = 1234
        flag = 0x0100
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0

        qname = qname.split('.')
        qdata = b''
        for q in qname:
            qdata += struct.pack('>B', len(q)) + q.encode('utf-8')
        qdata += b'\x00'

        # label_size = [len(i) for i in qname]
        # qname = struct.pack('>' + 'B' * len(qname), *label_size) + b''.join([bytes(part, 'utf-8') for part in qname]) + b'\x00'

        header = struct.pack('>HHHHHH', id, flag, qdcount, ancount, nscount, arcount)
        question = qdata + struct.pack('>HH', qtype, 1)

        return header + question
    
    def _parse_name(self, response: bytes, offset: int) -> tuple[str, int]:
        # print(type(response), type(offset) )
        nlen = response[offset]
        parts = []
        while nlen != 0:
            # print(type(response[offset+1:offset+nlen+1]), response[offset+1:offset+nlen+1])
            parts.append(response[offset+1:offset+nlen+1])
            offset += nlen + 1
            nlen = response[offset]
        return '.'.join(map(lambda x: x.decode('utf-8'), parts)), offset

    def _parse_response(self, response):
        dns = DNSRecord()
        dns.id = struct.unpack('>H', response[:2])[0]
        dns.flags = struct.unpack('>H', response[2:4])[0]
        dns.questions= struct.unpack('>H', response[4:6])[0]
        answer_n = struct.unpack('>H', response[6:8])[0]
        dns.authoritative = struct.unpack('>H', response[8:10])[0]
        dns.additional = struct.unpack('>H', response[10:12])[0]

        # Queries
        offset = 12
        for _ in range(dns.questions):
            nlen = response[offset]
            while nlen != 0:
                offset += nlen + 1
                nlen = response[offset]
            # skip Type and Class
            offset += 1 + 4

        # print('answer length', answer_n, 'offset', offset,':',' '.join(['{:02x}'.format(b) for b in response[offset:]]))
        for _ in range(answer_n):
            record = DNSResourceRecord()

            # 解析域名
            # print(response[offset:offset+2])
            # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
            if response[offset] & 0b11000000 == 0b11000000:
                message_compression = struct.unpack('>H', response[offset: offset+2])[0]
                name_offset = message_compression & 0b111111
                record.name, _offset = self._parse_name(response, name_offset)
                offset += 2
            else:
                record.name, _offset = self._parse_name(response, offset)
                offset = _offset+1

            # 解析类型和类
            # print(offset,':',' '.join(['{:02x}'.format(b) for b in response[offset:offset+4] ]))
            record.type, record.class_ = struct.unpack('>HH', response[offset:offset+4])
            offset += 4
            # print('record.type, record.class_',record.type, record.class_)

            # 解析ttl和数据长度
            # print(offset,':',' '.join(['{:02x}'.format(b) for b in response[offset:offset+6] ]))
            record.ttl, size = struct.unpack('>LH', response[offset:offset+6])
            offset += 6
            # print('record.ttl, size', record.ttl, size)

            # 解析数据
            # print(offset,':',' '.join(['{:02x}'.format(b) for b in response[offset:offset+size] ]))
            record.data = response[offset:offset+size]
            offset += size

            dns.answers.append(record)

        return dns

class DNSRecord:
    def __init__(self):
        self.id = None
        self.flags = None
        self.questions = None
        self.answers = []
        self.authoritative = None
        self.additional = None

class DNSResourceRecord:
    def __init__(self):
        self.class_ = None
        self.name = None
        self.type = None
        self.ttl = None
        self.data = None\
    
    @property
    def ip_address(self):
        return  socket.inet_ntoa(self.data)
    
def main():
    # try:
    #     domain = sys.argv[1]
    # except IndexError:
    #     domain = 'openai.com'
    # try:
    #     dns_server = sys.argv[2]
    # except IndexError:
    #     dns_server = '1.1.1.1'
    
    parser = argparse.ArgumentParser(
        description='Observing DNS pollution',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument('domain', help='query domain')
    parser.add_argument('-s','--server', default='1.1.1.1', help='DNS server')
    parser.add_argument('-w','--wait', default=3, help='wait time')
    parser.add_argument('-v', '--version', action='version', version=f'version: {__version__}')
    args = parser.parse_args()
    dns = DNSQuery(args.server, args.wait)  # 设置 DNS 服务器 IP
    querys = dns.query(args.domain)  # 查询记录信息

if __name__ == '__main__':
    main()