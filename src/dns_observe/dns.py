from __future__ import annotations
import socket
import struct
import time
import datetime
import argparse
import threading
import sys
import random

__version__ = "0.7.1"

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
# DNS query type  
class RecordType:
    A      = 1   # IPv4
    AAAA   = 28  # IPv6
    CNAME  = 5   # 域名别名
    NS     = 2   # DNS服务器地址
    PTR    = 12  # 指针记录指向另一个名称
    MX     = 15  # 邮件交换记录
    SOA    = 6   # 开始授权记录
    TXT    = 16  # 任意文本信息
    HTTPS  = 65  

QTYPE = {
    'A'   :  RecordType.A,
    'AAAA':  RecordType.AAAA,
    'CNAME': RecordType.CNAME,
    'TXT':   RecordType.TXT,
    'HTTPS': RecordType.HTTPS,
}

# 反向查找：数值 -> 类型名称
QTYPE_NAME = {v: k for k, v in QTYPE.items()}

class UnsupportTypeError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"'{self.message}' is unsupport type: "

def query_type(qtype: str) -> int:
        """ QTYPE: support query type
        """
        try:
            return QTYPE[qtype]
        except KeyError as exc:
            raise UnsupportTypeError(qtype) from exc

class DNSQuery:
    def __init__(self, server='1.1.1.1', wait_time=5, timeout=3, transaction_id=0):
        self.server = server
        self.wait_time = float(wait_time)     # 设置持续监听的时间
        self.timeout = timeout                # 设置 socket 超时时间
        self.transaction_id = transaction_id  # 默认值0则随机生成 transaction ID，用户也可以指定一个固定的 ID 以便于追踪
        self.sock = None
        self.stdout_msg = []
        self._msg_lock = threading.Lock()

    def query(self, qname: str, qtype=RecordType.A) -> list[DNSResponse]:
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
        answers = []
        qdata = self._build_request(qname, qtype)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            self.sock.sendto(qdata, (self.server, 53))
        except socket.error as err:
            raise RuntimeError('DNS request failed: %s' % err)
        
        start_time = time.time()
        while time.time() - start_time < self.wait_time:
            try:
                response, address = self.sock.recvfrom(1024)
                dns_msg = self._parse_response(response)
                answers.append(dns_msg)
                # use for stdout message
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                if len(dns_msg.answers) == 0:
                    code = dns_msg.flags & 0b1111
                    reply = DNS_RCODE.get(code, 'Unassigned')
                    stdout = f"Time: {now}, Reply code: {reply}({code}), Answer RRS: 0"
                    with self._msg_lock:
                        self.stdout_msg.append(stdout)
                if len(dns_msg.answers) == 1:
                    single = True
                if len(dns_msg.answers) > 1:
                    single = False
                for i,answer in enumerate(dns_msg.answers):
                    if single:
                        mark = '-'
                    else: # Unicode block: Box Drawing https://shapecatcher.com/unicode/block/Box_Drawing
                        if i == 0:
                            mark = '┌'
                        elif i == len(dns_msg.answers)-1:
                            mark = '└'
                        else:
                            mark = '│'
                    if answer.type == RecordType.A:
                        stdout = f"{mark} Time: {now}, Name: {answer.name}, TTL: {answer.ttl}, A: {answer.ipv4_address}"
                    elif answer.type == RecordType.AAAA:
                        stdout = f"{mark} Time: {now}, Name: {answer.name}, TTL: {answer.ttl}, AAAA: {answer.ipv6_address}"
                    elif answer.type == RecordType.CNAME:
                        message = decompression_message(response, answer.data)
                        stdout = f"{mark} Time: {now}, Name: {answer.name}, TTL: {answer.ttl}, CNAME: {message}"
                    elif answer.type == RecordType.HTTPS:
                        message = decompression_message(response, answer.data)
                        stdout = f"{mark} Time: {now}, Name: {answer.name}, TTL: {answer.ttl}, HTTPS: {message}"
                    else:
                        stdout = f"{mark} Time: {now}, Name: {answer.name}, Other Type!"
                    
                    with self._msg_lock:
                        self.stdout_msg.append(stdout)
            except socket.timeout as err:
                # print('{} fail'.format(time))
                pass
        self.sock.close()
        return answers

    def _build_request(self, qname: str, qtype: int) -> bytes:
        if self.transaction_id == 0:
            self.transaction_id = random.randint(1, 65535)
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

        header = struct.pack('>HHHHHH', self.transaction_id, flag, qdcount, ancount, nscount, arcount)
        question = qdata + struct.pack('>HH', qtype, 1)

        return header + question
    
    def _parse_name(self, response: bytes, offset: int) -> tuple[str, int]:
        # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
        nlen = response[offset]
        parts = []
        while nlen != 0:
            if nlen & 0b11000000 == 0b11000000:
                (message_compression,) = struct.unpack('>H', response[offset: offset+2])
                _offset = message_compression & 0b11111111111111
                p, _set = self._parse_name(response, _offset)  # 递归调用
                parts.extend(p)                                # list extend
                offset += 2
                nlen = 0  # break
            else:
                parts.append(response[offset+1:offset+nlen+1]) # list append
                offset += nlen + 1
                nlen = response[offset]
                if nlen == 0:  # offset + 1 before break
                    offset += 1

        return parts, offset

    def _parse_response(self, response) -> DNSResponse:
        dns = DNSResponse()
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
            name, offset = self._parse_name(response, offset)
            # print(f"record.name: {names}")
            record.name = '.'.join(map(lambda x: x.decode('utf-8'), name))

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
    
    def close(self):
        self.sock.close()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

class DNSResponse:
    def __init__(self):
        self.id = None
        self.flags = None
        self.questions = None
        self.answers = []
        self.authoritative = None
        self.additional = None

    def __str__(self):
        return f"DNSResponse(id=0x{self.id:04x}, flags=0x{self.flags:04x}, questions={self.questions}, answers=[{len(self.answers)} records], authoritative={self.authoritative}, additional={self.additional})"

class DNSResourceRecord:
    def __init__(self):
        self.class_ = None
        self.name = None
        self.type = None
        self.ttl = None
        self.data = None

    @property
    def ipv4_address(self):
        return socket.inet_ntop(socket.AF_INET, self.data)

    @property
    def ipv6_address(self):
        return socket.inet_ntop(socket.AF_INET6, self.data)
    
    @property
    def type_name(self) -> str:
        return QTYPE_NAME.get(self.type, f'TYPE{self.type}') 

    @property
    def _data_str_preview(self) -> str:
        if self.type == RecordType.A:
            return self.ipv4_address
        if self.type == RecordType.AAAA:
            return self.ipv6_address
        if self.type == RecordType.CNAME:
            # 检查是否包含压缩指针 (0b11xxxxxx = 192-255)
            try:            
                p = self.data.index(0xc0)  # 查找压缩指针的位置
                # print(f"！找到指针 {p} {self.data.hex()} {self.data[:p].hex()} {self.data[p:].hex()}")
                d = self.data[:p] + b'\x00'  # 跳过压缩指针的部分以追加一个0字节用来截止解析域名
                return decompression_message(d, d) + f'.&[0x{self.data[p:].hex()}]'
            except ValueError:
                return decompression_message(self.data, self.data) 
        return f'0x{self.data.hex()}'

    def __str__(self):
        return f"Answer(name={self.name}, type={self.type_name}, class_={self.class_}, ttl={self.ttl}, data='{self._data_str_preview}')"

def decompression_message(buff: bytes, data: bytes) -> str:
    parts = []
    offset = 0
    nlen = data[offset]
    # print("offset", data[0], data)
    while nlen != 0:
        # print("nlen", nlen)
        if nlen & 0b11000000 == 0b11000000:
            # buff
            (message_compression,) = struct.unpack('>H', data[offset: offset+2])
            _offset =  message_compression & 0b11111111111111
            nlen = buff[_offset]
            parts.append(buff[_offset+1:_offset+nlen+1])
            # offset += 2
            nlen = 0
        else:
            # data
            parts.append(data[offset+1:offset+nlen+1])
            offset += nlen + 1
            nlen = data[offset]
    # print(f"parts: {parts}")
    return '.'.join(map(lambda x: x.decode('utf-8'), parts))

def transaction_id_type(value):
    """验证 transaction_id 范围 1-65535，0表示随机生成"""
    ivalue = int(value)
    if ivalue < 1 or ivalue > 65535:
        raise argparse.ArgumentTypeError(f"transaction_id must be 1-65535, got {value}")
    return ivalue

def main():
    parser = argparse.ArgumentParser(
        description='Observing DNS pollution',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument('domain', help='query domain')
    parser.add_argument('-s','--dns_server', default='1.1.1.1', help='DNS server')
    parser.add_argument('-q', '--query_type', type=str.upper, default='A', choices=QTYPE.keys(), help="DNS record type")
    parser.add_argument('-t','--wait_time', type=float, default=5, help='socket reception duration in seconds')
    parser.add_argument('-id','--transaction_id', type=transaction_id_type, default=0, help='DNS transaction ID (0=random, 1-65535=fixed)')
    parser.add_argument('-v', '--version', action='version', version=f'version: {__version__}')
    args = parser.parse_args()
    dns = DNSQuery(server=args.dns_server, wait_time=args.wait_time, transaction_id=args.transaction_id)  # 设置 DNS 服务器 IP及持续监听时间
    from .console import Spinner
    has_time_arg = '-t' in sys.argv or '--wait_time' in sys.argv # 判断是否提供了 wait_time 参数
    if has_time_arg:
        with Spinner(dns, countdown=args.wait_time) as _:     # 有倒计时
            dns.query(args.domain, qtype=query_type(args.query_type))
    else:
        with Spinner(dns) as _:                                 # 无倒计时
            dns.query(args.domain, qtype=query_type(args.query_type))

def console_script():
    """CLI entry point with KeyboardInterrupt handling"""
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user!")

if __name__ == '__main__':
    main()
