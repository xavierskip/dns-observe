from __future__ import annotations
from .parameters import REPLY_CODE
from .utils import ResponseList
import socket
import struct
import time
import datetime
import argparse
import threading
import sys
import random

__version__ = "0.7.3"

_DNS_PORT = 53

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

# user argument choices for query type
QTYPE = {
    'A'   :  RecordType.A,
    'AAAA':  RecordType.AAAA,
    'CNAME': RecordType.CNAME,
    'TXT':   RecordType.TXT,
    'HTTPS': RecordType.HTTPS,
    'NS':    RecordType.NS,
    'MX':    RecordType.MX,
}

# 反向查找：数值 -> 类型名称
QTYPE_NAME = {v: k for k, v in QTYPE.items()}

class DNSQuery:
    def __init__(self, server='1.1.1.1', wait_time=5, timeout=3, transaction_id=0):
        self.server: str = server
        self.wait_time: float = float(wait_time)  # 设置持续监听的时间
        self.timeout: int = timeout  # 设置 socket 超时时间
        self.transaction_id: int = transaction_id  # 默认值0则随机生成 transaction ID，用户也可以指定一个固定的 ID 以便于追踪
        self.sock = None
        self.stdout_msg = []
        self._msg_lock = threading.Lock()

    def query(self, qname: str, qtype: RecordType=RecordType.A) -> ResponseList:
        """
        向指定 DNS 服务器查询 DNS 记录

        Parameters:
            - qname(str): 查询记录的域名
            - qtype(RecordType): 查询的记录类型，默认为 A 类型

        Returns:
            - DNSRecord: DNS 记录实例

        Raises:
            - RuntimeError: 当 DNS 请求失败时抛出运行时错误
        """
        responses = ResponseList()
        qdata = self._build_request(qname, qtype)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            self.sock.sendto(qdata, (self.server, _DNS_PORT))
        except socket.error as err:
            raise RuntimeError('DNS request failed: %s' % err)
        
        start_time = time.time()
        while time.time() - start_time < self.wait_time:
            try:
                response, address = self.sock.recvfrom(1024)
                dns_resp = self._parse_response(response)
                responses.append(dns_resp)
                # use for stdout message
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                if len(dns_resp.answer_RRs) == 0:
                    reply = dns_resp.reply
                    code  = dns_resp.rcode                    
                    stdout = f"⨯ Time: {now}, Reply: {reply}({code}), Answer: 0, Authority: {dns_resp.authority_n}, Additional: {dns_resp.additional_n}"
                    with self._msg_lock:
                        self.stdout_msg.append(stdout)
                if len(dns_resp.answer_RRs) == 1:
                    single = True
                else:
                    single = False # 如果为0，则不会进入循环，single的值无关紧要
                for i,answer in enumerate(dns_resp.answer_RRs):
                    if single:
                        mark = '-'
                    else: # Unicode block: Box Drawing https://shapecatcher.com/unicode/block/Box_Drawing
                        if i == 0:
                            mark = '┌'
                        elif i == len(dns_resp.answer_RRs)-1:
                            mark = '└'
                        else:
                            mark = '│'
                    if answer.type in QTYPE_NAME:
                        stdout = f"{mark} Time: {now}, Name: {answer.name}, TTL: {answer.ttl}, {answer.type_name}: {answer.data_view}"
                    else:
                        stdout = f"{mark} Time: {now}, Name: {answer.name}, Type: {answer.type_name}, Data: \"{answer.data_view}\""
                    
                    with self._msg_lock:
                        self.stdout_msg.append(stdout)
            except socket.timeout:
                # print('{} fail'.format(time))
                pass # 超时是预期行为，继续监听直到 wait_time 结束
        self.sock.close()
        return responses

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

    def _parse_response(self, response: bytes) -> DNSResponse:
        dns = DNSResponse()
        dns.id = struct.unpack('>H', response[:2])[0]
        dns.flags = struct.unpack('>H', response[2:4])[0]
        dns.questions = struct.unpack('>H', response[4:6])[0]
        dns.answer_n = struct.unpack('>H', response[6:8])[0]
        dns.authority_n = struct.unpack('>H', response[8:10])[0]
        dns.additional_n = struct.unpack('>H', response[10:12])[0]

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
        for _ in range(dns.answer_n):
            # 解析域名
            name, offset = self._parse_name(response, offset)
            # print(f"record.name: {names}")
            record_name = '.'.join(map(lambda x: x.decode('utf-8'), name))

            # 解析类型和类
            # print(offset,':',' '.join(['{:02x}'.format(b) for b in response[offset:offset+4] ]))
            record_type, record_class = struct.unpack('>HH', response[offset:offset+4])
            offset += 4
            # print('record.type, record.class_',record.type, record.class_)

            # 解析ttl和数据长度
            # print(offset,':',' '.join(['{:02x}'.format(b) for b in response[offset:offset+6] ]))
            record_ttl, size = struct.unpack('>LH', response[offset:offset+6])
            offset += 6
            # print('record.ttl, size', record.ttl, size)

            # 解析数据
            # print(offset,':',' '.join(['{:02x}'.format(b) for b in response[offset:offset+size] ]))
            record_data = response[offset:offset+size]
            offset += size
            
            if record_type == RecordType.A:
                record = DNSRecordTypeA(record_name, record_type, record_class, record_ttl, record_data)
            elif record_type == RecordType.AAAA:
                record = DNSRecordTypeAAAA(record_name, record_type, record_class, record_ttl, record_data)
            elif record_type == RecordType.CNAME:
                record = DNSRecordTypeCNAME(record_name, record_type, record_class, record_ttl, record_data, response)
            elif record_type == RecordType.TXT:
                record = DNSRecordTypeTXT(record_name, record_type, record_class, record_ttl, record_data)
            elif record_type == RecordType.HTTPS:
                record = DNSRecordTypeHTTPS(record_name, record_type, record_class, record_ttl, record_data)
            elif record_type == RecordType.NS:
                record = DNSRecordTypeNS(record_name, record_type, record_class, record_ttl, record_data, response)
            elif record_type == RecordType.MX:
                record = DNSRecordTypeMX(record_name, record_type, record_class, record_ttl, record_data)
                # record.parse_mail_exchange(response, record_data)
            else:
                record = DNSResourceRecord(record_name, record_type, record_class, record_ttl, record_data)
            
            dns.answer_RRs.append(record)
        
        # test: dns-observe -s a.gtld-servers.net example.com
        for _ in range(dns.authority_n):
            pass

        for _ in range(dns.additional_n):
            pass

        return dns
    
    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
    
    def __str__(self):
        return f"DNSQuery(server={self.server}, duration={self.wait_time}s, id={self.transaction_id}, msg=[{len(self.stdout_msg)} messages])"

    def __repr__(self):
        return f"DNSQuery(server={self.server!r}, id={self.transaction_id!r})"

class DNSResponse:
    def __init__(self):
        self.id = None
        self.flags = None
        self.questions:int    = None
        self.answer_n:int     = None
        self.authority_n:int  = None
        self.additional_n:int = None
        self.answer_RRs:list[DNSResourceRecord]     = []
        self.authority_RRs:list[DNSResourceRecord]  = []
        self.additional_RRs:list[DNSResourceRecord] = []

    @property
    def rcode(self) -> int:
        return self.flags & 0b1111

    @property
    def reply(self) -> str:
        return REPLY_CODE.get(self.rcode, 'Unassigned')

    def __str__(self):
        return f"DNSResponse(id=0x{self.id:04x}, reply='{self.reply}({self.rcode})', questions={self.questions}, answers={self.answer_n}, authoritative={self.authority_n}, additional={self.additional_n})"

    def __repr__(self):
        return f"DNSResponse(id=0x{self.id:04x}, answers={self.answer_n})"

class DNSResourceRecord:
    def __init__(self, name: str, type_: int, class_: int, ttl: int, data: bytes):
        self.name: str = name
        self.type: int = type_
        self.class_: int = class_
        self.ttl: int = ttl
        self.data: bytes = data
   
    @property
    def type_name(self) -> str:
        return QTYPE_NAME.get(self.type, f'TYPE{self.type}')
    
    @property
    def data_length(self) -> int:
        return len(self.data)

    @property
    def data_hex(self) -> str:
        return f'0x{self.data.hex()}'
    
    @property
    def data_view(self) -> str:
        return self.data_hex

    def __str__(self):
        return f"Answer(name={self.name}, type={self.type_name}, class={self.class_}, ttl={self.ttl}, data='{self.data_view}')"

    def __repr__(self):
        return f"Answer(name={self.name!r}, type={self.type_name!r})"
    
class DNSRecordTypeA(DNSResourceRecord):
    @property
    def A(self) -> str:
        return socket.inet_ntop(socket.AF_INET, self.data)
    
    @property
    def data_view(self) -> str:
        return self.A

class DNSRecordTypeAAAA(DNSResourceRecord):
    @property
    def AAAA(self) -> str:
        return socket.inet_ntop(socket.AF_INET6, self.data)
    
    @property
    def data_view(self) -> str:
        return self.AAAA

class DNSRecordTypeCNAME(DNSResourceRecord):
    def __init__(self, name: str, type_: int, class_: int, ttl: int, data: bytes, response: bytes):
        super().__init__(name, type_, class_, ttl, data)
        self.CNAME: str = decompression_message(response, self.data)

    @property
    def data_view(self) -> str:
        return self.CNAME

class DNSRecordTypeTXT(DNSResourceRecord):
    @property
    def TXT(self) -> str:
        length = self.data[0]
        return self.data[1:1+length].decode('utf-8')
    
    @property
    def data_view(self) -> str:
        return self.TXT

class DNSRecordTypeHTTPS(DNSResourceRecord):
    pass

class DNSRecordTypeNS(DNSResourceRecord):
    def __init__(self, name: str, type_: int, class_: int, ttl: int, data: bytes, response: bytes):
        super().__init__(name, type_, class_, ttl, data)
        self.NS: str = decompression_message(response, self.data)

    @property
    def data_view(self) -> str:
        return self.NS

class DNSRecordTypeMX(DNSResourceRecord):
    pass

def decompression_message(buff: bytes, data: bytes) -> str:
    parts = []
    _data = data
    _offset = 0
    nlen = _data[_offset]
    # print("offset", data[0], data)
    while nlen != 0:
        # print("nlen", nlen)
        if nlen & 0b11000000 == 0b11000000:
            # buff
            (message_compression,) = struct.unpack('>H', _data[_offset: _offset+2])
            _offset =  message_compression & 0b11111111111111
            _data = buff
            nlen = _data[_offset]

        parts.append(_data[_offset+1:_offset+nlen+1])
        _offset += nlen + 1
        nlen = _data[_offset]
    # print(f"parts: {parts}")
    return '.'.join(map(lambda x: x.decode('utf-8'), parts))

class UnsupportTypeError(Exception):
    def __init__(self, message: str):
        self.message: str = message
        super().__init__(message)

    def __str__(self):
        return f"Unsupported query type: '{self.message}'"

def query_type(qtype: str) -> int:
        """ QTYPE: support query type
        """
        try:
            return QTYPE[qtype]
        except KeyError as exc:
            raise UnsupportTypeError(qtype) from exc

def transaction_id_type(value: str) -> int:
    """
    验证 transaction_id 范围 1-65535，0表示随机生成
    value不能为0，就是要避免用户显式指定 0 然后又期待随机生成的歧义
    """
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
    parser.add_argument('-id','--transaction_id', type=transaction_id_type, default=0, help='DNS transaction ID (0=random, 1-65535=fixed),\
                        can use in wireshark display filter like `dns.id == 0x123` to track queries')
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
