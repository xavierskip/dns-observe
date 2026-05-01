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

__version__ = "0.8.1"

_DNS_PORT = 53

# DNS query type  
class RecordType:
    A      = 1   # ✅ IPv4 
    AAAA   = 28  # ✅ IPv6 
    CNAME  = 5   # ✅ 域名别名 
    TXT    = 16  # ✅ 任意文本信息 
    NS     = 2   # ✅ DNS服务器地址  
    MX     = 15  # ✅ 邮件交换记录
    HTTPS  = 65  # 🚧 HTTPSSVC记录，RFC 7553定义，提供HTTPS服务相关信息
    SOA    = 6   # 📝 开始授权记录
    PTR    = 12  # 📝 指针记录指向另一个名称
    SRV    = 33  # 📝 服务记录，定义了某个服务的主机和端口
    SSHFP  = 44  # 📝 SSH公钥指纹记录

# user argument choices for query type
QTYPE = {
    'A'   :  RecordType.A,
    'AAAA':  RecordType.AAAA,
    'CNAME': RecordType.CNAME,
    'TXT':   RecordType.TXT,
    'HTTPS': RecordType.HTTPS,
    'NS':    RecordType.NS,
    'MX':    RecordType.MX,
    'SOA':   RecordType.SOA,
}

# 反向查找：数值 -> 类型名称
QTYPE_NAME = {v: k for k, v in QTYPE.items()}

class DNSQuery:
    def __init__(self, server='1.1.1.1', port=53, wait_time=5, timeout=3, transaction_id=0):
        self.server: str = server
        self.port: int = port
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
            self.sock.sendto(qdata, (self.server, self.port))
        except socket.error as err:
            raise RuntimeError('DNS request failed: %s' % err)
        
        start_time = time.time()
        while time.time() - start_time < self.wait_time:
            try:
                response, address = self.sock.recvfrom(1024)
                dns_resp = self._parse_response(response)
                responses.append(dns_resp)
                # output DNS response summary
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                reply = dns_resp.reply
                code  = dns_resp.rcode                    
                stdout = f"↯ Time: {now}, Reply: {reply}({code}), Answer: {dns_resp.answer_n}, Authority: {dns_resp.authority_n}, Additional: {dns_resp.additional_n}"
                log_msgs = self._print_resource_records(dns_resp, now)
                with self._msg_lock:
                    self.stdout_msg.append(stdout)
                    self.stdout_msg.extend(log_msgs)         
            except socket.timeout:
                # print('{} fail'.format(time))
                pass # 超时是预期行为，继续监听直到 wait_time 结束
        self.sock.close()
        return responses

    def _print_record_section(self, records: list[DNSResourceRecord], now: str, label: str = "") -> list[str]:
        """打印一组 DNS 记录（answer/authority/additional）"""
        if not records:
            return []
        single = len(records) == 1
        stdout_msgs = []
        for i, record in enumerate(records):
            if single:
                mark = '-'
            else:
                if i == 0:
                    mark = '┌'
                elif i == len(records) - 1:
                    mark = '└'
                else:
                    mark = '│'
            if record.type in QTYPE_NAME:
                stdout = f"{mark} {label}: {record.name}, TTL: {record.ttl_view}, {record.type_name}: {record.data_view}"
            else:
                stdout = f"{mark} {label}: {record.name}, TTL: {record.ttl_view}, Type: {record.type_name}, Data: \"{record.data_view}\""
            stdout_msgs.append(stdout)
            
        return stdout_msgs

    def _print_resource_records(self, dns_resp: DNSResponse, now: str) -> list[str]:
        """打印完整的 DNS 响应（包含 answer/authority/additional）"""
        stdout_msgs = []

        if dns_resp.answer_RRs:
            stdout_msgs.extend(self._print_record_section(dns_resp.answer_RRs, now, label="Answer"))

        if dns_resp.authority_RRs:
            stdout_msgs.extend(self._print_record_section(dns_resp.authority_RRs, now, label="Authority"))

        if dns_resp.additional_RRs:
            stdout_msgs.extend(self._print_record_section(dns_resp.additional_RRs, now, label="Additional"))

        return stdout_msgs

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
                offset += 1
                nlen = 0  # break
            else:
                parts.append(response[offset+1:offset+nlen+1]) # list append
                offset += nlen + 1
                nlen = response[offset]

        return parts, offset+1
    
    def _parse_record(self, response: bytes, offset: int) -> tuple[DNSResourceRecord, int]:
            # 解析域名
            name, offset = self._parse_name(response, offset)
            record_name = '.'.join(map(lambda x: x.decode('utf-8'), name))
            # 解析类型和类
            record_type, record_class = struct.unpack('>HH', response[offset:offset+4])
            offset += 4
            # 解析ttl和数据长度
            record_ttl, size = struct.unpack('>LH', response[offset:offset+6])
            offset += 6
            # 解析数据
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
                record = DNSRecordTypeHTTPS(record_name, record_type, record_class, record_ttl, record_data, response)
            elif record_type == RecordType.NS:
                record = DNSRecordTypeNS(record_name, record_type, record_class, record_ttl, record_data, response)
            elif record_type == RecordType.MX:
                record = DNSRecordTypeMX(record_name, record_type, record_class, record_ttl, record_data, response)
            elif record_type == RecordType.SOA:
                record = DNSRecordTypeSOA(record_name, record_type, record_class, record_ttl, record_data, response)
            else:
                record = DNSResourceRecord(record_name, record_type, record_class, record_ttl, record_data)
            
            return record, offset

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
            record, offset = self._parse_record(response, offset)
            dns.answer_RRs.append(record)
        
        # test: dns-observe -s a.gtld-servers.net example.com
        for _ in range(dns.authority_n):
            record, offset = self._parse_record(response, offset)
            dns.authority_RRs.append(record)

        for _ in range(dns.additional_n):
            record, offset = self._parse_record(response, offset)
            dns.additional_RRs.append(record)

        return dns
    
    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
    
    @property
    def server_view(self) -> str:
        return f"{self.server}:{self.port}" if self.port != 53 else self.server

    def __str__(self):
        return f"DNSQuery(server={self.server_view}, duration={self.wait_time}s, id={self.transaction_id}, msg=[{len(self.stdout_msg)} messages])"

    def __repr__(self):
        return f"DNSQuery(server={self.server_view!r}, id={self.transaction_id!r})"

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
    def ttl_view(self) -> str:
        ttl = self.ttl
        parts = []
        days, ttl = divmod(ttl, 86400)
        hours, ttl = divmod(ttl, 3600)
        minutes, seconds = divmod(ttl, 60)
        if days:
            parts.append(f'{days}d')
        if hours:
            parts.append(f'{hours}h')
        if minutes:
            parts.append(f'{minutes}m')
        if seconds or not parts:
            parts.append(f'{seconds}s')
        return f"{self.ttl} ({' '.join(parts)})"

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
        self.CNAME,_ = decompression_message(response, self.data)

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
    """HTTPS SVCB记录解析 (RFC 9460)"""

    # SvcParam键名映射 (RFC 9460)
    SVC_PARAM_KEYS = {
        0: 'mandatory',
        1: 'alpn',
        2: 'no-default-alpn',
        3: 'port',
        4: 'ipv4hint',
        5: 'ech',
        6: 'ipv6hint',
        7: 'dohpath',
        8: 'ohttp',
    }

    def __init__(self, name: str, type_: int, class_: int, ttl: int, data: bytes, response: bytes):
        super().__init__(name, type_, class_, ttl, data)
        self._response = response
        offset = 0
        self.priority: int = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        self.target, self.target_len = decompression_message(response, data[offset:])
        offset += self.target_len
        self.params: dict[str, str] = self._parse_svc_params(data[offset:])

    def _parse_svc_params(self, data: bytes) -> dict[str, str]:
        params = {}
        offset = 0
        while offset + 4 <= len(data):
            key = struct.unpack('>H', data[offset:offset+2])[0]
            length = struct.unpack('>H', data[offset+2:offset+4])[0]
            offset += 4
            if offset + length > len(data):
                break
            value = data[offset:offset+length]
            offset += length
            param_name = self.SVC_PARAM_KEYS.get(key, f'key{key}')
            params[param_name] = self._format_param_value(param_name, value)
        return params

    def _format_param_value(self, name: str, value: bytes) -> str:
        if name == 'alpn':
            alpns = []
            offset = 0
            while offset < len(value):
                length = value[offset]
                offset += 1
                if offset + length <= len(value):
                    alpns.append(value[offset:offset+length].decode('utf-8'))
                    offset += length
            return ','.join(alpns)
        elif name == 'port':
            return str(struct.unpack('>H', value)[0])
        elif name == 'ipv4hint':
            ips = [socket.inet_ntop(socket.AF_INET, value[i:i+4]) for i in range(0, len(value), 4)]
            return ','.join(ips)
        elif name == 'ipv6hint':
            ips = [socket.inet_ntop(socket.AF_INET6, value[i:i+16]) for i in range(0, len(value), 16)]
            return ','.join(ips)
        elif name in ('dohpath', 'mandatory'):
            return value.decode('utf-8', errors='replace')
        elif name == 'no-default-alpn':
            return ''
        else:
            return f'0x{value.hex()}'

    @property
    def data_view(self) -> str:
        if self.priority == 0:
            return f'alias {self.target}'
        target_name = self.target if self.target else '<Root>'
        parts = [str(self.priority), target_name]
        for k, v in self.params.items():
            parts.append(f'{k}={v}' if v else k)
        return ' '.join(parts)

class DNSRecordTypeNS(DNSResourceRecord):
    def __init__(self, name: str, type_: int, class_: int, ttl: int, data: bytes, response: bytes):
        super().__init__(name, type_, class_, ttl, data)
        self.NS, _ = decompression_message(response, self.data)

    @property
    def data_view(self) -> str:
        return self.NS

class DNSRecordTypeMX(DNSResourceRecord):
    def __init__(self, name: str, type_: int, class_: int, ttl: int, data: bytes, response: bytes):
        super().__init__(name, type_, class_, ttl, data)
        self.PRIORITY:int = struct.unpack('>H', data[:2])[0]
        self.MAIL_EXCHANGE, _ = decompression_message(response, data[2:])

    @property
    def data_view(self) -> str:
        mx = self.MAIL_EXCHANGE if self.MAIL_EXCHANGE else '<Root>'
        return f'({self.PRIORITY}) {mx}'

class DNSRecordTypeSOA(DNSResourceRecord):
    def __init__(self, name: str, type_: int, class_: int, ttl: int, data: bytes, response: bytes):
        super().__init__(name, type_, class_, ttl, data)
        # SOA 记录格式: MNAME(域名) + RNAME(域名) + SERIAL + REFRESH + RETRY + EXPIRE + MINIMUM
        offset = 0

        # 解析 MNAME (主DNS服务器)
        self.MNAME, mname_len = decompression_message(response, data[offset:])
        offset += mname_len

        # 解析 RNAME (管理员邮箱)
        self.RNAME, rname_len = decompression_message(response, data[offset:])
        offset += rname_len  

        # 解析 5个32位整数
        self.SERIAL: int = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        self.REFRESH: int = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        self.RETRY: int = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        self.EXPIRE: int = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        self.MINIMUM: int = struct.unpack('>I', data[offset:offset+4])[0]

    @property
    def data_view(self) -> str:
        return f"{self.MNAME} {self.RNAME} {self.SERIAL} {self.REFRESH} {self.RETRY} {self.EXPIRE} {self.MINIMUM}"

def decompression_message(buff: bytes, data: bytes) -> tuple[str, int]:
    parts = []
    _data = data
    _offset = 0
    nlen = _data[_offset]
    skip = 0
    jump = 0
    while nlen != 0:
        if nlen & 0b11000000 == 0b11000000:
            # buff
            (message_compression,) = struct.unpack('>H', _data[_offset: _offset+2])
            _offset =  message_compression & 0b11111111111111
            _data = buff
            nlen = _data[_offset]
            jump += 1

        # 如果经过压缩指针，此时_data和_offset已经指向了新的位置
        parts.append(_data[_offset+1:_offset+nlen+1])

        if jump == 0:  # 没有经过压缩指针的部分
            skip += nlen + 1
        if jump == 1:  # 第一次遇到指针，且只增加一次指针的长度。
            skip += 1  # 指针长度为2，只增加1是因为，函数末尾还会加1
            jump += 1  # 既然已经经过指针，skip 长度将不再增加。

        # 读取下一个标签做准备
        _offset += nlen + 1
        nlen = _data[_offset]

    return '.'.join(map(lambda x: x.decode('utf-8'), parts)), skip+1

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

def port_type(value: str) -> int:
    """
    验证 port 范围 1-65535
    """
    ivalue = int(value)
    if ivalue < 1 or ivalue > 65535:
        raise argparse.ArgumentTypeError(f"port must be 1-65535, got {value}")
    return ivalue

def main():
    parser = argparse.ArgumentParser(
        description='Observing DNS pollution',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument('domain', help='query domain')
    parser.add_argument('-s','--dns_server', default='1.1.1.1', help='DNS server')
    parser.add_argument('-p','--port', type=port_type, default=53, help='DNS server port')
    parser.add_argument('-q', '--query_type', type=str.upper, default='A', choices=QTYPE.keys(), help="DNS record type")
    parser.add_argument('-t','--wait_time', type=float, default=5, help='socket reception duration in seconds')
    parser.add_argument('-id','--transaction_id', type=transaction_id_type, default=0, help='DNS transaction ID (0=random, 1-65535=fixed),\
                        can use in wireshark display filter like `dns.id == 0x123` to track queries')
    parser.add_argument('-v', '--version', action='version', version=f'version: {__version__}')
    args = parser.parse_args()
    dns = DNSQuery(server=args.dns_server, port=args.port, wait_time=args.wait_time, transaction_id=args.transaction_id)  # 设置 DNS 服务器 IP及持续监听时间
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
