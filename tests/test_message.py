from dns_observe import decompression_message as decompression
import base64
# www.example.com where \xc0\x0c points to offset 12
# data = \x03www\xc0\x0c
# buff contains: ...\x07example\x03com\x00 at offset 12

data = b'\x03www\xc0\x0c'  # 6 bytes: 1+3 + 2(pointer)
buff = b'\x00' * 12 + b'\x07example\x03com\x00'  # padding + original domain

domain, length = decompression(buff, data)

print(f"Compressed pointer: '{domain}', length={length}")

data = b'\x00\x00\x00'

domain, length = decompression(buff, data)

print(f"Compressed pointer: '{domain}', length={length}")


buff = base64.b64decode('FGqBgwABAAAAAQAACG5vdGV4aXN0CWV4YW1wbGUxMQNjb20AAAEAAcAVAAYAAQAAASwAMANuczEIc3RhY2tkbnPAHwpob3N0bWFzdGVywDhl8ou8AAAHCAAAA4QAEnUAAAABLA==')
data = b'\x0A\x68\x6F\x73\x74\x6D\x61\x73\x74\x65\x72\xC0\x38\x65\xf2\x8b\xbc\x00\x00\x07\x08\x00\x00\x03\x84\x00\x12\x75\x00\x00\x00\x01'

domain, length = decompression(buff, data)

print(f"Compressed pointer: '{domain}', length={length}")

# name 为空的情况
from dns_observe import DNSQuery, DNSResourceRecord
import struct
buff = base64.b64decode('g9yBgAABAAIAAAABB2V4YW1wbGUDY29tAAABAAHADAABAAEAAABPAARoFBeawAwAAQABAAAATwAErEKT8wAAKQTQAAAAAAAA')
data = buff[61:]
print(buff)
print(data)
d = DNSQuery()
name,offset = d._parse_name(buff,61)
record_name = '.'.join(map(lambda x: x.decode('utf-8'), name))
print(repr(record_name))
print(buff[offset:])
record_type, record_class = struct.unpack('>HH', buff[offset:offset+4])
offset += 4
# 解析ttl和数据长度
record_ttl, size = struct.unpack('>LH', buff[offset:offset+6])
offset += 6
# 解析数据
record_data = buff[offset:offset+size]
offset += size
record = DNSResourceRecord(record_name, record_type, record_class, record_ttl, record_data)
print(record)