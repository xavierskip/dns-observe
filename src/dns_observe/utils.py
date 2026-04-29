from __future__ import annotations
from typing import TYPE_CHECKING
import struct

if TYPE_CHECKING:
    from .dns import DNSResponse


class ResponseList(list):
    """DNSResponse 列表，支持 fake/real 分类方法"""

    def fakes(self) -> list[DNSResponse]:
        """返回判定为伪造的响应列表（除最后一个外的所有响应）"""
        if len(self) > 1:
            return self[:-1]
        return []

    def real(self) -> DNSResponse | None:
        """返回判定为真实的响应（最后一个响应）"""
        if len(self) > 0:
            return self[-1]
        return None

def decompression_message1(buff: bytes, data: bytes) -> tuple[str, int]:
    parts = []
    _data = data
    _offset = 0
    consumed = 0  # ✅ 初始化为 0
    jumped = False

    while _offset < len(_data):
        nlen = _data[_offset]

        if nlen == 0:
            if not jumped:
                consumed += 1
            break

        if nlen & 0b11000000 == 0b11000000:
            if not jumped:
                consumed += 2
                jumped = True
            (ptr,) = struct.unpack('>H', _data[_offset:_offset+2])
            _offset = ptr & 0x3fff
            _data = buff
        else:
            parts.append(_data[_offset+1:_offset+nlen+1])
            if not jumped:
                consumed += 1 + nlen  # ✅ 只在原始 data 中累加
            _offset += nlen + 1

    domain = '.'.join(map(lambda x: x.decode('utf-8'), parts))
    return domain, consumed

def calc_name_length(data: bytes) -> int:
    """计算域名在DNS数据中的实际长度（处理压缩指针）"""
    offset = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0b11000000 == 0b11000000:
            return offset + 2
        offset += 1 + length
    return len(data)