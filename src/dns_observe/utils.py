from __future__ import annotations
from typing import TYPE_CHECKING

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
