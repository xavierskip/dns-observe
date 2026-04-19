from typing import NamedTuple

class RCODE(NamedTuple):
    """DNS Response Code with value, name and description"""
    value: int
    name: str
    description: str

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-para meters-6
RCODE_LIST: list[RCODE] = [
    RCODE(0, "NOERROR", "No Error"),
    RCODE(1, "FORMERR", "Format Error"),
    RCODE(2, "SERVFAIL", "Server Failure"),
    RCODE(3, "NXDOMAIN", "Non-Existent Domain"),
    RCODE(4, "NOTIMP", "Not Implemented"),
    RCODE(5, "REFUSED", "Query Refused"),
    RCODE(6, "YXDOMAIN", "Name Exists when it should not"),
    RCODE(7, "YXRRSET", "RR Set Exists when it should not"),
    RCODE(8, "NXRRSET", "RR Set that should exist does not"),
    RCODE(9, "NOTAUTH", "Server Not Authoritative for zone"),
    RCODE(9, "NOTAUTH", "Not Authorized"),  # DNS UPDATE context
    RCODE(10, "NOTZONE", "Name not contained in zone"),
    RCODE(11, "DSOTYPENI", "DSO-TYPE Not Implemented"),
    RCODE(16, "BADVERS", "Bad OPT Version"),
    RCODE(16, "BADSIG", "TSIG Signature Failure"),
    RCODE(17, "BADKEY", "Key not recognized"),
    RCODE(18, "BADTIME", "Signature out of time window"),
    RCODE(19, "BADMODE", "Bad TKEY Mode"),
    RCODE(20, "BADNAME", "Duplicate key name"),
    RCODE(21, "BADALG", "Algorithm not supported"),
    RCODE(22, "BADTRUNC", "Bad Truncation"),
    RCODE(23, "BADCOOKIE", "Bad/missing Server Cookie"),
]

# 按数值索引的字典（支持同一数值多个描述,9、16有重复）
RCODE_BY_VALUE: dict[int, list[RCODE]] = {}
for rc in RCODE_LIST:
    RCODE_BY_VALUE.setdefault(rc.value, []).append(rc)

# 按名称索引的字典
RCODE_BY_NAME: dict[str, RCODE] = {rc.name: rc for rc in RCODE_LIST}

# 兼容旧代码：简单数值到描述的映射（默认取第一个）
REPLY_CODE: dict[int, str] = {rc.value: rc.description for rc in RCODE_LIST}
