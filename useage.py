from dns_observe import DNSQuery, RecordType, DNSResponse

def print_answers(responses: list[DNSResponse]):
    for res in responses:
        print(f'{res}')
        for ans in res.answers:
            print(f'└ {ans}')
    
    print('---\n')

# custom transaction ID for dns query, useful for tracking specific queries in logs or network captures
dns = DNSQuery('1.1.1.1', wait_time=3, transaction_id=0x666) 

responses: list[DNSResponse] = dns.query("api.openai.com")
print_answers(responses)

# query with type AAAA (IPv6 address)
responses = dns.query('api.openai.com', RecordType.AAAA)
print('fake responses:')  
print_answers(responses.fakes())           # 打印伪造的响应列表
print('real response:')   
print(responses.real())              # 打印真实的响应
print('---\n')

# query with type CNAME (canonical name record)
responses = dns.query('www.twitter.com', RecordType.CNAME)
print_answers(responses)

# querywith type TXT (text record)
responses = dns.query('example.com', RecordType.TXT)
print_answers(responses)

# querywith type HTTPS (HTTPSSVC record, RFC 7553)
responses = dns.query('example.com', RecordType.HTTPS)
print_answers(responses)

for msg in dns.stdout_msg:
    print(f'{msg}')