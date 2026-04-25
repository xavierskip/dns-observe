from dns_observe import DNSQuery, RecordType, ResponseList

def print_answers(responses: ResponseList):
    for res in responses:
        print(f'{res}')
        for ans in res.answer_RRs:
            print(f'└ {ans}')
    
    print('---\n')

# custom transaction ID for dns query, useful for tracking specific queries in logs or network captures
dns = DNSQuery('1.1.1.1', wait_time=3, transaction_id=53) 

responses: ResponseList = dns.query("api.openai.com")
print_answers(responses)

# query with type AAAA (IPv6 address)
responses = dns.query('api.openai.com', RecordType.AAAA)
print('🤥 fake responses:')  
print_answers(responses.fakes())           # 打印伪造的响应列表
print('👌 real response:')   
print(responses.real())              # 打印真实的响应
print('---\n')

with DNSQuery('8.8.8.8', wait_time=3) as dns2:
    responses = dns2.query('www.google.com', RecordType.A)
    print_answers(responses)

    # query with type CNAME (canonical name record)
    responses = dns2.query('www.twitter.com', RecordType.CNAME)
    print_answers(responses)

    # query with type TXT (text record)
    responses = dns2.query('example.com', RecordType.TXT)
    print_answers(responses)

    # query with type HTTPS (HTTPSSVC record, RFC 7553)
    responses = dns2.query('example.com', RecordType.HTTPS)
    print_answers(responses)

    # query with type NS (name server record)
    responses = dns2.query('example.com', RecordType.NS)
    print_answers(responses)

    # query with type MX (mail exchange record)
    responses = dns2.query('mails.dev', RecordType.MX)
    print_answers(responses)

    for msg in dns2.stdout_msg:
        print(f'{msg}')