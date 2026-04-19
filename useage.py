from dns_observe import DNSQuery, RecordType, DNSResponse

def print_responses(responses: list[DNSResponse]):
    for res in responses:
        print(f'{res}')
        for ans in res.answers:
            print(f'└ {ans}')
    
    print('---\n')

dns = DNSQuery('1.1.1.1', wait_time=3)

responses: list[DNSResponse] = dns.query("api.openai.com")
print_responses(responses)


# custom transaction ID for dns query, useful for tracking specific queries in logs or network captures
dns.transaction_id = 0x666
responses = dns.query('vscode-sync.trafficmanager.net', RecordType.AAAA)
print_responses(responses)

dns.transaction_id = 0x1234
responses = dns.query('www.twitter.com', RecordType.CNAME)
print_responses(responses)

for msg in dns.stdout_msg:
    print(f'{msg}')