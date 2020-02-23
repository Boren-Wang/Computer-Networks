import time
import datetime
import dns.message
import dns.query

def dns_resolver(hostname):
    start_time = time.time()
    when = datetime.datetime.now()
    dns_query = dns.message.make_query(hostname, "A")
    dns_response = dns.query.udp(dns_query, "198.41.0.4") # ask a root server to resolve google.com | return the IP address of a .com TLD server
    # dns_response = dns.query.udp(dns_query, "192.5.6.30") # ask a .com TLD server to resolve | return the IP address of a authoritative server of google.com
    # dns_response = dns.query.udp(dns_query, "216.239.34.10") # ask a google.com authoritative server for the IP address of google.com
    # answer = "172.217.12.174"

    while dns_response.answer==[]:
        ip = ""
        additional = False
        for a in dns_response.additional:
            if a.rdtype==1:
                ip = a[0].address
                additional = True
                break

        if not additional:
            for a in dns_response.authority:
                if a.rdtype==2:
                    ns = str(a.items[0].target)
                    ip = dns_resolver_helper(ns)
                    break

        dns_response = dns.query.udp(dns_query, ip)

    # answer = ""
    # cname = ""
    # for a in dns_response.answer:
    #     if a.rdtype==1:
    #         answer = a
    #         break
    #     elif a.rdtype==5:
    #         cname = str(a.name)
    #
    # if answer=="":
    #     dns_response = dns_resolver_helper(cname)
    #     answer = dns_response.answer[0]

    # query = dns_query
    # response = dns_response
    query_time = time.time() - start_time
    print("QUESTION SECTION:")
    print(dns_query.question[0])
    print()
    print("ANSWER SECTION:")
    print(dns_response.answer[0])
    # print(answer)
    print()
    print("Query time: " + str(round(query_time*1000)) + " msec")
    print("WHEN: " + str(when))
    print()
    return query_time

def dns_resolver_helper(hostname):
    dns_query = dns.message.make_query(hostname, "A")
    dns_response = dns.query.udp(dns_query, "198.41.0.4")  # ask a root server to resolve google.com | return the IP address of a .com TLD server
    # dns_response = dns.query.udp(dns_query, "192.5.6.30") # ask a .com TLD server to resolve | return the IP address of a authoritative server of google.com
    # dns_response = dns.query.udp(dns_query, "216.239.34.10") # ask a google.com authoritative server for the IP address of google.com
    # answer = "172.217.12.174"

    while dns_response.answer == []:
        ip = ""
        for a in dns_response.additional:
            if a.rdtype == 1:
                ip = a[0].address
                break
        dns_response = dns.query.udp(dns_query, ip)

    return dns_response.answer[0].items[0].address

def experiment1(hostname):
    total_query_time = 0
    for i in range(10):
        total_query_time+=dns_resolver(hostname)
    return total_query_time/10

dns_resolver("google.com")
dns_resolver("youtube.com")
dns_resolver("tmall.com")
dns_resolver("baidu.com")
dns_resolver("qq.com")
dns_resolver("facebook.com")
dns_resolver("sohu.com")
dns_resolver("login.tmall.com")
dns_resolver("taobao.com")
dns_resolver("360.com")
dns_resolver("google.co.jp")
# dns_resolver("www.tmall.com.danuoyi.tbcache.com")


