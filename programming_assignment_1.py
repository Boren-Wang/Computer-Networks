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
                    ip = dns_resolver_helper(ns, "A")
                    break

        dns_response = dns.query.udp(dns_query, ip)

    # query = dns_query
    # response = dns_response
    query_time = time.time() - start_time
    print("QUESTION SECTION:")
    print(dns_query.question[0])
    print()
    print("ANSWER SECTION:")
    print(dns_response.answer[0])
    print()
    print("Query time: " + str(round(query_time*1000)) + " msec")
    print("WHEN: " + str(when))
    print()

def dns_resolver_helper(hostname, type):
    dns_query = dns.message.make_query(hostname, type)
    dns_response = dns.query.udp(dns_query,
                                 "198.41.0.4")  # ask a root server to resolve google.com | return the IP address of a .com TLD server
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

dns_resolver("google.com")
dns_resolver("facebook.com")
dns_resolver("cnn.com")
dns_resolver("piazza.com")
dns_resolver("google.co.jp")
