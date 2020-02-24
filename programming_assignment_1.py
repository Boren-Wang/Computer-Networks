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
        ip = "198.41.0.4"
        additional = False
        for a in dns_response.additional: # if there is an A type record in additional, get its IP address
            if a.rdtype==1:
                ip = a[0].address
                additional = True
                break

        if not additional: # if additional is empty, get a NS type record from authority
            for a in dns_response.authority:
                if a.rdtype==2:
                    ns = str(a.items[0].target)
                    ip = dns_resolver_helper(ns) # call dns_resolver_helper to resolve the IP address for next dns name server
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

    query_time = time.time() - start_time # calculate query time
    print("------------------------------")
    print("QUESTION SECTION:")
    print(dns_query.question[0])
    print()
    print("ANSWER SECTION:")
    print(dns_response.answer[0])
    print()
    print("Query time: " + str(round(query_time*1000)) + " msec")
    print("WHEN: " + str(when))
    print("------------------------------")
    return query_time

def dns_resolver_helper(hostname):
    dns_query = dns.message.make_query(hostname, "A")
    dns_response = dns.query.udp(dns_query, "198.41.0.4")

    while dns_response.answer == []:
        ip = ""
        for a in dns_response.additional:
            if a.rdtype == 1:
                ip = a[0].address
                break
        dns_response = dns.query.udp(dns_query, ip)

    return dns_response.answer[0].items[0].address

print("Enter a hostname to resolve:")
hostname = input()
dns_resolver(hostname)



