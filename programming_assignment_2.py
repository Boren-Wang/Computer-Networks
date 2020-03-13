import dpkt.pcap
f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
flows = []
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    tcp = eth.data.data
    if tcp.flags == dpkt.tcp.TH_SYN:
        flow = []
        flow.append(tcp)
        flows.append(flow)
print(tcp)
