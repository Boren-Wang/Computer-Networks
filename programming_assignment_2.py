import dpkt.pcap
f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
current_flows = {}
ended_flows = []
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    tcp = eth.data.data
    if tcp.flags == dpkt.tcp.TH_SYN: # find the start of a tcp flow
        flow = []
        flow.append(tcp)
        port_tuple = tcp.sport, tcp.dport
        current_flows[port_tuple] = flow
    elif ( tcp.flags & dpkt.tcp.TH_FIN ) != 0 and ( tcp.flags & dpkt.tcp.TH_ACK ) != 0 and ( tcp.flags & dpkt.tcp.TH_PUSH) == 0: # find the end of a tcp flow
        port_tuple = tcp.sport, tcp.dport
        if(port_tuple not in current_flows):
            port_tuple = port_tuple[::-1] # reverse the tuple
        current_flows[port_tuple].append(tcp)
        ended_flows.append(current_flows[port_tuple]) # add the tcp flow into ended_flows
        del current_flows[port_tuple] # remove the tcp flow from the current_flows
    elif ( tcp.flags & dpkt.tcp.TH_ACK ) != 0:
        port_tuple = tcp.sport, tcp.dport
        if (port_tuple not in current_flows):
            port_tuple = port_tuple[::-1]  # reverse the tuple
        if(port_tuple in current_flows):
            current_flows[port_tuple].append(tcp)
        else: # this tcp is the last ack of a flow that is sent from sender to receiver
            for flow in ended_flows:
                if(flow[0].sport == port_tuple[1] and flow[0].dport == port_tuple[0]):
                    flow.append(tcp)
count = 0
for flow in ended_flows:
    count += 1
    sender = flow[0].sport
    receiver = flow[0].dport
    print("Flow from "+str(sender)+" to "+str(receiver))
    index_sender = 0
    index_receiver = 0
    seq_sender_base = flow[0].seq
    ack_sender_base = flow[2].ack
    seq_receiver_base = flow[1].seq
    ack_receiver_base = flow[1].ack

    win_scale_factor = 0
    opts = dpkt.tcp.parse_opts(flow[0].opts)
    for opt in opts:
        if opt[0] == dpkt.tcp.TCP_OPT_WSCALE:
            win_scale_factor = 2 ** (int.from_bytes(opt[1], "big"))

    for index, tcp in enumerate(flow):
        is_sender = False
        if(tcp.sport == sender): # sender -> receiver
            is_sender = True
            index_sender += 1
        else:
            index_receiver += 1
        if is_sender:
            if index_sender in [3, 4]:
                seq = tcp.seq - seq_sender_base
                ack = tcp.ack - ack_sender_base + 1
                print("Transaction "+str(index_sender - 2)+" sequence number is "+str(seq))
                print("Transaction "+str(index_sender - 2)+" acknowledgement number is "+str(ack))
                print("Transaction " + str(index_sender - 2) + " receive window size is " + str(win_scale_factor*tcp.win))
                print()
        else:
            if index_receiver in [2, 3]:
                seq = tcp.seq - seq_receiver_base
                ack = tcp.ack - ack_receiver_base + 1
                print("Transaction "+str(index_receiver - 1)+" response sequence number is " + str(seq))
                print("Transaction "+str(index_receiver - 1)+" response acknowledgement number is " + str(ack))
                print("Transaction " + str(index_sender - 2) + " response receive window size is " + str(win_scale_factor * tcp.win))
                print()
print("The number of TCP flows is "+str(count))
