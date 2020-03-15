import dpkt.pcap
import socket
print("Enter the path of the pcap file to be parsed:")
path = input()
f = open(path, 'rb')
# f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
current_flows = {}
ended_flows = []
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    src = eth.data.src
    dst = eth.data.dst
    tcp = eth.data.data
    tcp.src = src
    tcp.dst = dst
    ips = (src, dst)
    ports = (tcp.sport, tcp.dport)

    if tcp.flags == dpkt.tcp.TH_SYN: # find the start of a tcp flow
        flow = []
        tcp.ts = ts
        flow.append(tcp)
        port_tuple = (ips, ports)
        current_flows[port_tuple] = flow
    elif ( tcp.flags & dpkt.tcp.TH_FIN ) != 0 and ( tcp.flags & dpkt.tcp.TH_ACK ) != 0 and ( tcp.flags & dpkt.tcp.TH_PUSH) == 0: # find the end of a tcp flow
        port_tuple = (ips, ports)
        if(port_tuple not in current_flows):
            port_tuple = (ips[::-1], ports[::-1]) # reverse the tuple
        tcp.ts = ts
        current_flows[port_tuple].append(tcp)
        ended_flows.append(current_flows[port_tuple]) # add the tcp flow into ended_flows
        del current_flows[port_tuple] # remove the tcp flow from the current_flows
    elif ( tcp.flags & dpkt.tcp.TH_ACK ) != 0:
        tcp.ts = ts
        port_tuple = (ips, ports)
        if (port_tuple not in current_flows):
            port_tuple = (ips[::-1], ports[::-1])  # reverse the tuple
        if(port_tuple in current_flows):
            current_flows[port_tuple].append(tcp)
        else: # this tcp is the last ack of a flow that is sent from sender to receiver
            port_tuple = (ips[::-1], ports[::-1])
            for flow in ended_flows:
                # if(flow[0].sport == port_tuple[1] and flow[0].dport == port_tuple[0]):
                #     flow.append(tcp)
                if flow[0].src == src and flow[0].dst == dst and flow[0].sport == port_tuple[1][0] and flow[0].dport == port_tuple[1][1] and (flow[len(flow)].flags & dpkt.tcp.TH_FIN) !=0 :
                    flow.append(tcp)
count = 0
for flow in ended_flows:
    count += 1
    sender = flow[0].sport
    receiver = flow[0].dport
    print("Flow from "+socket.inet_ntoa(flow[0].src)+":"+str(sender)+" to "+socket.inet_ntoa(flow[0].src)+":"+str(receiver))
    print()
    index_sender = 0
    index_receiver = 0
    seq_sender_base = flow[0].seq
    ack_sender_base = flow[2].ack
    seq_receiver_base = flow[1].seq
    ack_receiver_base = flow[1].ack

    win_scale_factor = 0
    # start_time = 0
    opts = dpkt.tcp.parse_opts(flow[0].opts)
    for opt in opts:
        if opt[0] == dpkt.tcp.TCP_OPT_WSCALE:
            win_scale_factor = 2 ** (int.from_bytes(opt[1], "big"))

    time = flow[len(flow)-2].ts - flow[0].ts

    throughput = 0

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
            if index == len(flow)-1:
                continue
            header_length = tcp.off
            data_length = len(tcp.data)
            throughput += header_length + data_length
        else:
            if index_receiver in [2, 3]:
                seq = tcp.seq - seq_receiver_base
                ack = tcp.ack - ack_receiver_base + 1
                print("Transaction "+str(index_receiver - 1)+" response sequence number is " + str(seq))
                print("Transaction "+str(index_receiver - 1)+" response acknowledgement number is " + str(ack))
                print("Transaction " + str(index_receiver - 1) + " response receive window size is " + str(win_scale_factor * tcp.win))
                print()
    print("The throughput for this TCP flow is " + str(throughput / time) + " bytes/sec")

    rtt = round(flow[2].ts - flow[0].ts, 2)
    i = 1
    cwnd = 0
    start_time = flow[3].ts
    for index, tcp in enumerate(flow):
        if index < 3:
            continue
        if i==6:
            break
        if (tcp.ts - start_time)>=rtt:
            time_difference = tcp.ts - start_time
            print("Congestion window No." + str(i) + " is " + str(cwnd))
            i += 1
            cwnd = 0
            start_time = tcp.ts
            continue
        else:
            if tcp.sport == sender: # sender -> receiver
                cwnd+=1

    # retransmission
    retransmission = 0
    timeout = 0
    seq_dict = {}
    for index, tcp in enumerate(flow):
        if index<3:
            continue
        if(tcp.sport == sender):
            if tcp.seq in seq_dict:
                seq_dict[tcp.seq].append(tcp)
            else:
                seq_dict[tcp.seq] = [tcp]
    for key in seq_dict:
        if len(seq_dict[key]) >= 2:
            retransmission += (len(seq_dict[key]) - 1)
            repeated_tcps = seq_dict[key]
            for i, t in enumerate(repeated_tcps):
                if i==0:
                    continue
                if t.ts-repeated_tcps[i-1].ts >= 2*rtt:
                    timeout += 1

    fast_retransmission = retransmission - timeout


    print("The number of retransmission occured due to triple duplicate ack is "+str(fast_retransmission))
    print("The number of retransmission occured due to timeout is "+str(timeout))
    print("The number of retransmission in total is " + str(retransmission))

    print("------------------------------")

print("The number of TCP flows is "+str(count))

