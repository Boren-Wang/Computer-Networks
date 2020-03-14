import dpkt.pcap
import socket
print("Enter the path of the pcap file to be parsed:")
path = input()
f = open('assignment2.pcap', 'rb')
# f = open(path, 'rb')
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
        # elif opt[0] == dpkt.tcp.TCP_OPT_TIMESTAMP:
        #     start_time = opt[1]

    # end_time = 0
    # opts = dpkt.tcp.parse_opts(flow[len(flow)-1].opts)
    # for opt in opts:
    #     if opt[0] == dpkt.tcp.TCP_OPT_TIMESTAMP:
    #         end_time = opt[1]

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

    # congestion window
    # i = 1  # index for cwnd
    # cwnd = 0
    # next_cwnd = 0
    # response_count = 0
    # is_waiting_response = False
    # timeout = 0
    # max_seq = 0
    # for index, tcp in enumerate(flow):
    #     if index < 3:
    #         continue
    #     # if i==6:
    #     #     break
    #     if (tcp.sport == sender):  # sender -> receiver
    #         if(is_waiting_response):
    #             next_cwnd += 1
    #         else:
    #             cwnd += 1
    #         if(tcp.seq >= max_seq):
    #             max_seq = tcp.seq
    #         else:
    #             max_seq = tcp.seq
    #             timeout+=1
    #     else:
    #         response_count += 1
    #         is_waiting_response = True
    #
    #         if(response_count == cwnd+1):
    #             if i<6:
    #                 print("Congestion window No."+str(i)+" is "+str(cwnd))
    #             # if cwnd == 10 and i>1:
    #             #     timeout += 1
    #             i += 1
    #             cwnd = next_cwnd
    #             next_cwnd = 0
    #             response_count = 1
    #             is_waiting_response = True
    rtt = round(flow[2].ts - flow[0].ts, 2)
    i = 1
    cwnd = 0
    start_time = flow[3].ts
    for index, tcp in enumerate(flow):
        if index < 3:
            continue
        if i==6:
            break
        if tcp.sport == sender: # sender -> receiver
            cwnd+=1
        elif (tcp.ts - start_time)>=rtt:
            time_difference = tcp.ts - start_time
            print("Congestion window No." + str(i) + " is " + str(cwnd))
            i += 1
            cwnd = 0
            start_time = tcp.ts
            continue

    # retransmission
    retransmission = 0
    seq_dict = {}
    for index, tcp in enumerate(flow):
        if(tcp.sport == sender):
            if tcp.seq in seq_dict:
                seq_dict[tcp.seq] += 1
            else:
                seq_dict[tcp.seq] = 1
    for key in seq_dict:
        if seq_dict[key] >= 2:
            retransmission += (seq_dict[key] - 1)

    fast_retransmission = 0
    dup_dict = {}
    for index, tcp in enumerate(flow):
        if (tcp.dport == sender):
            if tcp.ack in dup_dict:
                dup_dict[tcp.ack] += 1
            else:
                dup_dict[tcp.ack] = 1
    for key in dup_dict:
        if dup_dict[key] >= 4:
            fast_retransmission += 1

    timeout = retransmission - fast_retransmission

    print("The number of retransmission occured due to triple duplicate ack is "+str(fast_retransmission))
    print("The number of retransmission occured due to timeout is "+str(timeout))
    print("The number of retransmission in total is " + str(retransmission))

    print("------------------------------")

print("The number of TCP flows is "+str(count))

