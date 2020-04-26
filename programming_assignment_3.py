import dpkt.pcap
# print("Enter the path of the pcap file to be parsed:")
# path = input()
# f = open(path, 'rb')
f = open('assignment3_my_arp.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
count = 0

# helper function for changing bytes to MAC address
def toMAC(address_bytes):
    res = ""
    for i in range(len(address_bytes)):
        res += str(address_bytes[i:i+1].hex())
        if(i<len(address_bytes)-1):
            res += ":"
    return res

# helper function for changing bytes to IP address
def toIP(address_bytes):
    res = ""
    for i in range(len(address_bytes)):
        res += str(address_bytes[i])
        if(i<len(address_bytes)-1):
            res += "."
    return res

for packet in pcap: # packet[0]: float, packet[1]: bytes
    bytes = packet[1]
    dest = bytes[0:6]
    src = bytes[6:12]
    type = bytes[12:14]
    if type == b'\x08\x06':
        count += 1
        hardware_type = int.from_bytes(bytes[14:16], "big")
        protocol_type = bytes[16:18].hex()
        hardware_size = int.from_bytes(bytes[18:19], "big")
        protocol_size = int.from_bytes(bytes[19:20], "big")
        optcode = int.from_bytes(bytes[20:22], "big")
        encoding = "utf_8"
        sender_mac = bytes[22:28]
        sender_ip = bytes[28:32]
        target_mac = bytes[32:38]
        target_ip = bytes[38:42]
        print("----------ARP message #"+str(count)+"----------")
        print("Hardware type: "+str(hardware_type))
        print("Protocol type: 0x" + str(protocol_type))
        print("Hardware size: " + str(hardware_size))
        print("Protocol size: " + str(protocol_size))
        print("Opcode: "+ str(optcode))
        print("Sender MAC address: " + toMAC(sender_mac))
        print("Sender IP address: " + toIP(sender_ip))
        print("Target MAC address: " + toMAC(target_mac))
        print("Target IP address: " + toIP(target_ip))
        print()

print("The number of ARP messages is: " + str(count))

