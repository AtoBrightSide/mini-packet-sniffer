import socket
import struct
from TCP_segment import tcp_segment
from UDP_segment import udp_segment
from IMCP_segment import icmp_packet

'''
    Ethernet
        IPv4
            TCP
            UDP
            ICMP
'''


def main():

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    ''' 
        this is going to be a loop
        it's going to sit and listen for packets
        when the packets are incoming, we are going to extract them
    '''
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print("Destination: {}, Source: {}, Protocol: {}".format(
            dest_mac, src_mac, eth_proto))

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_len, ttl, proto, src, target, data) = ipv4_packet(data)
            print("IPv4 Packet: ")
            print("Version: {}, Header Length: {}, Time to live: {}".format(
                version, header_len, ttl))
            print("Protocol: {}, Source: {}, Target: {}".format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print("ICMP Packet: ")
                print("Type: {}, Code: {}, Checksum: {}".format(
                    icmp_type, code, checksum))
                print("Data: {} ".format(data))

            elif proto == 6:
                (src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh,
                 flag_rsh, flag_syn, flag_fin, data) = tcp_segment(data)
                print("TCP")
                print("Source: {}, Destination: {}".format(src_port, dest_port))
                print("Sequence: {}, Acknowledgment: {}".format(seq, ack))
                print("Flags: ")
                print("URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(
                    flag_urg, flag_ack, flag_psh, flag_rsh, flag_syn, flag_fin))
                print("Data: {}".format(data))

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print("UDP")
                print('Source Port: {}\nDestination Port: {}\nLength: {}'.format(
                    src_port, dest_port, length))
            else:
                print("Data: {}".format(data))

# unpacking the ethernet frame


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# return a properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# unpacking the IPv4 packet


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    # you need the header length, cause that is what is going to be used to determine where the data starts
    header_len = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# return properly formatted IPv4 address


def ipv4(addr):
    return '.'.join(map(str, addr))

# unpacks ICMP packet




# unpack TCP segment



# unpack UDP segment




main()
