import socket
from Ethernet_segment import EthernetSeg
from TCP_segment import TCPSeg
from UDP_segment import UDPSeg
from ICMP_segment import ICMPSeg

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    ''' 
        this is going to be a loop
        it's going to sit and listen for packets
        when the packets are incoming, we are going to extract them
    '''
    dsp = '''
        ###############################################
        ###############################################
        # # # # # # # PYTHON PACKET SNIFFER # # # # # #
        ###############################################
        ###############################################
        Pick a filter, to listen to packets easier:
         1. TCP
         2. UDP
         3. ICMP 
    '''
    choice = eval(input(dsp))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        eth = EthernetSeg()
        dest_mac, src_mac, eth_proto, data = eth.ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8:
            (version, header_len, ttl, proto, src, target, data) = eth.ipv4_packet(data)
            print("# # # # # # # IPv4 Packet # # # # # # #")
            print(f"Version: {version}, Header Length: {header_len}, Time to live: {ttl}")
            print(f"Protocol: {proto}, Source: {src}, Target: {target}")

            if proto == 1 and choice == 3:
                icmp = ICMPSeg()
                icmp.display_icmp(data)
            elif proto == 6 and choice == 1:
                tcp = TCPSeg()
                tcp.display_tcp(data)
            elif proto == 17 and choice == 2:
                udp = UDPSeg()
                udp.display_udp(data)
            else:
                print(f"Data: {data}")

main()
