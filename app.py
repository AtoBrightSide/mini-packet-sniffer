import socket
from Ethernet_segment import EthernetSeg
from IP_header import IPHeader
from TCP_segment import TCPSeg
from UDP_segment import UDPSeg
from ICMP_segment import ICMPSeg

# when making requests, the request i wrapped around with IP packet, and the IP packet is in turn wrapped around by ethernet frame
# that is what is going to be unpacked first 
def main():
    # socket is needed to have a connection with other computers
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    dsp = '''
        
        # # # # # # # PYTHON PACKET SNIFFER # # # # # #
        
        Pick a filter, to listen to packets easier:
         1. TCP
         2. UDP
         3. ICMP 
    '''
    choice = eval(input(dsp))
    ''' 
        this is going to be an infinite loop
        it's going to sit and listen for packets
        when the packets are incoming, we are going to extract them, and log to console
    '''
    while True:
        # the number is the buffer size
        # addr is either the source or the destination address
        # raw data is the actual data
        raw_data, addr = conn.recvfrom(65536)
        eth = EthernetSeg()
        dest_mac, src_mac, eth_proto, data = eth.ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8:
            ip = IPHeader()
            (version, header_len, ttl, proto, src, target, data) = ip.ipv4_packet(data)
            print("\n# # # # # # # IP Packet # # # # # # #\n")
            print(f"Version: {version}, Header Length: {header_len}, Time to live: {ttl}")
            # the source and the destination address to know which websites are being accessed
            print(f"Protocol: {proto}, Source: {src}, Target: {target}")
            # TCP is the most common
            # UDP if domain server is being used
            # now look at the protocol, and the filters and choose the packet type
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
