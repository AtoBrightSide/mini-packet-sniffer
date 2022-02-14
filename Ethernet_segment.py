import socket
import struct

'''
 ETHERNET FRAME
 reciever -> sender -> type -> payload
 reciever(6byte) is either your pc or the router
 sender(6byte) is either your pc or the router
 type is the ethernet type(protocol), we used ipV4 for this project
 payload is the main data
'''
class EthernetSeg:
    def __init__(self):
        pass
    
    # unpacking the ethernet frame
    # when unpacking with struct, the first argument is format of it
    # use ! to signify that we are using network data
    # 6s => 6 characters for both the destination and the source
    # H => small unsigned integer which is 6bytes
    # so, the size of the unpacked stuff is 14bits(6+6+2*4)
    # socket.htons is used to change to bytes and make it human readable
    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # return a properly formatted MAC address
    # cause its currently messsed up
    # use map to pass a function and an iterable in there
    # 
    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()
