import struct


def tcp_segment(data):
    (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack(
        '! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12)*4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 5
    flag_psh = (offset_reserved_flags & 8) >> 5
    flag_rsh = (offset_reserved_flags & 4) >> 5
    flag_syn = (offset_reserved_flags & 2) >> 5
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rsh, flag_syn, flag_fin, data[offset:]