import re
from .packet import ICMP, TCP

tcp_flags_dict = {
    'F': 1,
    'S': 2,
    'R': 4,
    'P': 8,
    'A': 16,
    'U': 32,
    'E': 64,
    'C': 128,
}


def matched_ip_and_port(pkt, match):
     # Compares the packet's port(s) against the match's port(s) 
    if pkt.src_port:
        if not __matched_ports(pkt.dst_port, match.header_fields["dport"]):
            return False
        
        if not __matched_ports(pkt.src_port, match.header_fields["sport"]):
            return False

    # Compares the packet's IP(s) against the match's IP(s) 
    if not __matched_IP(pkt.dst_ip, match.header_fields["dst_ip"]):
        return False

    if not __matched_IP(pkt.src_ip, match.header_fields["src_ip"]):
        return False
    
    return True

# Compares the header fields of a packet against the ones for a match
def matched_header_fields(pkt, match):
    if not __matched_IP_fields(pkt, match.header_fields):
        return False
    
    if pkt.layer4_proto == ICMP and not __matched_ICMP_fields(pkt, match.header_fields):
        return False

    if pkt.layer4_proto == TCP and not __matched_TCP_fields(pkt, match.header_fields):
        return False
    
    return True

# Compares a packet's ports(s) against the ports(s) of a match. Individual ports are in a dict, while ranges are in a list.
def __matched_ports(pkt_port, match_ports):
    valid_port = False
    if pkt_port in match_ports[0]:
        return match_ports[0][pkt_port]
            
    for port_range in match_ports[1]:
        if port_range[1] and pkt_port in port_range[0]:
            valid_port = True
        elif not port_range[1] and pkt_port in port_range[0]:
            return False
        
    if valid_port:
        return True
    
    # If the pkt_port didn't match any port entry in the match, there are two options: 
    # If the match says to match any port with the exception of the port defined (i.e. pkt_port=15, match_port=[!15]), the pkt_port is valid
    # Else, the pkt_port should've matched a port to match this match, but it did not, meaning the port is not valid
    return not match_ports[2]

# Compares a packet's IP(s) against the IP(s) of a match. The IPs are in a Radix tree for quick search
def __matched_IP(pkt_ip, match_ips):
    best_match = match_ips[0].search_best(pkt_ip)
    if best_match:
        return best_match.data["match"]

    return not match_ips[1]

# Compares a packet's IP fields against the IP fields of a match 
def __matched_IP_fields(pkt, match_pkt_header): 
    if "ip_proto" in match_pkt_header and not __matched_ip_proto(pkt.layer4_proto, match_pkt_header["ip_proto"]["data"], match_pkt_header["ip_proto"]["comparator"]):
        return False
        
    if "ttl" in match_pkt_header and not compare_field(pkt.ttl, match_pkt_header["ttl"]["data"], match_pkt_header["ttl"]["comparator"]):
        return False

    if "id" in match_pkt_header and not compare_field(pkt.id, match_pkt_header["id"]["data"], match_pkt_header["id"]["comparator"]):
        return False
    
    if "ipopts" in match_pkt_header and not __matched_ipopts(pkt.ipotps, match_pkt_header["ipopts"]):
        return False

    if "fragbits" in match_pkt_header and not __matched_fragbits(pkt.fragbits, match_pkt_header["fragbits"]["data"], match_pkt_header["fragbits"]["comparator"]):
        return False

    return True

# Compares a packet's ICMP fields against the ICMP fields of a match 
def __matched_ICMP_fields(pkt, match_pkt_header):
    if "itype" in match_pkt_header and not compare_field(pkt.icmp_itype, match_pkt_header["itype"]["data"], match_pkt_header["itype"]["comparator"]):
        return False

    if "icode" in match_pkt_header and not compare_field(pkt.icmp_icode, match_pkt_header["icode"]["data"], match_pkt_header["icode"]["comparator"]):
        return False

    if "icmp_id" in match_pkt_header and pkt.icmp_id and not compare_field(pkt.icmp_id, match_pkt_header["icmp_id"]["data"], match_pkt_header["icmp_id"]["comparator"]):
        return False

    if "icmp_seq" in match_pkt_header and pkt.icmp_seq and not compare_field(pkt.icmp_seq, match_pkt_header["icmp_seq"]["data"], match_pkt_header["icmp_seq"]["comparator"]):
        return False
    return True

# Compares a packet's TCP fields against the TCP fields of a match 
def __matched_TCP_fields(pkt, match_pkt_header):
    # if "flags" in match_pkt_header and not __matched_tcp_flags(pkt.tcp_flags, match_pkt_header["flags"]):
    #     return False

    if "seq" in match_pkt_header and not compare_field(pkt.tcp_seq, match_pkt_header["seq"]["data"], match_pkt_header["seq"]["comparator"]):
        return False

    if "ack" in match_pkt_header and not compare_field(pkt.tcp_ack, match_pkt_header["ack"]["data"], match_pkt_header["ack"]["comparator"]):
        return False

    if "window" in match_pkt_header and not compare_field(pkt.tcp_window, match_pkt_header["window"]["data"], match_pkt_header["window"]["comparator"]):
        return False

    return True


# Compares a packet's field against a match's field using the follwoing operators: >,<,=,!,<=,>=,<>,<=>
def compare_field(pkt_data, number, comparator):
    if len(number) == 1:
        number = int(number[0])
        ops = {"":   pkt_data == number,
               "<":  pkt_data < number,
               ">":  pkt_data > number,
               "=":  pkt_data == number,
               "!":  pkt_data != number,
               "<=": pkt_data <= number,
               ">=": pkt_data >= number}
    else:
        ops = {"<>": pkt_data > int(number[0]) and  pkt_data < int(number[1]),
                     "<=>": pkt_data >= int(number[0]) and  pkt_data <= int(number[1])}

    return ops[comparator]


# Compares a packet's IP protocol field against the IP protocol field of a match
def __matched_ip_proto(pkt_ip_proto, match_ip_proto, match_comparator):
    ops = { "":  pkt_ip_proto == match_ip_proto,
           "<":  pkt_ip_proto < match_ip_proto,
           ">":  pkt_ip_proto > match_ip_proto,
           "!":  pkt_ip_proto != match_ip_proto}

    if ops[match_comparator]:
        return True

    return False

# Compares a packet's IP options against the IP options of a match
def __matched_ipopts(pkt_ipopts, match_ipopts):
    if not pkt_ipopts:
        return False

    if match_ipopts == 0xFF: # Any
        return True
    elif pkt_ipopts == match_ipopts:
        return True

    return False

# Compares a packet's fragmentation bits against the fragmentation bits of a match
def __matched_fragbits(pkt_fragbits, fragbits_num, comparator):
    if comparator == "" and pkt_fragbits == fragbits_num:
        return True
    elif comparator == "+" and (pkt_fragbits & fragbits_num == fragbits_num):
        return True
    elif comparator == "!" and pkt_fragbits != fragbits_num:
        return True
    elif comparator == "*" and (pkt_fragbits & fragbits_num >= 1):
        return True
    
    return False

# Compares a packet's TCP flags against the TCP flags of a match
def __matched_tcp_flags(pkt_tcp_flags, match_tcp_flags):
    pkt_tcp_flags = str(pkt_tcp_flags)
    if match_tcp_flags["exclude"]:
        expression = "["+match_tcp_flags["exclude"]+"]*"
        pkt_tcp_flags = re.sub(expression, "", pkt_tcp_flags)

    pkt_tcp_flags_num = sum(tcp_flags_dict[flag] for flag in pkt_tcp_flags) 

    if match_tcp_flags["comparator"] == "" and pkt_tcp_flags_num == match_tcp_flags["data"]:
        return True
    elif match_tcp_flags["comparator"] == "+" and (pkt_tcp_flags_num & match_tcp_flags["data"] == match_tcp_flags["data"]):
        return True
    elif match_tcp_flags["comparator"] == "!" and pkt_tcp_flags_num != match_tcp_flags["data"]:
        return True
    elif match_tcp_flags["comparator"] == "*" and (pkt_tcp_flags_num & match_tcp_flags["data"] >= 1):
        return True
    
    return False

