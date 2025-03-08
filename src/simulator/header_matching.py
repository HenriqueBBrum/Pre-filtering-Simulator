### Functions to match on header fuelds of a packet


def matched_ip_and_port(pkt, match):
     # Compares the packet's port(s) against the match's port(s) 
    if pkt.tcp or pkt.udp:
        if not __matched_ports(pkt.header["dport"], match.header_fields["dport"]):
            return False
        
        if not __matched_ports(pkt.header["sport"], match.header_fields["sport"]):
            return False

    # Compares the packet's IP(s) against the match's IP(s) 
    if not __matched_IP(pkt.header["dst_ip"], match.header_fields["dst_ip"]):
        return False

    if not __matched_IP(pkt.header["src_ip"], match.header_fields["src_ip"]):
        return False

    return True

# Compares the header fields of a packet against the ones for a match
def matched_header_fields(pkt, match):
    if not __matched_IP_fields(pkt.header, match.header_fields):
        return False

    if pkt.tcp and not __matched_TCP_fields(pkt.header, match.header_fields):
        return False
    
    if pkt.icmp and not __matched_ICMP_fields(pkt.header, match.header_fields):
        return False

    # Add SSL/TLS support
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
def __matched_IP_fields(pkt_header, match_fields):
    if "ip_proto" in match_fields and not __matched_ip_proto(pkt_header["ip_proto"], match_fields["ip_proto"]["data"], match_fields["ip_proto"]["comparator"]):
        return False
        
    if "ttl" in match_fields and not compare_field(pkt_header["ttl"], match_fields["ttl"]["data"], match_fields["ttl"]["comparator"]):
        return False

    if "id" in match_fields and not compare_field(pkt_header["id"], match_fields["id"]["data"], match_fields["id"]["comparator"]):
        return False
    
    if "ipopts" in match_fields and not __matched_ipopts(pkt_header["ipopts"], match_fields["ipopts"]):
        return False

    if "fragbits" in match_fields and not __matched_fragbits(pkt_header["fragbits"], match_fields["fragbits"]["data"], match_fields["fragbits"]["comparator"]):
        return False

    return True

# Compares a packet's TCP fields against the TCP fields of a match 
def __matched_TCP_fields(pkt_header, match_fields):
    if "flags" in match_fields and not __matched_tcp_flags(pkt_header["flags"], match_fields["flags"]):
        return False

    if "seq" in match_fields and not compare_field(pkt_header["seq"], match_fields["seq"]["data"], match_fields["seq"]["comparator"]):
        return False

    if "ack" in match_fields and not compare_field(pkt_header["ack"], match_fields["ack"]["data"], match_fields["ack"]["comparator"]):
        return False

    if "window" in match_fields and not compare_field(pkt_header["window"], match_fields["window"]["data"], match_fields["window"]["comparator"]):
        return False

    return True

# Compares a packet's ICMP fields against the ICMP fields of a match 
def __matched_ICMP_fields(pkt_header, match_fields):
    if "itype" in match_fields and not compare_field(pkt_header["itype"], match_fields["itype"]["data"], match_fields["itype"]["comparator"]):
        return False

    if "icode" in match_fields and not compare_field(pkt_header["icode"], match_fields["icode"]["data"], match_fields["icode"]["comparator"]):
        return False

    if "icmp_id" in match_fields and not compare_field(pkt_header["icmp_id"], match_fields["icmp_id"]["data"], match_fields["icmp_id"]["comparator"]):
        return False

    if "icmp_seq" in match_fields and not compare_field(pkt_header["icmp_seq"], match_fields["icmp_seq"]["data"], match_fields["icmp_seq"]["comparator"]):
        return False
    return True

# Compares a packet's field against a match's field using the follwoing operators: >,<,=,!,<=,>=,<>,<=>
def compare_field(pkt_data, number, comparator):
    if len(number) == 1:
        ops = {"":   pkt_data == int(number[0]),
               "<":  pkt_data < int(number[0]),
               ">":  pkt_data > int(number[0]),
               "=":  pkt_data == int(number[0]),
               "!":  pkt_data != int(number[0]),
               "<=": pkt_data <= int(number[0]),
               ">=": pkt_data >= int(number[0])}
    else:
        ops = {"<>": pkt_data > int(number[0]) and  pkt_data < int(number[1]),
                     "<=>": pkt_data >= int(number[0]) and  pkt_data <= int(number[1])}

    return ops[comparator]

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
def __matched_fragbits(pkt_fragbits, match_fragbits, comparator):
    if comparator == "" and pkt_fragbits == match_fragbits:
        return True
    elif comparator == "+" and (pkt_fragbits & match_fragbits == match_fragbits):
        return True
    elif comparator == "!" and pkt_fragbits != match_fragbits:
        return True
    elif comparator == "*" and (pkt_fragbits & match_fragbits >= 1):
        return True
    
    return False

# Compares a packet's IP protocol field against the IP protocol field of a match
def __matched_ip_proto(pkt_ip_proto, ip_proto, comparator):
    if comparator == "" and pkt_ip_proto == int(ip_proto):
        return True
    elif comparator == "<" and pkt_ip_proto < int(ip_proto):
        return True
    elif comparator == ">" and pkt_ip_proto > int(ip_proto):
        return True
    elif comparator == "!" and pkt_ip_proto != int(ip_proto):
        return True
    
    return False

# Compares a packet's TCP flags against the TCP flags of a match
def __matched_tcp_flags(pkt_tcp_flags, match_tcp_flags):
    pkt_tcp_flags = pkt_tcp_flags & (match_tcp_flags["exclude"] ^ 0XFF) # Get the complement of "excluded" and zero the "excluded" values in the pkt flags

    if match_tcp_flags["comparator"] == "" and pkt_tcp_flags == match_tcp_flags["data"]:
        return True
    elif match_tcp_flags["comparator"] == "+" and (pkt_tcp_flags & match_tcp_flags["data"] == tcp_match_tcp_flagsflags["data"]):
        return True
    elif match_tcp_flags["comparator"] == "!" and pkt_tcp_flags != match_tcp_flags["data"]:
        return True
    elif match_tcp_flags["comparator"] == "*" and (pkt_tcp_flags & match_tcp_flags["data"] >= 1):
        return True
    
    return False

