from scapy.all import IP,TCP,UDP,ICMP
import ipaddress
import re
import radix


possible_ipopts = {"RR": "rr", "EOL":"eol", "NOP":"nop", "Timestamp": "ts", "Security": "sec", "Extended Security": "esec", 
                        "LSRR": "lsrr", "LSSRE": "lsrre", "SSRR": "ssrr", "Stream Id":"satid"}


ip_flags_dict = {
    'M': 1,
    'D': 2,
    'R': 4
}

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


# Compares the header fields of packet against the ones for a rule # !!!!!!!!!!!!!!!!Parse for the service key
def compare_header_fields(pkt_fields, rule, rule_proto, icmp_in_pkt, tcp_in_pkt, upd_in_pkt): 
    if not __compare_IP(pkt_fields["src_ip"], rule.pkt_header["src_ip"]):
        return False

    if not __compare_IP(pkt_fields["dst_ip"], rule.pkt_header["dst_ip"]):
        return False

    if (rule_proto == "tcp" or rule_proto == "udp") and (tcp_in_pkt or upd_in_pkt):
        if not __compare_ports(pkt_fields["src_port"], rule.pkt_header["src_port"]):
            return False

        if not __compare_ports(pkt_fields["dst_port"], rule.pkt_header["dst_port"]):
            return False

    if not __matched_IP_fields(pkt_fields, rule.pkt_header):
        return False

    if rule_proto == "tcp" and tcp_in_pkt and not __matched_TCP_fields(pkt_fields, rule.pkt_header):
        return False
    
    if rule_proto == "icmp" and icmp_in_pkt and not __matched_ICMP_fields(pkt_fields, rule.pkt_header):
        return False

    return True

# Compares a packet's IP fields against the IP fields of a rule 
def __matched_IP_fields(pkt_fields, rule_pkt_header):
    if "ip_proto" in rule_pkt_header and not __compare_ip_proto(pkt_fields["ip_proto"], rule_pkt_header["ip_proto"][0]):
        return False
        
    if "ttl" in rule_pkt_header and not compare_fields(pkt_fields["ttl"], rule_pkt_header["ttl"][0]):
        return False

    if "id" in rule_pkt_header and not compare_fields(pkt_fields["id"], rule_pkt_header["id"][0]):
        return False
    
    if "ipopts" in rule_pkt_header and not __compare_ipopts(pkt_fields["ipopts"], rule_pkt_header["ipopts"][0]):
        return False

    if "fragbits" in rule_pkt_header and not __compare_fragbits(pkt_fields["fragbits"], rule_pkt_header["fragbits"][0]):
        return False

    return True

# Compares a packet's TCP fields against the TCP fields of a rule 
def __matched_TCP_fields(pkt_fields, rule_pkt_header):
    if "flags" in rule_pkt_header and not __compare_tcp_flags(pkt_fields["flags"], rule_pkt_header["flags"]):
        return False

    if "seq" in rule_pkt_header and not compare_fields(pkt_fields["seq"], rule_pkt_header["seq"][0]):
        return False

    if "ack" in rule_pkt_header and not compare_fields(pkt_fields["ack"], rule_pkt_header["ack"][0]):
        return False

    if "window" in rule_pkt_header and not compare_fields(pkt_fields["window"], rule_pkt_header["window"][0]):
        return False

    return True

# Compares a packet's ICMP fields against the ICMP fields of a rule 
def __matched_ICMP_fields(pkt_fields, rule_pkt_header):
    if "itype" in rule_pkt_header and not compare_fields(pkt_fields["itype"], rule_pkt_header["itype"][0]):
        return False

    if "icode" in rule_pkt_header and not compare_fields(pkt_fields["icode"], rule_pkt_header["icode"][0]):
        return False

    if "icmp_id" in rule_pkt_header and not compare_fields(pkt_fields["icmp_id"], rule_pkt_header["icmp_id"][0]):
        return False

    if "icmp_seq" in rule_pkt_header and not compare_fields(pkt_fields["icmp_seq"], rule_pkt_header["icmp_seq"][0]):
        return False
    return True


# Compares a packet's IP(s) against the IP(s) of a rule
def __compare_IP(pkt_ip, rule_ips):
    best_match = rule_ips[0].search_best(pkt_ip)
    if best_match:
        return best_match.data["match"]

    return not rule_ips[1]

# Compares a packet's ports(s) against the ports(s) of a rule
def __compare_ports(pkt_port, rule_ports):
    valid_port = False
    if pkt_port in rule_ports[0]:
        if rule_ports[0][pkt_port]:
            return True
        else:
            return False

    for port_range in rule_ports[1]:
        if port_range[1] and pkt_port in port_range[0]:
            valid_port = True
        elif not port_range[1] and pkt_port in port_range[0]:
            return False
        
    if valid_port:
        return True
    
    # If the pkt_port didn't match any port entry in the rule, there are two options: 
    # If the rule says to match any port with the exception of the port defined (i.e. pkt_port=15, rule_port=[!15]), the pkt_port is valid
    # Else, the pkt_port should have matched a port to match this rule but it did not
    return not rule_ports[2]

# Compares a packet's fields(s) against the fields(s) of a rule using the follwoing operators: >,<,=,!,<=,>=,<>,<=>
def compare_fields(pkt_data, rule_data):
    number = re.findall("[\d.]+", rule_data)
    comparator = re.sub("[\d.]", "", rule_data)

    ops = {}

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

# Compares a packet's IP options against the IP options of a rule
def __compare_ipopts(pkt_ipopts, rule_ipopts):
    if not pkt_ipopts:
        return False

    pkt_ipopts_name = " ".join(str(pkt_ipopts[0]).split("_")[1:])
    if rule_ipopts == "any" and pkt_ipopts_name in possible_ipopts:
        return True
    elif pkt_ipopts_name in possible_ipopts and possible_ipopts[pkt_ipopts_name] == rule_ipopts:
        return True

    return False

# Compares a packet's fragmentation bits against the fragmentation bits of a rule
def __compare_fragbits(pkt_fragbits, rule_fragbits):
    fragbits = re.sub("[\+\*\!]", "", rule_fragbits)
    fragbits_num = sum(ip_flags_dict[flag] for flag in fragbits)
    comparator = re.sub("[MDR.]", "", rule_fragbits)
    
    if pkt_fragbits == 0 and fragbits_num == 0:
        return True

    if comparator == "" and pkt_fragbits == fragbits_num:
        return True
    elif comparator == "+" and (pkt_fragbits & fragbits_num == fragbits_num):
        return True
    elif comparator == "!" and pkt_fragbits != fragbits_num:
        return True
    elif comparator == "*" and (pkt_fragbits & fragbits_num >= 1):
        return True
    
    return False

# Compares a packet's IP protocol field against the IP protocol field of a rule
def __compare_ip_proto(pkt_ip_proto, rule_ip_proto):
    proto = re.sub("[^\d.]+", "", rule_ip_proto)
    comparator = re.sub("[\d.]+", "", rule_ip_proto)

    ops = { "":  pkt_ip_proto == int(proto),
           "<":  pkt_ip_proto < int(proto),
           ">":  pkt_ip_proto > int(proto),
           "!":  pkt_ip_proto != int(proto)}

    if ops[comparator]:
        return True

    return False

# Compares a packet's TCP flags against the TCP flags of a rule
def __compare_tcp_flags(pkt_tcp_flags, rule_tcp_flags):
    def parse_flags(flags):
        tcp_flags = re.sub("[1]", "C", flags)
        tcp_flags = re.sub("[2]", "E", tcp_flags)
        tcp_flags = re.sub("[\+\*\!]", "", tcp_flags)

        return tcp_flags

    flags_to_match = rule_tcp_flags[0]
    pkt_tcp_flags = str(pkt_tcp_flags)
    if len(rule_tcp_flags) > 1:
        expression = "["+rule_tcp_flags[1]+"]*"
        pkt_tcp_flags = re.sub(expression, "", pkt_tcp_flags)

    tcp_flags = parse_flags(flags_to_match)
    tcp_flags_num = sum(tcp_flags_dict[flag] for flag in tcp_flags) 
    comparator = re.sub("[a-zA-Z.]", "", flags_to_match)

    pkt_tcp_flags_num = sum(tcp_flags_dict[flag] for flag in pkt_tcp_flags) 

    if comparator == "" and pkt_tcp_flags_num == tcp_flags_num:
        return True
    elif comparator == "+" and (pkt_tcp_flags_num & tcp_flags_num == tcp_flags_num):
        return True
    elif comparator == "!" and pkt_tcp_flags_num != tcp_flags_num:
        return True
    elif comparator == "*" and (pkt_tcp_flags_num & tcp_flags_num >= 1):
        return True
    
    return False

