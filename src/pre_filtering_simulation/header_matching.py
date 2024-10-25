from scapy.all import IP,TCP,UDP,ICMP
import re

from .rule_to_match import tcp_flags_dict

possible_ipopts = {"RR": "rr", "EOL":"eol", "NOP":"nop", "Timestamp": "ts", "Security": "sec", "Extended Security": "esec", 
                        "LSRR": "lsrr", "LSSRE": "lsrre", "SSRR": "ssrr", "Stream Id":"satid"}

# Compares the header fields of a packet against the ones for a rule
def compare_header_fields(pkt_to_match, rule, rule_proto):
     # Compares the packet's port(s) against the rule's port(s) 
    if (rule_proto == "tcp" or rule_proto == "udp") and (pkt_to_match.tcp_in_pkt or pkt_to_match.upd_in_pkt):
        if not __compare_ports(pkt_to_match.header["dst_port"], rule.pkt_header_fields["dst_port"]):
            return False

        if not __compare_ports(pkt_to_match.header["src_port"], rule.pkt_header_fields["src_port"]):
            return False

    # Compares the packet's IP(s) against the rule's IP(s) 
    if not __compare_IP(pkt_to_match.header["dst_ip"], rule.pkt_header_fields["dst_ip"]):
        return False

    if not __compare_IP(pkt_to_match.header["src_ip"], rule.pkt_header_fields["src_ip"]):
        return False

    if not __matched_IP_fields(pkt_to_match.header, rule.pkt_header_fields):
        return False

    if rule_proto == "tcp" and pkt_to_match.tcp_in_pkt and not __matched_TCP_fields(pkt_to_match.header, rule.pkt_header_fields):
        return False
    
    if rule_proto == "icmp" and pkt_to_match.icmp_in_pkt and not __matched_ICMP_fields(pkt_to_match.header, rule.pkt_header_fields):
        return False

    return True



# Compares a packet's ports(s) against the ports(s) of a rule. Individual ports are in a dict, while ranges are in a list.
def __compare_ports(pkt_port, rule_ports):
    valid_port = False
    if pkt_port in rule_ports[0]:
        return rule_ports[0][pkt_port]
            
    for port_range in rule_ports[1]:
        if port_range[1] and pkt_port in port_range[0]:
            valid_port = True
        elif not port_range[1] and pkt_port in port_range[0]:
            return False
        
    if valid_port:
        return True
    
    # If the pkt_port didn't match any port entry in the rule, there are two options: 
    # If the rule says to match any port with the exception of the port defined (i.e. pkt_port=15, rule_port=[!15]), the pkt_port is valid
    # Else, the pkt_port should've matched a port to match this rule, but it did not, meaning the port is not valid
    return not rule_ports[2]

# Compares a packet's IP(s) against the IP(s) of a rule. The IPs are in a Radix tree for quick search
def __compare_IP(pkt_ip, rule_ips):
    best_match = rule_ips[0].search_best(pkt_ip)
    if best_match:
        return best_match.data["match"]

    return not rule_ips[1]


# Compares a packet's IP fields against the IP fields of a rule 
def __matched_IP_fields(pkt_fields, rule_pkt_header):
    if "ip_proto" in rule_pkt_header and not __compare_ip_proto(pkt_fields["ip_proto"], rule_pkt_header["ip_proto"]["data"], rule_pkt_header["ip_proto"]["comparator"]):
        return False
        
    if "ttl" in rule_pkt_header and not compare_field(pkt_fields["ttl"], rule_pkt_header["ttl"]["data"], rule_pkt_header["ttl"]["comparator"]):
        return False

    if "id" in rule_pkt_header and not compare_field(pkt_fields["id"], rule_pkt_header["id"]["data"], rule_pkt_header["id"]["comparator"]):
        return False
    
    if "ipopts" in rule_pkt_header and not __compare_ipopts(pkt_fields["ipopts"], rule_pkt_header["ipopts"]):
        return False

    if "fragbits" in rule_pkt_header and not __compare_fragbits(pkt_fields["fragbits"], rule_pkt_header["fragbits"]["data"], rule_pkt_header["fragbits"]["comparator"]):
        return False

    return True

# Compares a packet's TCP fields against the TCP fields of a rule 
def __matched_TCP_fields(pkt_fields, rule_pkt_header):
    if "flags" in rule_pkt_header and not __compare_tcp_flags(pkt_fields["flags"], rule_pkt_header["flags"]):
        return False

    if "seq" in rule_pkt_header and not compare_field(pkt_fields["seq"], rule_pkt_header["seq"]["data"], rule_pkt_header["seq"]["comparator"]):
        return False

    if "ack" in rule_pkt_header and not compare_field(pkt_fields["ack"], rule_pkt_header["ack"]["data"], rule_pkt_header["ack"]["comparator"]):
        return False

    if "window" in rule_pkt_header and not compare_field(pkt_fields["window"], rule_pkt_header["window"]["data"], rule_pkt_header["window"]["comparator"]):
        return False

    return True

# Compares a packet's ICMP fields against the ICMP fields of a rule 
def __matched_ICMP_fields(pkt_fields, rule_pkt_header):
    if "itype" in rule_pkt_header and not compare_field(pkt_fields["itype"], rule_pkt_header["itype"]["data"], rule_pkt_header["itype"]["comparator"]):
        return False

    if "icode" in rule_pkt_header and not compare_field(pkt_fields["icode"], rule_pkt_header["icode"]["data"], rule_pkt_header["icode"]["comparator"]):
        return False

    if "icmp_id" in rule_pkt_header and not compare_field(pkt_fields["icmp_id"], rule_pkt_header["icmp_id"]["data"], rule_pkt_header["icmp_id"]["comparator"]):
        return False

    if "icmp_seq" in rule_pkt_header and not compare_field(pkt_fields["icmp_seq"], rule_pkt_header["icmp_seq"]["data"], rule_pkt_header["icmp_seq"]["comparator"]):
        return False
    return True


# Compares a packet's field against a rule's field using the follwoing operators: >,<,=,!,<=,>=,<>,<=>
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

# Compares a packet's IP options against the IP options of a rule
def __compare_ipopts(pkt_ipopts, rule_ipopts):
    if not pkt_ipopts:
        return False

    pkt_ipopts_name = " ".join(str(pkt_ipopts[0]).split("_")[1:])
    if rule_ipopts == "any" and pkt_ipopts_name in possible_ipopts:
        return True
    elif pkt_ipopts_name in possible_ipopts and possible_ipopts[pkt_ipopts_name] == rule_ipopts:
        return True

    print("not a match")
    return False

# Compares a packet's fragmentation bits against the fragmentation bits of a rule
def __compare_fragbits(pkt_fragbits, fragbits_num, comparator):
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
def __compare_ip_proto(pkt_ip_proto, rule_ip_proto, rule_comparator):
    ops = { "":  pkt_ip_proto == int(rule_ip_proto),
           "<":  pkt_ip_proto < int(rule_ip_proto),
           ">":  pkt_ip_proto > int(rule_ip_proto),
           "!":  pkt_ip_proto != int(rule_ip_proto)}

    if ops[rule_comparator]:
        return True

    return False

# Compares a packet's TCP flags against the TCP flags of a rule
def __compare_tcp_flags(pkt_tcp_flags, rule_tcp_flags):
    pkt_tcp_flags = str(pkt_tcp_flags)
    if rule_tcp_flags["exclude"]:
        expression = "["+rule_tcp_flags["exclude"]+"]*"
        pkt_tcp_flags = re.sub(expression, "", pkt_tcp_flags)

    pkt_tcp_flags_num = sum(tcp_flags_dict[flag] for flag in pkt_tcp_flags) 

    if rule_tcp_flags["comparator"] == "" and pkt_tcp_flags_num == rule_tcp_flags["data"]:
        return True
    elif rule_tcp_flags["comparator"] == "+" and (pkt_tcp_flags_num & rule_tcp_flags["data"] == rule_tcp_flags["data"]):
        return True
    elif rule_tcp_flags["comparator"] == "!" and pkt_tcp_flags_num != rule_tcp_flags["data"]:
        return True
    elif rule_tcp_flags["comparator"] == "*" and (pkt_tcp_flags_num & rule_tcp_flags["data"] >= 1):
        return True
    
    return False

