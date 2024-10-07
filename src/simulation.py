import re
import ipaddress
import binascii
from scapy.all import *
from multiprocessing import Manager,Process,cpu_count

from snort_rule_parser.rules_parser import group_header_and_payload_fields

ip_proto = {"ip": 0, "icmp": 1, "tcp": 6, "udp": 17}


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


def pre_filtering_simulation(rules, n=1000):
    # Find the optimal pre-filtering subset
    print("---- Separtes fields into pkt_header fields and payload fields ----")
    group_header_and_payload_fields(rules)

    pre_filtering_rules = optimal_pre_filtering_rules()

    start = time.time()
    pcap = rdpcap("/home/hbeckerbrum/NFSDatasets/CICIDS2017/Friday-WorkingHours.pcap", n)
    print("Time to read ", n, " packets in seconds: ", time.time() - start)

    suspicious_pkts = Manager().list()
    ip_pkt_count_list = Manager().list()
    processes = []

    num_processes = 1#cpu_count()
    share = round(len(pcap)/num_processes)
    for i in range(num_processes):
        pkts_sublist = pcap[i*share:(i+1)*share + int(i == (num_processes - 1))*-1*(num_processes*share - len(pcap))]
        process = Process(target=compare_pkt, args=(pkts_sublist, rules, suspicious_pkts, ip_pkt_count_list, i*share))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    print(len(suspicious_pkts), sum(ip_pkt_count_list), n) # Count IP packets

    # send_pkts_to_NIDS(pkts_to_NIDS)


# Generates the optimal pre-filtering ruleset using most header fields and part of the payload matches
def optimal_pre_filtering_rules():
    # get_header_and_payload_fields()

    # select_optimal_payload_config()

    return []


# Compare packets with rules
def compare_pkt(pkts, rules, suspicious_pkts, ip_pkt_count_list, start):
    pkt_id, ip_pkt_count = start, 0
    for pkt in pkts:
        if "IP" in pkt:
            for rule in rules[0:20]:
                print(rule.pkt_header)
                rule_proto = ip_proto[rule.pkt_header["proto"]]
                if pkt["IP"].proto != rule_proto and rule_proto != 0:
                    continue
                
                # if not compare_header_fields(pkt, rule, rule_proto):
                #     continue

                if not compare_payload(pkt, rule):
                    continue

                # suspicious_pkts.append((pkt_id, rule))
                # break 
            return None
            ip_pkt_count+=1
        pkt_id+=1
    ip_pkt_count_list.append(ip_pkt_count)


# Compares the header fields of packet against the ones for a rule
def compare_header_fields(pkt, rule, rule_proto): 
    if not _compare_IP(pkt["IP"].src, rule.pkt_header["src_ip"]):
        return False

    if not _compare_IP(pkt["IP"].dst, rule.pkt_header["dst_ip"]):
        return False

    if (rule_proto == 6 or rule_proto == 17) and (TCP in pkt or UDP in pkt):
        if not _compare_ports(pkt[rule.pkt_header["proto"].upper()].sport, rule.pkt_header["src_port"]):
            return False

        if not _compare_ports(pkt[rule.pkt_header["proto"].upper()].dport, rule.pkt_header["dst_port"]):
            return False

    if not _matched_IP_fields(pkt, rule.pkt_header):
        return False

    if rule_proto == 6 and not _matched_TCP_fields(pkt, rule.pkt_header):
        return False
    
    if rule_proto == 1 and not _matched_ICMP_fields(pkt, rule.pkt_header):
        return False

    return True

# Compares a packet's IP fields against the IP fields of a rule 
def _matched_IP_fields(pkt, rule_pkt_header):
    if "ttl" in rule_pkt_header and not _compare_fields(pkt[IP].ttl, rule_pkt_header["ttl"][0]):
        return False

    if "id" in rule_pkt_header and not _compare_fields(pkt[IP].id, rule_pkt_header["id"][0]):
        return False
    
    if "ipopts" in rule_pkt_header and not _compare_ipopts(pkt[IP].options, rule_pkt_header["ipopts"][0]):
        return False

    if "fragbits" in rule_pkt_header and not _compare_fragbits(pkt[IP].flags, rule_pkt_header["fragbits"][0]):
        return False

    if "ip_proto" in rule_pkt_header and not _compare_ip_proto(pkt[IP].proto, rule_pkt_header["ip_proto"][0]):
        return False

    return True

# Compares a packet's TCP fields against the TCP fields of a rule 
def _matched_TCP_fields(pkt, rule_pkt_header):
    if "flags" in rule_pkt_header and not _compare_tcp_flags(pkt[TCP].flags, rule_pkt_header["flags"]):
        return False

    if "seq" in rule_pkt_header and not _compare_fields(pkt[TCP].seq, rule_pkt_header["seq"][0]):
        return False

    if "ack" in rule_pkt_header and not _compare_fields(pkt[TCP].ack, rule_pkt_header["ack"][0]):
        return False

    if "window" in rule_pkt_header and not _compare_fields(pkt[TCP].window, rule_pkt_header["window"][0]):
        return False

    return True

# Compares a packet's ICMP fields against the ICMP fields of a rule 
def _matched_ICMP_fields(pkt, rule_pkt_header):
    if "itype" in rule_pkt_header and not _compare_fields(pkt[ICMP].type, rule_pkt_header["itype"][0]):
        return False

    if "icode" in rule_pkt_header and not _compare_fields(pkt[ICMP].code, rule_pkt_header["icode"][0]):
        return False

    if "icmp_id" in rule_pkt_header and not _compare_fields(pkt[ICMP].id, rule_pkt_header["icmp_id"][0]):
        return False

    if "icmp_seq" in rule_pkt_header and not _compare_fields(pkt[ICMP].seq, rule_pkt_header["icmp_seq"][0]):
        return False

    return True

# Compares a packet's IP(s) against the IP(s) of a rule
def _compare_IP(pkt_ip, rule_ips):
    valid_ip = False
    for ip in rule_ips:
        if ip[1] and ipaddress.ip_address(pkt_ip) in ipaddress.ip_network(ip[0]):
            valid_ip = True

        if not ip[1] and ipaddress.ip_address(pkt_ip) in ipaddress.ip_network(ip[0]):
            valid_ip = False
            break

        if not ip[1] and ipaddress.ip_address(pkt_ip) not in ipaddress.ip_network(ip[0]):
            valid_ip = True
    return valid_ip

# Compares a packet's ports(s) against the ports(s) of a rule
def _compare_ports(pkt_port, rule_ports):
    valid_port = False
    for port in rule_ports:
        if port[1] and type(port[0]) != range and pkt_port == port[0]:
            valid_port = True
            break
        elif not port[1] and type(port[0]) != range and pkt_port != port[0]:
            valid_port = True
        elif not port[1] and type(port[0]) != range and pkt_port == port[0]:
            valid_port = False
            break
        elif port[1] and type(port[0]) == range and pkt_port in port[0]:
            valid_port = True
        elif not port[1] and type(port[0]) == range and pkt_port in port[0]:
            valid_port = False
            break
        elif not port[1] and type(port[0]) == range and pkt_port not in port[0]:
            valid_port = True
    return valid_port

# Compares a packet's fields(s) against the fields(s) of a rule using the follwoing operators: >,<,=,!,<=,>=,<>,<=>
def _compare_fields(pkt_data, rule_data):
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
def _compare_ipopts(pkt_ipopts, rule_ipopts):
    if not pkt_ipopts:
        return False

    pkt_ipopts_name = " ".join(str(pkt_ipopts[0]).split("_")[1:])
    if rule_ipopts == "any" and pkt_ipopts_name in possible_ipopts:
        return True
    elif pkt_ipopts_name in possible_ipopts and possible_ipopts[pkt_ipopts_name] == rule_ipopts:
        return True

    return False

# Compares a packet's fragmentation bits against the fragmentation bits of a rule
def _compare_fragbits(pkt_fragbits, rule_fragbits):
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
def _compare_ip_proto(pkt_ip_proto, rule_ip_proto):
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
def _compare_tcp_flags(pkt_tcp_flags, rule_tcp_flags):
    def parse_flags(flags):
        tcp_flags = re.sub("[1]", "C", flags)
        tcp_flags = re.sub("[2]", "E", tcp_flags)
        tcp_flags = re.sub("[\+\*\!]", "", tcp_flags)

        return tcp_flags

    flags_to_match = rule_tcp_flags[0]
    # flags_to_ignore_sum = 0

    # if len(rule_tcp_flags)>1:
    #     flags_to_ignore = rule_tcp_flags[1]
    #     flags_to_ignore = parse_flags(flags_to_ignore)
    #     flags_to_ignore_sum = sum(tcp_flags_dict[flag] for flag in flags_to_ignore)


    tcp_flags = parse_flags(flags_to_match)
    tcp_flags_num = sum(tcp_flags_dict[flag] for flag in tcp_flags) 
    comparator = re.sub("[a-zA-Z.]", "", flags_to_match)

    if comparator == "" and pkt_tcp_flags == tcp_flags_num:
        return True
    elif comparator == "+" and (pkt_tcp_flags & tcp_flags_num == tcp_flags_num):
        return True
    elif comparator == "!" and pkt_tcp_flags != tcp_flags_num:
        return True
    elif comparator == "*" and (pkt_tcp_flags & tcp_flags_num >= 1):
        return True
    
    return False


def compare_payload(pkt, rule):
    # if "dsize" in rule.payload_fields and not _compare_fields(len(pkt[rule.pkt_header["proto"].upper()].payload), rule.payload_fields["dsize"][0][1][0]):
    #     return False

    if "content" in rule.payload_fields and not _compare_content(pkt[rule.pkt_header["proto"].upper()].payload, rule.payload_fields["content"]):
        return False
    
    if "pcre" in rule.payload_fields and not _compare_pcre():
        return False

    return True



def _compare_content(pkt_payload, rule_content):
    position = 0
    for content in rule_content:
        print(content)
        str_to_match = _clean_content_and_hexify(content[1][0]) 
                
        start, end = 0, len(pkt_payload)
        for modifier in content[1][1:]:
            modifier_split = modifier.split(" ")
            modifier_name = modifier_split[0]
            if len(modifier_split)>1:
                num = int(modifier_split[1])
                if modifier_name == "offset":
                    start = num
                elif modifier_name == "depth":
                    end = start+num
                elif modifier_name == "distance":
                    start = position+num 
                elif modifier_name == "within":
                    end = position+num
            elif modifier_name == "nocase":
                str_to_match = str_to_match.lower()
                # payload.lower()
        
        if start > end:
            end+=start

        position = end
        print(str_to_match)
        print(start, end)
        # #if not pkt_payload.contains(str_to_match)

        # print(start, end)
        # print(content)
    return True

## Turn
def _clean_content_and_hexify(str_to_match):
    clean_content = ""
    temp = ""
    hex_now, escaped = False, False
    for char in str_to_match:
        if char == '|' and not hex_now:
            hex_now = True
            clean_content+=temp.encode('ascii').hex()
            temp = ""
            continue
        elif char == '|' and hex_now:
            hex_now = False
            clean_content+=re.sub(r"\s+", "", temp)
            temp = ""
            continue

        if escaped and (char == ';' or char == '"' or char == '\\'):
            temp+=char
        elif escaped:
            temp+='/'

        escaped = False

        if char == '/':
            escaped = True
        else:
            temp+=char

    clean_content+=temp.encode('ascii').hex()
    return clean_content


def _compare_pcre():
    pass

    

# Sends the remaining packets to a NIDS using the desired configuration
#def send_pkts_to_NIDS():