import re
import ipaddress
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
    print("---- Separtes fields into packet_header fields and payload fields ----")
    group_header_and_payload_fields(rules)

    pre_filtering_rules = optimal_pre_filtering_rules()

    start = time.time()
    pcap = rdpcap("/home/hbeckerbrum/NFSDatasets/CICIDS2017/Friday-WorkingHours.pcap", n)
    print("Time to read ", n, " packets in seconds: ", time.time() - start)

    print(pcap[999].show2())
    print(len(bytes(pcap[999][UDP].payload)))
    return []

    suspicious_pkts = Manager().list()
    ip_pkt_count_list = Manager().list()
    processes = []

    num_processes = cpu_count()
    share = round(len(pcap)/num_processes)
    for i in range(num_processes):
        pkts_sublist = pcap[i*share:(i+1)*share + int(i == (num_processes - 1))*-1*(num_processes*share - len(pcap))]
        process = Process(target=compare_header_fields, args=(pkts_sublist, rules, suspicious_pkts, ip_pkt_count_list, i*share))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    print(len(suspicious_pkts), sum(ip_pkt_count_list), n) # Count IP packets

    processes = []
    pkts_to_NIDS = Manager().list()
    for i in range(num_processes):
        pkts_sublist = pcap[i*share:(i+1)*share + int(i == (num_processes - 1))*-1*(num_processes*share - len(pcap))]
        process = Process(target=compare_payload, args=(pkts_sublist, rules, suspicious_pkts, ip_pkt_count_list, i*share))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    # send_pkts_to_NIDS(pkts_to_NIDS)


# Generates the optimal pre-filtering ruleset using most header fields and part of the payload matches
def optimal_pre_filtering_rules():
    # get_header_and_payload_fields()

    # select_optimal_payload_config()

    return []

# Compares the header fields of packet against the ones for a rule
def compare_header_fields(pkts, rules, suspicious_pkts, ip_pkt_count_list, start):
    pkt_id, ip_pkt_count = start, 0
    for pkt in pkts:
        if "IP" in pkt:
            for rule in rules:
                rule_proto = ip_proto[rule.packet_header["proto"]]
                if pkt["IP"].proto != rule_proto and rule_proto != 0:
                    continue

                if not _compare_IP(pkt["IP"].src, rule.packet_header["src_ip"]):
                    continue

                if not _compare_IP(pkt["IP"].dst, rule.packet_header["dst_ip"]):
                    continue

                if (rule_proto == 6 or rule_proto == 17) and (TCP in pkt or UDP in pkt):
                    if not _compare_ports(pkt[rule.packet_header["proto"].upper()].sport, rule.packet_header["src_port"]):
                        continue

                    if not _compare_ports(pkt[rule.packet_header["proto"].upper()].dport, rule.packet_header["dst_port"]):
                        continue

                if not _matched_IP_fields(pkt, rule.packet_header):
                    continue

                if rule_proto == 6 and not _matched_TCP_fields(pkt, rule.packet_header):
                    continue
                
                if rule_proto == 1 and not _matched_ICMP_fields(pkt, rule.packet_header):
                    continue

                suspicious_pkts.append((pkt_id, rule.id))
                break
            ip_pkt_count+=1
        pkt_id+=1
    ip_pkt_count_list.append(ip_pkt_count)

# Compares a packet's IP fields against the IP fields of a rule 
def _matched_IP_fields(packet, rule_packet_header):
    if "ttl" in rule_packet_header and not _compare_fields(packet[IP].ttl, rule_packet_header["ttl"][0]):
        return False

    if "id" in rule_packet_header and not _compare_fields(packet[IP].id, rule_packet_header["id"][0]):
        return False
    
    if "ipopts" in rule_packet_header and not _compare_ipopts(packet[IP].options, rule_packet_header["ipopts"][0]):
        return False

    if "fragbits" in rule_packet_header and not _compare_fragbits(packet[IP].flags, rule_packet_header["fragbits"][0]):
        return False

    if "ip_proto" in rule_packet_header and not _compare_ip_proto(packet[IP].proto, rule_packet_header["ip_proto"][0]):
        return False

    return True

# Compares a packet's TCP fields against the TCP fields of a rule 
def _matched_TCP_fields(packet, rule_packet_header):
    if "flags" in rule_packet_header and not _compare_tcp_flags(packet[TCP].flags, rule_packet_header["flags"]):
        return False

    if "seq" in rule_packet_header and not _compare_fields(packet[TCP].seq, rule_packet_header["seq"][0]):
        return False

    if "ack" in rule_packet_header and not _compare_fields(packet[TCP].ack, rule_packet_header["ack"][0]):
        return False

    if "window" in rule_packet_header and not _compare_fields(packet[TCP].window, rule_packet_header["window"][0]):
        return False

    return True

# Compares a packet's ICMP fields against the ICMP fields of a rule 
def _matched_ICMP_fields(packet, rule_packet_header):
    if "itype" in rule_packet_header and not _compare_fields(packet[ICMP].type, rule_packet_header["itype"][0]):
        return False

    if "icode" in rule_packet_header and not _compare_fields(packet[ICMP].code, rule_packet_header["icode"][0]):
        return False

    if "icmp_id" in rule_packet_header and not _compare_fields(packet[ICMP].id, rule_packet_header["icmp_id"][0]):
        return False

    if "icmp_seq" in rule_packet_header and not _compare_fields(packet[ICMP].seq, rule_packet_header["icmp_seq"][0]):
        return False

    return True

# Compares a packet's IP(s) against the IP(s) of a rule
def _compare_IP(packet_ip, rule_ips):
    valid_ip = False
    for ip in rule_ips:
        if ip[1] and ipaddress.ip_address(packet_ip) in ipaddress.ip_network(ip[0]):
            valid_ip = True

        if not ip[1] and ipaddress.ip_address(packet_ip) in ipaddress.ip_network(ip[0]):
            valid_ip = False
            break

        if not ip[1] and ipaddress.ip_address(packet_ip) not in ipaddress.ip_network(ip[0]):
            valid_ip = True
    return valid_ip

# Compares a packet's ports(s) against the ports(s) of a rule
def _compare_ports(packet_port, rule_ports):
    valid_port = False
    for port in rule_ports:
        if port[1] and type(port[0]) != range and packet_port == port[0]:
            valid_port = True
            break
        elif not port[1] and type(port[0]) != range and packet_port != port[0]:
            valid_port = True
        elif not port[1] and type(port[0]) != range and packet_port == port[0]:
            valid_port = False
            break
        elif port[1] and type(port[0]) == range and packet_port in port[0]:
            valid_port = True
        elif not port[1] and type(port[0]) == range and packet_port in port[0]:
            valid_port = False
            break
        elif not port[1] and type(port[0]) == range and packet_port not in port[0]:
            valid_port = True
    return valid_port

# Compares a packet's fields(s) against the fields(s) of a rule using the follwoing operators: >,<,=,!,<=,>=,<>,<=>
def _compare_fields(packet_data, rule_data):
    number = re.findall("[\d.]+", rule_data)
    comparator = re.sub("[\d.]", "", rule_data)

    ops = {}

    if len(number) == 1:
        ops = {"":   packet_data == int(number[0]),
               "<":  packet_data < int(number[0]),
               ">":  packet_data > int(number[0]),
               "=":  packet_data == int(number[0]),
               "!":  packet_data != int(number[0]),
               "<=": packet_data <= int(number[0]),
               ">=": packet_data >= int(number[0])}
    else:
        ops = {"<>": packet_data > int(number[0]) and  packet_data < int(number[1]),
                     "<=>": packet_data >= int(number[0]) and  packet_data <= int(number[1])}

    return ops[comparator]

# Compares a packet's IP options against the IP options of a rule
def _compare_ipopts(packet_ipopts, rule_ipopts):
    if not packet_ipopts:
        return False

    packet_ipopts_name = " ".join(str(packet_ipopts[0]).split("_")[1:])
    if rule_ipopts == "any" and packet_ipopts_name in possible_ipopts:
        return True
    elif packet_ipopts_name in possible_ipopts and possible_ipopts[packet_ipopts_name] == rule_ipopts:
        return True

    return False

# Compares a packet's fragmentation bits against the fragmentation bits of a rule
def _compare_fragbits(packet_fragbits, rule_fragbits):
    fragbits = re.sub("[\+\*\!]", "", rule_fragbits)
    fragbits_num = sum(ip_flags_dict[flag] for flag in fragbits)
    comparator = re.sub("[MDR.]", "", rule_fragbits)
    
    if packet_fragbits == 0 and fragbits_num == 0:
        return True

    if comparator == "" and packet_fragbits == fragbits_num:
        return True
    elif comparator == "+" and (packet_fragbits & fragbits_num == fragbits_num):
        return True
    elif comparator == "!" and packet_fragbits != fragbits_num:
        return True
    elif comparator == "*" and (packet_fragbits & fragbits_num >= 1):
        return True
    
    return False

# Compares a packet's IP protocol field against the IP protocol field of a rule
def _compare_ip_proto(packet_ip_proto, rule_ip_proto):
    proto = re.sub("[^\d.]+", "", rule_ip_proto)
    comparator = re.sub("[\d.]+", "", rule_ip_proto)

    ops = { "":  packet_ip_proto == int(proto),
           "<":  packet_ip_proto < int(proto),
           ">":  packet_ip_proto > int(proto),
           "!":  packet_ip_proto != int(proto)}

    if ops[comparator]:
        return True

    return False

# Compares a packet's TCP flags against the TCP flags of a rule
def _compare_tcp_flags(packet_tcp_flags, rule_tcp_flags):
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

    if comparator == "" and packet_tcp_flags == tcp_flags_num:
        return True
    elif comparator == "+" and (packet_tcp_flags & tcp_flags_num == tcp_flags_num):
        return True
    elif comparator == "!" and packet_tcp_flags != tcp_flags_num:
        return True
    elif comparator == "*" and (packet_tcp_flags & tcp_flags_num >= 1):
        return True
    
    return False


def compare_payload(pkts, rules, pkts_to_NIDS, start):
    for pkt in pkts:
        for rule in rules:
            
            pass

# Sends the remaining packets to a NIDS using the desired configuration
#def send_pkts_to_NIDS():