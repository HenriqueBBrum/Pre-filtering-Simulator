### Main file that compiles a Snort rule file according to the snort.conf and classification.conf to P4 table entries
# Args: config path, rules_path
#       - config_path: Path to the configuration files
#       - rules_path: Path to a single rule file or to a directory containing multiple rule files
#       - compiler_goal: Compiler goals, such as the p4 target and the rules priority
#       - compiler_output_file: Output file path for the compiled p4 table entries



## Standard and 3rd-party imports
import sys
from datetime import datetime
from json import load
import random
import re

import ipaddress
from scapy.all import *
import time


## Local imports
from snort_config_parser import SnortConfiguration
from snort_rule_parser.rules_parser import get_rules, dedup_rules, adjust_rules, group_header_and_payload_fields
from snort_rule_parser.rule_statistics import RuleStatistics



def main(config_path, rules_path):
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)
    print("*" * 80)
    print("*" * 80)
    print("*" * 26 + " SNORT RULES PARSING STAGE " + "*" * 27+ "\n\n")
    modified_rules = rule_parsing_stage(config, rules_path)

    pre_filtering_simulation(modified_rules)
   

# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def rule_parsing_stage(config, rules_path):
    ignored_rule_files = {}

    print("---- Getting and parsing rules..... ----")
    print("---- Splitting bidirectional rules..... ----")
    original_rules, fixed_bidirectional_rules = get_rules(rules_path, ignored_rule_files) # Get all rules from multiple files or just one
    stats = RuleStatistics(config, original_rules)
    
    print("---- Adjusting rules. Replacing variables,grouping ports into ranges and adjusting negated port rules..... ----")
    modified_rules = adjust_rules(config, fixed_bidirectional_rules) 

    print("---- Separating fields into packet_header fields and payload fields ----")
    group_header_and_payload_fields(modified_rules)

    # stats.print_all()

    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total rules after fixing bidirectional rules: {}".format(len(fixed_bidirectional_rules)))
    print("Total non-negated IP rules: {}".format(len(modified_rules)))
    
    return modified_rules

tcp_flags_dict = {
    'F': 1,
    'S': 2,
    'R': 4,
    'P': 8,
    'A': 16,
    'U': 32,
    'E': 128,
    'C': 256,
}

ip_flags_dict = {
    'M': 1,
    'D': 2,
    'R': 4
}

ip_proto = {"ip": 0, "icmp": 1, "tcp": 6, "udp": 17}

def pre_filtering_simulation(rules):
    # Find the optmial pre-filtering subset
    # pre_filtering_rules = optimal_pre_filtering_rules()

    n = 1000
    start = time.time()
    pcap = rdpcap("/home/hbeckerbrum/NFSDatasets/CICIDS2017/Friday-WorkingHours.pcap", n)
    print("Time to read ", n, " packets in seconds: ", time.time() - start)
    packet_id, ip_packet_id = 0, 0
    send_to_NIDS_pkts = []
    for packet in pcap:
        if "IP" in packet:
            for rule in rules:
                rule_proto = ip_proto[rule.packet_header["proto"]]
                if packet["IP"].proto != rule_proto and rule_proto != 0:
                    continue

                if not _compare_IP(packet["IP"].src, rule.packet_header["src_ip"]):
                    continue

                if not _compare_IP(packet["IP"].dst, rule.packet_header["dst_ip"]):
                    continue

                if rule_proto == 6 or rule_proto == 17:
                    if not _compare_ports(packet[rule.packet_header["proto"].upper()].sport, rule.packet_header["src_port"]):
                        continue

                    if not _compare_ports(packet[rule.packet_header["proto"].upper()].dport, rule.packet_header["dst_port"]):
                        continue

                if not _matched_IP_fields(packet, rule.packet_header):
                    continue

                if rule_proto == 6 and not _matched_TCP_fields(packet, rule.packet_header):
                    continue

                if rule_proto == 1 and not _matched_ICMP_fields(packet, rule.packet_header):
                    continue

                send_to_NIDS_pkts.append((packet_id, rule.id))
                break
            ip_packet_id+=1
        packet_id+=1

    print(len(send_to_NIDS_pkts), ip_packet_id, packet_id)


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

def _matched_TCP_fields(packet, rule_packet_header):
    if "flags" in rule_packet_header and not _compare_tcp_flags(packet[TCP].flags, rule_packet_header["flags"][0]):
        return False

    if "seq" in rule_packet_header and not _compare_fields(packet[TCP].seq, rule_packet_header["seq"][0]):
        return False

    if "ack" in rule_packet_header and not _compare_fields(packet[TCP].ack, rule_packet_header["ack"][0]):
        return False

    if "window" in rule_packet_header and not _compare_fields(packet[TCP].window, rule_packet_header["window"][0]):
        return False

    return True

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

def _compare_fields(packet_data, rule_data):
    number = re.findall("[\d.]+", rule_data)
    comparator = re.sub("[\d.]", "", rule_data)
    print(number, comparator)

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

def _compare_ipopts(packet_ipopts, rule_ipopts):
    possible_ipopts = {"RR": "rr", "EOL":"eol", "NOP":"nop", "Timestamp": "ts", "Security": "sec", "Extended Security": "esec", 
                        "LSRR": "lsrr", "LSSRE": "lsrre", "SSRR": "ssrr", "Stream Id":"satid"}

    if not packet_ipopts:
        return False

    packet_ipopts_name = " ".join(str(packet_ipopts[0]).split("_")[1:])
    if rule_ipopts == "any" and packet_ipopts_name in possible_ipopts:
        return True
    elif packet_ipopts_name in possible_ipopts and possible_ipopts[packet_ipopts_name] == rule_ipopts:
        return True


    return False

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

def _compare_tcp_flags(packet_tcp_flags, rule_tcp_flags):
    tcp_flags = re.sub("[\+\*\!]", "", rule_tcp_flags)
    tcp_flags_num = sum(tcp_flags_dict[flag] for flag in tcp_flags)
    comparator = re.sub("[a-zA-Z.]", "", rule_tcp_flags)

    if packet_tcp_flags == 0 and tcp_flags_num == 0:
        return True

    if comparator == "" and packet_tcp_flags == tcp_flags_num:
        return True
    elif comparator == "+" and (packet_tcp_flags & tcp_flags_num == tcp_flags_num):
        return True
    elif comparator == "!" and packet_tcp_flags != tcp_flags_num:
        return True
    elif comparator == "*" and (packet_tcp_flags & tcp_flags_num >= 1):
        return True
    
    return False

if __name__ == '__main__':
    config_path = sys.argv[1]
    rules_path = sys.argv[2]
    compiler_goal = sys.argv[3]

    main(config_path, rules_path)

   
