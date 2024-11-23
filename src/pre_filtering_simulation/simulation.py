from scapy.all import IP,UDP,TCP 
from scapy.layers.http import HTTPRequest,HTTPResponse 
from scapy.utils import PcapWriter, rdpcap 
from scapy.contrib.gtp import GTPHeader 
from scapy.contrib.gtp_v2 import GTPHeader as GTPHeader_v2 

from multiprocessing import Manager,Process,cpu_count
from collections import Counter

from socket import getservbyport
import os
from time import time
import traceback

from .header_matching import compare_header_fields
from .payload_matching import compare_payload
from .packet_to_match import PacketToMatch

# Main simulation function where packets are compared against the pre-filtering rules
def pre_filtering_simulation(rules, pcaps_path, pre_filtering_scenario, ruleset_name):
    pre_filtering_rules = get_pre_filtering_rules(rules)
   
    for pcap_file in os.listdir(pcaps_path):
        start = time()
        print("Reading PCAP "+pcaps_path+pcap_file)
        pcap = rdpcap(pcaps_path+pcap_file)
        print("Time to read ", len(pcap), " packets in seconds: ", time() - start)

        print("Starting "+pcaps_path+pcap_file+" processing: ")
        suspicious_pkts = Manager().list()
        ip_pkt_count_list = Manager().list()
        tcp_tracker = Manager().dict()
        processes = []
        num_processes = cpu_count() # Use the cpu_count as the number of processes
        share = round(len(pcap)/num_processes)

        start = time()
        # for i in range(num_processes):
        #     pkts_sublist = pcap[i*share:(i+1)*share + int(i == (num_processes - 1))*-1*(num_processes*share - len(pcap))]  # Send a batch of packets for each processor
        #     process = Process(target=compare_pkts_to_rules, args=(pkts_sublist, pre_filtering_rules, suspicious_pkts, ip_pkt_count_list, tcp_tracker, i*share))
        #     process.start()
        #     processes.append(process)

        # for process in processes:
        #     process.join()

        compare_pkts_to_rules(pcap, pre_filtering_rules, suspicious_pkts, ip_pkt_count_list, tcp_tracker, 0)

        print(Counter(elem[1] for elem in suspicious_pkts))

        print("Time to process", sum(ip_pkt_count_list), "packets against ",len(rules), "rules in seconds: ", time() - start)
        print("Suspicious packets:", len(suspicious_pkts),",  IP packets:", sum(ip_pkt_count_list),", Packets:", len(pcap), "\n") # Count IP packets
        print("Finished with file: ", pcap_file)
        print("*"*50)

        save_suspicious_pkts(pre_filtering_scenario, ruleset_name ,pcap_file.split(".")[0], suspicious_pkts)

# Generates the optimal pre-filtering ruleset using most header fields and part of the payload matches
def get_pre_filtering_rules(rules):
    rules_dict = {}
    for rule in rules:
        proto = rule.pkt_header_fields["proto"]
        if proto not in rules_dict:
            rules_dict[proto] = [rule]
        else:
            rules_dict[proto].append(rule)

    rules_dict["icmp"] = rules_dict["ip"]+rules_dict["icmp"]
    rules_dict["tcp"] = rules_dict["ip"]+rules_dict["tcp"]
    rules_dict["udp"] = rules_dict["ip"]+rules_dict["udp"]
    
    return rules_dict

# Compares a list of packets with rules
def compare_pkts_to_rules(pkts, rules, suspicious_pkts, ip_pkt_count_list, tcp_tracker, start):
    pkt_count, ip_pkt_count = start, 0
    for pkt in pkts:
        if IP in pkt:
            matched = False
            if unsupported_protocol(pkt):
                suspicious_pkts.append((pkt_count, "unsupported"))
                matched = True
            elif TCP in pkt: 
                flow = pkt[IP].dst+str(pkt[TCP].dport)+pkt[IP].src+str(pkt[TCP].sport) #Invert order to match flow
                if str(pkt[TCP].flags) == "A" and flow in tcp_tracker and pkt[TCP].seq == tcp_tracker[flow]["ack"]:
                    suspicious_pkts.append((pkt_count, "tcp_ack"))
                    matched = True 
                    tcp_tracker.pop(flow)
               
            if not matched: 
                pkt_to_match = PacketToMatch(pkt, rules.keys())
                rules_to_compare = get_pkt_related_rules(pkt_to_match, rules)
                for rule in rules_to_compare:
                    try:
                        if not compare_header_fields(pkt_to_match, rule, rule.pkt_header_fields["proto"]):
                            continue

                        if not compare_payload(pkt_to_match, rule):
                            continue
                        
                        suspicious_pkts.append((pkt_count, rule.sids()[0]))
                        if TCP in pkt: # Check if I can limit to packets with payload                    
                            flow = pkt[IP].src+str(pkt[TCP].sport)+pkt[IP].dst+str(pkt[TCP].dport)
                            tcp_tracker[flow] = {"seq": pkt[TCP].seq, "ack": pkt[TCP].ack, "pkt_count": pkt_count}
                            
                    except Exception as e:
                        print("Exception")
                        print(traceback.format_exc())
                        print(pkt)
                        suspicious_pkts.append((pkt_count, "error"))
                    break
            ip_pkt_count+=1
        pkt_count+=1
    ip_pkt_count_list.append(ip_pkt_count)


ip_proto = {1:"icmp", 6:"tcp", 17:"udp"}
# Returns the rules related to the protocol and services of a packet
def get_pkt_related_rules(pkt_to_match, rules):
    pkt_proto = ip_proto.get(pkt_to_match.header["ip_proto"], "ip")
    if ((pkt_proto == "udp" and not pkt_to_match.upd_in_pkt) or 
                (pkt_proto == "tcp" and not pkt_to_match.tcp_in_pkt) or (pkt_proto == "icmp" and not pkt_to_match.icmp_in_pkt)):
        pkt_proto = "ip"
    
    service = None
    if pkt_to_match.upd_in_pkt or pkt_to_match.tcp_in_pkt:
        try:
            service = getservbyport(pkt_to_match[pkt_proto.upper()].dport, pkt_proto)
        except:
            try:
                service = getservbyport(pkt_to_match[pkt_proto.upper()].sport, pkt_proto)
            except:
                service = None

        if service == "http-alt":
            service == "http"

        if service == "http" and (HTTPRequest not in pkt_to_match or HTTPResponse not in pkt_to_match):
            service = None
        
    return rules[pkt_proto]+(rules[service] if service in rules else [])



sip_ports = {5060, 5061, 5080}
# CIP, IEC104 and S7Comm not here
def unsupported_protocol(pkt):
     if TCP in pkt or UDP in pkt:
        if GTPHeader in pkt or GTPHeader_v2 in pkt:
            return True
 
        transport_layer = pkt.getlayer(UDP) if pkt.getlayer(UDP) else pkt.getlayer(TCP)
        sport = pkt[transport_layer.name].sport
        dport = pkt[transport_layer.name].dport

        if sport == 19999 or sport == 20000 or dport == 19999 or dport == 20000: # DNP3
            return True

        if sport == 135 or dport == 135: # DCE-RPC
            return True 

        if sport in sip_ports or dport in sip_ports: # SIP
            return True 

        if sport == 651 or dport == 651: # MMS
            return True 

        if sport == 502 or sport == 802 or dport == 502 or dport == 802: # DNP3
            return True
        

def save_suspicious_pkts(pre_filtering_scenario, ruleset_name, pcap_name, suspicious_pkts):
    scenario_results_folder = "suspicious_pkts/"+pre_filtering_scenario+"/" 
    if not os.path.exists(scenario_results_folder):
        os.makedirs(scenario_results_folder)

    ruleset_output_folder = "suspicious_pkts/"+pre_filtering_scenario+"/"+ruleset_name+"/"
    if not os.path.exists(ruleset_output_folder):
        os.makedirs(ruleset_output_folder)

    suspicious_pkts_output = "suspicious_pkts/"+pre_filtering_scenario+"/"+ruleset_name+"/"+pcap_name+".txt"
    with open(suspicious_pkts_output, 'w') as file:
        for match in sorted(suspicious_pkts, key=lambda x: x[0]):
            file.write(f"{match[0]}\n")
