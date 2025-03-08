import os
import json
import traceback
from time import time
from collections import Counter
from socket import getservbyport


from scapy.all import IP,UDP,TCP 
from scapy.utils import PcapReader 
from scapy.contrib.gtp import GTPHeader 
from scapy.contrib.gtp_v2 import GTPHeader as GTPHeader_v2 

from .header_matching import matched_ip_and_port, matched_header_fields
from .payload_matching import matched_payload
from .packet_to_match import PacketToMatch

from .analysis import compare_to_baseline

import sys
sys.path.append("..")
from utils.ports import SIP_PORTS,SMB_PORTS



# Simulate the pre-filtering of packets based on signature rules]
def pre_filtering_simulation(sim_config, rules, rules_info, output_folder):
    info = rules_info | {"type": "pre_filtering"}
    pcaps_path = sim_config["pcaps_path"]

    for pcap_file in os.listdir(pcaps_path):
        current_trace = pcap_file.split(".")[0] # Remove ".pcap" to get day
        print(current_trace)
        info[current_trace] = {}

        start = time()
        suspicious_pkts, temp_info = find_suspicious_packets(pcaps_path+pcap_file, rules)
      
        info[current_trace]["total_time_to_process"] = time() - start
        info[current_trace].update(temp_info)

        info[current_trace]["number_of_suspicious_pkts"] = len(suspicious_pkts)
        info[current_trace]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)
        info = compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info)
        print(json.dump(info , sys.stdout, ensure_ascii=False, indent=4))
    return info

# Find the suspicious packets
def find_suspicious_packets(pcap_file, rules):
    suspicious_pkts = []
    time_to_process = []
    tcp_tracker = {}
    ftp_tracker = set()
    pkt_count, ip_pkt_count = 0, 0
    for pkt in PcapReader(pcap_file):
        if IP in pkt:
            start = time()
           
            suspicious_pkt, tcp_tracker, ftp_tracker = is_packet_suspicious(pkt, pkt_count, rules, tcp_tracker, ftp_tracker)
            if suspicious_pkt:
                suspicious_pkts.append(suspicious_pkt)

            ip_pkt_count+=1
            time_to_process.append(time()-start)
        pkt_count+=1

    info = {}

    info["pcap_size"] = pkt_count
    info["avg_pkt_processing_time"] = sum(time_to_process)/len(time_to_process)
    info["pkts_processed"] = ip_pkt_count
    
    return suspicious_pkts, info


# Checks if a packet is suspicous, unsupported or is in a tcp stream
def is_packet_suspicious(pkt, pkt_count, rules, tcp_tracker, ftp_tracker):
    suspicious_pkt = None
    if unsupported_protocols(pkt):
        suspicious_pkt = (pkt_count, "unsupported")
    else:
        pkt_to_match = PacketToMatch(pkt)
        protocol, rules_to_compare = get_pkt_related_rules(pkt_to_match, rules)
        for header_group in rules_to_compare:
            if suspicious_pkt:
                break
            try:
                if not matched_ip_and_port(pkt_to_match, rules_to_compare[header_group][0]): 
                    continue
            
                # Matched the groups' ip and port header, compare with the other fields of each rule in this group
                for rule in rules_to_compare[header_group]:
                    if not matched_header_fields(pkt_to_match, rule):
                        continue

                    if not matched_payload(pkt_to_match, rule):
                        continue
                    
                    suspicious_pkt = (pkt_count, rule.sids()[0])
                    if TCP in pkt:
                        flow = pkt_to_match.header["src_ip"]+str(pkt_to_match.header["sport"])+pkt_to_match.header["dst_ip"]+str(pkt_to_match.header["dport"])
                        if pkt_to_match.header["flags"] == "A":
                            tcp_tracker[flow] = {"seq": pkt_to_match.header["seq"], "ack": pkt_to_match.header["ack"]}    
                        elif pkt_to_match.header["flags"] == "PA":
                            tcp_tracker[flow] = {"seq": pkt_to_match.header["seq"]+pkt_to_match.payload_size, "ack": pkt_to_match.header["ack"]}   

                    break
            except Exception as e:
                print("Exception: ", traceback.format_exc())
                suspicious_pkt = (pkt_count, "error")

            if not suspicious_pkt and pkt_to_match.tcp_in_pkt: 
                if "ftp" not in protocol:  
                    suspicious_pkt, tcp_tracker = check_stream_tcp(pkt_to_match, tcp_tracker, pkt_count)
                else:
                    flow = pkt_to_match.header["src_ip"]+str(pkt_to_match.header["sport"])+pkt_to_match.header["dst_ip"]+str(pkt_to_match.header["dport"])
                    if "ftp" in protocol and flow not in ftp_tracker and "pass " in pkt_to_match.payload_buffers["nocase"]["pkt_data"]:
                        suspicious_pkt = (pkt_count, "ftp")
                        ftp_tracker.add(flow)
    
    return suspicious_pkt, tcp_tracker, ftp_tracker

# CIP, IEC104 and S7Comm not here
def unsupported_protocols(pkt):
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

        if sport == 651 or dport == 651: # MMS
            return True 

        if sport == 502 or sport == 802 or dport == 502 or dport == 802: # DNP3
            return True
        
        if sport in SIP_PORTS or dport in SIP_PORTS: # SIP
            return True 
        
        if sport in SMB_PORTS or dport in SMB_PORTS: #SMB
            return True

ip_proto = {1:"icmp", 6:"tcp", 17:"udp"}
# Returns the rules related to the protocol and services of a packet
def get_pkt_related_rules(pkt, rules):
    pkt_proto = ip_proto.get(pkt.header["ip_proto"], "ip")
    if ((pkt_proto == "udp" and not pkt.udp_in_pkt) or 
                (pkt_proto == "tcp" and not pkt.tcp_in_pkt) or (pkt_proto == "icmp" and not pkt.icmp_in_pkt)):
        pkt_proto = "ip"
    
    service = None
    if pkt.udp_in_pkt or pkt.tcp_in_pkt:
        service = get_service(pkt, pkt_proto, rules.keys(), "dport", True) # Get service based on dport
      
    if service in rules:
        pkt_proto = service

    return pkt_proto, rules[pkt_proto]

def get_service(pkt, transport_proto, rules_services, port, check_src):
    service = None
    try:
        service = getservbyport(pkt.header[port], transport_proto)
    except:
        service = None

    change_map = {"http-alt": "http", "microsoft-ds": "netbios-ssn", "domain": "dns", "mdns":"dns", "https": None}
    if service:
        if service in change_map:
            service = change_map[service]
            
        if service == "http" and not (pkt.http_res_in_pkt or pkt.http_req_in_pkt):
            service = None

        if not service:
            return service
        
        service = transport_proto+"_"+service
        if check_src and service not in rules_services: 
            service = get_service(pkt, transport_proto, rules_services, "sport", False)
    
    if check_src and not service:
        service = get_service(pkt, transport_proto, rules_services, "sport", False)
 
    return service

def check_stream_tcp(pkt_to_match, tcp_tracker, pkt_count):
    suspicious_pkt = None
    flow = pkt_to_match.header["src_ip"]+str(pkt_to_match.header["sport"])+pkt_to_match.header["dst_ip"]+str(pkt_to_match.header["dport"])
    reversed_flow = pkt_to_match.header["dst_ip"]+str(pkt_to_match.header["dport"])+pkt_to_match.header["src_ip"]+str(pkt_to_match.header["sport"]) #Invert order to match flow

    stream_tcp = False
    if flow in tcp_tracker and pkt_to_match.header["flags"] == "A" and pkt_to_match.header["seq"] == tcp_tracker[flow]["seq"]:
        stream_tcp = True
    elif flow in tcp_tracker and "PA" in pkt_to_match.header["flags"] and pkt_to_match.header["ack"] == tcp_tracker[flow]["ack"]:
        stream_tcp = True
    elif reversed_flow in tcp_tracker and pkt_to_match.header["flags"]  == "A" and pkt_to_match.header["seq"] == tcp_tracker[reversed_flow]["ack"]:
        stream_tcp = True
    elif reversed_flow in tcp_tracker and "PA" in pkt_to_match.header["flags"] and pkt_to_match.header["ack"] == tcp_tracker[reversed_flow]["seq"]:
        stream_tcp = True

    if "R" in pkt_to_match.header["flags"]:
        stream_tcp = True
    elif "F" in pkt_to_match.header["flags"] :
        stream_tcp = True
        tcp_tracker = remove_flow(tcp_tracker, flow, reversed_flow)

    if stream_tcp:
        suspicious_pkt = (pkt_count, "stream_tcp")
    else:
        tcp_tracker = remove_flow(tcp_tracker, flow, reversed_flow)

    return suspicious_pkt, tcp_tracker

def remove_flow(tcp_tracker, flow, reversed_flow):
    if flow in tcp_tracker:
        tcp_tracker.pop(flow)
    elif reversed_flow in tcp_tracker:
        tcp_tracker.pop(reversed_flow)

    return tcp_tracker
