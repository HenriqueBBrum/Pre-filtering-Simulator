import os
import traceback
import numpy as np

from time import time
from collections import Counter
from socket import getservbyport
from multiprocessing import Process, Manager, Lock

from scapy.all import IP,UDP,TCP,DNSQR, DNS 
from scapy.utils import PcapReader 
from scapy.contrib.gtp import GTPHeader 
from scapy.contrib.gtp_v2 import GTPHeader as GTPHeader_v2 

from .header_matching import matched_ip_and_port, matched_header_fields
from .payload_matching import matched_payload
from .packet_to_match import PacketToMatch

from .analysis import compare_to_baseline

import sys
sys.path.insert(0,'../utils')
from utils.port_services import ip_proto_num_to_str, port_to_service_map, change_map

# Simulate the pre-filtering of packets based on signature rules]
def rule_based_simulation(sim_config, matches, no_content_matches, info):
    lock = Lock()
    shared_info = Manager().dict()
    comparisons_info = Manager().dict()
    jobs = []
    for pcap_file in os.listdir(sim_config["pcaps_path"]):
        if not os.path.isfile(os.path.join(sim_config["pcaps_path"], pcap_file)):
            continue

        if not pcap_file.endswith(".pcap"):
            continue

        p = Process(target=individual_pcap_simulation, args=(sim_config, pcap_file, matches, no_content_matches, shared_info, comparisons_info, lock))
        jobs.append(p)
        p.start()
       
    for proc in jobs:
        proc.join()

    info.update(shared_info)
    return info, comparisons_info

# Individual process for each pcap
def individual_pcap_simulation(sim_config, pcap_file, matches, no_content_matches, shared_info, shared_comparisons_info, lock):
    current_trace = pcap_file.split(".")[0] # Remove ".pcap" to get day
    print(current_trace)
    local_dict = {current_trace:{}}

    start = time()
    suspicious_pkts, temp_info, comparisons_info = find_suspicious_packets(sim_config, sim_config["pcaps_path"]+pcap_file, matches, no_content_matches)
    
    local_dict[current_trace]["total_time_to_process"] = time() - start
    local_dict[current_trace].update(temp_info)

    local_dict[current_trace]["pkts_fowarded"] = len(suspicious_pkts)
    local_dict[current_trace]["pkts_filtered"] = local_dict[current_trace]["pkts_processed"] - local_dict[current_trace]["pkts_fowarded"]
    local_dict[current_trace]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)
    
    lock.acquire()
    compare_to_baseline(sim_config, current_trace, suspicious_pkts, local_dict)
    lock.release()

    shared_info[current_trace] = local_dict[current_trace]
    shared_comparisons_info[current_trace] = comparisons_info

# Find the suspicious packets
def find_suspicious_packets(sim_config, pcap_filepath, matches, no_content_matches):
    suspicious_pkts = []
    pkt_count, ip_pkt_count = 0, 0
    tcp_stream_tracker = set()
    comparisons_to_header, comparisons_to_content, comparisons_to_pcre = [], [], []
    for scapy_pkt in PcapReader(pcap_filepath):
        header_check, content_checks, pcre_checks = 1, 0, 0
        if IP in scapy_pkt:
            if unsupported_protocols(scapy_pkt):
                header_check+=1
                suspicious_pkt = (pkt_count, "unsupported")
            else:
                try:
                    pkt = PacketToMatch(scapy_pkt)
                except Exception as e:
                    print("Could not parse packet properly from pcap:", pcap_filepath, ". Exception: ", traceback.format_exc())
                    suspicious_pkts.append((pkt_count, "error"))
                    continue

                matches_key = get_related_matches_key(pkt, no_content_matches.keys() if pkt.payload_size == 0 else matches.keys()) 
                suspicious_pkt = None
                if sim_config["scenario"] != "header_only" and sim_config["scenario"] != "fast_pattern" and (pkt.tcp or pkt.udp):
                    flow = pkt.header["src_ip"]+str(pkt.header["sport"])+pkt.header["dst_ip"]+str(pkt.header["dport"]) 
                    reversed_flow = pkt.header["dst_ip"]+str(pkt.header["dport"])+pkt.header["src_ip"]+str(pkt.header["sport"]) # Invert order to match flow
                    if "tls" in matches_key and ord(pkt.payload_buffers["pkt_data"][0][0]) == 0x16:
                        suspicious_pkt = (pkt_count, "tls")
                        header_check+=1
                    elif "ftp" in matches_key and ord(pkt.payload_buffers["pkt_data"][0][0]) >= 0x30:
                        suspicious_pkt = (pkt_count, "ftp") 
                        header_check+=2
                    elif DNS in scapy_pkt and scapy_pkt[DNS].opcode == 0 and scapy_pkt[DNS].ancount == 0 and DNSQR in scapy_pkt:
                        suspicious_pkt = (pkt_count, "dns")
                        header_check+=3
                    elif pkt.tcp:
                        suspicious_pkt = tcp_tracker(pkt, pkt_count, flow, reversed_flow, tcp_stream_tracker)
                        header_check+=4

                    if not suspicious_pkt:
                        header_check+=4
            
                if not suspicious_pkt: 
                    final_matches = no_content_matches[matches_key] if pkt.payload_size == 0 else matches[matches_key]                
                    suspicious_pkt, ch, content_checks, pcre_checks = is_packet_suspicious(pkt, pkt_count, final_matches, tcp_stream_tracker, sim_config["scenario"])
                    header_check+=ch

            if suspicious_pkt:
                suspicious_pkts.append(suspicious_pkt)

            ip_pkt_count+=1
            
        comparisons_to_header.append(header_check)
        comparisons_to_content.append(content_checks)
        comparisons_to_pcre.append(pcre_checks)  
            
        pkt_count+=1

    info = {}
    info["pcap_size"] = pkt_count
    info["pkts_processed"] = ip_pkt_count

    comparisons_info = {}
    comparisons_info["num_header_compared_to"] = np.array(comparisons_to_header)
    comparisons_info["num_contents_compared_to"] = np.array(comparisons_to_content)
    comparisons_info["num_pcre_compared_to"] = np.array(comparisons_to_pcre)

    return suspicious_pkts, info, comparisons_info

# DNP3, MMS, SMB
unsupported_protocols_port = {135, 139, 445, 502, 651, 802, 3020, 5060, 5061, 5080, 19999, 20000}
# CIP, IEC104 and S7Comm not here
def unsupported_protocols(pkt):
    if TCP in pkt or UDP in pkt:
        if GTPHeader in pkt or GTPHeader_v2 in pkt:
            return True

        transport_layer = pkt.getlayer(UDP) if pkt.getlayer(UDP) else pkt.getlayer(TCP)
        sport = pkt[transport_layer.name].sport
        dport = pkt[transport_layer.name].dport

        if sport in unsupported_protocols_port or dport in unsupported_protocols_port:
            return True

# Returns the key indicating the transport layer protocol and (if there is) the application layer service
#  to reduce the number of rules this packet is compared to
def get_related_matches_key(pkt, matches_keys):
    proto = pkt.header["ip_proto"]
    pkt_proto = ip_proto_num_to_str[proto] if proto in ip_proto_num_to_str else proto
    applayer_proto =  None
    if pkt.tcp or pkt.udp:
        applayer_proto = get_applayer_proto(pkt, pkt_proto)

    key = "ip"
    if pkt_proto in matches_keys:
        key = pkt_proto
        if applayer_proto and key+"_"+applayer_proto in matches_keys:
            key+="_"+applayer_proto

    return key

# Returns the applayer proto if it is a valid one and the payload for the layer4 protocol is more than 0
def get_applayer_proto(pkt, proto_str):
    applayer_proto = None
    try:
        applayer_proto = getservbyport(pkt.header["dport"], proto_str)
    except Exception as e:
        try:
            applayer_proto = getservbyport(pkt.header["sport"], proto_str)
        except  Exception as e:
            pass

    # Check if port is related to some app that getservbyport does not know. Use the NIDS configuration as well     
    if not applayer_proto:
        applayer_proto = port_to_service_map.get(pkt.header["dport"])

    if not applayer_proto:
        applayer_proto = port_to_service_map.get(pkt.header["sport"])

    if applayer_proto:
        if pkt.payload_size == 0:
            applayer_proto = proto_str
            
        if applayer_proto in change_map: # getservbyport and Snort and Suricata have different ideas on the app layer proto for the same port
            applayer_proto = change_map[applayer_proto]

        if applayer_proto == "http" and not (pkt.http_res or pkt.http_req):
            applayer_proto = proto_str
            
    return applayer_proto 


# Check Snort and Suricata flow requirements
def tcp_tracker(pkt, pkt_count, flow, reversed_flow, tcp_stream_tracker):
    if pkt.header["flags"] & 2 == 2: # SYN in flags
        return (pkt_count, "syn")
    elif "R" in pkt.header["flags"]:
        return (pkt_count, "reset")
    elif "F" in pkt.header["flags"]:
        remove_flow(flow, reversed_flow, tcp_stream_tracker)
        return (pkt_count, "fin")
    
    stream_tcp = False    
    if (flow in tcp_stream_tracker or reversed_flow in tcp_stream_tracker) and (pkt.header["flags"] == 16 or pkt.header["flags"] & 24 == 24):
        stream_tcp = True
        remove_flow(flow, reversed_flow, tcp_stream_tracker)

    if stream_tcp:
        return (pkt_count, "stream_tcp")
    
    return None

def remove_flow(flow, reversed_flow, tcp_stream_tracker):
    if flow in tcp_stream_tracker:
        tcp_stream_tracker.remove(flow)
    elif reversed_flow in tcp_stream_tracker:
        tcp_stream_tracker.remove(reversed_flow)

# Compare a packet against the related rules depeding on the packets transport protocol and app layer service
def is_packet_suspicious(pkt, pkt_count, matches, tcp_stream_tracker, scenario):
    comparisons_to_header, comparisons_to_content, comparisons_to_pcre = 0, 0, 0
    for header_group in matches:
        try:
            comparisons_to_header+=1
            if not matched_ip_and_port(pkt, matches[header_group][0]): 
                continue

            # Matched the groups' ip and port header, compare with the other fields of each rule in this group
            for match in matches[header_group]:
                if match.max_content_size > pkt.payload_size: # All further matches have at least the same max_content_size as the current match
                    break
                
                comparisons_to_header+=1
                if not matched_header_fields(pkt, match):
                    continue                    

                if scenario != "header_only":
                    matched, compared_to_content, compared_to_pcre = matched_payload(pkt, match)
                    comparisons_to_content+=compared_to_content
                    comparisons_to_pcre+=compared_to_pcre
                    if not matched:
                        continue
                    
                    if scenario != "fast_pattern" and pkt.tcp:
                        flow = pkt.header["src_ip"]+str(pkt.header["sport"])+pkt.header["dst_ip"]+str(pkt.header["dport"])
                        if (pkt.header["flags"] == 16 or pkt.header["flags"] & 24 == 24):
                            tcp_stream_tracker.add(flow) 

                return (pkt_count, match.sids()[0]), comparisons_to_header, comparisons_to_content, comparisons_to_pcre
        except Exception as e:
            print("Exception: ", traceback.format_exc())
            return (pkt_count, "error"), comparisons_to_header, comparisons_to_content, comparisons_to_pcre

    return None, comparisons_to_header, comparisons_to_content, comparisons_to_pcre