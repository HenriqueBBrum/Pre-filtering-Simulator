from scapy.all import IP,UDP,TCP 
from scapy.utils import rdpcap, PcapReader, PcapWriter 
from scapy.contrib.gtp import GTPHeader 
from scapy.contrib.gtp_v2 import GTPHeader as GTPHeader_v2 

from multiprocessing import Manager,Process,cpu_count
from collections import Counter

from socket import getservbyport
import os
from time import time
import traceback
import json
import subprocess

from .header_matching import matched_ip_and_port, matched_header_fields
from .payload_matching import matched_payload
from .packet_to_match import PacketToMatch

import sys
#sys.tracebacklimit = 0
sys.path.append("..")
from utils.ports import SIP_PORTS,SMB_PORTS

# Flow sampling simulation to compare againast our pre-filtering proposal. time_threshold in seconds
def flow_sampling_simulation(sim_config, output_folder):
    info = {"type": "flow_sampling"}

    pcaps_path = sim_config["pcaps_path"]
    for pcap_file in os.listdir(pcaps_path):
        current_trace = pcap_file.split(".")[0] # Remove .pcap to get day
        info[current_trace] = {}
    
        start = time()
        suspicious_pkts, temp_info = sample_flows(pcaps_path+pcap_file, sim_config["flow_count_threshold"], sim_config["time_threshold"])

        info[current_trace]["total_time_to_process"] = time() - start
        info[current_trace].update(temp_info)
        
        info[current_trace]["number_of_suspicious_pkts"] = len(suspicious_pkts)
        info[current_trace]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)

        info = compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info)
    return info

# Run the flow sampling method over the packets in the PCAP
def sample_flows(pcap_file, flow_count_threshold, time_threshold):
    pkt_count, ip_pkt_count = 0, 0
    suspicious_pkts = []
    time_to_process = []
    flow_tracker = {} # One entry is (current_count, last_pkt_time)

    for pkt in PcapReader(pcap_file):
        if IP in pkt:
            start = time()
            proto = str(pkt[IP].proto)
            if TCP in pkt:
                five_tuple = proto+pkt[IP].src+str(pkt[TCP].sport)+pkt[IP].dst+str(pkt[TCP].dport) # Bidirectional flows?
            elif UDP in pkt:
                five_tuple = proto+pkt[IP].src+str(pkt[UDP].sport)+pkt[IP].dst+str(pkt[UDP].dport)
            else:
                five_tuple = proto+pkt[IP].src+pkt[IP].dst

            if five_tuple not in flow_tracker:
                flow_tracker[five_tuple] = (1, pkt.time)
                suspicious_pkts.append((pkt_count, "first_time"))
            else:
                last_pkt_time = flow_tracker[five_tuple][1]
                if pkt.time-last_pkt_time >= time_threshold:
                    flow_tracker[five_tuple] = (1, pkt.time)
                    suspicious_pkts.append((pkt_count, "time_reset"))
                else:
                    flow_tracker[five_tuple] = (flow_tracker[five_tuple][0]+1, pkt.time)
                    if flow_tracker[five_tuple][0] < flow_count_threshold:
                        suspicious_pkts.append((pkt_count, "within_flow_threhold"))

            ip_pkt_count+=1
            time_to_process.append(time()-start)
        pkt_count+=1

    info = {}

    info["pcap_size"] = pkt_count
    info["avg_pkt_processing_time"] = sum(time_to_process)/len(time_to_process)
    info["pkts_processed"] = ip_pkt_count
    info["number_of_flows"] = len(flow_tracker.keys())
    info["top_five_biggest_flows"] = [x[0] for x in sorted(list(flow_tracker.values()), key=lambda x: x[0], reverse=True)[:5]]
    return suspicious_pkts, info



# Simulate the pre-filtering of packets based on signature rules]
def pre_filtering_simulation(sim_config, rules, rules_info, output_folder):
    info = rules_info | {"type": "pre_filtering"}
    pcaps_path = sim_config["pcaps_path"]

    for pcap_file in os.listdir(pcaps_path):
        # if "Wednesday" not in pcap_file:
        #     continue
        
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

    if flow in tcp_tracker or reversed_flow in tcp_tracker:
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




def compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info): 
    baseline_pcap = sim_config["pcaps_path"]+current_trace+".pcap"

    suspicious_pkts_pcap = get_suspicious_pkts_pcap(baseline_pcap, suspicious_pkts, output_folder, current_trace)
    suspicious_pkts_alert_file, snort_processing_time = snort_with_suspicious_pcap(suspicious_pkts_pcap, sim_config["snort_config_file"], sim_config["ruleset_path"], output_folder, current_trace)
    info[current_trace]["snort_processing_time"] = snort_processing_time

    baseline_pkt_alerts, baseline_flow_alerts = parse_alerts(sim_config["baseline_alerts_path"]+current_trace+".txt") # Baseline alerts
    experiment_pkt_alerts, experiment_flow_alerts = parse_alerts(suspicious_pkts_alert_file)

    # Alert metrics for individual packets
    info[current_trace]["baseline_pkt_alerts"] = len(baseline_pkt_alerts)
    info[current_trace]["experiment_pkt_alerts"] =  len(experiment_pkt_alerts)
    info[current_trace]["pkt_alerts_true_positive"] = len(set(baseline_pkt_alerts) & set(experiment_pkt_alerts))
    info[current_trace]["pkt_alerts_false_negative"] = len(set(baseline_pkt_alerts) - set(experiment_pkt_alerts))
    info[current_trace]["pkt_alerts_false_positive"] = len(set(experiment_pkt_alerts) - set(baseline_pkt_alerts))

    # Alert metrics for flows
    info[current_trace]["baseline_flow_alerts"] = len(baseline_flow_alerts)
    info[current_trace]["experiment_flow_alerts"] =  len(experiment_flow_alerts)
    info[current_trace]["flow_alerts_true_positive"] = len(set(baseline_flow_alerts) & set(experiment_flow_alerts))
    info[current_trace]["flow_alerts_false_negative"] = len(set(baseline_flow_alerts) - set(experiment_flow_alerts))
    info[current_trace]["flow_alerts_false_positive"] = len(set(experiment_flow_alerts) - set(baseline_flow_alerts))

    # counter = {}
    # for key in set(baseline_pkt_alerts.keys()) - set(experiment_pkt_alerts.keys()):
    #     print(key, baseline_pkt_alerts[key]["rule"], baseline_pkt_alerts[key]["proto"], baseline_pkt_alerts[key]["src_ap"], baseline_pkt_alerts[key]["dst_ap"])
    #     if baseline_pkt_alerts[key]["rule"] in counter:
    #         counter[baseline_pkt_alerts[key]["rule"]]+=1
    #     else:
    #         counter[baseline_pkt_alerts[key]["rule"]]=1

    # print("\n\n")
    # print(counter)

    # counter = {}
    # for key in set(experiment_pkt_alerts.keys()) - set(baseline_pkt_alerts.keys()):
    #     print(key, experiment_pkt_alerts[key]["rule"], experiment_pkt_alerts[key]["proto"], experiment_pkt_alerts[key]["src_ap"], experiment_pkt_alerts[key]["dst_ap"])
    #     if experiment_pkt_alerts[key]["rule"] in counter:
    #         counter[experiment_pkt_alerts[key]["rule"]]+=1
    #     else:
    #         counter[experiment_pkt_alerts[key]["rule"]]=1

    # print("\n\n")
    # print(counter)

    #os.remove(suspicious_pkts_pcap)
    return info

# Generate a PCAP with the suspicious pkts to find the alerts
def get_suspicious_pkts_pcap(baseline_pcap, suspicious_pkts, output_folder, file_name):
    suspicious_pkts_pcap = output_folder+file_name+".pcap"
    pcap_writer = PcapWriter(suspicious_pkts_pcap)
    sorted_suspicious_pkts = sorted(suspicious_pkts, key=lambda x: x[0])

    pkt_count = 0
    suspicious_pkts_list_count = 0
    for packet in PcapReader(baseline_pcap):
        if suspicious_pkts_list_count == len(sorted_suspicious_pkts):
            break

        if pkt_count == sorted_suspicious_pkts[suspicious_pkts_list_count][0]:
            pcap_writer.write(packet)
            pcap_writer.flush()
            suspicious_pkts_list_count+=1

        pkt_count+=1
    return suspicious_pkts_pcap

# Run snort with the new suspicious pkts pcap
def snort_with_suspicious_pcap(suspicious_pkts_pcap, snort_config_path, ruleset_path,  output_folder, file_name):
    start = time()
    subprocess.run(["snort", "-c", snort_config_path, "--rule-path",ruleset_path, "-r",suspicious_pkts_pcap, "-l",output_folder, \
                    "-A","alert_json",  "--lua","alert_json = {file = true}"], stdout=subprocess.DEVNULL)
    
    snort_processing_time = time() - start
    new_filepath = output_folder+file_name+".txt"
    os.rename(output_folder+"alert_json.txt", new_filepath)
    return new_filepath, snort_processing_time

# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_alerts(alerts_filepath):
    pkt_alerts = {}
    flow_alerts = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            parsed_line = json.loads(line)

            pkt_key = parsed_line["timestamp"] # + "_" + parsed_line["rule"]                
            if pkt_key not in pkt_alerts:
               pkt_alerts[pkt_key] = parsed_line

            flow_key = parsed_line["proto"] + "_" + parsed_line["src_ap"] + "_" + parsed_line["dst_ap"]
            if flow_key not in flow_alerts:
               flow_alerts[flow_key] = parsed_line
               
    return pkt_alerts, flow_alerts
