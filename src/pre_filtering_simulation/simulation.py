from scapy.all import IP,UDP,TCP 
from scapy.layers.http import HTTPRequest,HTTPResponse 
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


from .header_matching import compare_header_fields
from .payload_matching import compare_payload
from .packet_to_match import PacketToMatch

# Flow sampling simulation to compare againast our pre-filtering proposal. time_threshold in seconds
def flow_sampling_simulation(sim_config, sim_results_folder):
    info = {"type": "flow_sampling"}

    output_folder = sim_results_folder+"flow_sampling_"+str(sim_config["flow_count_threshold"])+"_"+str(sim_config["time_threshold"])+"/"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    pcaps_path = sim_config["baseline_path"]+"pcaps/"
    for pcap_file in os.listdir(pcaps_path):
        current_trace = pcap_file.split(".")[0] # Remove .pcap to get day
        info[current_trace] = {}
        start = time()
        pcap = rdpcap(pcaps_path+pcap_file)
        info[current_trace]["pcap_size"] = len(pcap)
        info[current_trace]["time_to_read"] = time() - start

        start = time()

        ip_pkt_count, suspicious_pkts, flow_tracker = sample_flows(pcap, sim_config["flow_count_threshold"], sim_config["time_threshold"])

        info[current_trace]["time_to_process"] = time() - start
        info[current_trace]["pkts_processed"] = ip_pkt_count
        info[current_trace]["number_of_flows"] = len(flow_tracker.keys())
        info[current_trace]["top_five_biggest_flows"] = [x[0] for x in sorted(list(flow_tracker.values()), key=lambda x: x[0], reverse=True)[:5]]
        info[current_trace]["number_of_suspicious_pkts"] = len(suspicious_pkts)
        info[current_trace]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)

        info = compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info)

    with open(output_folder + "analysis.txt", 'w') as f:
        json.dump(info , f, ensure_ascii=False, indent=4)

# Run the flow sampling method over the packets in the PCAP
def sample_flows(pcap, flow_count_threshold, time_threshold):
    pkt_count, ip_pkt_count = 0, 0
    suspicious_pkts = []
    flow_tracker = {} # One entry is (current_count, last_pkt_time)

    for pkt in pcap:
        if IP in pkt:
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
                current_pkt_time = pkt.time
                last_pkt_time = flow_tracker[five_tuple][1]
                if current_pkt_time-last_pkt_time >= time_threshold:
                    flow_tracker[five_tuple] = (1, pkt.time)
                    suspicious_pkts.append((pkt_count, "time_reset"))
                else:
                    flow_tracker[five_tuple] = (flow_tracker[five_tuple][0]+1, pkt.time)
                    if flow_tracker[five_tuple][0] < flow_count_threshold:
                        suspicious_pkts.append((pkt_count, "within_flow_threhold"))

            ip_pkt_count+=1
        pkt_count+=1

    return ip_pkt_count, suspicious_pkts, flow_tracker




# Simulate the pre-filtering of packets based on signature rules]
def pre_filtering_simulation(sim_config, rules, rules_info, sim_results_folder):
    pre_filtering_rules = get_pre_filtering_rules(rules)

    info = rules_info | {"type": "pre_filtering"}
    output_folder = sim_results_folder+"pre_filtering_"+sim_config["scenario"]+"_"+sim_config["ruleset_name"]+"/"
    pcaps_path = sim_config["baseline_path"]+"pcaps/"
    for pcap_file in os.listdir(pcaps_path):
        file_name = pcap_file.split(".")[0] # Remove .pcap to get day
        info[pcap_file] = {"number_of_rules": len(rules)}
        start = time()
        pcap = rdpcap(pcaps_path+pcap_file)
        info[pcap_file]["pcap_size"] = len(pcap)
        info[pcap_file]["time_to_read"] = time() - start

        suspicious_pkts, ip_pkt_count_list = Manager().list(), Manager().list() 
        tcp_tracker = Manager().dict()
        processes = []
        num_processes = cpu_count() # Use the cpu_count as the number of processes
        share = round(len(pcap)/num_processes)

        start = time()
        for i in range(num_processes):
            pkts_sublist = pcap[i*share:(i+1)*share + int(i == (num_processes - 1))*-1*(num_processes*share - len(pcap))]  # Send a batch of packets for each processor
            process = Process(target=compare_pkts_to_rules, args=(pkts_sublist, pre_filtering_rules, suspicious_pkts, ip_pkt_count_list, tcp_tracker, i*share))
            process.start()
            processes.append(process)

        for process in processes:
            process.join()

        # compare_pkts_to_rules(pcap, pre_filtering_rules, suspicious_pkts, ip_pkt_count_list, tcp_tracker, 0)
        info[pcap_file]["time_to_process"] = time() - start
        info[pcap_file]["pkts_processed"] = sum(ip_pkt_count_list)
        info[pcap_file]["number_of_suspicious_pkts"] = len(suspicious_pkts)
        info[pcap_file]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)

        info = compare_to_baseline(sim_config, suspicious_pkts, file_name, output_folder, info)

    with open(output_folder + "analysis.txt", 'w') as f:
        json.dump(info , f, ensure_ascii=False, indent=4)

   
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
                if str(pkt[TCP].flags) == "A" and flow in tcp_tracker:
                    if pkt[TCP].seq == tcp_tracker[flow]["ack"]:
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
                        if TCP in pkt:                  
                            flow = pkt[IP].src+str(pkt[TCP].sport)+pkt[IP].dst+str(pkt[TCP].dport)
                            tcp_tracker[flow] = {"seq": pkt[TCP].seq, "ack": pkt[TCP].ack, "pkt_count": pkt_count}        
                    except Exception as e:
                        print("Exception: ", traceback.format_exc())
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


# Add NetBIOS and SMB
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

def compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info): 
    baseline_pcap = sim_config["baseline_path"]+"pcaps/"+current_trace+".pcap"
    print(baseline_pcap)
    suspicious_pkts_pcap = get_suspicious_pkts_pcap(baseline_pcap, suspicious_pkts, output_folder, current_trace)
    suspicious_pkts_alert_file = snort_with_suspicious_pcap(suspicious_pkts_pcap, sim_config["snort_config_file"], sim_config["ruleset_path"], output_folder, current_trace)

    original_pcap_alerts = parse_alerts(sim_config["baseline_path"]+"alerts_registered/"+current_trace+".txt") # Baseline alerts
    reduced_pcap_alerts = parse_alerts(suspicious_pkts_alert_file)

    info[current_trace]["baseline_alerts"] = len(original_pcap_alerts)
    info[current_trace]["suspicious_pkts_alerts"] =  len(reduced_pcap_alerts)
    info[current_trace]["alerts_true_positive"] = len(set(original_pcap_alerts.keys()) & set(reduced_pcap_alerts.keys()))
    info[current_trace]["alerts_false_negative"] = len(set(original_pcap_alerts.keys()) - set(reduced_pcap_alerts.keys()))
    info[current_trace]["alerts_false_positive"] = len(set(reduced_pcap_alerts.keys()) - set(original_pcap_alerts.keys()))
    # counter = {}
    # for key in set(original_pcap_alerts.keys()) - set(reduced_pcap_alerts.keys()):
    #     timestamp_sid = key.split("_")
    #     print(timestamp_sid[0], timestamp_sid[1], original_pcap_alerts[key]["proto"], original_pcap_alerts[key]["pkt_gen"])
    #     if timestamp_sid[1] in counter:
    #         counter[timestamp_sid[1]]+=1
    #     else:
    #         counter[timestamp_sid[1]]=1

    # print("\n\n")
    # print(counter)

    os.remove(suspicious_pkts_pcap)
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
    subprocess.run(["snort", "-c", snort_config_path, "--rule-path",ruleset_path, "-r",suspicious_pkts_pcap, "-l",output_folder, \
                    "-A","alert_json",  "--lua","alert_json = {file = true}"], stdout=subprocess.DEVNULL)
    
    new_filepath = output_folder+file_name+".txt"
    os.rename(output_folder+"alert_json.txt", new_filepath)
    return new_filepath

# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_alerts(alerts_filepath):
    alerted_pkts = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            parsed_line = json.loads(line)
            key = parsed_line["timestamp"] + "_" + parsed_line["rule"]
            if key not in alerted_pkts:
               alerted_pkts[key] = parsed_line
               
    return alerted_pkts
