import os
from time import time
from collections import Counter

from scapy.all import IP,UDP,TCP 
from scapy.utils import PcapReader 

from multiprocessing import Process, Manager, Lock

from .analysis import compare_to_baseline


# Packet sampling simulation to compare against the pre-filtering proposal. time_threshold in seconds
def packet_sampling_simulation(sim_config, n, t, info):
    lock = Lock()
    shared_info = Manager().dict()
    jobs = []
    for pcap_file in os.listdir(sim_config["pcaps_path"]):
        if not os.path.isfile(os.path.join(sim_config["pcaps_path"], pcap_file)):
            continue

        if not pcap_file.endswith(".pcap"):
            continue
        
        p = Process(target=individual_pcap_simulation, args=(sim_config, pcap_file, n, t, shared_info, lock))
        jobs.append(p)
        p.start()
       
    for proc in jobs:
        proc.join()

    info.update(shared_info)
    return info

# Individual process for each pcap
def individual_pcap_simulation(sim_config, pcap_file, n, t, shared_info, lock):
    current_trace = pcap_file.split(".")[0] # Remove ".pcap" to get day
    print(current_trace)
    local_dict = {current_trace:{}}

    start = time()
    suspicious_pkts, temp_info = sample_flows(sim_config["pcaps_path"]+pcap_file, n, t)
    
    local_dict[current_trace]["total_time_to_process"] = time() - start
    local_dict[current_trace].update(temp_info)

    local_dict[current_trace]["pkts_fowarded"] = len(suspicious_pkts)
    local_dict[current_trace]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)
    
    lock.acquire()
    compare_to_baseline(sim_config, current_trace, suspicious_pkts, local_dict)
    lock.release()

    shared_info[current_trace] = local_dict[current_trace]  
# Run the packet sampling method over the packets in the PCAP
def sample_flows(pcap_filepath, flow_count_threshold, time_threshold):
    pkt_count, ip_pkt_count = 0, 0
    suspicious_pkts = []
    time_to_process = []
    flow_tracker = {} # One entry is (current_count, last_pkt_time)

    for pkt in PcapReader(pcap_filepath):
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
