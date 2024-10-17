from scapy.all import *
from multiprocessing import Manager,Process,cpu_count
from scapy.layers.http import * 
from scapy.utils import PcapWriter
from socket import getservbyport

from header_matching import compare_header_fields
from payload_matching import compare_payload

def pre_filtering_simulation(rules, n=100000):
    # Find the optimal pre-filtering subset   
    #pre_filtering_rules = optimal_pre_filtering_rules()
    rules_dict = {}
    for rule in rules:
        proto = rule.pkt_header["proto"]
        if proto not in rules_dict:
            rules_dict[proto] = [rule]
        else:
            rules_dict[proto].append(rule)

    rules_dict["icmp"] = rules_dict["icmp"]+rules_dict["ip"]
    rules_dict["tcp"] = rules_dict["tcp"]+rules_dict["ip"]
    rules_dict["udp"] = rules_dict["udp"]+rules_dict["ip"]

    start = time.time()
    pcap = rdpcap("/home/hbeckerbrum/NFSDatasets/CICIDS2017/Friday-WorkingHours.pcap", n)
    print("Time to read ", n, " packets in seconds: ", time.time() - start)
    suspicious_pkts = Manager().list()
    ip_pkt_count_list = Manager().list()
    processes = []

    start = time.time()
    num_processes = cpu_count() # Use the cout_count as the number of processes
    share = round(len(pcap)/num_processes)
    for i in range(num_processes):
        pkts_sublist = pcap[i*share:(i+1)*share + int(i == (num_processes - 1))*-1*(num_processes*share - len(pcap))]  # Send a batch of packets for each processor
        process = Process(target=compare_pkts, args=(pkts_sublist, rules_dict, suspicious_pkts, ip_pkt_count_list, i*share))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()


    # compare_pkts(pcap, rules_dict, suspicious_pkts, ip_pkt_count_list,0)

    print("Time to process", n, "packets against ",len(rules), "rules in seconds: ", time.time() - start)
    print(len(suspicious_pkts), sum(ip_pkt_count_list), n) # Count IP packets
    send_pkts_to_NIDS(pcap, suspicious_pkts)


# Generates the optimal pre-filtering ruleset using most header fields and part of the payload matches
def optimal_pre_filtering_rules():
    # get_header_and_payload_fields()

    # select_optimal_payload_config()

    return []


ip_proto = {1:"icmp", 6:"tcp", 17:"udp"}

# Compares a list of packets with rules
def compare_pkts(pkts, rules_dict, suspicious_pkts, ip_pkt_count_list, start):
    pkt_id, ip_pkt_count = start, 0
    match_count = 0
    for pkt in pkts:
        if IP in pkt:
            pkt_proto = ip_proto.get(pkt[IP].proto, "ip")
            service = None
            if UDP in pkt or TCP in pkt:
                try:
                    service = getservbyport(pkt[pkt_proto.upper()].dport, pkt_proto)
                except:
                    try:
                        service = getservbyport(pkt[pkt_proto.upper()].sport, pkt_proto)
                    except:
                        service = None

                if service == "http-alt":
                    service == "http"
                
            final_rules = rules_dict[pkt_proto]+(rules_dict[service] if service in rules_dict.keys() else [])
            for i, rule in enumerate(final_rules):
                if not compare_header_fields(pkt, rule, rule.pkt_header["proto"]):
                    continue

                if not compare_payload(pkt, rule, rule.pkt_header["proto"]):
                    continue

                suspicious_pkts.append((pkt_id, rule))
                break 
            ip_pkt_count+=1
        pkt_id+=1
    ip_pkt_count_list.append(ip_pkt_count)


    
# Sends the remaining packets to a NIDS using the desired configuration
def send_pkts_to_NIDS(pcap, suspicious_pkts):
    suspicious_pkts_pcap = PcapWriter("suspicious_pkts.pcap", append=True, sync=True)
    for match in sorted(suspicious_pkts, key=lambda x: x[0]):
        suspicious_pkts_pcap.write(pcap[match[0]])

    # run os command to send packets to Snort and save the output somewhere
