from scapy.all import *
from multiprocessing import Manager,Process,cpu_count
from scapy.layers.http import * 

from snort_rule_parser.rules_parser import group_header_and_payload_fields
from header_matching import compare_header_fields
from payload_matching import compare_payload


ip_proto = {"ip": 0, "icmp": 1, "tcp": 6, "udp": 17}


def pre_filtering_simulation(rules, n=10000):
    # Find the optimal pre-filtering subset
    # print("---- Separates fields into pkt_header fields and payload fields ----")
    group_header_and_payload_fields(rules)

    pre_filtering_rules = optimal_pre_filtering_rules()

    start = time.time()
    pcap = rdpcap("/home/hbeckerbrum/NFSDatasets/CICIDS2017/Friday-WorkingHours.pcap", n)
    print("Time to read ", n, " packets in seconds: ", time.time() - start)
    suspicious_pkts = Manager().list()
    ip_pkt_count_list = Manager().list()
    processes = []

    num_processes = 1#cpu_count() # Use the cout_count as the number of processes
    share = round(len(pcap)/num_processes)
    # Splits the rules each process processes
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


# Compares a list of packets with rules
def compare_pkt(pkts, rules, suspicious_pkts, ip_pkt_count_list, start):
    pkt_id, ip_pkt_count = start, 0
    for pkt in pkts:
        if IP in pkt and HTTP in pkt:
            print(len(pkt), len(pkt[HTTP].payload)) 
            print()  
            if HTTPResponse in pkt:
                print(len(pkt[HTTPResponse]), len(pkt[HTTPResponse].payload)) 
                print(HTTPResponse in pkt[HTTP])
                pkt.show2() 
            print("------")
            # for i, rule in enumerate(rules[0:1]):
            #     rule_proto = ip_proto[rule.pkt_header["proto"]]
            #     if pkt[IP].proto != rule_proto and rule_proto != 0:
            #         continue

            #     # # if not compare_header_fields(pkt, rule, rule_proto):
            #     # #     continue

            #     if not compare_payload(pkt, rule):
            #         continue

            #     suspicious_pkts.append((pkt_id, rule))
            #     break 
            ip_pkt_count+=1
        pkt_id+=1
    ip_pkt_count_list.append(ip_pkt_count)


    
# Sends the remaining packets to a NIDS using the desired configuration
#def send_pkts_to_NIDS():