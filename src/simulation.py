from scapy.all import *
from multiprocessing import Manager,Process,cpu_count
from scapy.layers.http import * 
from scapy.utils import PcapWriter
from socket import getservbyport

from header_matching import compare_header_fields
from payload_matching import compare_payload

def pre_filtering_simulation(rules, n=10000):
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
    # for i in range(num_processes):
    #     pkts_sublist = pcap[i*share:(i+1)*share + int(i == (num_processes - 1))*-1*(num_processes*share - len(pcap))]  # Send a batch of packets for each processor
    #     process = Process(target=compare_pkts, args=(pkts_sublist, rules_dict, suspicious_pkts, ip_pkt_count_list, i*share))
    #     process.start()
    #     processes.append(process)

    # for process in processes:
    #     process.join()

    compare_pkts(pcap, rules_dict, suspicious_pkts, ip_pkt_count_list,0)

    print("Time to process", n, "packets against ",len(rules), "rules in seconds: ", time.time() - start)
    print(len(suspicious_pkts), sum(ip_pkt_count_list), n) # Count IP packets
    send_pkts_to_NIDS(pcap, suspicious_pkts)


# Generates the optimal pre-filtering ruleset using most header fields and part of the payload matches
def optimal_pre_filtering_rules():
    # get_header_and_payload_fields()

    # select_optimal_payload_config()

    return []



# Compares a list of packets with rules
def compare_pkts(pkts, rules_dict, suspicious_pkts, ip_pkt_count_list, start):
    pkt_id, ip_pkt_count = start, 0
    match_count = 0
    for pkt in pkts:
        if IP in pkt:
            icmp_in_pkt, tcp_in_pkt, upd_in_pkt = ICMP in pkt, TCP in pkt, UDP in pkt
            pkt_header_fields = get_pkt_header_fields(pkt)   

            len_pkt_payload = {} # The payload length of each protocol. Since a TCP pkt has the IP proto and might others (e.g., HTTP) each protocol has different payload sizes
            for proto in rules_dict.keys():
                proto = proto.upper()
                if proto in pkt:
                    len_pkt_payload[proto] = len(pkt[proto].payload)

            http_req_in_pkt, http_res_in_pkt = HTTPRequest in pkt, HTTPResponse in pkt
            pkt_payload_buffers = get_pkt_payload_buffers(pkt, len_pkt_payload.keys(), http_req_in_pkt, http_res_in_pkt)
            for i, rule in enumerate(get_related_rules(pkt, rules_dict)):
                if not compare_header_fields(pkt_header_fields, rule, rule.pkt_header["proto"], icmp_in_pkt, tcp_in_pkt, upd_in_pkt):
                    continue

                if not compare_payload(pkt, len_pkt_payload, pkt_payload_buffers, rule):
                    continue

                # pkt.show2()
                # print(rule.pkt_header)
                # print(rule.payload_fields)
                # print(rule.sid_rev_list)
                # input()
                suspicious_pkts.append((pkt_id, rule))
                break 
            ip_pkt_count+=1
        pkt_id+=1
    ip_pkt_count_list.append(ip_pkt_count)


def get_pkt_header_fields(pkt):
    pkt_fields = {"src_ip": pkt[IP].src, "dst_ip": pkt[IP].dst, "ttl": pkt[IP].ttl, "id": pkt[IP].id, \
                    "ipopts": pkt[IP].options, "fragbits": pkt[IP].flags, "ip_proto": pkt[IP].proto}
    
    if ICMP in pkt:
        pkt_fields["itype"] = pkt[ICMP].type
        pkt_fields["icode"] = pkt[ICMP].code
        pkt_fields["icmp_id"] = pkt[ICMP].id
        pkt_fields["icmp_seq"] = pkt[ICMP].seq
    elif TCP in pkt:
        pkt_fields["src_port"] = pkt[TCP].sport
        pkt_fields["dst_port"] = pkt[TCP].dport
        pkt_fields["flags"] = pkt[TCP].flags
        pkt_fields["seq"] = pkt[TCP].seq
        pkt_fields["ack"] = pkt[TCP].ack
        pkt_fields["window"] = pkt[TCP].window
    elif UDP in pkt:
        pkt_fields["src_port"] = pkt[UDP].sport
        pkt_fields["dst_port"] = pkt[UDP].dport
    return pkt_fields


def get_pkt_payload_buffers(pkt, protocols_in_pkt, http_req_in_pkt, http_res_in_pkt):
    payload_buffers = {"pkt_data":{}, "raw_data":{}}
    for proto in protocols_in_pkt:
        payload_buffers["pkt_data"][proto] = payload_buffers["raw_data"][proto] = bytes(pkt[proto].payload)

    http_type = None
    if http_req_in_pkt:
        http_type = HTTPRequest
    elif http_res_in_pkt:
        http_type = HTTPResponse

    if http_type != None:
        payload_buffers["http_client_body"] = payload_buffers["http_raw_body"] = bytes(pkt[http_type].payload)

        payload_buffers["http_header"] = bytes(__get_http_header(pkt[http_type], True), 'utf-8')
        payload_buffers["http_raw_header"] = __get_http_header(pkt[http_type], False) # Already returns bytes()

        payload_buffers["http_cookie"] = bytes(__get_http_cookie(pkt[http_type], True), 'utf-8')
        payload_buffers["http_raw_cookie"] = bytes(__get_http_cookie(pkt[http_type], False), 'utf-8')

        payload_buffers["http_param"] = bytes(pkt[http_type])

        if http_req_in_pkt:
            payload_buffers["http_uri"] = bytes(__normalize_http_text("http_uri", pkt[HTTPRequest].Path.decode("utf-8"), "http://"+pkt[HTTPRequest].Host.decode("utf-8")), 'utf-8') 
            payload_buffers["http_raw_uri"] = bytes("http://"+pkt[HTTPRequest].Host.decode("utf-8")+pkt[HTTPRequest].Path.decode("utf-8"), 'utf-8') 
            payload_buffers["http_method"] = pkt[HTTPRequest].Method
        elif http_res_in_pkt:
            payload_buffers["http_stat_code"] = pkt[HTTPResponse].Status_Code
            payload_buffers["http_stat_msg"] = pkt[HTTPResponse].Reason_Phrase
    return payload_buffers

def __normalize_http_text(header_name, raw_http_text, normalized_start=""):
    normalized_text = ""
    uri_segment = 0 # 0 - path, 1 - query, 2 - fragment
    escape_temp = ""
    escape_hex, normalize_path = False, 0
    for i, char in enumerate(raw_http_text):
        if char == "%":
            escape_hex = True
            continue

        if escape_hex:
            escape_temp+=char
            if len(escape_temp) == 2:
                normalized_text+=bytes.fromhex(escape_temp).decode('utf-8')
                escape_temp = ""
                escape_hex = False
            continue
        
        if header_name == "http_uri":
            if char == "?":
                uri_segment = 1
                normalize_path = 1
            elif char == "#":
                uri_segment = 2
                normalize_path = 1
            elif char == "\\":
                char = "/"

            if uri_segment >=1 and char == "+":
                char = " "

            if normalize_path == 1:
                normalized_text = os.path.normpath(normalized_text)
                normalize_path = -1
        
        normalized_text+=char

    if normalize_path != 1 and normalized_text:
        normalized_text = normalized_text = os.path.normpath(normalized_text)

    return normalized_start+normalized_text

def __get_http_header(http_header, normalized):
    http_header.remove_payload()
    return __normalize_http_text("http_header", bytes(http_header).decode('utf-8')) if normalized else http_header

def __get_http_cookie(http_header, normalized):
    cookie = ""  
    if HTTPRequest in http_header and http_header[HTTPRequest].Cookie:
        cookie = http_header.Cookie.decode("utf-8")
    elif HTTPResponse in http_header and http_header[HTTPResponse].Set_Cookie:
        cookie = http_header.Set_Cookie.decode("utf-8")

    return __normalize_http_text("http_cookie", cookie) if normalized else cookie




ip_proto = {1:"icmp", 6:"tcp", 17:"udp"}

def get_related_rules(pkt, rules_dict):
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
        
    return rules_dict[pkt_proto]+(rules_dict[service] if service in rules_dict.keys() else [])


# Sends the remaining packets to a NIDS using the desired configuration
def send_pkts_to_NIDS(pcap, suspicious_pkts):
    suspicious_pkts_pcap = PcapWriter("suspicious_pkts.pcap", append=True, sync=True)
    for match in sorted(suspicious_pkts, key=lambda x: x[0]):
        suspicious_pkts_pcap.write(pcap[match[0]])

    # run os command to send packets to Snort and save the output somewhere
