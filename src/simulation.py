from scapy.all import *
from multiprocessing import Manager,Process,cpu_count
from scapy.layers.http import * 
from scapy.utils import PcapWriter
from socket import getservbyport
import collections

from header_matching import compare_header_fields
from payload_matching import compare_payload

def pre_filtering_simulation(rules, n=10000):
    # Find the optimal pre-filtering subset   
    # pre_filtering_rules = optimal_pre_filtering_rules()
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

    start = time.time()
    pcap = rdpcap("/home/hbeckerbrum/NFSDatasets/CICIDS2017/Friday-WorkingHours.pcap")#, n)
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
    print(collections.Counter(suspicious_pkts))

    print("Time to process", n, "packets against ",len(rules), "rules in seconds: ", time.time() - start)
    print(len(suspicious_pkts), sum(ip_pkt_count_list), n) # Count IP packets
    # send_pkts_to_NIDS(pcap, suspicious_pkts)


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

            pkt_payload_buffers = get_pkt_payload_buffers(pkt, len_pkt_payload.keys())
            rules_to_compare = get_related_rules(pkt, rules_dict)
            if not rules_to_compare:
                suspicious_pkts.append((pkt_id, rule))
            else:
                for i, rule in enumerate(rules_to_compare):
                    if not compare_header_fields(pkt_header_fields, rule, rule.pkt_header_fields["proto"], icmp_in_pkt, tcp_in_pkt, upd_in_pkt):
                        continue

                    if not compare_payload(pkt, len_pkt_payload, pkt_payload_buffers, rule):
                        continue
                    
                    suspicious_pkts.append(rule.sids()[0])
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


smtp_ports = {25, 465, 587, 2525, 3535}
imap_ports = {143, 220, 585, 993}
ftp_ports = {20, 21, 69, 152, 989, 990, 2100, 2811, 3305, 3535, 3721, 5402, 6086, 6619, 6622}
smb_ports = {139, 445, 3020}

def get_pkt_payload_buffers(pkt, protocols_in_pkt):
    payload_buffers = {"original":{}, "nocase":{}}
    for proto in protocols_in_pkt:
        if pkt[proto].payload:
            payload_buffers["original"]["pkt_data_"+proto] = bytes(pkt[proto].payload).decode('utf-8', errors = 'ignore')
            payload_buffers["original"]["raw_data_"+proto] = payload_buffers["original"]["pkt_data_"+proto]

    http_type = None
    if HTTPRequest in pkt:
        http_type = HTTPRequest
    elif HTTPResponse in pkt:
        http_type = HTTPResponse

    if TCP in pkt or UDP in pkt:
        transport_layer = pkt.getlayer(UDP) if pkt.getlayer(UDP) else pkt.getlayer(TCP)
        if pkt[transport_layer.name].payload:
            sport = pkt[transport_layer.name].sport
            dport = pkt[transport_layer.name].dport
            
            is_pop3 = True if sport == 110 or sport == 995 else ( True if dport == 110 or dport == 995 else False)
            is_smtp = True if sport in smtp_ports else (True if dport in smtp_ports else False) 
            is_imap = True if sport in imap_ports else (True if dport in imap_ports else False) 
            is_ftp = True if sport in ftp_ports else (True if dport in ftp_ports else False) 
            is_smb = True if sport in smb_ports else (True if dport in smb_ports else False) 
            if is_pop3 or is_smtp or is_imap or is_ftp or is_smb:
                payload_buffers["original"]["file_data"] = payload_buffers["original"]["pkt_data_"+transport_layer.name]

    if http_type != None:
        payload_buffers["original"]["http_client_body"] = bytes(pkt[http_type].payload).decode('utf-8', errors = 'ignore')
        payload_buffers["original"]["http_raw_body"] = payload_buffers["original"]["http_client_body"]
        payload_buffers["original"]["file_data"] = payload_buffers["original"]["http_client_body"]

        payload_buffers["original"]["http_header"] = __get_http_header(pkt[http_type], True)
        payload_buffers["original"]["http_raw_header"] = __get_http_header(pkt[http_type], False)

        payload_buffers["original"]["http_cookie"] = __get_http_cookie(pkt[http_type], True)
        payload_buffers["original"]["http_raw_cookie"] = __get_http_cookie(pkt[http_type], False)

        payload_buffers["original"]["http_param"] = bytes(pkt[http_type]).decode('utf-8', errors = 'ignore')

        if HTTPRequest in pkt:
            payload_buffers["original"]["http_uri"] = __normalize_http_text("http_uri", pkt[HTTPRequest].Path.decode("utf-8"), "http://"+pkt[HTTPRequest].Host.decode("utf-8"))
            payload_buffers["original"]["http_raw_uri"] = "http://"+pkt[HTTPRequest].Host.decode("utf-8")+pkt[HTTPRequest].Path.decode("utf-8")
            payload_buffers["original"]["http_method"] = pkt[HTTPRequest].Method.decode("utf-8")
        elif HTTPResponse in pkt:
            payload_buffers["original"]["http_stat_code"] = pkt[HTTPResponse].Status_Code.decode("utf-8")
            payload_buffers["original"]["http_stat_msg"] = pkt[HTTPResponse].Reason_Phrase.decode("utf-8")

    for key in payload_buffers["original"]:
        payload_buffers["nocase"][key] = payload_buffers["original"][key].lower()

    return payload_buffers


def __get_http_header(http_header, normalized):
    http_header.remove_payload()
    return __normalize_http_text("http_header", bytes(http_header).decode('utf-8')) if normalized else bytes(http_header).decode('utf-8')

def __get_http_cookie(http_header, normalized):
    cookie = ""  
    if HTTPRequest in http_header and http_header[HTTPRequest].Cookie:
        cookie = http_header.Cookie.decode("utf-8")
    elif HTTPResponse in http_header and http_header[HTTPResponse].Set_Cookie:
        cookie = http_header.Set_Cookie.decode("utf-8")

    return __normalize_http_text("http_cookie", cookie) if normalized else cookie

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
                try:
                    normalized_text+=bytes.fromhex(escape_temp).decode('utf-8')
                except:
                    normalized_text+="%"+escape_temp
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

ip_proto = {1:"icmp", 6:"tcp", 17:"udp"}

def get_related_rules(pkt, rules_dict):
    pkt_proto = ip_proto.get(pkt[IP].proto, "ip")
    if (pkt_proto == "udp" and UDP not in pkt) or (pkt_proto == "tcp" and TCP not in pkt) or (pkt_proto == "icmp" and ICMP not in pkt):
        pkt_proto = "ip"
    
    service = None
    if UDP in pkt or TCP in pkt:
        try:
            service = getservbyport(pkt[pkt_proto.upper()].sport, pkt_proto)
        except:
            try:
                service = getservbyport(pkt[pkt_proto.upper()].dport, pkt_proto)
            except:
                service = None

        if service == "http-alt":
            service == "http"

        if service == "http" and (HTTPRequest not in pkt or HTTPResponse not in pkt):
            service = None
        
    return rules_dict[pkt_proto]+(rules_dict[service] if service in rules_dict.keys() else [])


# Sends the remaining packets to a NIDS using the desired configuration
def send_pkts_to_NIDS(pcap, suspicious_pkts):
    suspicious_pkts_pcap = PcapWriter("suspicious_pkts.pcap", append=True, sync=True)
    for match in sorted(suspicious_pkts, key=lambda x: x[0]):
        suspicious_pkts_pcap.write(pcap[match[0]])

    # run os command to send packets to Snort and save the output somewhere
