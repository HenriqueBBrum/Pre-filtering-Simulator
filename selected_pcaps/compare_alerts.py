import os
import re
import sys
import json

original_alerts_folder = "alerts_registered/"
no_track_alerts_folder = "alerts_registered_no_track/"

def main():    
    for file in os.listdir(original_alerts_folder):
        print(file)
        if "log" in file or "txt" not in file:
            continue

        original_pcap_alerts = parse_alerts(original_alerts_folder+file)
        no_track_pcap_alerts = parse_alerts(no_track_alerts_folder+file)

        print(len(original_pcap_alerts))
        print(len(no_track_pcap_alerts))
        print(len(set(original_pcap_alerts.keys()) & set(no_track_pcap_alerts.keys())))
        print(len(set(original_pcap_alerts.keys()) - set(no_track_pcap_alerts.keys())))
        print(len(set(no_track_pcap_alerts.keys()) - set(original_pcap_alerts.keys())))
        if "Friday" in file:
            print(set(original_pcap_alerts.keys()) - set(no_track_pcap_alerts.keys()))

        

# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_alerts(alerts_filepath):
    alerted_pkts = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            parsed_line = json.loads(line)
            key = parsed_line["proto"] + parsed_line["src_ap"] + parsed_line["dst_ap"]
            if key not in alerted_pkts:
                alerted_pkts[key] = 1
            else:
                alerted_pkts[key]=+1
               
    return alerted_pkts




if __name__ == '__main__':
    main()