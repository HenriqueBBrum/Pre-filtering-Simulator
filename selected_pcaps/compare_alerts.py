import os
import re
import sys
import json

original_alerts_folder = "./alerts_registered/"
no_established_alerts_folder = "./alerts_registered_no_established/"

def main():
    for file in os.listdir(original_alerts_folder):
        print(file)
        original_pcap_alerts = parse_alerts(original_alerts_folder+file)
        no_established_alerts = parse_alerts(no_established_alerts_folder+file)

        print("\nOriginal ruleset num. of alerts: ",len(original_pcap_alerts))
        print("No 'established' keyword ruleset num. of alerts: ",len(no_established_alerts))
        print("\nAlerts in both:", len(original_pcap_alerts & no_established_alerts))
        print("Num. of alerts only with the original ruleset:", len(original_pcap_alerts - no_established_alerts))
        if original_pcap_alerts - no_established_alerts:
            print("Alerts only with the original ruleset:")
            print(original_pcap_alerts - no_established_alerts)
            print()
        print("Num. of alerts only with the no 'established' keyword ruleset:", len(no_established_alerts - original_pcap_alerts))
        if no_established_alerts - original_pcap_alerts:
            print("Alerts only with the no 'established' keyword ruleset:")
            print(no_established_alerts - original_pcap_alerts)

        print("------------------------------\n")




# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_alerts(alerts_filepath):
    alerted_pkts = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
           parsed_line = json.loads(line)
           if parsed_line["pkt_num"] not in alerted_pkts:
               alerted_pkts[parsed_line["pkt_num"]] = ";".join([parsed_line["proto"],parsed_line["dir"], parsed_line["src_ap"], parsed_line["dst_ap"]])
               
    return set(alerted_pkts.values())


if __name__ == '__main__':
    main()