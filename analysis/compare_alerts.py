import json
import os
import re
import sys

import pprint
import argparse

import pprint

def main(baseline_folder, exps_folder, nids_name):
    missed_signatures_counter = {}
    for alert_file in os.listdir(exps_folder):  
        if ".log" not in alert_file:
            continue

        baseline_signatures = parse_alerts(baseline_folder+alert_file, nids_name) # Baseline alerts
        experiment_signatures = parse_alerts(exps_folder+alert_file, nids_name)
        
        aditional_signatures = 0
        print(alert_file)
        for key in baseline_signatures.keys() | experiment_signatures.keys():
            if key not in missed_signatures_counter:
                missed_signatures_counter[key] = 0

            if key not in baseline_signatures:
                base = (0, set())
            else:
                base = baseline_signatures.get(key, 0)

            if key not in experiment_signatures:
                exp = (0, set())    
            else:
                exp = experiment_signatures.get(key, 0)

            if base[0]-exp[0]>0:
                print("Missed signatures for sid:", key, "; = ", base[0]-exp[0])
                missed_signatures_counter[key]+=base[0]-exp[0]
                pprint.pprint(base[1] - exp[1])
            elif base[0]-exp[0]:
                aditional_signatures+=exp[0]-base[0]


        print("end of trace, ", alert_file)
    pprint.pprint(missed_signatures_counter, sort_dicts=True)

# Parses an alert file and calculate the amount of detected signatures. 
def parse_alerts(alerts_filepath, nids_name):
    signatures = {}
    flows = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            if nids_name == "snort":
                parsed_line = json.loads(line)
                signature = parsed_line["rule"].split(':')[1]
                flow = parsed_line["proto"]+ " " +parsed_line["src_ap"]+ " -> " +parsed_line["dst_ap"]
            elif nids_name == "suricata":
                l = line.strip()
                signature = re.search("\[\d*:\d*:\d*]", l).group(0).split(':')[1]
                flow_match = re.search(r"\{(\w+)\}\s([\d\.]+):(\d+)\s->\s([\d\.]+):(\d+)", l)
                if flow_match:
                    flow = flow_match.group(1) + " " + flow_match.group(2)+ ":" + flow_match.group(3) + " -> " + flow_match.group(4) + ":" + flow_match.group(5)
                    
            if signature not in signatures:
                signatures[signature]=[1, {flow}]
            else:
                signatures[signature][0]+=1
                signatures[signature][1].add(flow)
    return signatures



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Compare alerts between baseline and experiment folders.")
    parser.add_argument("baseline_folder", help="Path to the baseline folder containing alert files.")
    parser.add_argument("exps_folder", help="Path to the experiment folder containing alert files.")
    parser.add_argument("nids_name", choices=["snort", "suricata"], help="Name of the NIDS (snort or suricata).")
    args = parser.parse_args()

    main(args.baseline_folder, args.exps_folder, args.nids_name)