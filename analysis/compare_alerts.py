import json
import os
import re
import sys

import pprint

def main(baseline_folder, experimnets_folder, nids_name):
    missed_signatures_counter = {}
    for alert_file in os.listdir(baseline_folder): 
        current_trace = alert_file.split(".")[0] # Remove ".pcap" to get day
        baseline_signatures = parse_alerts(baseline_folder+current_trace+(".txt" if nids_name == "snort" else ".log"), nids_name) # Baseline alerts
        experiment_signatures = parse_alerts(experimnets_folder+current_trace+(".txt" if nids_name == "snort" else ".log"), nids_name)
        
        missed_signatures = 0
        aditional_signatures = 0
        print(current_trace)
        for key in baseline_signatures.keys() | experiment_signatures.keys():
            if key not in missed_signatures_counter:
                missed_signatures_counter[key] = 0

            base = baseline_signatures.get(key, 0)
            exp = experiment_signatures.get(key, 0)
            if base-exp>0:
                missed_signatures+=base-exp
                missed_signatures_counter[key]+=base-exp
            elif base-exp:
                aditional_signatures+=exp-base

        print("end of trace, ", current_trace)
    pprint.pprint(missed_signatures_counter, sort_dicts=True)

# Parses an alert file and calculate the amount of detected signatures. 
def parse_alerts(alerts_filepath, nids_name):
    signatures = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            if nids_name == "snort":
                parsed_line = json.loads(line)
                signature = parsed_line["rule"].split(':')[1]
            elif nids_name == "suricata":
                l = line.strip()
                signature = re.search("\[\d*:\d*:\d*]", l).group(0).split(':')[1]

            if signature not in signatures:
                signatures[signature]=1
            else:
                signatures[signature]+=1
      
    return signatures



if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])