from time import time
import sys
import json

from snort_parser.config_parser import SnortConfiguration
from snort_parser.parsing_rules import get_rules, adjust_rules, dedup_rules
from pre_filtering_simulation.simulation import pre_filtering_simulation, flow_sampling_simulation

def main(simulation_config_path, sim_results_folder):
    with open(simulation_config_path, 'r') as f:
        simulation_config = json.load(f)

    start = time()
    if simulation_config["type"] == "pre_filtering":
        config = SnortConfiguration(snort_version=2, configuration_dir=simulation_config["snort_config_path"])
        print("*" * 80)
        print("*" * 26 + " SNORT RULES PARSING STAGE " + "*" * 27+ "\n\n")
        modified_rules = parse_rules(config, simulation_config["scenario"], simulation_config["ruleset_path"])
        rules_info = get_rules_size(modified_rules)
        
        print("PRE-FILTERING SIMULATION")
        pre_filtering_simulation(simulation_config, modified_rules, rules_info, sim_results_folder)
    elif simulation_config["type"] == "flow_sampling":
        print("FLOW SAMPLING SIMULATION")
        flow_sampling_simulation(simulation_config, sim_results_folder)
    else:
        print("Wrong simulation type")
        exit(1)

    print("Simulation time: ", time() - start)

# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def parse_rules(config, pre_filtering_scenario, ruleset_path):
    print("---- Getting and parsing rules..... ----")
    print("---- Splitting bidirectional rules..... ----")
    original_rules, fixed_bidirectional_rules = get_rules(ruleset_path) # Get all rules from multiple files or just one
    
    print("---- Adjusting rules. Replacing variables..... ----")
    modified_rules = adjust_rules(config, fixed_bidirectional_rules) 

    print("---- Deduping rules based on the packet header and payload matching fields..... ----")
    deduped_rules = dedup_rules(config, modified_rules, pre_filtering_scenario)

    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total adjusted and filtered rules: {}".format(len(modified_rules)))
    print("Total deduped rules: {}".format(len(deduped_rules)))

    return deduped_rules

# Calculates the amount of bytes required by python to store the rules
def get_rules_size(rules):
    total_header_size = 0
    total_payload_size = 0
    for rule in rules:
        for key, header_field_value in rule.pkt_header_fields.items():
            if key == "proto" or key == "ipopts":
                total_header_size+=sys.getsizeof(header_field_value)
            elif key == "src_ip" or key == "dst_ip":
                for ip in header_field_value[0].prefixes():
                    total_header_size+=sys.getsizeof(ip)
            elif key == "src_port" or key == "dst_port":
                for port in header_field_value[0]:
                    total_header_size+=sys.getsizeof(port)

                for port_range in header_field_value[1]:
                    total_header_size+=sys.getsizeof(port_range[0])
                    total_header_size+=sys.getsizeof(port_range[-1])
            else:
                total_header_size+=sys.getsizeof(header_field_value["data"])+sys.getsizeof(header_field_value["comparator"])
                if key == "flags":
                    total_header_size+=sys.getsizeof(header_field_value["exclude"])

        for key, payload_value in rule.payload_fields.items():
            if key == "dsize":
                total_payload_size+=sys.getsizeof(payload_value["data"])+sys.getsizeof(payload_value["comparator"])
            else:
                for content_pcre in payload_value:
                    if content_pcre:
                        total_payload_size+=sys.getsizeof(content_pcre[1]) # Buffer name
                        total_payload_size+=sys.getsizeof(content_pcre[3]) # Content or pcre string
                        if content_pcre[4]:
                            if type(content_pcre[4]) is str:
                                total_payload_size+=sys.getsizeof(content_pcre[4])
                            else:
                                for modifier in content_pcre[4]:
                                    total_payload_size+=sys.getsizeof(modifier)

    return {"header_size": total_header_size/1000000, "payload_size": total_payload_size/1000000, "total_size":(total_header_size+total_payload_size)/1000000}

    

if __name__ == '__main__':
    simulation_config_file = sys.argv[1]
    sim_results_folder = "simulation_results/"
    main(simulation_config_file, sim_results_folder)