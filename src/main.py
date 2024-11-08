from time import time
import sys
import csv

from snort_parser.config_parser import SnortConfiguration
from snort_parser.parsing_rules import get_rules, adjust_rules, dedup_rules
from pre_filtering_simulation.simulation import pre_filtering_simulation

def main(config_path, rules_path, ruleset_name, pre_filtering_scenario):
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)

    print("*" * 80)
    print("*" * 80)
    print("*" * 26 + " SNORT RULES PARSING STAGE " + "*" * 27+ "\n\n")
    modified_rules = parse_rules(config, rules_path, pre_filtering_scenario)

    print("*" * 80)
    print("*" * 80)
    print("*" * 34 + " SIMULATION " + "*" * 34+ "\n\n")
    pcaps_path="selected_pcaps/pcaps/"

    start = time()
    pre_filtering_simulation(modified_rules, ruleset_name, pre_filtering_scenario, pcaps_path)
    print("Simulation time: ", time() - start)


# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def parse_rules(config, rules_path, pre_filtering_scenario):
    ignored_rule_files = {}

    print("---- Getting and parsing rules..... ----")
    print("---- Splitting bidirectional rules..... ----")
    original_rules, fixed_bidirectional_rules = get_rules(rules_path, ignored_rule_files) # Get all rules from multiple files or just one
    
    print("---- Adjusting rules. Replacing variables..... ----")
    modified_rules = adjust_rules(config, fixed_bidirectional_rules) 

    print("---- Deduping rules based on the packet header and payload matching fields..... ----")
    deduped_rules = dedup_rules(config, modified_rules, pre_filtering_scenario)

    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total adjusted and filtered rules: {}".format(len(modified_rules)))
    print("Total deduped rules: {}".format(len(deduped_rules)))

    get_rules_size(deduped_rules)

    return deduped_rules


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

    print("\nHeader size: ", total_header_size/1000000,"MB")
    print("Payload size: ", total_payload_size/1000000,"MB")
    print("Total size: ", (total_header_size+total_payload_size)/1000000,"MB")
    

if __name__ == '__main__':
    config_path = sys.argv[1]
    rules_path = sys.argv[2]
    ruleset_name = sys.argv[3]
    pre_filtering_scenario = sys.argv[4]

    main(config_path, rules_path, ruleset_name, pre_filtering_scenario)