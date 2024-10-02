### Main file that compiles a Snort rule file according to the snort.conf and classification.conf to P4 table entries
# Args: config path, rules_path
#       - config_path: Path to the configuration files
#       - rules_path: Path to a single rule file or to a directory containing multiple rule files
#       - compiler_goal: Compiler goals, such as the p4 target and the rules priority
#       - compiler_output_file: Output file path for the compiled p4 table entries



## Standard and 3rd-party imports
import sys
from datetime import datetime
from json import load
import random
import scapy


## Local imports
from snort_config_parser import SnortConfiguration
from snort_rule_parser.rules_parser import get_rules, dedup_rules, adjust_rules, group_header_and_payload_fields
from snort_rule_parser.rule_statistics import RuleStatistics



def main(config_path, rules_path):
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)
    print("*" * 80)
    print("*" * 80)
    print("*" * 26 + " SNORT RULES PARSING STAGE " + "*" * 27+ "\n\n")
    modified_rules = rule_parsing_stage(config, rules_path)

    pre_filtering_simulation(modified_rules)
   

# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def rule_parsing_stage(config, rules_path):
    ignored_rule_files = {}

    print("---- Getting and parsing rules..... ----")
    print("---- Splitting bidirectional rules..... ----")
    original_rules, fixed_bidirectional_rules = get_rules(rules_path, ignored_rule_files) # Get all rules from multiple files or just one
    stats = RuleStatistics(config, original_rules)
    
    print("---- Adjusting rules. Replacing variables,grouping ports into ranges and adjusting negated port rules..... ----")
    modified_rules = adjust_rules(config, fixed_bidirectional_rules) 

    print("---- Separating fields into packet_header fields and payload fields ----")
    group_header_and_payload_fields(modified_rules)

    # stats.print_all()

    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total rules after fixing bidirectional rules: {}".format(len(fixed_bidirectional_rules)))
    print("Total non-negated IP rules: {}".format(len(modified_rules)))
    
    return modified_rules

def pre_filtering_simulation(rules):
    # Find the optmial pre-filtering subset
    # pre_filter = optmial_pre_filter()

    pcap = scapy.rdpcap 
    run_simulation()




if __name__ == '__main__':
    config_path = sys.argv[1]
    rules_path = sys.argv[2]
    compiler_goal = sys.argv[3]

    main(config_path, rules_path, compiler_goal)

   
