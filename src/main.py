import time
import sys


from snort_config_parser import SnortConfiguration
from snort_rule_parser.rules_parser import get_rules, dedup_rules, adjust_rules, group_header_and_payload_fields
from simulation import pre_filtering_simulation

def main(config_path, rules_path):
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)
    print("*" * 80)
    print("*" * 80)
    print("*" * 26 + " SNORT RULES PARSING STAGE " + "*" * 27+ "\n\n")
    modified_rules = parse_rules(config, rules_path)
    start = time.time()

    pre_filtering_simulation(modified_rules)
    print("Simulation time: ", time.time() - start)


# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def parse_rules(config, rules_path):
    ignored_rule_files = {}

    print("---- Getting and parsing rules..... ----")
    print("---- Splitting bidirectional rules..... ----")
    original_rules, fixed_bidirectional_rules = get_rules(rules_path, ignored_rule_files) # Get all rules from multiple files or just one
    
    print("---- Adjusting rules. Replacing variables,grouping ports into ranges and adjusting negated port rules..... ----")
    modified_rules = adjust_rules(config, fixed_bidirectional_rules) 

    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total rules after fixing bidirectional rules: {}".format(len(fixed_bidirectional_rules)))
    print("Total non-negated IP rules: {}".format(len(modified_rules)))
    
    return modified_rules


if __name__ == '__main__':
    config_path = sys.argv[1]
    rules_path = sys.argv[2]
    compiler_goal = sys.argv[3]

    main(config_path, rules_path)