from time import time
import sys

from snort_parser.config_parser import SnortConfiguration
from snort_parser.parsing_rules import get_rules, adjust_rules, dedup_rules
from pre_filtering_simulation.simulation import pre_filtering_simulation

def main(config_path, rules_path, ruleset_name):
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)
    print("*" * 80)
    print("*" * 80)
    print("*" * 26 + " SNORT RULES PARSING STAGE " + "*" * 27+ "\n\n")
    modified_rules = parse_rules(config, rules_path)

    print("*" * 80)
    print("*" * 80)
    print("*" * 26 + " SIMULATION " + "*" * 36+ "\n\n")
    start = time()
    pre_filtering_simulation(modified_rules, ruleset_name)
    print("Simulation time: ", time() - start)


# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def parse_rules(config, rules_path):
    ignored_rule_files = {}

    print("---- Getting and parsing rules..... ----")
    print("---- Splitting bidirectional rules..... ----")
    original_rules, fixed_bidirectional_rules = get_rules(rules_path, ignored_rule_files) # Get all rules from multiple files or just one
    
    print("---- Adjusting rules. Replacing variables..... ----")
    modified_rules = adjust_rules(config, fixed_bidirectional_rules) 

    print("---- Deduping rules based on the packet header and payload matching fields..... ----")
    deduped_rules = dedup_rules(config, modified_rules)

    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total adjusted rules: {}".format(len(modified_rules)))
    print("Total deduped rules: {}".format(len(deduped_rules)))

    return deduped_rules


if __name__ == '__main__':
    config_path = sys.argv[1]
    rules_path = sys.argv[2]
    ruleset_name = sys.argv[3]

    main(config_path, rules_path, ruleset_name)