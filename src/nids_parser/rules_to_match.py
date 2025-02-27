# File containing methods to parse snort rules. THe operations include:
# - Retrieve rules from file
# - Raw parsing of rule via snort_rule_parser.parser.Parser
# - Deduplicate rules
# - Replace system variables, fix negated ports and group ports into ranges

from os import listdir
from os.path import isfile, join
from re import search
from copy import deepcopy

from .rules_parser import RulesParser
from .match_tree import MatchTree
from .match import Match

import sys
sys.path.append("..")

from utils.validation_dicts import Dicts


supported_header_fields = {"proto", "src_ip", "sport", "dst_ip", "dport", "ip_port_key"}
supported_options = {"dsize", "content", "pcre"}

# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def convert_rules_to_matches(simulation_config, nids_config):
    print(f'---- Parsing rules from { simulation_config["ruleset_path"]} ----')
    parser = RulesParser(simulation_config, nids_config)
    original_rules, modified_rules = parser.parse_rules() # Returns a list of Rules
    
    print("---- Deduping rules based on the packet header and payload matching fields, and convert them to Match ----")
    deduped_matches = __dedup_rules_to_matches(simulation_config["scenario"], nids_config, modified_rules)

    match_tree = __group_by_protocol(deduped_matches)
    for key, node in match_tree.nodes.items():
        for match in node.matches:
            if match.header_key in node.groupped_matches:
                node.groupped_matches[match.header_key].append(match)
            else:
                node.groupped_matches[match.header_key] = [match]
   
    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total adjusted and filtered rules: {}".format(len(modified_rules)))
    print("Total deduped matches: {}".format(len(deduped_matches)))

    return match_tree, len(deduped_matches)


### Functions to dedup rules ###

# Deduplicate rules with the same fields and extract fields for quick matching with packets.
def __dedup_rules_to_matches(pre_filtering_scenario, nids_config, rules):
    deduped_matches = {}
    for rule in rules:
        header_fields, payload_fields = {}, {}
        for header_field in rule.header:
            if header_field in supported_header_fields:
                header_fields[header_field] = rule.header[header_field]

        for option in rule.options: 
            if option in supported_options:
                payload_fields[option] = rule.options[option]

        rule_id = hash(str(header_fields)+str(payload_fields))
        if rule_id not in deduped_matches:
            match = Match(header_fields, payload_fields, pre_filtering_scenario)
            deduped_matches[rule_id] = match

        sid = rule.get_simple_option_value("sid")
        rev = rule.get_simple_option_value("rev")
        sid_rev_string = f"{sid}/{rev}"

        classtype = rule.get_simple_option_value("classtype")
        priority = nids_config.classification_priority.get(classtype)
        
        deduped_matches[rule_id].priority_list.append(priority)
        deduped_matches[rule_id].sid_rev_list.append(sid_rev_string)

    return list(deduped_matches.values())



### Functions to group rules based on protocols so each packet is compared against fewer rules ###   
def __group_by_protocol(matches):
    match_tree = MatchTree([("", "ip", {"icmp", "tcp", "udp"}), ("ip", "icmp", set()), ("ip", "tcp", set()), ("ip", "udp", set())])
    for match in matches:
        proto = match.header_fields["proto"] 
        if proto == "ip":
            if "ip_proto" not in match.header_fields:
                match_tree.add_match("ip", match)
            else:
                ip_proto = match.header_fields["ip_proto"]["data"]
                ip_proto = ip_proto if ip_proto != 1 else "icmp"
                match_tree.safe_match_add(proto, ip_proto, match)
        elif proto == "icmp":
            match_tree.add_match(proto, match)
        elif proto == "udp" or proto == "tcp":
            if match.service:
                if type(match.service) is list:
                    for service in match.service:
                        match_tree.safe_match_add({"tcp", "udp"}, service, match) # parent, node, match
                else:
                    match_tree.safe_match_add({"tcp", "udp"}, match.service, match)
            else:
                match_tree.add_match(proto, match) # Add match to either udp or tcp since there is not service
        elif proto == "file": # Snort file options can mean the following protocols
            match_tree.safe_match_add({"tcp", "udp"}, "http", match)
            match_tree.safe_match_add({"tcp", "udp"}, "smtp", match)

            match_tree.safe_match_add("tcp", "pop3", match)
            match_tree.safe_match_add("tcp", "imap", match)
            match_tree.safe_match_add("tcp", "netbios-ssn", match) # Instead of SMB
            match_tree.safe_match_add("tcp", "ftp", match)
        elif "tcp-" in proto:
             match_tree.add_match("tcp", match)
        else:
            match_tree.safe_match_add({"tcp", "udp"}, proto, match) 

    return match_tree