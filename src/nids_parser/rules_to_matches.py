# File containing methods to parse snort rules. THe operations include:
# - Retrieve rules from file
# - Raw parsing of rule via snort_rule_parser.parser.Parser
# - Deduplicate rules
# - Replace system variables, fix negated ports and group ports into ranges

from .rules_parser import RulesParser
from .match import Match

import sys
sys.path.append("..")

from utils.validation_dicts import Dicts

# Class represeting the matches of a protocol
class Node:
    def __init__(self, parents, name, applayer=False):
        self.parents = parents
        self.name = name

        self.applayer = applayer
        self.children = set()

        self.matches = []

class MatchTree:
    def __init__(self, root, base_node_names):
        self.nodes = {}
        self.root = root
        self.nodes[root] = Node([], root)

        for parents, name in base_node_names:
            self.add_node(parents, name)


    def get_root(self):
        return self.nodes[self.root]

    def add_node(self, parents, node_name, applayer=False):
        if node_name in self.nodes:
            raise Exception(f"Node already exists: {node_name}")
        if type(parents) == str:
            parents = [parents]

        for parent in parents:
            if parent not in self.nodes:
                raise Exception(f"No parent with this name: {parent}")
        
        self.nodes[node_name] = Node(parents, node_name, applayer)
        if node_name != self.root:
            for parent in parents:
                self.nodes[parent].children.add(node_name)
        
    def add_match(self, node_name, match):
        if node_name not in self.nodes:
            raise Exception("Node does not exist")
        else:
            self.nodes[node_name].matches.append(match)

    def safe_match_add(self, parents, node_name, match, applayer):
        if node_name not in self.nodes:
            self.add_node(parents, node_name, applayer)

        self.add_match(node_name, match)

    def get_related_matches(self, start_node, wrong_transport_node, node_name):
        if wrong_transport_node:
            if start_node.name == wrong_transport_node:
                return []
                        
        if start_node.name == node_name: # Base case: Has found the node
            return start_node.matches
            
        if len(start_node.children) == 0: # Base case: Not the desired node and it has no children
            return []
        
        matches = start_node.matches
        for child in start_node.children: # Checking each node
            r = self.get_related_matches(self.nodes[child], wrong_transport_node, node_name)
            if r:
                return start_node.matches + r # Has found the node, return to root

        return matches if start_node.name == node_name else []
        
    def print_nodes(self):
       for key, node in self.nodes.items():
           print(node.parents, node.name, node.children, len(node.matches))

# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def convert_rules_to_matches(simulation_config, nids_config):
    print(f'---- Parsing rules from { simulation_config["ruleset_path"]} ----')
    parser = RulesParser(simulation_config, nids_config)
    original_rules, modified_rules = parser.parse_rules() # Returns a list of Rules
    
    print("---- Deduping rules based on the packet header and payload matching fields, and convert them to Match ----")
    deduped_matches = __dedup_rules_to_matches(simulation_config["scenario"], nids_config, modified_rules)

    final_matches = __group_matches(deduped_matches)
    
    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total adjusted and filtered rules: {}".format(len(modified_rules)))
    print("Total deduped matches: {}".format(len(deduped_matches)))

    return final_matches, len(deduped_matches)


### Functions to dedup rules ###

# DO I need supported heade fields?????
supported_header_fields = {"proto", "src_ip", "sport", "dst_ip", "dport", "ip_port_key"}
supported_payload_options = {"dsize", "content", "pcre", "service"}

# Deduplicate rules with the same fields and extract fields for quick matching with packets.
def __dedup_rules_to_matches(pre_filtering_scenario, nids_config, rules):
    deduped_matches = {}
    for rule in rules:
        header_fields, payload_fields = {}, {}
        for header_field in rule.header:
            if header_field in supported_header_fields:
                header_fields[header_field] = rule.header[header_field]

        for option in rule.options: 
            if option in supported_payload_options:
                payload_fields[option] = rule.options[option]
            elif Dicts.non_payload_options(option):
                header_fields[option] = rule.options[option]

        rule_id = hash(str(header_fields)+str(payload_fields))
        if rule_id not in deduped_matches:
            deduped_matches[rule_id] = Match(header_fields, payload_fields, pre_filtering_scenario)

        sid = rule.get_simple_option_value("sid")
        rev = rule.get_simple_option_value("rev")
        sid_rev_string = f"{sid}/{rev}"

        classtype = rule.get_simple_option_value("classtype")
        priority = nids_config.classification_priority.get(classtype)
        
        deduped_matches[rule_id].priority_list.append(priority)
        deduped_matches[rule_id].sid_rev_list.append(sid_rev_string)

    return list(deduped_matches.values())


def __group_matches(matches):
    match_tree = __group_by_protocol(matches)
    return __group_by_rule_header(match_tree)


### Functions to group rules based on protocols so each packet is compared against fewer rules ###   
def __group_by_protocol(matches):
    match_tree = MatchTree("ip", [("ip", "icmp"), ("ip", "tcp"), ("ip", "udp")])

    for match in matches:
        proto = match.header_fields["proto"] 
        if proto == "ip":
            if "ip_proto" not in match.header_fields:
                match_tree.add_match("ip", match)
            else:
                ip_proto = match.header_fields["ip_proto"]["data"]
                ip_proto = "icmp" if ip_proto == 1 else "ip"
                match_tree.safe_match_add(proto, ip_proto, match, applayer=False)
        elif proto == "icmp":
            match_tree.add_match(proto, match)
        elif proto == "udp" or proto == "tcp":
            if match.service:
                if type(match.service) is list:
                    for service in match.service:
                        match_tree.safe_match_add(["tcp", "udp"], service, match, applayer=True) # parent, node, match
                else:
                    match_tree.safe_match_add(["tcp", "udp"], match.service, match, applayer=True)
            else:
                match_tree.add_match(proto, match) # Add match to either udp or tcp since there is not service
        elif proto == "file": # Snort file options can mean the following protocols
            match_tree.safe_match_add(["tcp", "udp"], "http", match, applayer=True)
            match_tree.safe_match_add(["tcp", "udp"], "smtp", match, applayer=True)

            match_tree.safe_match_add("tcp", "pop3", match, applayer=True)
            match_tree.safe_match_add("tcp", "imap", match, applayer=True)
            match_tree.safe_match_add("tcp", "netbios-ssn", match, applayer=True) # Instead of SMB
            match_tree.safe_match_add("tcp", "ftp", match, applayer=True)
        elif "tcp-" in proto:
             match_tree.add_match("tcp", match)
        else:
            match_tree.safe_match_add(["tcp", "udp"], proto, match, applayer=True) 

    match_tree.print_nodes()
    return match_tree


### Returns a map of map with
def __group_by_rule_header(match_tree):
    def group(matches):
        groupped_matches = {}
        for match in matches:
            if match.header_key in groupped_matches:
                groupped_matches[match.header_key].append(match)
            else:
                groupped_matches[match.header_key] = [match]

        return groupped_matches

    final_matches = {}
    for key, node in match_tree.nodes.items():
        if node.applayer:
            tcp_matches = match_tree.get_related_matches(match_tree.get_root(), "udp", key)  # Don't go by the udp path
            final_matches["tcp"+key] = group(tcp_matches)
            udp_matches = match_tree.get_related_matches(match_tree.get_root(), "tcp", key) # Don't go by the tcp path
            final_matches["udp"+key] = group(udp_matches)
        else:
            final_matches[key] = group(match_tree.get_related_matches(match_tree.get_root(), None, key))

    return final_matches

    
   