# File containing methods to parse snort rules. THe operations include:
# - Retrieve rules from file
# - Raw parsing of rule via snort_rule_parser.parser.Parser
# - Deduplicate rules
# - Replace system variables, fix negated ports and group ports into ranges

from os import listdir
from os.path import isfile, join
from re import search
import copy
import sys

from .rule_parser import RuleParser
from .validation_dicts import Dicts

from .rule_to_match import RuleToMatch


# Functions related to the parsing of Snort/Suricata rules from multiple files, and the subsequent deduplication, 
# replacement of system variables, port groupping and fixing negated headers 
def parse_rules(config, pre_filtering_scenario, ruleset_path):
    print("---- Parsing rules ----")
    original_rules, modified_rules = __read_and_fix_rules(config, ruleset_path) # Get all rules from multiple files or just one
    
    print("---- Deduping rules based on the packet header and payload matching fields ----")
    deduped_rules = __dedup_rules(config, modified_rules, pre_filtering_scenario)

    grouped_by_protocol = __group_rules_by_protocol(deduped_rules)

    grouped_by_src_and_dst =  __group_by_src_and_dst(grouped_by_protocol)

    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total adjusted and filtered rules: {}".format(len(modified_rules)))
    print("Total deduped rules: {}".format(len(deduped_rules)))

    for key in grouped_by_src_and_dst:
        print(key)
        for src_dst in grouped_by_src_and_dst[key]:
            print(src_dst)
            print(len(grouped_by_src_and_dst[key][src_dst]))

    return grouped_by_src_and_dst

# Returns two list of rules from one or multiple files. 
# The first list contains the parsed rules similar as they apperead in the files but saving the values in dictionaries. 
# The second list contains adjusted bidirectional rules, with port groupping and with the IP and port variables exchanged with the real values.
def __read_and_fix_rules(config, rules_path, ignored_rule_files={}):
    files = []
    if isfile(rules_path):
        files =  [rules_path]
    else:
        for file in listdir(rules_path):
            file_full_path = join(rules_path, file)
            if isfile(file_full_path) and ".rules" in file and file not in ignored_rule_files:
                files.append(join(rules_path, file))

    original_rules, modified_rules = [], []
    for rule_file in files:
        parsed_rules, temp_modified_rules = __read_rules_from_file(config, rule_file)
        original_rules.extend(parsed_rules)
        modified_rules.extend(temp_modified_rules)
        
    return original_rules, modified_rules


regex_to_find_unsupported_keywords = "; *(sip_|dce_|base64_|sd_pattern|cvs|md5|sha256|sha512|gtp_|dnp3_|cip_|iec104_|mms_|modbus_|s7commplus|rpc:)"

# Parse each rule from a rule file
def __read_rules_from_file(config, rule_file):
    parsed_rules, modified_rules = [], []
    with open(rule_file, 'r') as file:
        lines = file.readlines()
        parser = RuleParser()
        for line in lines:
            if line.startswith("#") or len(line)<=1:
                continue

            parsed_rule = parser.parse_rule(line)
            parsed_rules.append(parsed_rule)

            if search(regex_to_find_unsupported_keywords, line):
                continue

            if len(parsed_rule.header) <= 2:
                modified_rules.append(parsed_rule)

            copied_rule = copy.deepcopy(parsed_rule)
            copied_rule.header["src_ap"] = copied_rule.header["src_ip"]+copied_rule.header["src_port"]
            copied_rule.header["dst_ap"] = copied_rule.header["dst_ip"]+copied_rule.header["dst_port"]
            print(copied_rule.header["src_ip"])

            copied_rule.header["src_ip"] = __replace_system_variables(copied_rule.header["src_ip"],  config.ip_addresses)
            copied_rule.header["src_port"] = __replace_system_variables(copied_rule.header["src_port"],  config.ports)
            copied_rule.header["dst_ip"] = __replace_system_variables(copied_rule.header["dst_ip"], config.ip_addresses)
            copied_rule.header["dst_port"] = __replace_system_variables(copied_rule.header["dst_port"],  config.ports)

            if copied_rule.header.get("direction") == "bidirectional":
                copied_rule.header["direction"] = "unidirectional"

                swap_dir_rule = copy.deepcopy(copied_rule)
                swap_dir_rule.header["src_ap"] = copied_rule.header["dst_ap"]
                swap_dir_rule.header["dst_ap"] = copied_rule.header["src_ap"]
                swap_dir_rule.header["src_ip"], swap_dir_rule.header["dst_ip"] =  swap_dir_rule.header["dst_ip"], swap_dir_rule.header["src_ip"]
                swap_dir_rule.header["src_port"], swap_dir_rule.header["dst_port"] =  swap_dir_rule.header["dst_port"], swap_dir_rule.header["src_port"]
                
                modified_rules.append(copied_rule)
                modified_rules.append(swap_dir_rule)
            else:
                modified_rules.append(copied_rule)
    return parsed_rules, modified_rules

# Substitute system variables for the real values in the config file
def __replace_system_variables(header_field, existing_variables):
    var_sub_results = []
    for value, bool_ in header_field:
        if isinstance(value, str) and "$" in value :
            name = value.replace('$', '')
            variable_values = copy.deepcopy(existing_variables.get(name, "ERROR"))
            if not bool_:
                for index, (variable_value, variable_value_bool) in enumerate(variable_values):
                    variable_values[index] = (variable_value, bool(~(bool_ ^ variable_value_bool)+2))
            
            var_sub_results.extend(variable_values)
        else:
            var_sub_results.append((value, bool_))

    return var_sub_results



### Functions to dedup rules ###

# Deduplicate signature rules with the same fields and extract fields for quick matching with packets.
def __dedup_rules(config, rules, pre_filtering_scenario):
    deduped_rules = {}
    for rule in rules:
        rule_id, pkt_header_fields, payload_fields = __useful_header_and_payload_fields(rule.header, rule.options)
        
        if rule_id not in deduped_rules:
            rule_to_match = RuleToMatch(pkt_header_fields, payload_fields, pre_filtering_scenario)
            if len(rule_to_match.pkt_header_fields) + len(rule_to_match.payload_fields) <= 5: # Exclude rules that only have the five-tuple
                continue
            deduped_rules[rule_id] = rule_to_match

        sid = __get_simple_option_value("sid", rule.options)
        rev = __get_simple_option_value("rev", rule.options)
        sid_rev_string = f"{sid}/{rev}"

        classtype = __get_simple_option_value("classtype", rule.options)
        priority = config.classification_priority.get(classtype)
        
        deduped_rules[rule_id].priority_list.append(priority)
        deduped_rules[rule_id].sid_rev_list.append(sid_rev_string)

    return list(deduped_rules.values())

# Define the fields that are part of the packet header and the ones for the payload that are going to be used in the pre-filtering simulation
def __useful_header_and_payload_fields(rule_header, rule_options):
    non_payload_options = Dicts.non_payload_options()
    payload_options = Dicts.payload_options()

    pkt_header_fields, payload_fields = {}, {}

    desired_header_fields = ["proto", "src_ip", "src_port", "src_ap", "dst_ip", "dst_port", "dst_ap"]
    unsupported_non_payload_fields = {"flow", "flowbits", "file_type", "rpc", "stream_reassemble", "stream_size"}
    for key in desired_header_fields:
        if key in rule_header:
            pkt_header_fields[key] = rule_header[key]

    for option in rule_options: 
        if option in non_payload_options and option not in unsupported_non_payload_fields:
            pkt_header_fields[option] = rule_options[option][1]
        elif option in payload_options or option == "content_pcre" or option == "service":
            payload_fields[option] = rule_options[option]

    return str(pkt_header_fields)+str(payload_fields), pkt_header_fields, payload_fields

# Returns value of key in rule options. Option value format: (option_index, [option_index_values])
def __get_simple_option_value(key, options, position=0, default=""):
    try:
        if type(options[key]) is tuple:
            return options[key][1]
        else:
            return options[key][1][position]
    except Exception as e:
        print("WARNING -- Error when searching for key {} in rule options \n Returning: {}".format(key, default))
        return default


### Functions and classes to group rules based on protocols so each packet is compared against fewer rules ###

# Class represeting a protocol or node
class Node:
    def __init__(self, parent, name, children=set()):
        self.parent = parent
        self.name = name
        self.children = children

        self.rules = []

class RulesTree:
    def __init__(self, base_node_names):
        self.nodes = {}
        for parent, name, children in base_node_names:
            self.nodes[name] = Node(parent, name, children)

    def add_node(self, parent_name, new_node_name):
        if parent_name not in self.nodes:
            raise Exception("No parent with this name")
        elif new_node_name in self.nodes[parent_name].children:
            print("Node already exists")
        else:
            self.nodes[new_node_name] = Node(parent_name, new_node_name)
            self.nodes[parent_name].children.add(new_node_name)
        
    def add_rule(self, node_name, rule):
        if node_name not in self.nodes:
            print("Node does not exist")
        else:
            self.nodes[node_name].rules.append(rule)

    def safe_rule_add(self, parent_name, new_node_name, rule):
        if new_node_name not in self.nodes[parent_name].children:
            self.add_node(parent_name, new_node_name)

        self.add_rule(new_node_name, rule)

    def get_related_rules(self, start_node, node_name):
        if start_node.name == node_name: # Base case: Has found the node
            return start_node.rules
            
        if len(start_node.children) == 0: # Base case: No the desired node but it has no children
            return []
        
        rules = []
        for child in start_node.children: # Checking each node
            r = self.get_related_rules(self.nodes[child], node_name)
            if r:
                rules = start_node.rules + r # Has found the node, return to root
                return rules

        return rules
        
    def print_nodes(self):
       for key, node in self.nodes.items():
           print(node.parent, node.name, node.children, len(node.rules))
        
def __group_rules_by_protocol(rules):
    rules_tree = RulesTree([("", "ip", {"icmp", "tcp", "udp"}), ("ip", "icmp", set()), ("ip", "tcp", set()), ("ip", "udp", set())])
    for rule in rules:
        proto = rule.pkt_header_fields["proto"] 
        if proto == "ip":
            if "ip_proto" not in rule.pkt_header_fields:
                rules_tree.add_rule("ip", rule)
            else:
                ip_proto = rule.pkt_header_fields["ip_proto"]["data"]
                ip_proto = ip_proto if ip_proto != 1 else "icmp"
                rules_tree.safe_rule_add(proto, ip_proto, rule)
        elif proto == "icmp":
            rules_tree.add_rule(proto, rule)
        elif proto == "udp" or proto == "tcp":
            if rule.service:
                if type(rule.service) is list:
                    for service in rule.service:
                        rules_tree.safe_rule_add(proto, proto+"_"+service, rule) # parent, node, rule
                else:
                    rules_tree.safe_rule_add(proto, proto+"_"+rule.service, rule)
            else:
                rules_tree.add_rule(proto, rule) # Add rule to either udp or tcp since there is not service
        else:
            if proto == "netflow" or proto == "dns":
                rules_tree.safe_rule_add("udp", "udp_"+proto, rule)
            else:
                rules_tree.safe_rule_add("tcp", "tcp_"+proto, rule)

    groups = {}
    for proto_or_service in rules_tree.nodes.keys():
        groups[proto_or_service] = rules_tree.get_related_rules(rules_tree.nodes["ip"], proto_or_service)

    return groups



### Groups rules now based on the src_ap and dst-ap irrepective of the protocol
def __group_by_src_and_dst(groups):
    groupped_rules = {}
    for key, rules in groups.items():
        groupped_rules[key] = {}
        print(key, len(rules))
        for rule in rules:
            rule_4tuple_flow = rule.header_key # src_ap + dst_ap
            print(rule_4tuple_flow)
            if rule_4tuple_flow not in groupped_rules[key]:
                groupped_rules[key][rule_4tuple_flow] = [rule]
            else:
                groupped_rules[key][rule_4tuple_flow].append(rule)








# Calculates the amount of bytes required by python to store the rules
def __calculate_rules_size(rules):
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