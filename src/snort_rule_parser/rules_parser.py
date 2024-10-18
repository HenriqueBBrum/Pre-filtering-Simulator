# File containing methods to parse snort rules. THe operations include:
# - Retrieve rules from file
# - Raw parsing of rule via snort_rule_parser.parser.Parser
# - Deduplicate rules
# - Replace system variables, fix negated ports and group ports into ranges

from os import listdir
from os.path import isfile, join
import copy
import radix

from .parser import Parser
from .rule_related_classes import *
from .validation_dicts import Dicts

MIN_PORT = 0
MAX_PORT = 65535


# Returns two list of rules from one or multiple files. 
# The first list contains the parsed rules similar as they apperead in the files but saving the values in dictionaries. 
# The second list contains adjusted bidirectional rules, with port groupping and with the IP and port variables exchanged with the real values.
def get_rules(rules_path, ignored_rule_files):
    files = []
    if isfile(rules_path):
        files =  [rules_path]
    else:
        for file in listdir(rules_path):
            file_full_path = join(rules_path, file)
            if isfile(file_full_path) and '.rules' in file and file not in ignored_rule_files:
                files.append(join(rules_path, file))

    original_rules, modified_rules = [], []
    for rule_file in files:
        parsed_rules, temp_modified_rules = __parse_rules(rule_file)
        original_rules.extend(parsed_rules)
        modified_rules.extend(temp_modified_rules)
    return original_rules, modified_rules


non_supported_keywords = {"dce_iface", "dce_opnum", "dce_stub_data", "file_data", "base64_data"}

# Parse each rule from a rule file
def __parse_rules(rule_file):
    parsed_rules, modified_rules = [], []
    with open(rule_file, 'r') as file:
        lines = file.readlines()
        parser = Parser()
        for line in lines:
            if line.startswith("#") or len(line)<=1:
                continue

            parsed_rule = parser.parse_rule(line)
            if not parsed_rule.header:
                continue

            if "content" not in parsed_rule.options.keys() or bool(parsed_rule.options.keys() & non_supported_keywords):
                continue

            parsed_rules.append(parsed_rule)
            copied_rule = copy.deepcopy(parsed_rule)
            if copied_rule.header.get("direction") == "bidirectional":
                copied_rule.header['direction'] = "unidirectional"

                swap_dir_rule = copy.deepcopy(copied_rule)
                swap_dir_rule.header['src_ip'], swap_dir_rule.header['dst_ip'] =  swap_dir_rule.header['dst_ip'], swap_dir_rule.header['src_ip']
                swap_dir_rule.header['src_port'], swap_dir_rule.header['dst_port'] =  swap_dir_rule.header['dst_port'], swap_dir_rule.header['src_port']

                modified_rules.append(copied_rule)
                modified_rules.append(swap_dir_rule)
            else:
                modified_rules.append(copied_rule)
    return parsed_rules, modified_rules

# Replace system variables
def adjust_rules(config, rules):
    modified_rules = []
    count = 0
    for rule in rules:
        if len(rule.header) <= 2:
            modified_rules.append(rule)
            continue

        copied_header = copy.deepcopy(rule.header)
       
        copied_header['src_ip'] = __replace_system_variables(copied_header['src_ip'],  config.ip_addresses)
        copied_header['src_port'] = __replace_system_variables(copied_header['src_port'],  config.ports)
        copied_header['dst_ip'] = __replace_system_variables(copied_header['dst_ip'], config.ip_addresses)
        copied_header['dst_port'] = __replace_system_variables(copied_header['dst_port'],  config.ports)

        copied_header['src_ip'] = __convert_ip_list_to_radix_tree(copied_header['src_ip'])
        copied_header['dst_ip'] = __convert_ip_list_to_radix_tree(copied_header['dst_ip'])

        copied_header['src_port'] = __turn_port_list_into_dict(copied_header['src_port'])
        copied_header['dst_port'] = __turn_port_list_into_dict(copied_header['dst_port'])

        rule.header = copied_header
        rule.id = count
        
        modified_rules.append(rule)
        count+=1
    return modified_rules

# Substitute system variables for the real values in the config file
def __replace_system_variables(header_field, config_variables):
    var_sub_results = []
    for value, bool_ in header_field:
        if isinstance(value, str) and "$" in value :
            key_temp = value.replace('$', '')
            variable_values = copy.deepcopy(config_variables.get(key_temp, "ERROR"))

            if not bool_:
                for index, (variable_value, variable_value_bool) in enumerate(variable_values):
                    variable_values[index] = (variable_value, bool(~(bool_ ^ variable_value_bool)+2))
            
            var_sub_results.extend(variable_values)
        else:
            var_sub_results.append((value, bool_))

    return var_sub_results


def __convert_ip_list_to_radix_tree(ips):
    must_match = None
    rtree = radix.Radix()
    for ip in ips:
        rnode = rtree.add(ip[0])
        rnode.data["match"] = ip[1]

        must_match = ip[1] if must_match == None else must_match | ip[1]

    return (rtree, must_match)

# Individual ports are saved in a dict for quick comparsions, ranges in a list for linear search, and a bool to signal if all values are accetable
def __turn_port_list_into_dict(ports):
    must_match = None
    individual_ports = {}
    port_ranges = []
    for port in ports:
        if isinstance(port[0], range):
            port_ranges.append(port)
        else:
            individual_ports[port[0]] = port[1]

        must_match = port[1] if must_match == None else must_match | port[1]

    return (individual_ports,port_ranges,must_match)



# Define the fields that are part of the packet header and the ones for the payload
def group_header_and_payload_fields(rules):
    non_payload_options = Dicts.non_payload_options()
    payload_options = Dicts.payload_options()

    rule_header_fields = ["proto", "src_ip", "src_port", "dst_ip", "dst_port"]
    unsupported_non_payload_fields = {"flow", "flowbits", "file_type", "rpc", "stream_reassemble", "stream_size"}
    for rule in rules:
        for key in rule_header_fields:
            if key in rule.header:
                rule.pkt_header[key] = rule.header[key]

        for option in rule.options: 
            if option in non_payload_options and option not in unsupported_non_payload_fields:
                rule.pkt_header[option] = rule.options[option][1]
            elif option in payload_options:
                rule.payload_fields[option] = rule.options[option]

# Deduplicate signature rules with the same fields.
def dedup_rules(config, rules):
    deduped_rules = {}
    for rule in rules:
        rule_id = rule.rule_to_string()
      
        if rule_id not in deduped_rules:
            deduped_rules[rule_id] = AggregatedRule(rule.pkt_header, rule.payload_fields, priority_list=[], sid_rev_list=[])

        sid = __get_simple_option_value("sid", rule.options)
        rev = __get_simple_option_value("rev", rule.options)
        sid_rev_string = f'{sid}/{rev}'

        classtype = __get_simple_option_value("classtype", rule.options)
        priority = config.classification_priority.get(classtype)
        
        deduped_rules[rule_id].priority_list.append(priority)
        deduped_rules[rule_id].sid_rev_list.append(sid_rev_string)

    return list(deduped_rules.values())

# Returns value of key in rule options. Option value format: (option_index, [option_index_values])
def __get_simple_option_value(key, options, position=0, default=""):
    try:
        return options[key][1][position]
    except Exception as e:
        print("WARNING -- Error when searching for key {} in rule options \n Returning: {}".format(key, default))
        return default



