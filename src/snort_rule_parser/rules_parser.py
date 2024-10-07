# File containing methods to parse snort rules. THe operations include:
# - Retrieve rules from file
# - Raw parsing of rule via snort_rule_parser.parser.Parser
# - Deduplicate rules
# - Replace system variables, fix negated ports and group ports into ranges

from os import listdir
from os.path import isfile, join
import copy

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
        parsed_rules, adjusted_rules = _parse_rules(rule_file)
        original_rules.extend(parsed_rules)
        modified_rules.extend(adjusted_rules)
    return original_rules, modified_rules

# Parse each rule from a rule file
def _parse_rules(rule_file):
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

# Replace system variables, modify negated ports and group ports
def adjust_rules(config, rules):
    modified_rules = []
    count = 0
    for rule in rules:
        copied_header = copy.deepcopy(rule.header)
       
        copied_header['src_ip'] = _replace_system_variables(copied_header['src_ip'],  config.ip_addresses)
        copied_header['src_port'] = _replace_system_variables(copied_header['src_port'],  config.ports)
        copied_header['dst_ip'] = _replace_system_variables(copied_header['dst_ip'], config.ip_addresses)
        copied_header['dst_port'] = _replace_system_variables(copied_header['dst_port'],  config.ports)

        rule.header = copied_header
        rule.id = count
        
        modified_rules.append(rule)

        count+=1

    return modified_rules

# Substitute system variables for the real values in the config file and group ports into range
def _replace_system_variables(header_field, config_variables):
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
           
# Checks if an IP list has a negated entry
def _IP_negated(ip_list):
    for ip in ip_list:
        if ip[1] == False:
            print("WARNING -- Negated IPs are not supported ", ip)
            return True

    return False

# Exchange the negated ports by their positive counterparts e.g., !10 == (range(0, 10), range(11, 65535)) 
def _modify_negated_ports(ports):
    new_port_list = []
    for port in ports:
        if not port[1]:
            if isinstance(port[0], range):
                new_port_list.append((range(MIN_PORT, port[0].start), True))
                new_port_list.append((range(port[0].stop, MAX_PORT+1), True))
            else:
                new_port_list.append((range(MIN_PORT, int(port[0])), True))
                new_port_list.append((range(int(port[0])+1, MAX_PORT+1), True))
        else:
            new_port_list.append(port)

    return new_port_list

# Groups ports into ranges. Assumes no intersecting range value and duplicates. Sill simple
def _group_ports_into_ranges(ports):
    count = 0
    initial_port = -1
    grouped_ports = []
    if len(ports) == 1:
        return ports

    sorted_ports = sorted(ports, key=lambda x: (int(x[0].start) if isinstance(x[0], range) else int(x[0])))
    for index, item in enumerate(sorted_ports):
        if isinstance(item[0], range):
            grouped_ports.append(item)
            continue

        if count == 0:
            initial_port = item[0]
            bool_ = item[1]

        try:
            next_tuple= sorted_ports[index+1] 
            if isinstance(next_tuple[0], range):
                next_tuple= (-1, False)
        except Exception as e:
            next_tuple= (-1, False)

        if int(item[0]) == int(next_tuple[0]) - 1 and item[1]==next_tuple[1]:
            count+=1
        else:
            if count == 0:
                grouped_ports.append((initial_port, bool_))
                continue
            
            grouped_ports.append((range(int(initial_port), int(initial_port)+count), bool_))
            count = 0
            initial_port = -1
    return grouped_ports


# Define the fields that are part of the packet header and the one for the payload
def group_header_and_payload_fields(rules):
    non_payload_detect = Dicts.non_payload_options()
    for rule in rules:
        for key in ["proto", "src_ip", "src_port", "dst_ip", "dst_port"]:
            rule.pkt_header[key] = rule.header[key]

        for option in rule.options: 
            if option in non_payload_detect and option not in {"flow", "flowbits", "file_type", "rpc", "stream_reassemble", "stream_size"}:
                rule.pkt_header[option] = rule.options[option][1]
            else:
                rule.payload_fields[option] = rule.options[option]

# Deduplicate signature rules with same match. Save each duplicate rule's priority and sid/rev 
def dedup_rules(config, rules):
    deduped_rules = {}
    for rule in rules:
        rule_id = rule.rule_id()
       
        if rule_id not in deduped_rules:
            deduped_rules[rule_id] = AggregatedRule(header=rule.header, flags=_get_simple_option_value("flags", rule.options, []), \
                                                            priority_list=[], sid_rev_list=[])

        sid = _get_simple_option_value("sid", rule.options)
        rev = _get_simple_option_value("rev", rule.options)
        sid_rev_string = f'{sid}/{rev}'

        classtype = _get_simple_option_value("classtype", rule.options)
        priority = config.classification_priority.get(classtype)
        
        deduped_rules[rule_id].priority_list.append(priority)
        deduped_rules[rule_id].sid_rev_list.append(sid_rev_string)

    return list(deduped_rules.values())

# Returns value of key in rule options. Option value format: (option_index, [option_index_values])
def _get_simple_option_value(key, options, default="ERROR"):
    try:
        return options[key][1][0]
    except Exception as e:
        print("WARNING -- Error when searching for key {} in rule options \n Returning: {}".format(key, default))
        return default


# Remove udp and tcp rules that have src port and dst port equal to any
def remove_port_wildcard_rules(rules):
    final_rules = []
    for rule in rules:
        # Assume wildcards IP and ports contain only one object, i.e. the wildcard IP and port values
        # Remove rules that are udp or tcp with empty flags that have wildcard src and dst port and with one wildcard IP
        if(rule.header["proto"] == "udp" or (rule.header["proto"] == "tcp" and len(rule.flags) == 0)  
            and (len(rule.header["src_port"]) == 1 and len(rule.header["dst_port"]) == 1 
            and rule.header["src_port"][0] == (range(0, 65536), True) and rule.header["dst_port"][0] == (range(0, 65536), True))
            and ((len(rule.header["src_ip"]) == 1 and rule.header["src_ip"][0] == ('0.0.0.0/0', True))
            or  (len(rule.header["dst_ip"]) == 1 and rule.header["dst_ip"][0] == ('0.0.0.0/0', True)))):
            print("-------")
            print(rule.header)
            print(rule.flags)
            print("-------")
            continue
        
        final_rules.append(rule)
    return final_rules




