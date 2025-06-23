import re
import ipaddress

from os import listdir
from os.path import isfile, join
from re import search
from copy import deepcopy

import sys
sys.path.append("..")
from utils.validation_dicts import Dicts

MIN_PORT = 0
MAX_PORT = 65535

# Class representing a NIDS rule.
class Rule(object):
    def __init__(self, rule, header, options, has_negation):
        self.str = rule # Original rule string

        self.header = header
        self.options = options

        self.has_negation = has_negation # IP or port is negated

        self.data = {"header": self.header, "options": self.options}
        self.all = self.data

    def __str__(self):
        return "Header: " + str(self.header) + "\nPayload: " + str(self.options)
    
    # Returns value of key in rule options. Option value format: (option_index, [option_index_values])
    def get_simple_option_value(self, key, position=0, default=""):
        try:
            if key in self.options:
                return self.options[key][position]
        except Exception as e:
            print("WARNING -- Error when searching for key {} in rule options \n Returning: {}".format(key, default))
            return default

        
### 
#   Parses Snort/Suricata rules and returns two lists with all the rules parsed:
#       One contains the original rules with minimals changes
#       The other contains only supported rules, without system variables and no bidirectional rules (divided into two) 
#   If there are invalid options in the rule an Error is raised. 
###

regex_unsupported_keywords = "; *(sip_|dce_|base64_|sd_pattern|cvs|md5|sha256|sha512|gtp_|dnp3_|cip_|iec104_|mms_|modbus_|s7commplus|rpc:|ja3_)"
unsupported_rules = 0

class RulesParser(object):
    def __init__(self, simulation_config, nids_config):
        self.dicts = Dicts()

        self.ruleset_path = simulation_config["ruleset_path"]
        self.nids_name = simulation_config["nids_name"]
        self.nids_config = nids_config
        self.remove_generic_rules = True if "header_only" in simulation_config["scenario"] else False

    # Returns two list of rules from one or multiple files. 
    # The first list contains the parsed rules similar as they apperead in the files but saving the values in dictionaries. 
    # The second list contains adjusted bidirectional rules, with port groupping and with the IP and port variables exchanged with the real values.
    def parse_rules(self, ignored_rule_files={}):
        files = []
        if isfile(self.ruleset_path):
            files =  [self.ruleset_path]
        else:
            for file in listdir(self.ruleset_path):
                file_full_path = join(self.ruleset_path, file)
                if isfile(file_full_path) and ".rules" in file and file not in ignored_rule_files:
                    files.append(join(self.ruleset_path, file))

        original_rules, modified_rules = [], []
        for rule_file in files:
            parsed_rules, temp_modified_rules = self.__read_rules_from_file(rule_file)
            original_rules.extend(parsed_rules)
            modified_rules.extend(temp_modified_rules)
        
        global unsupported_rules
        print("Unsupported: ", unsupported_rules)
        return original_rules, modified_rules

    # Parse each rule from a rule file
    def __read_rules_from_file(self, rule_file):
        parsed_rules, modified_rules = [], []
        with open(rule_file, 'r') as file:
            lines = file.readlines()
            for line in lines:
                if line.startswith("#") or len(line)<=1:
                    continue

                header, has_negation = self.__parse_header(line)
                options = self.__parse_options(line) 
                parsed_rule = Rule(line, header, options, has_negation)
                parsed_rules.append(parsed_rule)
               
                if search(regex_unsupported_keywords, line):
                    global unsupported_rules
                    unsupported_rules+=1
                    continue

                cp_rule = deepcopy(parsed_rule)
                cp_rule.header["src_ip"] = self.__replace_system_variables(cp_rule.header["src_ip"],  self.nids_config.ip_addresses)
                cp_rule.header["sport"] =  self.__replace_system_variables(cp_rule.header["sport"],  self.nids_config.ports)
                cp_rule.header["dst_ip"] =  self.__replace_system_variables(cp_rule.header["dst_ip"], self.nids_config.ip_addresses)
                cp_rule.header["dport"] =  self.__replace_system_variables(cp_rule.header["dport"],  self.nids_config.ports)

                if self.remove_generic_rules:
                    any_fields = [
                        any(ip[0] == '0.0.0.0/0' for ip in cp_rule.header["src_ip"]),
                        any(ip[0] == '0.0.0.0/0' for ip in cp_rule.header["dst_ip"]),
                        any(ip[0] == range(0, 65536) for ip in cp_rule.header["sport"]),
                        any(ip[0] == range(0, 65536) for ip in cp_rule.header["dport"]),
                    ]
                    if sum(any_fields) > 0: # 2
                        continue

                if cp_rule.header.get("direction") == "bidirectional":
                    cp_rule.header["direction"] = "unidirectional"

                    swap_dir_rule = deepcopy(cp_rule)
                    temp = cp_rule.header["ip_port_key"].split("-")
                    swap_dir_rule.header["ip_port_key"] = temp[1]+"-"+temp[0]

                    swap_dir_rule.header["src_ip"], swap_dir_rule.header["dst_ip"] =  swap_dir_rule.header["dst_ip"], swap_dir_rule.header["src_ip"]
                    swap_dir_rule.header["sport"], swap_dir_rule.header["dport"] =  swap_dir_rule.header["dport"], swap_dir_rule.header["sport"]
                    
                    modified_rules.append(cp_rule)
                    modified_rules.append(swap_dir_rule)
                else:
                    modified_rules.append(cp_rule)
        return parsed_rules, modified_rules

    # Substitute system variables for the real values in the config file
    def __replace_system_variables(self, header_field, existing_variables):
        var_sub_results = []
        for value, bool_ in header_field:
            if isinstance(value, str) and "$" in value :
                name = value.replace('$', '')
                variable_values = deepcopy(existing_variables.get(name, "ERROR"))
                if not bool_:
                    for index, (variable_value, variable_value_bool) in enumerate(variable_values):
                        variable_values[index] = (variable_value, bool(~(bool_ ^ variable_value_bool)+2))
                
                var_sub_results.extend(variable_values)
            else:
                var_sub_results.append((value, bool_))

        return var_sub_results
        
    
    ### HEADER PARSING FUNCTIONS ###
    # Parses the rule header, validates it, and returns a dictionary
    def __parse_header(self, rule):
        if self.__get_header(rule):
            header = self.__get_header(rule)
            has_negation =  "!" in header

            # Remove whitespaces between list elements
            if re.search(r"[,\[\]]\s", header): 
                header = re.sub(r",\s+", ",", header)
                header = re.sub(r"\s+,", ",", header)
                header = re.sub(r"\[\s+", "[", header)
                header = re.sub(r"\s+\]", "]", header)
            header = header.split()
        else:
            raise Exception("Header is mising or unparsable")
        
        header = list(filter(None, header))
        if not len(header) == 7 and not len(header) == 2:
            raise Exception("Snort rule header is malformed ", header)
        
        return self.__header_list_to_dict(header), has_negation
    
    # Returns a string with the following format: "action proto src_ip sport direction dst_ip dport"
    def __get_header(self, rule):
        if re.match(r'(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))', rule.lstrip()): #simplify
            header = rule.split('(', 1)
            return header[0]
        else:
            raise SyntaxError("Error in syntax, check if rule has been closed properly ", rule)
    
    # Receives a list "[<action>, <proto>, <src_ip>, <sport>, <direction>, <dst_ip>, <dport>", parses and validates each field
    # Returns a dictionary
    def __header_list_to_dict(self, header):
        header_dict = {}
        
        header_dict["action"] = self.dicts.action(header[0])
        header_dict["proto"] = self.dicts.proto(header[1])
        # Converts some protos to another to have the same name
        if header_dict["proto"] == "http1":
            header_dict["proto"] = "http"
        elif header_dict["proto"] == "ssl":
            header_dict["proto"] = "tls"
        elif header_dict["proto"] == "smb":
            header_dict["proto"] = "netbios-ssn"

        if len(header) == 2: # Rules like: "alert http (...)"
            header_dict["src_ip"] = self.__ip("any")
            header_dict["sport"] = self.__port("any")
            header_dict["direction"] = self.__direction("<>")
            header_dict["dst_ip"] = self.__ip("any")
            header_dict["dport"] = self.__port("any")
            header_dict["ip_port_key"] = "any"+"any"+"-"+"any"+"any"
        else:
            header_dict["src_ip"] = self.__ip(header[2])
            header_dict["sport"] = self.__port(header[3])
            header_dict["direction"] = self.__direction(header[4])
            header_dict["dst_ip"] = self.__ip(header[5])
            header_dict["dport"] = self.__port(header[6])
            header_dict["ip_port_key"] = header[2]+header[3]+"-"+header[5]+header[6]
        return header_dict

    # Parses one IP or a list of IPs. 
    # Each input IP turns to the following output (<value>, <bool>) 
    # <value> is the actual IP and <bool> indicates if the actual value or the negatated value should be used
    def __ip(self, ip):
        parsed_ips = []
        if isinstance(ip, str):
            if ip == "any":
                return [("0.0.0.0/0", True)]
            elif ip == "!any":
                raise ValueError("Invalid IP: ", ip)
            
            if re.search(r",|(!?\[.*\])", ip):
                parsed_ips = self.__flatten_list(ip, self.__parse_ip)
            else:
                parsed_ips.append(self.__parse_ip(ip, True))
                
            if not self.__validate_ip(parsed_ips):
                raise ValueError("Unvalid IP or IP variable: ", ip)        
        return parsed_ips   

    # Removes all sub-lists and parses the individual elements
    def __flatten_list(self, _list, individual_parser):
        list_deny = True
        if _list.startswith("!"):
            list_deny = False
            _list = _list.lstrip("!")
        
        _list = re.sub(r'^\[|\]$', '', _list)
        _list = re.sub(r'"', '', _list)

        return_list = []
        if re.search(r"(\[.*\])", _list): # If there is(are) a sub-list(s) process it(them)
            _list = re.sub(r',', '', _list)
            nested_lists = re.split(r"(!?\[.*\])", _list)
            nested_lists = filter(None, nested_lists)
            for sublist in nested_lists: 
                if re.match(r"^\[|^!\[", sublist): # If there are more sub-lists in lower levels process them # match is just the first one 
                    flattened_lists = self.__flatten_list(sublist, self.__parse_ip)
                    for value, bool_ in flattened_lists:
                        return_list.append((value, bool(~(bool_ ^ list_deny)+2)))
                else:
                    for element in sublist.split(","):
                        return_list.append(individual_parser(element, list_deny))
        else:
            for element in _list.split(","):
                return_list.append(individual_parser(element, list_deny))

        return return_list
    
    # Parses an individual IP
    def __parse_ip(self, ip, parent_bool):
        local_bool = True
        if ip.startswith("!"):
            ip = ip[1:]
            local_bool = False
        
        return (ip, bool(~(local_bool ^ parent_bool)+2))
        
    # Validate if the IP is either an OS variable (e.g. $HOME_NET) or a valid IPv4 or IPv6 address
    def __validate_ip(self, ips):
        for ip, bool_ in ips:
            if ip[0] != "$":
                try:
                    ipaddress.ip_network(ip, False)
                except:
                    return False
            else:
                if not self.dicts.ip_variables(ip):
                    return False 
        return True
    
    # Parses one port or a list of ports. 
    # Each input port turns to the following output (<value>, <bool>) 
    # <value> is the actual port (or port range) and <bool> indicates if the actual value or the negatated value should be used
    def __port(self, port):
        parsed_ports = []
        if isinstance(port, str):
            if port == "any":
                return [(range(MIN_PORT, MAX_PORT+1), True)]
            elif port == "!any":
                raise ValueError("Invalid ports: ", port)
            
            if re.search(r",|(!?\[.*\])", port):
                parsed_ports = self.__flatten_list(port, self.__parse_port)
            else:
                parsed_ports.append(self.__parse_port(port, True))
                
            if not self.__validate_port(parsed_ports):
                raise ValueError("Unvalid port or variable: ", port)
        return parsed_ports  
     
    # Parses an individual port or port range
    def __parse_port(self, port, parent_bool):
        local_bool = True
        if port.startswith("!"):
            port = port[1:]
            local_bool = False

        if re.match(r'^(!?[0-9]+:|:[0-9]+)', port):
            range_ = port.split(":")
            if len(range_) != 2 or "!" in range_[1]:
                raise ValueError("Wrong range values", range_)
            
            if range_[1] == "":
                return(range(int(range_[0]), MAX_PORT+1), bool(~(local_bool ^ parent_bool)+2))
            elif range_[0] == "":
                return(range(MIN_PORT, int(range_[1])+1), bool(~(local_bool ^ parent_bool)+2))
            
            lower_bound = int(range_[0]) if int(range_[0]) > MIN_PORT else MIN_PORT
            upper_bound = int(range_[1]) if int(range_[1]) < MAX_PORT else MAX_PORT
            return (range(lower_bound, upper_bound+1), bool(~(local_bool ^ parent_bool)+2))
        
        return (port, bool(~(local_bool ^ parent_bool)+2))
    
    # Validates if the port is an OS variable (e.g. $HTTP_PORTS) or inside the valid port range
    def __validate_port(self, ports):
        for port, bool_ in ports:
            if isinstance(port, str):
                if not self.dicts.port_variables(port) and not re.match(r"^\$+", port):
                    if int(port) < MIN_PORT or int(port) > MAX_PORT:
                        raise ValueError("Port is outside TCP and UDP port range: ", port)
            elif isinstance(port, range):    
               if  port.start > port.stop:
                   raise ValueError("Invalid port range: ", port)
               
               if (port.start < MIN_PORT or port.start > MAX_PORT+1) or (port.stop < MIN_PORT or port.stop > MAX_PORT+1):
                    raise ValueError("Port range is outside TCP and UDP port range: ",  port)
               
        return True
              
    # Parses the direction
    def __direction(self, direction):
        directions = {"->": "unidirectional",
                        "<>": "bidirectional"}

        if direction in directions:
            return directions[direction]
        else:
            raise ValueError("Invalid direction variable ", direction)
        

        
    ### OPTIONS PARSING FUNCTIONS ###
    # Parses the rule body or options, validates it and returns a dictionary where each option is now a list. 
    # Parses for both snort and suricata rules
    def __parse_options(self, rule):
        options_list = self.__get_options_as_list(rule)
        options_dict = {}
        current_buffer = "pkt_data"
        snort = True if self.nids_name == "snort" else False

        for option_string in options_list:
            key, value = option_string, ""
            if ':' in option_string:
                key, value = option_string.split(":", 1)
            
            if not self.dicts.is_option(key) or (snort and self.dicts.suricata_only_options(key)):
                raise KeyError("Unrecognized option: ", key)
            
            # Save the current buffer
            if self.dicts.sticky_buffers(key):
                if (snort and self.dicts.supported_snort_sticky_buffers(key)) or \
                    (not snort and self.dicts.supported_suricata_sticky_buffers(key)): # Save the current buffer keyword
                    current_buffer = self.__simplify_buffers(key) 
                else:
                    current_buffer = "pkt_data"
                continue

            # Suricata only: Add content modifiers to the last content option
            if not snort and self.dicts.content_modifiers(key):
                if "content_pcre" not in options_dict:
                    raise Exception("Content modifiers without a content")
                if  options_dict["content_pcre"][-1][0] == 0:
                    options_dict["content_pcre"][-1][-1].append(option_string)
                continue

            if key == "content":
                parsed_value = self.__parse_content(value, current_buffer, snort)
                key = "content_pcre"
            elif key == "pcre":
                parsed_value = self.__parse_pcre(value, current_buffer)
                key = "content_pcre"
            else:
                value = value.split(",")
                parsed_value = value[0] if len(value) == 1 else value
                
            if key not in options_dict:
                if isinstance(parsed_value, list):
                    options_dict[key] = parsed_value
                else:
                    options_dict[key] = [parsed_value]
            else:
                options_dict[key].append(parsed_value)
     
        return options_dict


    # Turns the options string, i.e. "(<option>: <settings>; ... <option>: <settings>;)"), into a list of options
    def __get_options_as_list(self, rule):
        options = "{}".format(rule.split('(', 1)[-1].lstrip().rstrip()) # Get everything after the first '('
        if not options.endswith(")"):
            raise Exception("Rule options is not closed properly, "
                             "you have a syntax error")

        op_list = list()
        option, last_char = "", ""
        for char in options.rstrip(")"):
            if char != ";" or (char == ";" and last_char == "\\"):
                option = option + char

            if char == ";" and last_char != "\\":
                op_list.append(option.strip())
                option = ""

            last_char = char
        return op_list
    
    # Fix buffer names
    def __simplify_buffers(self, buffer_name):
        buffer_name = buffer_name.replace('.', '_')
        if buffer_name == "http_uri_raw":
            return "http_raw_uri"
        elif buffer_name == "http_header_raw":
            return "http_raw_header"
        elif buffer_name == "http_header_names":
            return "http_raw_header"
        elif buffer_name == "http_response_body":
            return "http_server_body"
        elif buffer_name == "http_request_body":
            return "http_client_body"
        
        return buffer_name

    # Parses the "content" and "pcre" fields for the string to match and modifiers
    def __parse_content(self, value, buffer_name, snort):
        negate = re.search('^!', value)
        if negate:
            value = value[1:]

        # Snort has the modifiers within the content keyword
        if snort: 
            re_search = re.search('[\w ,-]*$', value)
            modifiers = []
            if re_search.group(0)[1:]:
                modifiers = re_search.group(0)[1:].split(",") # Remove the first ','
            content = value[:re_search.span()[0]][1:-1]
            parsed_value = (0, buffer_name, False if negate else True, content, modifiers)
        else:
            parsed_value = (0, buffer_name, False if negate else True, value[1:-1], [])

        return parsed_value

    # Fix PCRE parsing for suricata since it has sticky buffers on the options
    def __parse_pcre(self, value, buffer_name):
        negate = re.search('^!', value)
        if negate:
            value = value[1:]

        value = value[1:-1] # Remove '"'
        re_search = re.search('[\w ]*$', value) # Get modifiers at the end
        modifiers = re_search.group(0) 
        pcre = value[1:re_search.span()[0]-1] # Don't return the '/' chars and grab only the PCRE string

        return (1, buffer_name, False if negate else True, pcre, modifiers)
