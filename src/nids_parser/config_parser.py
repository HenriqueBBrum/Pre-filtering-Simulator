### This file contains a class that parsers the network variables defined by Snort and Suricata
## The config files to parse are based on Snort 2.* config

import re
import sys

MIN_PORT = 0
MAX_PORT = 65535

class NIDSConfiguration():
    ports = {}
    ip_addresses = {}
    classification_priority = {}

    def __init__(self, configuration_dir):
        self.configuration_dir = configuration_dir

        self.__parse()
    
    # Parses the ip and port variables file and the classification priority
    def __parse(self):
        ip_port_vars= "{}/ip_port_vars.config".format(self.configuration_dir) 
        priority_classification_file = "{}/classification.config".format(self.configuration_dir)
        self.__parse_ip_port_vars(ip_port_vars)
        self.__parse_classification_priority(priority_classification_file)

    # Translates the ip and port variables to their real values (e.g: $HOME_NET ->[10.0.0.1, 10.0.02, ...])
    # For more info, go to -> https://suricata.readthedocs.io/en/suricata-4.1.4/rules/intro.html#source-and-destination
    def __parse_ip_port_vars(self, ip_port_vars):
        with open(ip_port_vars, 'r') as config_file:
            lines  = config_file.readlines()
            for line in lines:
                if line.startswith("ipvar"):
                    ipvar_line_elements = line.split(" ", 2) # ipvar NAME IPs
                    name = ipvar_line_elements[1]
                    self.ip_addresses[name] = self.__parse_ips(ipvar_line_elements[2].rstrip('\n').replace(" ",""))
                elif line.startswith("portvar"):
                    portvar_line_elements = line.split(" ", 2) # portvar NAME IPs
                    name = portvar_line_elements[1]
                    self.ports[name] = self.__parse_ports(portvar_line_elements[2].rstrip('\n').replace(" ",""))
           
    # Parses one IP or a list of IPs
    ### Does not work with lists within another inner list since they aren't used in NIDS rules, e.g. [[...], [..., [...]]]
    ### TODO validate input line?
    def __parse_ips(self, raw_ips):
        if raw_ips == "any":
            return [("0.0.0.0/0", True)]
        elif raw_ips == "!any":
            raise ValueError("Invalid IP ", raw_ips)
        
        parsed_ips = []
        if re.search(r",|(!?\[.*\])", raw_ips):
            parsed_ips = self.__flatten_list(raw_ips, self.__parse_ip)
        else:
            parsed_ips.extend(self.__parse_ip(raw_ips, True))

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
            nested_lists = re.split(r",(!?\[.*\])", _list)
            nested_lists = filter(None, nested_lists)
            for _lists in nested_lists: 
                if re.match(r"^\[|^!\[", _lists): # If there are more sub-lists in lower levels process them # match is just the first one 
                    flattened_lists = self.__flatten_list(_lists, self.__parse_ip)
                    for value, bool_ in flattened_lists:
                        return_list.append((value, bool(~(bool_ ^ list_deny)+2)))
                else:
                    for element in _lists.split(","):
                        return_list.extend(individual_parser(element, list_deny))
        else:
            for element in _list.split(","):
                return_list.extend(individual_parser(element, list_deny))

        return return_list

    # Parses individual IPs. 
    # Obs: Variable inputs (e.g. $HOME_NET) even if they are a list, they are already parsed lists with no sublists and other vars. 
    def __parse_ip(self, raw_ip, parent_bool):
        local_bool = True
        if raw_ip.startswith("!"):
            raw_ip = raw_ip[1:]
            local_bool = False

        if re.match(r'^!?\$', raw_ip):
            ips = self.ip_addresses[re.sub(r'^!?\$', '', raw_ip)]
            return_ips = []
            bool_multiplier = bool(~(local_bool ^ parent_bool)+2)
            for value, bool_ in ips:
                return_ips.append((value, bool(~(bool_ ^ bool_multiplier)+2)))  #xnor because !! = true

            return return_ips
        
        return [(raw_ip, bool(~(local_bool ^ parent_bool)+2))]

    # Parses one port or a list of ports
    def __parse_ports(self, raw_ports):
        if raw_ports == "any":
            return [(range(MIN_PORT, MAX_PORT+1), True)]
        elif raw_ports == "!any":
            raise Exception("Invalid ports")
        
        parsed_ports = []
        if re.search(r",|(!?\[.*\])", raw_ports):
            parsed_ports = self.__flatten_list(raw_ports, self.__parse_port)
        else:
             parsed_ports.extend(self.__parse_port(raw_ports, True))

        return parsed_ports   

    # Parses a raw port that might contain the following operators: "!" (negation), ":" (range), "$" (variable)
    def __parse_port(self, raw_port, parent_bool):
        local_bool = True
        if raw_port.startswith("!"):
            raw_port = raw_port[1:]
            local_bool = False

        # Replaces the variable for the true values and updates the bool indicating the negation operator
        if re.match(r'^!?\$', raw_port):
            ports = self.ports[re.sub(r'^!?\$', '', raw_port)]
            return_ports = []
            bool_multiplier = bool(~(local_bool ^ parent_bool)+2)
            for value, bool_ in ports:
                return_ports.append((value, bool(~(bool_ ^ bool_multiplier)+2)))  #xnor because !! = true
            return return_ports
        # Replaces a port range with the actual values
        elif re.match(r'^(!?[0-9]+:|:[0-9]+)', raw_port):
            range_ = raw_port.split(":")
            if len(range_) != 2 or "!" in range_[1]:
                raise ValueError("Wrong range values ", range_)
            
            if range_[1] == "":
                return [(range(int(range_[0]), MAX_PORT+1), bool(~(local_bool ^ parent_bool)+2))]
            elif range_[0] == "":
                return [(range(MIN_PORT, int(range_[1])+1), bool(~(local_bool ^ parent_bool)+2))]
            
            lower_bound = int(range_[0]) if int(range_[0]) > MIN_PORT else MIN_PORT
            upper_bound = int(range_[1]) if int(range_[1]) > MAX_PORT else MAX_PORT
            return [(range(lower_bound, upper_bound+1), bool(~(local_bool ^ parent_bool)+2))]
        
        return [(raw_port, bool(~(local_bool ^ parent_bool)+2))]

    # Reads line by line and parses the lines containing classification priorities (lines starting with "config classification:")
    def __parse_classification_priority(self, priority_classification_file):    
        with open(priority_classification_file, 'r') as class_file:
            lines  = class_file.readlines()
            for line in lines:
                if not line.startswith("config classification:"):
                    continue

                class_info = line.replace("config classification: ", "").split(',') # shortname,short_description,priority
                self.classification_priority[class_info[0]] = int(class_info[2])
            
