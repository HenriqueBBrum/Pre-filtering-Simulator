import re
import ipaddress
import collections
import shlex

from snort_rule_parser.rule_related_classes import Rule

try:
    from .validation_dicts import Dicts
except ImportError:
    from compiler.snort_rule_parser.validation_dicts import Dicts

        
### 
#   Parses a Snort/Suricata rule and returns two dictionaris:
#       One containing the header values
#       THe other containing the options values
#   If there are invalid option in the rule an Error is raised. 
###
class Parser(object):

    MIN_PORT = 0
    MAX_PORT = 65535

    def __init__(self):
        self.dicts = Dicts()
    
    def parse_rule(self, rule: str) -> Rule:
        header, has_negation = self.__parse_header(rule)
        options = self.__parse_options(rule) 

        if options["sid"][1][0] == "498":
            header = {}

        return Rule(rule, header, options, has_negation)
    
    def str_rule_id(self):
        return str(self.header)+self.options["flags"]
       

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
            raise ValueError("Header is missing, or unparsable")
        
        header = list(filter(None, header))
        if not len(header) == 7 and not len(header) == 2:
            msg = "Snort rule header is malformed %s" % header
            raise ValueError(msg)
        
        return self.__header_list_to_dict(header), has_negation
    
    # Returns a string with the following format: "action proto src_ip src_port direction dst_ip dst_port"
    def __get_header(self, rule):
        if re.match(r'(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))', rule.lstrip()): #simplify
            header = rule.split('(', 1)
            return header[0]
        else:
            msg = 'Error in syntax, check if rule'\
                  'has been closed properly %s ' % rule
            raise SyntaxError(msg)
    
    # Receives a list "[<action>, <proto>, <src_ip>, <src_port>, <direction>, <dst_ip>, <dst_port>", parses and validates each field
    # Returns a dictionary
    def __header_list_to_dict(self, header):
        header_dict = {}
        
        header_dict["action"] = self.__action(header[0])
        header_dict["proto"] = self.__proto(header[1])
        if len(header) == 2:
            header_dict["src_ip"] = self.__ip("any")
            header_dict["src_port"] = self.__port("any")
            header_dict["direction"] = self.__direction("<>")
            header_dict["dst_ip"] = self.__ip("any")
            header_dict["dst_port"] = self.__port("any")
            return header_dict

        header_dict["src_ip"] = self.__ip(header[2])
        header_dict["src_port"] = self.__port(header[3])
        header_dict["direction"] = self.__direction(header[4])
        header_dict["dst_ip"] = self.__ip(header[5])
        header_dict["dst_port"] = self.__port(header[6])

        return header_dict

    # Validates actions
    @staticmethod
    def __action(action: str) -> str:
        actions = {
            "alert",
            "log",
            "pass",
            "activate",
            "dynamic",
            "drop",
            "reject",
            "sdrop",
            "rewrite"
        }

        if action in actions:
            return action
        else:
            msg = "Invalid action specified %s" % action
            raise ValueError(msg)

    # Validates protocols/services that are used by the Snort 3 Community and Registered rulesets
    @staticmethod
    def __proto(proto: str) -> str:
        protos = {
            "tcp",
            "udp",
            "icmp",
            "ip", 
            "http",
            "file",
            "smtp",
            "ssh",
            "ssl"
        }

        if proto.lower() in protos:
            return proto
        else:
            msg = "Unsupported Protocol %s " % proto
            raise ValueError(msg)

    # Parses one IP or a list of IPs. 
    # Each input IP turns to the following output (<value>, <bool>) 
    # <value> is the actual IP and <bool> indicates if the actual value or the negatated value should be used
    def __ip(self, ip):
        parsed_ips = []
        if isinstance(ip, str):
            if ip == "any":
                return [("0.0.0.0/0", True)]
            elif ip == "!any":
                raise Exception("Invalid IP %s" % ip)
            
            if re.search(r",|(!?\[.*\])", ip):
                parsed_ips = self.__flatten_list(ip, self.__parse_ip)
            else:
                parsed_ips.append(self.__parse_ip(ip, True))
                
            if not self.__validate_ip(parsed_ips):
                raise ValueError("Unvalid ip or variable: %s" % ip)        
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
                return [(range(self.MIN_PORT, self.MAX_PORT+1), True)]
            elif port == "!any":
                raise Exception("Invalid ports %s" % port)
            
            if re.search(r",|(!?\[.*\])", port):
                parsed_ports = self.__flatten_list(port, self.__parse_port)
            else:
                parsed_ports.append(self.__parse_port(port, True))
                
            if not self.__validate_port(parsed_ports):
                raise ValueError("Unvalid port or variable: %s" % port)
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
                raise ValueError("Wrong range values")
            
            if range_[1] == "":
                return(range(int(range_[0]), self.MAX_PORT+1), bool(~(local_bool ^ parent_bool)+2))
            elif range_[0] == "":
                return(range(self.MIN_PORT, int(range_[1])+1), bool(~(local_bool ^ parent_bool)+2))
            
            lower_bound = int(range_[0]) if int(range_[0]) > self.MIN_PORT else self.MIN_PORT
            upper_bound = int(range_[1]) if int(range_[1]) < self.MAX_PORT else self.MAX_PORT
            return (range(lower_bound, upper_bound+1), bool(~(local_bool ^ parent_bool)+2))
        
        return (port, bool(~(local_bool ^ parent_bool)+2))
    
    # Validates if the port is an OS variable (e.g. $HTTP_PORTS) or inside the valid port range
    def __validate_port(self, ports):
        for port, bool_ in ports:
            if isinstance(port, str):
                if not self.dicts.port_variables(port) and not re.match(r"^\$+", port):
                    if int(port) < self.MIN_PORT or int(port) > self.MAX_PORT:
                        raise ValueError("Port is out of range %s" % port)
            elif isinstance(port, range):    
               if  port.start > port.stop:
                   raise ValueError("Invalid port range %s" % port)
               
               if (port.start < self.MIN_PORT or port.start > self.MAX_PORT+1) or (port.stop < self.MIN_PORT or port.stop > self.MAX_PORT+1):
                    raise ValueError("Port is out of range %s" % port)
               
        return True
              
    # Validates the direction
    def __direction(self, direction):
        directions = {"->": "unidirectional",
                        "<>": "bidirectional"}

        if direction in directions:
            return directions[direction]
        else:
            msg = "Invalid direction variable %s" % direction
            raise ValueError(msg)
        
    ### OPTIONS PARSING FUNCTIONS ###
    # Parses the rule body or options, validates it and returns a dictionary
    def __parse_options(self, rule):
            options_list = self.__get_options(rule)
            options_dict = collections.OrderedDict()
            current_buffer = ""
            for index, option_string in enumerate(options_list):
                key = option_string
                value = ""
                
                if ':' in option_string:
                    key, value = option_string.split(":", 1)

                if self.dicts.sticky_buffers(key):
                    current_buffer = key
                          
                if key == "content":
                    negate = re.search('^!', value)
                    content = re.search('"([^"]*)"', value).group(0)[1:-1]
                    modifiers = re.search('[\w, ]*$', value).group(0)[1:]
                    value = [current_buffer]
                    value.append(False if negate else True)
                    value.append(content)
                    if modifiers:
                        value.append(modifiers)   
                elif key!="pcre":
                    value = value.split(",")

                if self.dicts.payload_options(key): 
                    if key in options_dict:
                        options_dict[key].append((index, value))
                    else:
                        options_dict[key] = [(index, value)]
                    continue

                options_dict[key] = (index, value)

            self.__validate_options(options_dict)
            return options_dict
    
    # Turns the options string, i.e. "(<option>: <settings>; ... <option>: <settings>;)"), into a list of options
    def __get_options(self, rule):
        options = "{}".format(rule.split('(', 1)[-1].lstrip().rstrip())
        if not options.endswith(")"):
            raise ValueError("Snort rule options is not closed properly, "
                             "you have a syntax error")

        op_list = list()
        option = ""
        last_char = ""

        for char in options.rstrip(")"):
            if char != ";":
                option = option + char

            if char == ";" and last_char != "\\":
                op_list.append(option.strip())
                option = ""

            last_char = char
        return op_list
    
    # Verifies if the option key is valid or if the classtype option has a valid value
    def __validate_options(self, options):
        for key, data in options.items():
            if self.dicts.payload_options(key):
                for index, value in data:                
                    valid_option = self.dicts.verify_option(key)
                    if not valid_option[1]:
                        raise ValueError("Unrecognized option: %s" % key)
            else:
                valid_option = self.dicts.verify_option(key)
                if not valid_option[1]:
                    raise ValueError("Unrecognized option: %s" % key)
                
                if key=="classtype":
                    classification = self.dicts.classtypes(data[1][0]) # {"classtype : (index, [value])"}
                    if not classification:
                        raise ValueError("Unrecognized rule classification: %s" % value)
            
        return options