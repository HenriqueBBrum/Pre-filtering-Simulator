import attr
import radix
import re

# Class representing a NIDS rule.
class Rule(object):
    def __init__(self, rule, header, options, has_negation):
        self.id = None
        self.rule = rule # Original rule string

        self.header = header
        self.options = options

        self.has_negation = has_negation # IP or port is negated

        self.data = {"header": self.header, "options": self.options}
        self.all = self.data

    def rule_to_string(self):    
        return str(self.header)+str(self.options)
    

    def __getitem__(self, key):
        if key == 'all':
            return self.data
        else:
            return self.data[key]

        
ip_flags_dict = {
    'M': 1,
    'D': 2,
    'R': 4
}

tcp_flags_dict = {
    'F': 1,
    'S': 2,
    'R': 4,
    'P': 8,
    'A': 16,
    'U': 32,
    'E': 64,
    'C': 128,
}
# Class that contains all the fields required to match against networking packets 
class RuleToMatch(object):
    def __init__(self, pkt_header_fields, payload_fields, priority_list=[], sid_rev_list=[]):
        self.pkt_header_fields = pkt_header_fields
        self.payload_fields = payload_fields

        self.adjust_fields_for_pkt_matching()
      
        self.priority_list = priority_list
        self.sid_rev_list = sid_rev_list


    def adjust_fields_for_pkt_matching(self):
        self.pkt_header_fields['src_ip'] = self.__convert_ip_list_to_radix_tree(self.pkt_header_fields['src_ip'])
        self.pkt_header_fields['dst_ip'] = self.__convert_ip_list_to_radix_tree(self.pkt_header_fields['dst_ip'])

        self.pkt_header_fields['src_port'] = self.__turn_port_list_into_dict(self.pkt_header_fields['src_port'])
        self.pkt_header_fields['dst_port'] = self.__turn_port_list_into_dict(self.pkt_header_fields['dst_port'])

        if "ip_proto" in self.pkt_header_fields:
            rule_ip_proto = self.pkt_header_fields["ip_proto"]
            comparator = re.search("^[!|>|<]", rule_ip_proto)
            comparator = comparator.group(0) if comparator != None else ""
            self.pkt_header_fields["ip_proto"] = {"data": re.search("[\d]+", rule_ip_proto).group(0), "comparator": comparator}
        
        for key in ["ttl", "id", "seq", "ack", "window", "itype", "icode", "icmp_id", "icmp_seq"]:
            if key in self.pkt_header_fields:
                value = self.pkt_header_fields[key]
                comparator = re.search("[^\d]+", value)
                comparator = comparator.group(0) if comparator != None else ""
                self.pkt_header_fields[key] = {"data": re.findall("[\d]+", value), "comparator": comparator}

        if "fragbits" in self.pkt_header_fields:
            fragbits = re.sub("[\+\*\!]", "", self.pkt_header_fields["fragbits"])
            fragbits_num = sum(ip_flags_dict[flag] for flag in fragbits)
            comparator = re.sub("[MDR.]", "", self.pkt_header_fields["fragbits"])
            self.pkt_header_fields["fragbits"] = {"data": fragbits_num, "comparator": comparator}

        if "flags" in self.pkt_header_fields:
            flags_to_match = self.pkt_header_fields["flags"]
            exclude = ""
            if type(self.pkt_header_fields["flags"]) is list:
                flags_to_match = self.pkt_header_fields["flags"][0]
                exclude = self.pkt_header_fields["flags"][1]

            flags_to_match = re.sub("[1]", "C", flags_to_match)
            flags_to_match = re.sub("[2]", "E", flags_to_match)
            tcp_flags = re.sub("[\+\*\!]", "", flags_to_match)
            tcp_flags_num = sum(tcp_flags_dict[flag] for flag in tcp_flags) 
            comparator = re.sub("[a-zA-Z.]", "", flags_to_match)
            self.pkt_header_fields["flags"] = {"data": tcp_flags_num, "comparator": comparator, "exclude": exclude}

        if self.payload_fields:
            self.__adjust_payload_matching_fields()


    def __convert_ip_list_to_radix_tree(self, ips):
        must_match = None
        rtree = radix.Radix()
        for ip in ips:
            rnode = rtree.add(ip[0])
            rnode.data["match"] = ip[1]

            must_match = ip[1] if must_match == None else must_match | ip[1]

        return (rtree, must_match)

    # Individual ports are saved in a dict for quick comparsions, ranges in a list for linear search, and a bool to signal if all values are accetable
    def __turn_port_list_into_dict(self, ports):
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


    def __adjust_payload_matching_fields(self):
        temp_payload_fields = {}
        if "dsize" in self.payload_fields:
            value = self.payload_fields["dsize"][1]
            comparator = re.search("[^\d]+", value)
            comparator = comparator.group(0) if comparator != None else ""
            temp_payload_fields["dsize"] = {"data": re.findall("[\d]+", value), "comparator": comparator}

        if "content_pcre" in self.payload_fields:
            if type(self.payload_fields["content_pcre"]) != list:
                self.payload_fields["content_pcre"] = [self.payload_fields["content_pcre"]]

            content_pcre = []
            for match_pos, match in self.payload_fields["content_pcre"]:
                if match[0] == 0:
                    match_str = self.__clean_content_and_hexify(match[3], "nocase" in match[3])
                    modifiers = self.__adjust_content_modifiers(match[4])
                    content_pcre.append((match[0], match[1], match[2], match_str, modifiers))
                else:
                    content_pcre.append((match[0], match[1], match[2], match[3], match[4]))
                    
            temp_payload_fields["content_pcre"] = content_pcre

        self.payload_fields = temp_payload_fields



    # Turn content to hex string. Ex: "A|4E 20 3B| Ok" - > "414e203b4f6b"
    def __clean_content_and_hexify(self, str_to_match, nocase=False):
        clean_content = ""
        temp_content = ""
        hex_now, escaped = False, False
        add_to_clean_content = False
        for char in str_to_match:
            if hex_now or char == '|':
                temp_content, hex_now, add_to_clean_content = self.__process_hex(char, temp_content, nocase, hex_now)
                if add_to_clean_content: 
                    clean_content+=temp_content
                    temp_content=""
            else:
                temp_content, escaped = self.__process_non_hex_section(char, temp_content, nocase, escaped)
        
        clean_content+=temp_content.encode('utf-8').hex()
        return clean_content

    # Process hex number of content. Mainly checking if it is required to consider the case
    def __process_hex(self, char, temp_content, nocase, hex_now):
        add_to_clean_content = False
        # Check if hex section has started or finished. Either way, add existing text to the final string
        if char == '|':  
            if hex_now:
                if nocase and (int(temp_content, 16) >= 65 and int(temp_content, 16) <= 90): # If it is nocase and the remaining text is a letter
                    temp_content=hex(int(temp_content, 16) + 32)[2:]
            else:
                temp_content = temp_content.encode('utf-8').hex() # If hex section has started now, add the plain text in temp to the final string

            hex_now = not hex_now
            add_to_clean_content = True
        elif char == " ": # Add hex bytes to final string and adjust case if required
            if nocase and (int(temp_content, 16) >= 65 and int(temp_content, 16) <= 90):
                temp_content=hex(int(temp_content, 16) + 32)[2:] # Turn hex alpha to lower case: (hex, dec, char) - (0x41, 65, A) -> (0x61, 97, a)
            add_to_clean_content=True
        else:
            temp_content+=char.lower()

        return temp_content, hex_now, add_to_clean_content

    # Process the strings of the "content" field
    def __process_non_hex_section(self, char, temp_content, nocase, escaped):
        if nocase and char.isupper():
            char = char.lower()

        # Add escaped char or add '/' since it was not used to escape a char
        if escaped and (char == ';' or char == '"' or char == '\\'):
            temp_content+=char
        elif escaped:
            temp_content+='/'

        escaped = False

        # Check if it is the escape char : "/" otherwise just add to the string
        if char == '/':
            escaped = True
        else:
            temp_content+=char

        return temp_content, escaped

    def __adjust_content_modifiers(self, modifiers):
        modifiers_dict = None
        if modifiers:
            modifiers_dict = {}
            for item in modifiers.split(","):
                modifier_name = item
                modifier_value = True
                if item == "fast_pattern":
                    continue

                if item != "nocase":
                    split_modifier = item.split(" ")
                    modifier_name = split_modifier[0]
                    modifier_value = split_modifier[1]

                if modifier_name in modifiers_dict:
                    raise ValueError("Two identical modifiers in the same content matching: ", modifiers_dict)

                modifiers_dict[modifier_name] = modifier_value

            if ("offset" in modifiers_dict or "depth" in modifiers_dict) and ("within" in modifiers_dict or "distance" in modifiers_dict):
                raise ValueError("Modifiers are not correctly configured: ", modifiers_dict)
            
        return modifiers_dict
        

    def sids(self):
        return list(set(self.sid_rev_list))