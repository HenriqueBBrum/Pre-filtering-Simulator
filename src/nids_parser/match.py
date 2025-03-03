import radix
import re
import socket

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
    '1': 128,
    '2': 64,
    'E': 64,
    '1': 128,
    'C': 128,
}

ipotps_to_hex = {"eol":0x00, "nop":0x01,  "sec": 0x02, "rr": 0x07,  "ts": 0x44, "lsrr": 0x83, "lsrre": 0x83,  "esec": 0x85, "satid": 0x88, "ssr": 0x89, "any": 0XFF}

native_pcre_modifiers = {'i', 's', 'm', 'x'}

# Class that contains all the fields required to match against networking packets 
class Match(object):

    def __init__(self, header_fields, payload_fields, pre_filtering_scenario="full"):
        self.header_fields = header_fields
        self.payload_fields = payload_fields

        self.header_key = header_fields["ip_port_key"]
        self.service = None
        if "service" in self.payload_fields:
            self.service = self.payload_fields["service"][1] # Get the services only 

        self.priority_list = []
        self.sid_rev_list = []

        self.__adjust_header_for_match()
        self.__adjust_payload_for_match(pre_filtering_scenario)
      
    # How to deal with multiple values of a field?
    def __get_header_field_value(self, key, pos=0):
        return self.header_fields[key][pos][1]

    # Adjust header fields for quick matching against packets
    def __adjust_header_for_match(self):
        self.header_fields['src_ip'] = self.__convert_ip_list_to_radix_tree(self.header_fields['src_ip'])
        self.header_fields['dst_ip'] = self.__convert_ip_list_to_radix_tree(self.header_fields['dst_ip'])

        self.header_fields['sport'] = self.__turn_port_list_into_dict(self.header_fields['sport'])
        self.header_fields['dport'] = self.__turn_port_list_into_dict(self.header_fields['dport'])

        # Determine the data and comparator for the "ip_proto" keyword
        if "ip_proto" in self.header_fields:
            rule_ip_proto = self.__get_header_field_value("ip_proto")
            comparator = re.search("^[!|>|<]", rule_ip_proto)
            comparator = comparator.group(0) if comparator != None else ""
            self.header_fields["ip_proto"] = {"data": int(re.search("[\d]+", rule_ip_proto).group(0)), "comparator": comparator}
        
        # Determine the data and comparator for the "ttl", "id", "seq", "ack", "window", "itype", "icode", "icmp_id", "icmp_seq" keywords
        for key in ["ttl", "id", "seq", "ack", "window", "itype", "icode", "icmp_id", "icmp_seq"]:
            if key in self.header_fields:
                value = self.__get_header_field_value(key)
                comparator = re.search("[^\d]+", value)
                comparator = comparator.group(0) if comparator != None else ""
                self.header_fields[key] = {"data": re.findall("[\d]+", value), "comparator": comparator}


        # Determine the data and comparator for the "fragbits" keyword
        if "ipopts" in self.header_fields:
            self.header_fields["ipopts"] = ipotps_to_hex[self.__get_header_field_value("ipopts")]

        # Determine the data and comparator for the "fragbits" keyword
        if "fragbits" in self.header_fields:
            fragbits = re.sub("[\+\*\! ]", "", self.__get_header_field_value("fragbits"))
            fragbits_num = sum(ip_flags_dict[flag] for flag in fragbits)
            comparator = re.sub("[MDR. ]", "", self.__get_header_field_value("fragbits"))
            self.header_fields["fragbits"] = {"data": fragbits_num, "comparator": comparator}

        # Determine the data, comparator and flags to exclude for the (TCP) "flags" keyword
        if "flags" in self.header_fields:
            flags_to_match = self.__get_header_field_value("flags")
            exclude = ""
            if type(flags_to_match) is list:
                flags_to_match = self.__get_header_field_value("flags")[0]
                exclude = self.__get_header_field_value("flags")[1]
            
            tcp_flags = re.sub("[\+\*\! ]", "", flags_to_match)
            tcp_flags_num = sum(tcp_flags_dict[flag] for flag in tcp_flags)
            exclude_num = sum(tcp_flags_dict[flag] for flag in exclude)  
            comparator = re.sub("[a-zA-Z.]", "", flags_to_match)
            self.header_fields["flags"] = {"data": tcp_flags_num, "comparator": comparator, "exclude": exclude_num}

    # Converts IP list to a radix tree for quick? search
    def __convert_ip_list_to_radix_tree(self, ips):
        must_match = None
        rtree = radix.Radix()
        for ip in ips:
            rnode = rtree.add(ip[0])
            rnode.data["match"] = ip[1] # Should the pkt's IP actually match the rules?

            must_match = ip[1] if must_match == None else must_match | ip[1]

        return (rtree, must_match)

    # Individual ports are saved in a dict for quick comparsions, ranges in a list for linear search, and a bool to signal if a port should've matched something
    def __turn_port_list_into_dict(self, ports):
        must_match = None
        individual_ports = {}
        port_ranges = []
        for port in ports:
            if isinstance(port[0], range):
                port_ranges.append(port)
            else:
                individual_ports[int(port[0])] = port[1]

            must_match = port[1] if must_match == None else must_match | port[1]

        return (individual_ports,port_ranges,must_match)
    

    # Adjust the "dsize" and "content_pcre" rule data
    def __adjust_payload_for_match(self, pre_filtering_scenario):
        if "dsize" in self.payload_fields:
            value = self.payload_fields["dsize"][0][1] # Options/Paylod_fields are stored as {"key": [(index, value), ]}
            comparator = re.search("[^\d]+", value)
            comparator = comparator.group(0) if comparator != None else ""
            self.payload_fields["dsize"] = {"data": re.findall("[\d]+", value), "comparator": comparator}

        final_content_list = []
        if "content" in self.payload_fields:
            fast_pattern_match = None
            for content_pos, content in self.payload_fields["content"]:
                modifiers, fast_pattern = self.__parse_content_modifiers(content[2])
                match_str = self.__hexify_content(content[1], "nocase" in modifiers).encode()
                final_content_list.append((content[0], match_str, modifiers)) # negation, string, modifiers
                if fast_pattern:
                    fast_pattern_match = final_content_list[-1]
        
            self.payload_fields["content"] = final_content_list

            self.__apply_pre_filtering_scenario(fast_pattern_match, pre_filtering_scenario)

        pcre = []
        if "pcre" in self.payload_fields:
            for match_pos, match in self.payload_fields["pcre"]:
                parsed_pcre_str, nids_modifiers = self.__parse_pcre_modifiers(match[1], match[2])
                pcre.append((match[0], parsed_pcre_str.encode(), nids_modifiers))

            self.payload_fields["pcre"] = pcre
        
    # Parse content modifiers
    def __parse_content_modifiers(self, modifiers):
        modifiers_dict = {}
        fast_pattern = False
        if modifiers:
            modifiers_dict = {}
            for item in modifiers:
                modifier_name = item
                modifier_value = True
                if item == "fast_pattern":
                    fast_pattern = True
                    continue

                if item != "nocase":
                    modifier_name = re.search('^[a-zA-Z]*', item).group(0)
                    modifier_value = re.search('\d*$', item).group(0)

                if modifier_name in modifiers_dict:
                    raise Exception("Two identical modifiers in the same content matching: ", modifiers_dict)

                modifiers_dict[modifier_name] = modifier_value

            if ("offset" in modifiers_dict or "depth" in modifiers_dict) and ("within" in modifiers_dict or "distance" in modifiers_dict):
                raise Exception("Modifiers are not correctly configured: ", modifiers_dict)
            
        return modifiers_dict, fast_pattern

    # Converts content to hex only
    def __hexify_content(self, content, nocase):
        clean_content, temp_str = "", ""
        escaped = False
        i = 0
        while i < len(content):
            # Handle escape chars
            if escaped and (content[i] == ';' or content[i] == '"' or content[i] == '\\'):
                clean_content+=format(ord(content[i]), "x")
                i+=1
            elif escaped:
                clean_content+=format(ord('/'), "x") # Add previously missing '/'

            escaped = False

            # Get hex numbers
            if content[i] == '|' and i+1<len(content):
                i+=1
                while content[i] != '|':
                    if content[i] != ' ':
                        temp_str+=content[i]

                    if len(temp_str) == 2:
                        temp = int(temp_str, 16)
                        if nocase and (temp >= 65 and temp <=90):
                            clean_content+=(f'{(temp+32):x}'.upper())
                        else:
                            clean_content+=temp_str
                        temp_str = ""

                    i+=1
            else:
                if content[i] == '/':
                    escaped = True

                if not escaped:
                    clean_content+=(format(ord(content[i].lower()), "x") if nocase else format(ord(content[i]), "x"))

            i+=1
        return clean_content
        
    ## Add pcre modifiers to the pcre string since the re module can process them
    # Possible pcre modifiers as detailed by Snort: i,s,m,x,A,E,G,O,R
    # Native pcre modifiers supported by Python 'i', 's', 'm', 'x' 
    # Modifier G (Ungreedy) and D are not supported by python. Modifier O appear to be only required for the Snort engine
    # Suricata supports different modifiers to compar with specific HTTP sections
    def __parse_pcre_modifiers(self, pcre_string, modifiers):
        if not modifiers:
            return pcre_string, modifiers

        if len(set(modifiers)) != len(modifiers):
            raise Exception("PCRE string with duplicate modifiers, fix it. PCRE: ", pcre_string, " modifiers: ", modifiers)

        prepend_modifiers, snort_only_modifiers = "", ""
        for char in modifiers:
            if char in native_pcre_modifiers:
                prepend_modifiers+=char
            elif char == 'A' and pcre_string[0] != '^':
                pcre_string = '^' + pcre_string
            elif char == 'R':
                snort_only_modifiers = char

        if prepend_modifiers:
            pcre_string = "(?"+prepend_modifiers+')'+pcre_string
        return pcre_string, snort_only_modifiers

        
    def __apply_pre_filtering_scenario(self, fast_pattern_match, pre_filtering_scenario):
        final_content_pcre = []
        # if pre_filtering_scenario == "first":
        #     final_content_pcre = [content_pcre[0]]
        # elif pre_filtering_scenario =="longest":
        #     longest, size = None, 0
        #     for content in content_pcre:
        #         if len(content[3]) > size:
        #             longest = content
        #             size = len(content[3])

        #     final_content_pcre = [longest]
        # elif pre_filtering_scenario =="first_last":
        #     final_content_pcre = [content_pcre[0]] if len(content_pcre) == 1 else [content_pcre[0],content_pcre[-1]]
        # elif pre_filtering_scenario =="first_second":
        #     final_content_pcre = [content_pcre[0]] if len(content_pcre) == 1 else [content_pcre[0],content_pcre[1]]
        # elif pre_filtering_scenario == "fast_pattern":
        #     longest, size = None, 0   
        #     if fast_pattern_match:
        #         final_content_pcre = [fast_pattern_match] 
        #     else:          
        #         for content in content_pcre:
        #             if len(content[3]) > size:
        #                 longest = content
        #                 size = len(content[3])
                        
        #         final_content_pcre = [longest]
        # else:
        #     final_content_pcre = content_pcre

        return final_content_pcre

    def sids(self):
        return list(set(self.sid_rev_list))