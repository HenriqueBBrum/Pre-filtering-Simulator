import radix
import re

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

ipotps_to_hex = {"eol":0x00, "nop":0x01,  
                 "sec": 0x02, "rr": 0x07,  
                 "ts": 0x44, "lsrr": 0x83, 
                 "lsrre": 0x83,  "esec": 0x85, 
                 "satid": 0x88, "ssr": 0x89, 
                 "ssrr": 0x89, "any": 0XFF}

pcre_modifier_to_buffer = {"U":"http_uri", "I": "http_raw_uri", 
                           "P": "http_body", "Q": "http_body", 
                           "H": "http_header", "D": "http_raw_header",
                           "M": "http_method", "C": "http_cookie",
                           "S": "http_stat_code", "Y": "http_stat_msg",
                           "V": "http_user_agent", "W": "http_host"}

native_pcre_modifiers = {'i', 's', 'm', 'x'}

# Class that contains all the fields required to match against networking packets 
class Match(object):
    def __init__(self, header_fields, payload_fields, pre_filtering_scenario="full"):
        self.header_key = header_fields["ip_port_key"]
        self.service = None
        if "service" in payload_fields:
            self.service = payload_fields["service"] # Get the services only 

        self.priority_list = []
        self.sid_rev_list = []

        self.header_fields = self.__adjust_header_for_match(header_fields)
        self.payload_fields = self.__adjust_payload_for_match(payload_fields, pre_filtering_scenario)
      

    def sids(self):
        return list(set(self.sid_rev_list))
    
    # Adjust header fields for quick matching against packets> Assuming they are not lists...
    def __adjust_header_for_match(self, header_fields):
        header_fields['src_ip'] = self.__convert_ip_list_to_radix_tree(header_fields['src_ip'])
        header_fields['dst_ip'] = self.__convert_ip_list_to_radix_tree(header_fields['dst_ip'])

        header_fields['sport'] = self.__turn_port_list_into_dict(header_fields['sport'])
        header_fields['dport'] = self.__turn_port_list_into_dict(header_fields['dport'])

        # Determine the data and comparator for the "ip_proto" keyword
        if "ip_proto" in header_fields:
            rule_ip_proto = header_fields["ip_proto"][0]
            comparator = re.search("^[!|>|<]", rule_ip_proto)
            comparator = comparator.group(0) if comparator != None else ""
            header_fields["ip_proto"] = {"data": int(re.search("[\d]+", rule_ip_proto).group(0)), "comparator": comparator}
        
         # Determine the data and comparator for the "fragbits" keyword
        if "ipopts" in header_fields:
            header_fields["ipopts"] = ipotps_to_hex[header_fields["ipopts"][0]]

        # Determine the data and comparator for the "ttl", "id", "seq", "ack", "window", "itype", "icode", "icmp_id", "icmp_seq" keywords
        for key in ["ttl", "id", "seq", "ack", "window", "itype", "icode", "icmp_id", "icmp_seq"]:
            if key in header_fields:
                value = header_fields[key][0]
                comparator = re.search("[^\d ]+", value)
                comparator = comparator.group(0) if comparator != None else ""
                header_fields[key] = {"data": re.findall("[\d]+", value), "comparator": comparator}

         # Determine the data and comparator for the "fragbits" keyword
        if "fragbits" in header_fields:
            fragbits = re.sub("[\+\*\! ]", "", header_fields["fragbits"][0])
            fragbits_num = sum(ip_flags_dict[flag] for flag in fragbits)
            comparator = re.sub("[MDR. ]", "", header_fields["fragbits"][0])
            header_fields["fragbits"] = {"data": fragbits_num, "comparator": comparator}

        # Determine the data, comparator and flags to exclude for the (TCP) "flags" keyword
        if "flags" in self.pkt_header_fields:
            flags_to_match = header_fields["flags"][0]
            exclude = ""
            if type(self.pkt_header_fields["flags"]) is list:
                flags_to_match = header_fields["flags"][0]
                exclude = header_fields["flags"][1]

            tcp_flags = re.sub("[\+\*\! ]", "", flags_to_match)
            tcp_flags_num = sum(tcp_flags_dict[flag] for flag in tcp_flags)
            exclude_num = sum(tcp_flags_dict[flag] for flag in exclude)  
            comparator = re.sub("[a-zA-Z.]", "", flags_to_match)
            header_fields["flags"] = {"data": tcp_flags_num, "comparator": comparator, "exclude": exclude_num}

        return header_fields


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
    def __adjust_payload_for_match(self, payload_fields, pre_filtering_scenario):
        if "dsize" in payload_fields:
            value = payload_fields["dsize"][0] # Options/Paylod_fields are stored as {"key": [(value), ]}
            comparator = re.search("[^\d ]+", value)
            comparator = comparator.group(0) if comparator != None else ""
            payload_fields["dsize"] = {"data": re.findall("[\d]+", value), "comparator": comparator}

        final_content_list = []
        if "content" in payload_fields:
            fast_pattern_match = None
            for content in payload_fields["content"]:
                match_str = self.__clean_content(match[-2], "nocase" in match[-1] if match[-1] else False)
                modifiers, fast_pattern = self.__parse_content_modifiers(content[-1])
                final_content_list.append((content[0], content[1], match_str, modifiers)) # buffer, negation, string, modifiers
                if fast_pattern:
                    fast_pattern_match = final_content_list[-1]
        
            payload_fields["content"] = final_content_list

            # self.__apply_pre_filtering_scenario(fast_pattern_match, pre_filtering_scenario)

        pcre = []
        if "pcre" in payload_fields:
            for match in payload_fields["pcre"]:
                parsed_pcre_str, nids_only_modifiers, buffer_name = self.__parse_pcre_modifiers(match[2], match[3])
                if not buffer_name:
                    buffer_name == match[0]
                pcre.append((buffer_name, match[1], parsed_pcre_str, nids_only_modifiers))
    
            payload_fields["pcre"] = pcre

        return payload_fields                    


    # Clean escaped chars in the string part of content, and convert the hex part to char. Also adjusts the case if needed 
    def __clean_content(self, str_to_match, nocase):
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
        
        if escaped:
            temp_content+="/"
        clean_content+=temp_content
        return clean_content

    # Process hex number of the content. Mainly checking if it is required to consider the case
    def __process_hex(self, char, temp_content, nocase, hex_now):
        add_to_clean_content = False
        # Check if hex section has started or finished. Either way, add existing text to the final string
        if char == '|' or char == ' ':  
            if hex_now:
                if nocase and (int(temp_content, 16) >= 65 and int(temp_content, 16) <= 90):
                    temp_content = chr(int(temp_content, 16) + 32) # Turn hex alpha to lower case: (hex, dec, char) - (0x41, 65, A) -> (0x61, 97, a)
                else:
                    temp_content = chr(int(temp_content, 16))
            elif char == '|' and not hex_now:
                temp_content = temp_content # If hex section has started now, add the plain text in temp to the final string

            hex_now = not hex_now if char == '|' else hex_now
            add_to_clean_content = True  
        else:
            temp_content+=char

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

                if item!="nocase" and "fast" not in item:
                    modifier_name = re.search('^[a-zA-Z]*', item).group(0)
                    modifier_value = re.search('\d*$', item).group(0)
                
                if modifier_name in modifiers_dict:
                    raise Exception("Two identical modifiers in the same content matching: ", modifiers_dict)

                if modifier_name == "nocase" or modifier_value:
                    modifiers_dict[modifier_name] = modifier_value

            if ("offset" in modifiers_dict or "depth" in modifiers_dict) and ("within" in modifiers_dict or "distance" in modifiers_dict):
                raise Exception("Modifiers are not correctly configured: ", modifiers_dict)
        return modifiers_dict, fast_pattern
        
    ## Add pcre modifiers to the pcre string since the re module can process them
    # Possible pcre modifiers as detailed by Snort: i,s,m,x,A,E,G,O,R
    # Native pcre modifiers supported by Python 'i', 's', 'm', 'x' 
    # Modifier G (Ungreedy) and D are not supported by python. Modifier O appear to be only required for the Snort engine
    def __parse_pcre_modifiers(self, pcre_string, modifiers):
        relative_match = False
        buffer_name = None

        if not modifiers:
            return pcre_string, relative_match, buffer_name

        if len(set(modifiers)) != len(modifiers):
            raise Exception("PCRE string with duplicate modifiers, fix it. PCRE: ", pcre_string, " modifiers: ", modifiers)

        prepend_modifiers = ""
        for char in modifiers:
            if char in native_pcre_modifiers:
                prepend_modifiers+=char
            elif char == 'A' and pcre_string[0] != '^':
                pcre_string = '^' + pcre_string
            elif char == 'R':
                relative_match = True
            elif char in pcre_modifier_to_buffer:
                buffer_name = pcre_modifier_to_buffer[char]

        if prepend_modifiers:
            pcre_string = "(?"+prepend_modifiers+')'+pcre_string
            
        return pcre_string, relative_match, buffer_name


        
    # def __apply_pre_filtering_scenario(self, content_pcre, fast_pattern_match, pre_filtering_scenario):
    #     final_content_pcre = []
    #     if pre_filtering_scenario == "first":
    #         final_content_pcre = [content_pcre[0]]
    #     elif pre_filtering_scenario =="longest":
    #         longest, size = None, 0
    #         for content in content_pcre:
    #             if len(content[3]) > size:
    #                 longest = content
    #                 size = len(content[3])

    #         final_content_pcre = [longest]
    #     elif pre_filtering_scenario =="first_last":
    #         final_content_pcre = [content_pcre[0]] if len(content_pcre) == 1 else [content_pcre[0],content_pcre[-1]]
    #     elif pre_filtering_scenario =="first_second":
    #         final_content_pcre = [content_pcre[0]] if len(content_pcre) == 1 else [content_pcre[0],content_pcre[1]]
    #     elif pre_filtering_scenario == "fast_pattern":
    #         longest, size = None, 0   
    #         if fast_pattern_match:
    #             final_content_pcre = [fast_pattern_match] 
    #         else:          
    #             for content in content_pcre:
    #                 if len(content[3]) > size:
    #                     longest = content
    #                     size = len(content[3])
                        
    #             final_content_pcre = [longest]
    #     else:
    #         final_content_pcre = content_pcre

    #     return final_content_pcre
