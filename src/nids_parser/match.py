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
    '2': 64,
    'E': 64,
    '1': 128,
    'C': 128,
}

ipopts_to_dict = {"eol":0x00, "nop":0x01,  
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
        self.service = []
        # Adjust some services based on Snort, suricata and getservbyport 
        if "service" in payload_fields:
            for service in payload_fields["service"]:
                if service == "ssl":
                    self.service.append("tls")
                elif service == "wins":
                    self.service.append("netbios-ns")
                elif service == "vnc-server":
                   self.service.append("vnc")
                else:
                    self.service.append(service)

        self.priority_list = []
        self.sid_rev_list = []

        self.header_fields = self.__adjust_header(header_fields)
        self.payload_fields = self.__adjust_payload(payload_fields, pre_filtering_scenario)

        max_len = 0
        if "content_pcre" in self.payload_fields and self.payload_fields["content_pcre"]:
            for content_pcre in self.payload_fields["content_pcre"]:
                if content_pcre[0] == 0:
                    content_len = len(content_pcre[3])
                    if content_len > max_len:
                        max_len = content_len
            
        self.max_content_size = max_len
        
    def sids(self):
        return list(set(self.sid_rev_list))
    
    # Adjust header fields for quick matching against packets> Assuming they are not lists...
    def __adjust_header(self, header_fields):
        clean_header_fields = {"proto": header_fields["proto"]}
        clean_header_fields['src_ip'] = self.__convert_ip_list_to_radix_tree(header_fields['src_ip'])
        clean_header_fields['dst_ip'] = self.__convert_ip_list_to_radix_tree(header_fields['dst_ip'])

        clean_header_fields['sport'] = self.__turn_port_list_into_dict(header_fields['sport'])
        clean_header_fields['dport'] = self.__turn_port_list_into_dict(header_fields['dport'])

        # Determine the data and comparator for the "ip_proto" keyword
        if "ip_proto" in header_fields:
            rule_ip_proto = header_fields["ip_proto"][0]
            comparator = re.search("^[!|>|<]", rule_ip_proto)
            comparator = comparator.group(0) if comparator != None else ""
            clean_header_fields["ip_proto"] = {"data": int(re.search("[\d]+", rule_ip_proto).group(0)), "comparator": comparator}
        
         # Determine the data and comparator for the "fragbits" keyword
        if "ipopts" in header_fields:
            clean_header_fields["ipopts"] = ipopts_to_dict[header_fields["ipopts"][0]]

        # Determine the data and comparator for the "ttl", "id", "seq", "ack", "window", "itype", "icode", "icmp_id", "icmp_seq" keywords
        for key in ["ttl", "id", "seq", "ack", "window", "itype", "icode", "icmp_id", "icmp_seq"]:
            if key in header_fields:
                value = header_fields[key][0]
                comparator = re.search("[^\d ]+", value)
                comparator = comparator.group(0) if comparator != None else ""
                clean_header_fields[key] = {"data": re.findall("[\d]+", value), "comparator": comparator}
               
         # Determine the data and comparator for the "fragbits" keyword
        if "fragbits" in header_fields:
            fragbits = re.sub("[\+\*\! ]", "", header_fields["fragbits"][0])
            fragbits_num = sum(ip_flags_dict[flag] for flag in fragbits)
            comparator = re.sub("[MDR. ]", "", header_fields["fragbits"][0])
            clean_header_fields["fragbits"] = {"data": fragbits_num, "comparator": comparator}

        # Determine the data, comparator and flags to exclude for the (TCP) "flags" keyword
        if "flags" in header_fields:
            flags_to_match = header_fields["flags"][0]
            exclude = ""
            if len(header_fields["flags"]) == 2:
                flags_to_match = header_fields["flags"][0]
                exclude = header_fields["flags"][1]

            tcp_flags = re.sub("[\+\*\! ]", "", flags_to_match)
            tcp_flags_num = sum(tcp_flags_dict[flag] for flag in tcp_flags)
            exclude_num = sum(tcp_flags_dict[flag] for flag in exclude)  
            comparator = re.sub("[a-zA-Z12]", "", flags_to_match)
            clean_header_fields["flags"] = {"data": tcp_flags_num, "comparator": comparator, "exclude": exclude_num}

        return clean_header_fields


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
    def __adjust_payload(self, payload_fields, pre_filtering_scenario):
        final_payload_fileds = {}
        if "dsize" in payload_fields:
            value = payload_fields["dsize"][0] # Options/Paylod_fields are stored as {"key": [(value), ]}
            comparator = re.search("[^\d ]+", value)
            comparator = comparator.group(0) if comparator != None else ""
            final_payload_fileds["dsize"] = {"data": re.findall("[\d]+", value), "comparator": comparator}

        content_pcre_list = []
        if "content_pcre" in payload_fields:
            fast_pattern_match = None
            for type, buffer_name, should_match, match_str, modifiers in payload_fields["content_pcre"]:
                if type == 0:
                    match_str = self.__adjust_content(match_str, "nocase" in modifiers if modifiers else False)
                    modifiers, fast_pattern = self.__parse_content_modifiers(modifiers)
                    content_pcre_list.append((type, buffer_name, should_match, match_str, modifiers)) # buffer, negation, string, modifiers
                    if fast_pattern:
                        fast_pattern_match = content_pcre_list[-1]
                else:
                    final_buffer_name, parsed_pcre_str, relative_match = self.__parse_pcre_modifiers(match_str, modifiers)
                    if not final_buffer_name:
                        final_buffer_name = buffer_name
                    
                    content_pcre_list.append((type, final_buffer_name, should_match, parsed_pcre_str, relative_match))
            final_payload_fileds["content_pcre"] = self.__apply_pre_filtering_scenario(content_pcre_list, fast_pattern_match, pre_filtering_scenario)
           
        return final_payload_fileds                    


    # Clean escaped chars in the string part of content, and convert the hex part to char. Also adjusts the case if needed 
    def __adjust_content(self, match_str, nocase):
        clean_content = ""
        temp_content = ""
        escaped = False
        i = 0
        while i < len(match_str):
            # Process hex decimal values
            if match_str[i] == '|' and not escaped:
                temp_content = ""
                i+=1
                while match_str[i] != '|':
                    if match_str[i] == ' ':
                        i+=1
                        continue
                    
                    temp_content+=match_str[i]
                    if len(temp_content) == 2:
                        if nocase and (int(temp_content, 16) >= 65 and int(temp_content, 16) <= 90):
                            new_hex = hex(int(temp_content, 16) + 32)[2:]
                            clean_content+=bytes.fromhex(new_hex).decode('latin-1', errors='replace') # Turn hex alpha to lower case: (hex, dec, char) - (0x41, 65, A) -> (0x61, 97, a)
                        else:
                            clean_content+=bytes.fromhex(temp_content).decode('latin-1', errors='replace')# chr(int(temp_content, 16))
                        temp_content=""
                    i+=1
            # Process normal char
            else:
                # Add escaped char or add '/' since it was not used to escape a char
                if escaped:
                    escaped = False
                    if (match_str[i] == '|' or match_str[i] == ';' or match_str[i] == '"' or match_str[i] == '\\'):
                        clean_content+=match_str[i]
                        continue

                if match_str[i] == '\\':
                    escaped = True
                else:
                    clean_content+=(match_str[i].casefold() if nocase else match_str[i])
            i+=1
        return clean_content

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
            return buffer_name, pcre_string, relative_match

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
            
        return buffer_name, pcre_string, relative_match


    # Applies one of different scenarios to reduce or tranform the rules. 
    # wang_chang takes the fast pattern if there is or the longest content. If there is no final content the rule will be discarded
    def __apply_pre_filtering_scenario(self, content_pcre, fast_pattern_match, pre_filtering_scenario):
        final_content_pcre = []
        if pre_filtering_scenario == "wang_chang":
            longest, size = None, 0   
            if fast_pattern_match:
                final_content_pcre = [fast_pattern_match] 
            else:          
                for content in content_pcre:
                    if content[0] == 1:
                        continue
                    
                    if len(content[3]) > size:
                        longest = content
                        size = len(content[3])
                
                if not longest:
                    final_content_pcre = None
                else:
                    final_content_pcre = [longest]
        else:
            final_content_pcre = content_pcre

        return final_content_pcre
