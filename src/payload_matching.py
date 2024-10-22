from urllib.parse import urlparse
from scapy.layers.http import * 
import binascii
import urllib
# import pcre

from header_matching import compare_fields

unsupported_buffers = {"file_data", "json_data", "vba_data", "base64_data"}  # Scapy seens to decompress and process chunks for HTTP so "file_data" (for http) seems plausible
http_request_buffers = {"http_uri", "http_raw_uri", "http_method"}
http_response_buffers = {"http_stat_code", "http_stat_msg"}

# Compares a rules payload fields against a packet's payload. 
# A "False" return value means the packet does not match the rule and is not suspicious acording to the rule
def compare_payload(pkt, len_pkt_payload, pkt_payload_buffers, rule):
    rule_proto = rule.pkt_header_fields["proto"].upper()
    if "dsize" in rule.payload_fields and not compare_fields(len_pkt_payload[rule_proto], rule.payload_fields["dsize"]["data"], \
                                                                                            rule.payload_fields["dsize"]["comparator"]):
        return False

    # Packet has no payload but the rule has payload fields
    if len_pkt_payload[rule_proto] == 0 and ("content_pcre" in rule.payload_fields):
        return False

    # Only compare packets that have payload with rules that have fields for payload comparison
    if "content_pcre" in rule.payload_fields and not __compare_content_pcre(pkt, pkt_payload_buffers, rule_proto, rule.payload_fields["content_pcre"]):
        return False

    print(rule.sids())
    return True


# Guarentees: Packet has payload and the rule has "content" fields
def __compare_content_pcre(pkt, pkt_payload_buffers, rule_proto, rule_content_pcre):
    position_dict = {}
    buffer, prev_buffer_name = "", ""
    position = 0
    print(rule_content_pcre)
    for match_type, match_buffer, should_match, match_str, match_modifiers in rule_content_pcre:
        if match_buffer in unsupported_buffers:
            continue

        if "http" in match_buffer and HTTPRequest not in pkt and HTTPResponse not in pkt:
            return False
        elif match_buffer in http_response_buffers and not HTTPResponse in pkt:
            return False 
        elif match_buffer in http_request_buffers and not HTTPRequest in pkt:
            return False 

        if match_buffer:
            if match_buffer == "pkt_data" or match_buffer == "raw_data":
                match_buffer+="_"+rule_proto
                
            buffer = pkt_payload_buffers["nocase"][match_buffer]
            position = 0
            if match_buffer in position_dict:
                position = position_dict[match_buffer]

        if not buffer and not match_buffer:
            match_buffer = "pkt_data_"+rule_proto
            buffer = pkt_payload_buffers["nocase"][match_buffer]
            
        prev_buffer_name = match_buffer if match_buffer else prev_buffer_name
        start, end, nocase = __process_content_modifiers(match_modifiers, position, len(buffer))
        buffer = buffer if nocase else pkt_payload_buffers["original"][match_buffer]
        print(match_buffer, start, end, buffer[2*start:2*end], nocase)
        print(match_str)
        if match_type == 0:
            match_pos = buffer[2*start:2*end].find(match_str) # Match pos is the number of char (not bytes) from start
        else:
            match_pos == -1

        # Did not find a match but the rule says to only accept if a match was found or Found a match but the rule says to only accept if no matches were found
        if (match_pos == -1 and should_match) or (match_pos >= 0 and not should_match):
            print("-------------------") 
            return False

        position = start+int(match_pos/2)+int(len(match_str)/2) # Match_pos and str_too_match are in the hex char string, while start is in bytes. That's why they are divided
        position_dict[prev_buffer_name] = position
    print("-------------------")
    return True


def __process_content_modifiers(modifiers, position, len_current_buffer):
    start, end, nocase = 0, len_current_buffer, False
    if modifiers:
        modifiers_dict = {}
        for item in modifiers.split(","):
            if item == "nocase":
                nocase = True
            else:
                split_mod = item.split(" ")
                modifiers_dict[split_mod[0]] = split_mod[1]
            try:
                if "offset" in modifiers:
                    start = int(modifiers_dict["offset"])
                elif "depth" in modifiers:
                    end = start+int(modifiers_dict["depth"])
                elif "distance" in modifiers:
                    start = position+int(modifiers_dict["distance"])
                elif "within" in modifiers:
                    if start == 0:
                        start = position
                    end = start+int(modifiers_dict["within"])
            except:
                print("Variable in location of num: ", modifiers)
    return start, end, nocase

