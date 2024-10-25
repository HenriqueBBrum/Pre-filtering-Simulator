import re

from .header_matching import compare_field

## Compares the payload of packet against the payload-related fields of a rule
# A "False" return value means the packet does not match the rule and is not suspicious acording to the rule
def compare_payload(pkt_to_match, rule):
    rule_proto = rule.pkt_header_fields["proto"].upper()
    try:
        len_pkt_payload = pkt_to_match.len_payload[rule_proto]
    except: # No scapy layer for this protocol, SSH, SMTP, etc
        layers = pkt.layers
        len_pkt_payload = len(pkt[Raw]) if layers[-1] is Raw else 0

    # Compare the packet's payload size against the rule's desired (payload) size
    if "dsize" in rule.payload_fields and not compare_field(len_pkt_payload, rule.payload_fields["dsize"]["data"], \
                                                                                            rule.payload_fields["dsize"]["comparator"]):
        return False

    # If the packet has no payload but the rule has payload fields, return that it does not match the rule
    if len_pkt_payload == 0 and ("content_pcre" in rule.payload_fields):
        return False

    # Compare packets that have payload with rules that have the "content" or "pcre" keywords
    if "content_pcre" in rule.payload_fields and not __compare_content_pcre(pkt_to_match, rule_proto, rule.payload_fields["content_pcre"]):
        return False

    return True


## Compares "content" and "pcre" strings against the desired packet's buffer
# Guarentees: Packet has payload and the rule has "content" or "pcre" fields

unsupported_buffers = {"json_data", "vba_data", "base64_data"}
http_request_buffers = {"http_uri", "http_raw_uri", "http_method"}
http_response_buffers = {"http_stat_code", "http_stat_msg", "file_data"}

def __compare_content_pcre(pkt_to_match, rule_proto, rule_content_pcre):
    position_dict = {}
    buffer, prev_buffer_name = "", ""
    position = 0
    for match_type, match_buffer, should_match, match_str, match_modifiers in rule_content_pcre:
        if match_buffer in unsupported_buffers:
            continue

        if "http" in match_buffer and not pkt_to_match.http_res_in_pkt and not pkt_to_match.http_req_in_pkt:
            return False
        elif match_buffer in http_response_buffers and not pkt_to_match.http_res_in_pkt:
            return False 
        elif match_buffer in http_request_buffers and not pkt_to_match.http_req_in_pkt:
            return False 

        if match_buffer:
            if match_buffer == "pkt_data" or match_buffer == "raw_data":
                match_buffer+="_"+rule_proto
                
            buffer = pkt_to_match.payload_buffers["nocase"][match_buffer]
            position = 0
            if match_buffer in position_dict:
                position = position_dict[match_buffer]

        if not buffer and not match_buffer:
            match_buffer = "pkt_data_"+rule_proto
            buffer = pkt_to_match.payload_buffers["nocase"][match_buffer]
            
        prev_buffer_name = match_buffer if match_buffer else prev_buffer_name
        start, end, nocase = 0, len(buffer), False
        if match_type == 0:
            start, end, nocase = __process_content_modifiers(match_modifiers, position, end)
            buffer = buffer if nocase else pkt_to_match.payload_buffers["original"][prev_buffer_name]
            match_pos = buffer[start:end].find(match_str)
        else:
            if match_modifiers and 'R' in match_modifiers:
                start = position

            match = re.search(match_str, pkt_to_match.payload_buffers["original"][prev_buffer_name][start:end])
            if match:
                match_pos = match.start()
                match_str = match.group(0)
            else:
                match_pos = -1 

        # Did not find a match but the rule says to only accept if a match was found or Found a match but the rule says to only accept if no matches were found
        if (match_pos == -1 and should_match) or (match_pos >= 0 and not should_match):
            return False

        if match_pos != -1:
            position = start+int(match_pos)+int(len(match_str)) # Match_pos and str_too_match are in the hex char string, while start is in bytes. That's why they are divided
            position_dict[prev_buffer_name] = position

    return True

# Process the modifiers of the keyword "content"
def __process_content_modifiers(modifiers, position, len_current_buffer):
    start, end, nocase = 0, len_current_buffer, False
    if modifiers:
        if "nocase" in modifiers:
            nocase = True
        try:
            if "offset" in modifiers:
                start = int(modifiers["offset"])
            
            if "depth" in modifiers:
                end = start+int(modifiers["depth"])
            
            if "distance" in modifiers:
                start = position+int(modifiers["distance"])
            
            if "within" in modifiers:
                if start == 0:
                    start = position
                end = start+int(modifiers["within"])
        except: 
            # The modifiers value is a variable, which is not supported by this program
            return 0, len_current_buffer, nocase
    return start, end, nocase

