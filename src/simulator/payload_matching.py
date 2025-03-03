from re import search,IGNORECASE
from .header_matching import compare_field

unsupported_buffers = {"json_data", "vba_data", "base64_data"}
http_request_buffers = {"http_uri", "http_raw_uri", "http_method"}
http_response_buffers = {"http_stat_code", "http_stat_msg", "file_data"}

## Compares the payload of packet against the payload-related fields of a match
# A "False" return value means there was no match and the packet is not suspicious acording
def matched_payload(pkt_to_match, match, fast_pattern):
    # Compare the packet's payload size against the rule's desired (payload) size
    if "dsize" in match.payload_fields and not compare_field(pkt_to_match.payload_len, match.payload_fields["dsize"]["data"], \
                                                                                            match.payload_fields["dsize"]["comparator"]):
        return False

    # If the packet has no payload but the rule has payload fields, return that it does not match the rule
    if pkt_to_match.payload_len == 0 and ("content" in match.payload_fields or "pcre" in match.payload_fields):
        return False
    
    # Compare packets that have payload with rules that have the "content" or "pcre" keywords
    if "content" in match.payload_fields and not __matched_content(pkt_to_match, match.payload_fields["content"]):
        return False
    
    # Compare packets that have payload with rules that have the "content" or "pcre" keywords
    # if not fast_pattern:
    #     if "pcre" in match.payload_fields and not __matched_pcre(pkt_to_match, match.payload_fields["pcre"]):
    #         return False
        
    # print()
    # print(match.payload_fields["pcre"])

    return True

    

def __matched_content(pkt_to_match, content_matches):
    for should_match, match_str, modifiers in content_matches:
        if "nocase" in modifiers:
            match_pos = pkt_to_match.payload_lower_case.find(match_str)
        else:
            match_pos = pkt_to_match.payload.find(match_str)
   
        # Return false if no match was found but the rule required finding a match or if a match was found but the rule required not fiding the match
        if (match_pos == -1 and should_match) or (match_pos >= 0 and not should_match):
            return False    
    return True


def __matched_pcre(pkt_to_match, pcre_matches):
    for should_match, match_str, modifiers in pcre_matches:
        # if modifiers == 'R':
        #     start = position

        match = search(match_str, pkt_to_match.payload)
        if match:
            match_pos = match.start()
            match_str = match.group(0) # Differently from the content keyword, in PCRE the matched string is not the PCRE string
        else:
            match_pos = -1 

        # Return false if no match was found but the rule required finding a match or if a match was found but the rule required not fiding the match
        if (match_pos == -1 and should_match) or (match_pos >= 0 and not should_match):
            return False
            
    return True

# Process the modifiers of the keyword "content"
# def __process_content_modifiers(modifiers, position, len_current_buffer):
#     start, end, nocase = 0, len_current_buffer, False
#     if modifiers:
#         if "nocase" in modifiers:
#             nocase = True
#         try:
#             if "offset" in modifiers:
#                 start = int(modifiers["offset"])
            
#             if "depth" in modifiers:
#                 end = start+int(modifiers["depth"])
            
#             if "distance" in modifiers:
#                 start = position+int(modifiers["distance"])
            
#             if "within" in modifiers:
#                 if start == 0:
#                     start = position
#                 end = start+int(modifiers["within"])
#         except: 
#             # The modifiers value is a variable, which is not supported by this program
#             return 0, len_current_buffer, nocase
#     return start, end, nocase




## Compares "content" and "pcre" strings against the desired packet's buffer
# Guarentees: Packet has payload and the rule has "content" or "pcre" fields
# def __matched_content_pcre(pkt_to_match, rule_content_pcre):
#     position_dict = {}
#     buffer, actual_buffer_name = "", ""
#     position = 0

#     for match_type, match_buffer, should_match, match_str, match_modifiers in rule_content_pcre:
#         # Check some conditions regarding the buffers and the packet type     
#         if match_buffer in unsupported_buffers:
#             continue

        
#         # Decide on the buffer to match. By default the buffer is "pkt_data"
#         if match_buffer:
#             buffer = pkt_to_match.payload_buffers["nocase"][match_buffer]
#             position = position_dict[match_buffer] if match_buffer in position_dict else 0 # There is a pointer in the buffer already. Start from there
#         else:
#             if not buffer:
#                 match_buffer = "pkt_data"
#                 buffer = pkt_to_match.payload_buffers["nocase"][match_buffer]
            
#         actual_buffer_name = match_buffer if match_buffer else actual_buffer_name

#         # Match the "match_str" with the buffer according to the position defined in the modifiers and some other options
#         start, end, nocase = 0, len(buffer), False
#         if match_type == 0: # "content" keyword match
#             start, end, nocase = __process_content_modifiers(match_modifiers, position, end)
#             buffer = buffer if nocase else pkt_to_match.payload_buffers["original"][actual_buffer_name]
#             match_pos = buffer[start:end].find(match_str)
#         else: # "pcre" keyword match
#             if match_modifiers == 'R':
#                 start = position

#             match = search(match_str, pkt_to_match.payload_buffers["original"][actual_buffer_name][start:end])
#             if match:
#                 match_pos = match.start()
#                 match_str = match.group(0) # Differently from the content keyword, in PCRE the matched string is not the PCRE string
#             else:
#                 match_pos = -1 

#         # Return false if no match was found but the rule required finding a match or if a match was found but the rule required not fiding the match
#         if (match_pos == -1 and should_match) or (match_pos >= 0 and not should_match):
#             return False
        
#         # The packet had the desired match or the packet did not have the undesired match
#         if match_pos != -1:
#             position = start+int(match_pos)+int(len(match_str))
#             position_dict[actual_buffer_name] = position
#     return True
