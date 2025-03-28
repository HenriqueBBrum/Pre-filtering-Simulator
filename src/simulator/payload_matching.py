from re import search
from .header_matching import compare_field

## Compares the payload of packet against the payload-related fields of a match
# A "False" return value means the packet does not match the match and is not suspicious acording to the match
def matched_payload(pkt, match):
    # Compare the packet's payload size against the match's desired (payload) size
    if "dsize" in match.payload_fields and not compare_field(pkt.payload_size, match.payload_fields["dsize"]["data"], \
                                                                                            match.payload_fields["dsize"]["comparator"]):
        return False, 0, 0
    
    # Compare packets that have payload with matches that have the "content" or "pcre" keywords
    if "content_pcre" in match.payload_fields:
        return __matched_content_pcre(pkt, match.payload_fields["content_pcre"])

    return True, 0, 0

# Comapre the payload of packet with the "content" or "pcre" keyword of a match
def __matched_content_pcre(pkt, match_contents):
    compared_to_content = 0
    compared_to_pcre = 0
    position_dict = {}
    for match_type, buffer_name, should_match, match_str, modifiers in match_contents:
        if buffer_name not in pkt.payload_buffers or not pkt.payload_buffers[buffer_name][0]: 
            return False, compared_to_content, compared_to_pcre
        
        start = 0
        position = position_dict[buffer_name] if buffer_name in position_dict else 0
        buffer = pkt.payload_buffers[buffer_name][0]
        if match_type == 0: # "content" keyword
            start, end, nocase = __process_content_modifiers(modifiers, position, len(buffer))
            match_pos = pkt.payload_buffers[buffer_name][nocase][start:end].find(match_str)
            compared_to_content+=1
        else: # "pcre" keyword
            if modifiers:
                start = position
        
            match = search(match_str, pkt.payload_buffers[buffer_name][0][start:])
            compared_to_pcre+=1
            if match:
                match_pos = match.start()
                match_str = match.group(0) # Differently from the content keyword, in PCRE the matched string is not the PCRE string
            else:
                match_pos = -1 

        # Return false if no match was found but the match required finding a match or if a match was found but the match required not fiding the match
        if (match_pos == -1 and should_match) or (match_pos >= 0 and not should_match):
            return False, compared_to_content, compared_to_pcre
        
        # The packet had the desired match or the packet did not have the undesired match
        if match_pos != -1:
            position = start+int(match_pos)+int(len(match_str))
            position_dict[buffer_name] = position
    return True, compared_to_content, compared_to_pcre


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

