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
    rule_proto = rule.pkt_header["proto"].upper()
    if "dsize" in rule.payload_fields and not compare_fields(len_pkt_payload[rule_proto], rule.payload_fields["dsize"][0][1][0]):
        return False

    # Packet has no payload but the rule has payload fields
    if len_pkt_payload[rule_proto] == 0 and ("content" in rule.payload_fields or "pcre" in rule.payload_fields):
        return False

    # Only compare packets that have payload with rules that have fields for payload comparison
    if "content" in rule.payload_fields and not _compare_content_and_pcre(pkt, pkt_payload_buffers, rule_proto, rule.payload_fields["content"]):
        return False

    return True


# Guarentees: Packet has payload and the rule has "content" fields
def _compare_content_and_pcre(pkt, pkt_payload_buffers, rule_proto, rule_content):
    position_dict = {}
    buffer, prev_buffer_name = "", ""
    position = 0
    for content_id, content in rule_content:
        if content[0] in unsupported_buffers:
            continue

        if "http" in content[0] and HTTPRequest not in pkt and HTTPResponse not in pkt:
            return False
        elif content[0] in http_response_buffers and not HTTPResponse in pkt:
            return False 
        elif content[0] in http_request_buffers and not HTTPRequest in pkt:
            return False 

        buffer_name = content[0]
        if buffer_name:
            if buffer_name == "pkt_data" or buffer_name == "raw_data":
                buffer_name+="_"+rule_proto
                
            buffer = pkt_payload_buffers["nocase"][buffer_name]
            position = 0
            if buffer_name in position_dict:
                position = position_dict[buffer_name]

        if not buffer and not buffer_name:
            buffer_name = "pkt_data"
            buffer = pkt_payload_buffers[buffer_name][rule_proto]
            
        prev_buffer_name = buffer_name if buffer_name else prev_buffer_name
        start, end, nocase = __process_content_modifiers(content, position, len(buffer))
        buffer = buffer if nocase else pkt_payload_buffers["original"][buffer_name]
        print(buffer_name, start, end, buffer[2*start:2*end], nocase)
        str_to_match = __clean_content_and_hexify(content[2], nocase) 
        print(content[2], str_to_match)
        match_pos = buffer[2*start:2*end].find(str_to_match) # Match pos is the number of char (not bytes) from start

        # Did not find a match but the rule says to only accept if a match was found or Found a match but the rule says to only accept if no matches were found
        if (match_pos == -1 and content[1]) or (match_pos >= 0 and not content[1]):
            print("-------------------") 
            return False

        position = start+int(match_pos/2)+int(len(str_to_match)/2) # Match_pos and str_too_match are in the hex char string, while start is in bytes. That's why they are divided
        position_dict[prev_buffer_name] = position

    print("-------------------")
    return True


def __process_content_modifiers(content, position, len_current_buffer):
    start, end, nocase = 0, len_current_buffer, False
    if len(content) > 3:
        modifiers = {}
        for item in content[3].split(","):
            if item == "nocase":
                nocase = True
            else:
                split_mod = item.split(" ")
                modifiers[split_mod[0]] = split_mod[1]

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
            print("Variable in location of num: ", modifiers)
    return start, end, nocase


# Turn content to hex string. Ex: "A|4E 20 3B| Ok" - > "414e203b4f6b"
def __clean_content_and_hexify(str_to_match, nocase):
    clean_content = ""
    temp_content = ""
    hex_now, escaped = False, False
    add_to_clean_content = False
    for char in str_to_match:
        if hex_now or char == '|':
            temp_content, hex_now, add_to_clean_content = __process_hex(char, temp_content, nocase, hex_now)
            if add_to_clean_content:
                clean_content+=temp_content
                temp_content=""
        else:
            temp_content, escaped = __process_string(char, temp_content, nocase, escaped)
    
    clean_content+=temp_content.encode('utf-8').hex()
    return clean_content

# Process hex number of content. Mainly checking if it is required to consider the case
def __process_hex(char, temp_content, nocase, hex_now):
    add_to_clean_content = False
    if hex_now and char == " ":
        return temp_content, hex_now, add_to_clean_content

    if nocase and hex_now and len(temp_content) == 2:
        if (int(temp_content, 16) >= 65 and int(temp_content, 16) <= 90):
            print(temp_content)
            temp_content=hex(int(temp_content, 16) + 32)[2:] # Turn hex alpha to lower case: (hex, dec, char) - (0x41, 65, A) -> (0x61, 97, a)
        else:
            temp_content=temp_content.lower() #Uses lower case for hex string: 4E -> 4e
        add_to_clean_content=True

    if char == '|':
        temp_content=(temp_content.lower() if hex_now else temp_content.encode('utf-8').hex())
        hex_now = not hex_now
        add_to_clean_content = True
    else:
        temp_content+=char
    
    return temp_content, hex_now, add_to_clean_content

# Process the strings of the "content" field
def __process_string(char, temp_content, nocase, escaped):
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
