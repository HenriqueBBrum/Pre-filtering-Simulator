from urllib.parse import urlparse
import binascii
import urllib
from scapy.layers.http import * 


unsupported_buffers = {"file_data", "json_data", "vba_data", "base64_data"}

http_request_buffers = {"http_uri", "http_raw_uri", "http_method"}
http_response_buffers = {"http_stat_code", "http_stat_msg"}

# Compares a rules payload fields against a packet's payload. 
# A "False" return value means the packet does not match the rule and is not suspicious acording to the rule
def compare_payload(pkt, rule):
    len_pkt_payload = len(pkt[rule.pkt_header["proto"].upper()].payload)
    # if "dsize" in rule.payload_fields and not _compare_fields(len_pkt_payload, rule.payload_fields["dsize"][0][1][0]):
    #     return False

    # Packet has no payload but the rule has payload fields
    if len_pkt_payload == 0 and ("content" in rule.payload_fields or "pcre" in rule.payload_fields):
        return False

    # Only compare packets that have payload with rules that have fields for payload comparison
    if "content" in rule.payload_fields and not _compare_content(pkt, rule.pkt_header["proto"].upper(),  rule.payload_fields["content"]):
        return False
    
    # if "pcre" in rule.payload_fields and not _compare_pcre():
    #     return False

    return True


# Guarentees: Packet has payload and the rule has "content" fields
def _compare_content(pkt, proto, rule_content):
    buffers_dict = {}
    buffer, prev_buffer_name = "", ""
    position = 0
    for content_id, content in rule_content:
        if content[0] in unsupported_buffers:
            continue

        if "http" in content[0] and HTTP not in pkt:
            return False

        if content[0] in http_response_buffers and not HTTPResponse in pkt:
            return False 

        if content[0] in http_request_buffers and not HTTPRequest in pkt:
            return False 

        if content[0]:
            if content[0] not in buffers_dict:
                buffer, position = buffers_dict[content[0]] = (buffer_functions["get_"+content[0]](pkt, proto), 0)
            else:
                buffer, position = buffers_dict[content[0]]
            
        prev_buffer_name = content[0]
        if not buffer:
            buffer, position = buffers_dict["pkt_data"] = (buffer_functions["get_pkt_data"](pkt, proto), 0)
            prev_buffer_name = "pkt_data"

        start, end, nocase = _process_content_modifiers(content, position, len(buffer))
        temp_buffer_nocase = ""
        if nocase:
            temp_buffer = bytes(buffer, 'utf-8')[start:end].hex() if type(buffer) == str else bytes(buffer)[start:end].hex()
            temp_buffer_nocase = _adjust_buffer_case(temp_buffer)
        else:
            temp_buffer = bytes(buffer, 'utf-8')[start:end].hex() if type(buffer) == str else bytes(buffer)[start:end].hex()

        str_to_match = _clean_content_and_hexify(content[2], nocase) 

        if position > 0:
            print(str_to_match)
            print(len(buffer), len(temp_buffer), start, end, position)
            print(temp_buffer)
        # Match pos is the number of char (not bytes) from start
        match_pos = temp_buffer.find(str_to_match) if not nocase else temp_buffer_nocase.find(str_to_match)

        # Did not find a match but the rule says to only accept if a match was found
        # Found a match but the rule says to only accept if no matches were found
        if (match_pos == -1 and content[1]) or (match_pos >= 0 and not content[1]): 
            return False

        print(str_to_match)
        print(len(buffer), len(temp_buffer), start, end)
        print(temp_buffer)
        position = start+int(match_pos/2)+int(len(str_to_match)/2) # Match_pos and str_too_match are in the hex char string, while start is in bytes. That's why they are divided
        print(position, match_pos/2, len(str_to_match)/2)
        print("-------")
        print(buffers_dict)
        buffers_dict[prev_buffer_name] = buffers_dict[prev_buffer_name][0], position
    return True



def get_http_uri(pkt, proto):
    uri = "http://"+pkt[HTTP].Host.decode("utf-8")
    path = pkt[HTTP].Path.decode("utf-8")
    segment = 0 # 0 - path, 1 - query, 2 - fragment
    escape_temp = ""
    escape_hex, normalize_path = False, False
    for char in path:
        if char == "%":
            escape_hex = True
            continue

        if escape_hex:
            escape_temp+=char
            if len(escape_temp) == 2:
                uri+=bytes.fromhex(escape_temp).decode('utf-8')
                escape_temp = ""
                escape_hex = False
            continue
        
        if char == "?":
            segment = 1
            normalize_path = True
        elif char == "#":
            segment = 2
            normalize_path = True
        elif char == "\\":
            char = "/"

        if segment >=1 and char == "+":
            char = " "

        if normalize_path:
            uri = os.path.normpath(uri)
            normalize_path = False
        
        uri+=char
    return uri

def get_http_raw_uri(pkt, proto):
    uri = "http://"+pkt[HTTP].Host.decode("utf-8")
    path = pkt[HTTP].Path.decode("utf-8")
    return uri+path

def get_http_header(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_raw_header(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_client_body(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_raw_body(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_cookie(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_raw_cookie(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_param(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_method(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_stat_code(pkt, proto):
    buffer, buffer_nocase = "", ""
    return buffer, buffer_nocase

def get_http_stat_msg(pkt, proto):
    buffer, buffer_nocase = "", ""
    return pkt[HTTP].Reason_Phrase

def get_pkt_data(pkt, proto):
    return pkt[proto].payload

def get_raw_data(pkt, proto):
    return pkt[proto].payload

buffer_functions = {"get_http_uri": get_http_uri, "get_http_raw_uri": get_http_raw_uri, "get_http_header": get_http_header, "get_http_raw_header": get_http_raw_header,
        "get_http_client_body": get_http_client_body, "get_http_raw_body": get_http_raw_body, "get_http_cookie": get_http_cookie, "get_http_raw_cookie": get_http_raw_cookie,
        "get_http_param": get_http_param, "get_http_method": get_http_method, "get_http_stat_code": get_http_stat_code, "get_http_stat_msg": get_http_stat_msg,
        "get_pkt_data": get_pkt_data, "get_raw_data": get_raw_data}


def _adjust_buffer_case(buffer):
    hex_str_buffer_nocase = ""
    for pos, hex_num in enumerate(buffer[::2]):
        byte = buffer[pos*2:pos*2+2]
        if int(byte, 16) >= 65 and int(byte, 16) <= 90:
            byte = hex(int(byte, 16) + 32)[2:]

        hex_str_buffer_nocase+=byte

    return hex_str_buffer_nocase


def _process_content_modifiers(content, position, len_current_buffer):
    start, end, nocase = 0, len_current_buffer, False
    if len(content) > 3:
        for modifier in content[3].split(","):
            modifier_split = modifier.split(" ")
            modifier_name = modifier_split[0]
            if len(modifier_split)>1:
                num = int(modifier_split[1]) # !!!!! Check if modifier is a variable
                if modifier_name == "offset":
                    start = num 
                elif modifier_name == "depth":
                    end = start+num
                elif modifier_name == "distance":
                    start = position+num 
                elif modifier_name == "within":
                    end = position+num
            elif modifier_name == "nocase":
                nocase = True
    
        if start > end: # Fix start,end in case "depth" appears before "offset"
            end+=start

    return start, end, nocase

## Turn content to hex string. Ex: "A|4E 20 3B| Ok" - > "414e203b4f6b"
def _clean_content_and_hexify(str_to_match, nocase):
    clean_content = ""
    temp_content = ""
    hex_now, escaped = False, False
    add_to_clean_content = False
    for char in str_to_match:
        if hex_now or char == '|':
            temp_content, hex_now, add_to_clean_content = _process_hex(char, temp_content, nocase, hex_now)
            if add_to_clean_content:
                clean_content+=temp_content
                temp_content=""
        else:
            temp_content, escaped = _process_string(char, temp_content, nocase, escaped)
    
    clean_content+=temp_content.encode('utf-8').hex()
    return clean_content

# Process hex number of content. Mainly checking if it is required to consider the case
def _process_hex(char, temp_content, nocase, hex_now):
    add_to_clean_content = False
    if hex_now and char == " ":
        return temp_content, hex_now, add_to_clean_content

    if nocase and hex_now and len(temp_content) == 2:
        if (int(temp_content, 16) >= 65 and int(temp_content, 16) <= 90):
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
def _process_string(char, temp_content, nocase, escaped):
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


def _compare_pcre():
    pass