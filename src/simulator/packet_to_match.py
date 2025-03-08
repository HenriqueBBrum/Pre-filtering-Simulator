import os
from scapy.all import IP,TCP,UDP,ICMP
from scapy.layers.http import HTTPResponse,HTTPRequest 

import sys
sys.path.append("..")
from utils.ports import SMTP_PORTS,IMAP_PORTS,FTP_PORTS,SMB_PORTS

import pprint

class PacketToMatch(object):
    def __init__(self, pkt):
        self.icmp = ICMP in pkt
        self.tcp = TCP in pkt
        self.udp = UDP in pkt

        self.http_res = HTTPResponse in pkt
        self.http_req = HTTPRequest in pkt

        self.__get_header_fields(pkt) 

        transport_layer_name = pkt[IP].getlayer(1).name if pkt[IP].getlayer(1) else None
        if transport_layer_name:
            self.payload_size = len(pkt[transport_layer_name].payload)
        else:
            self.payload_size = len(pkt[IP].payload)
    
        self.payload_buffers = self.__get_payload_buffers(pkt, transport_layer_name)

    # Put the pkt header fields in a dict for quick checking
    def __get_header_fields(self, pkt):
        self.header = {"src_ip": pkt[IP].src, "dst_ip": pkt[IP].dst, "ttl": pkt[IP].ttl, "id": pkt[IP].id, \
                        "ipopts": pkt[IP].options, "fragbits": pkt[IP].flags, "ip_proto": pkt[IP].proto}
        
        if self.icmp:
            self.header["itype"] = pkt[ICMP].type
            self.header["icode"] = pkt[ICMP].code
            self.header["icmp_id"] = pkt[ICMP].id
            self.header["icmp_seq"] = pkt[ICMP].seq
        elif self.tcp:
            self.header["sport"] = pkt[TCP].sport
            self.header["dport"] = pkt[TCP].dport
            self.header["flags"] = pkt[TCP].flags
            self.header["seq"] = pkt[TCP].seq
            self.header["ack"] = pkt[TCP].ack
            self.header["window"] = pkt[TCP].window
        elif self.udp:
            self.header["sport"] = pkt[UDP].sport
            self.header["dport"] = pkt[UDP].dport


    ## Returns the Snort buffers of a packet
    # Buffers not supported include: "json_data", "vba_data", "base64_data"
    def __get_payload_buffers(self, pkt, transport_layer_name):
        payload_buffers = {}
        # Get pkt_data and raw_data buffer for each protocol
        if transport_layer_name:
            payload_buffers["pkt_data"] = [bytes(pkt[transport_layer_name].payload).decode('utf-8', errors = 'replace')] # The payload size changes
        else:
            payload_buffers["pkt_data"] = [bytes(pkt[IP].payload).decode('utf-8', errors = 'replace')]

        payload_buffers["raw_data"] = payload_buffers["pkt_data"]

        # Get the file_data buffer for the existing service in the pkt except http that has its own section
        if self.tcp or self.udp:
            if pkt[transport_layer_name].payload:
                sport = pkt[transport_layer_name].sport
                dport = pkt[transport_layer_name].dport
                
                is_pop3 = True if sport == 110 or sport == 995 else ( True if dport == 110 or dport == 995 else False)
                is_smtp = True if sport in SMTP_PORTS else (True if dport in SMTP_PORTS else False) 
                is_imap = True if sport in IMAP_PORTS else (True if dport in IMAP_PORTS else False) 
                is_ftp = True if sport in FTP_PORTS else (True if dport in FTP_PORTS else False) 
                is_smb = True if sport in SMB_PORTS else (True if dport in SMB_PORTS else False) 
                if is_pop3 or is_smtp or is_imap or is_ftp or is_smb:
                    payload_buffers["file_data"] = payload_buffers["pkt_data"]

        http_type = None
        if self.http_req:
            http_type = HTTPRequest
        elif self.http_res:
            http_type = HTTPResponse
        
        if http_type:
            self.__get_http_buffers(pkt, payload_buffers, http_type)
        
        for key in payload_buffers:
            payload_buffers[key].append(payload_buffers[key][0].lower())

        return payload_buffers

    # Get http_* and file_data buffers for HTTP packets
    def __get_http_buffers(self, pkt, payload_buffers, http_type):
        if http_type:
            payload_buffers["http_raw_body"] = [bytes(pkt[http_type].payload).decode('utf-8', errors = 'ignore')]
            payload_buffers["file_data"] = payload_buffers["http_raw_body"]

            pkt[http_type].remove_payload()
            payload_buffers["http_raw_header"] = [bytes(pkt[http_type]).decode('utf-8')]
            payload_buffers["http_header"] = [self.__normalize_http_text("http_header", bytes(pkt[http_type]).decode('utf-8'))]
            payload_buffers["http_param"] = payload_buffers["http_raw_header"]
            # payload_buffers["http_header_names"] =  

            payload_buffers["http_cookie"] = [self.__get_http_cookie(pkt[http_type], True)]
            payload_buffers["http_raw_cookie"] = [self.__get_http_cookie(pkt[http_type], False)]
            payload_buffers["http_content_type"] = [self.__decode_http_field(pkt[http_type].Content_Type)]
            payload_buffers["http_content_len"] = [self.__decode_http_field(pkt[http_type].Content_Length)]
            payload_buffers["http_connection"] = [self.__decode_http_field(pkt[http_type].Connection)]

            if self.http_req:
                uri_path = self.__decode_http_field(pkt[HTTPRequest].Path)
                uri_host = self.__decode_http_field(pkt[HTTPRequest].Host)

                payload_buffers["http_raw_uri"] = ["http://"+uri_host+uri_path]
                payload_buffers["http_uri"] = [self.__normalize_http_text("http_uri", uri_path, "http://"+uri_host)]

                payload_buffers["http_accept"] = [self.__decode_http_field(pkt[HTTPRequest].Accept)]
                payload_buffers["http_accept_enc"] = [self.__decode_http_field(pkt[HTTPRequest].Accept_Encoding)]
                payload_buffers["http_accept_lang"] = [self.__decode_http_field(pkt[HTTPRequest].Accept_Language)]
                payload_buffers["http_host"] = [uri_host]
                payload_buffers["http_method"] = [self.__decode_http_field(pkt[HTTPRequest].Method)]
                payload_buffers["http_referer"] = [self.__decode_http_field(pkt[HTTPRequest].Referer)]
                payload_buffers["http_user_agent"] = [self.__decode_http_field(pkt[HTTPRequest].User_Agent)]

                payload_buffers["http_client_body"] = payload_buffers["http_raw_body"]
            elif self.http_res:
                payload_buffers["http_location"] = [self.__decode_http_field(pkt[HTTPResponse].Location)]
                payload_buffers["http_server"] =  [self.__decode_http_field(pkt[HTTPResponse].Server)]
                payload_buffers["http_stat_code"] = [self.__decode_http_field(pkt[HTTPResponse].Status_Code)]
                payload_buffers["http_stat_msg"] = [self.__decode_http_field(pkt[HTTPResponse].Reason_Phrase)]

                payload_buffers["http_server_body"] = payload_buffers["http_raw_body"]


    # If the HTTP field is valid return the field decoded
    def __decode_http_field(self, http_field):
        return http_field.decode("utf-8") if http_field else ""

    # Returns the parsed HTTP Cookie field
    def __get_http_cookie(self, http_header, normalized):
        cookie = ""  
        if self.http_req and http_header[HTTPRequest].Cookie:
            cookie = http_header.Cookie.decode("utf-8")
        elif self.http_res in http_header and http_header[HTTPResponse].Set_Cookie:
            cookie = http_header.Set_Cookie.decode("utf-8")

        return self.__normalize_http_text("http_cookie", cookie) if normalized else cookie

    # Snort Normalization of HTTP fields (mostly) works mostly for URI
    # Replaces hex escaped values ex: %3d -> =
    # NOrmalizes path of uri 
    def __normalize_http_text(self, header_name, raw_http_text, normalized_start=""):        
        normalized_text = ""
        uri_segment = 0 # 0 - path, 1 - query, 2 - fragment
        escape_temp = ""
        escape_hex, normalize_path = False, 0
        for i, char in enumerate(raw_http_text):
            if char == "%":
                escape_hex = True
                continue

            if escape_hex:
                escape_temp+=char
                if len(escape_temp) == 2:
                    try:
                        normalized_text+=bytes.fromhex(escape_temp).decode('utf-8')
                    except:
                        normalized_text+="%"+escape_temp
                    escape_temp = ""
                    escape_hex = False
                continue
            
            if header_name == "http_uri":
                if char == "?":
                    uri_segment = 1
                    normalize_path = 1
                elif char == "#":
                    uri_segment = 2
                    normalize_path = 1
                elif char == "\\":
                    char = "/"

                if uri_segment >=1 and char == "+":
                    char = " "

                if normalize_path == 1:
                    normalized_text = os.path.normpath(normalized_text)
                    normalize_path = -1
            
            normalized_text+=char

        if normalize_path != 1 and normalized_text:
            normalized_text = normalized_text = os.path.normpath(normalized_text)

        return normalized_start+normalized_text
