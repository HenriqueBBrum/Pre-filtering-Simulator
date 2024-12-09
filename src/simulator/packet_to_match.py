from scapy.all import IP,TCP,UDP,ICMP
from scapy.layers.http import * 

smtp_ports = {25, 465, 587, 2525, 3535}
imap_ports = {143, 220, 585, 993}
ftp_ports = {20, 21, 69, 152, 989, 990, 2100, 2811, 3305, 3535, 3721, 5402, 6086, 6619, 6622}
smb_ports = {139, 445, 3020}

class PacketToMatch(object):
    def __init__(self, pkt, protocols_in_rules):
        self.icmp_in_pkt = ICMP in pkt
        self.tcp_in_pkt = TCP in pkt
        self.udp_in_pkt = UDP in pkt

        self.http_res_in_pkt = HTTPResponse in pkt
        self.http_req_in_pkt = HTTPRequest in pkt

        self.__get_header_fields(pkt)   
        self.len_payload = {} # The payload length of each protocol. Since a TCP pkt has the IP proto and might others (e.g., HTTP) each protocol has different payload sizes
        for proto in protocols_in_rules:
            proto = proto.upper()
            if proto in pkt:
                self.len_payload[proto] = len(pkt[proto].payload)

        self.payload_buffers = self.__get_payload_buffers(pkt, self.len_payload.keys())


    # Put the pkt header fields in a dict for quick checking
    def __get_header_fields(self, pkt):
        self.header = {"src_ip": pkt[IP].src, "dst_ip": pkt[IP].dst, "ttl": pkt[IP].ttl, "id": pkt[IP].id, \
                        "ipopts": pkt[IP].options, "fragbits": pkt[IP].flags, "ip_proto": pkt[IP].proto}
        
        if self.icmp_in_pkt:
            self.header["itype"] = pkt[ICMP].type
            self.header["icode"] = pkt[ICMP].code
            self.header["icmp_id"] = pkt[ICMP].id
            self.header["icmp_seq"] = pkt[ICMP].seq
        elif self.tcp_in_pkt:
            self.header["src_port"] = pkt[TCP].sport
            self.header["dst_port"] = pkt[TCP].dport
            self.header["flags"] = pkt[TCP].flags
            self.header["seq"] = pkt[TCP].seq
            self.header["ack"] = pkt[TCP].ack
            self.header["window"] = pkt[TCP].window
        elif self.udp_in_pkt:
            self.header["src_port"] = pkt[UDP].sport
            self.header["dst_port"] = pkt[UDP].dport


    ## Returns the Snort buffers of a packet
    # Buffers not supported include: "json_data", "vba_data", "base64_data"
    def __get_payload_buffers(self, pkt, protocols_in_pkt):
        payload_buffers = {"original":{}, "nocase":{}}
        # Get pkt_data and raw_data buffer for each protocol
        
        for proto in protocols_in_pkt:
            if pkt[proto].payload:
                payload_buffers["original"]["pkt_data_"+proto] = bytes(pkt[proto].payload).decode('utf-8', errors = 'replace')
                payload_buffers["original"]["raw_data_"+proto] = payload_buffers["original"]["pkt_data_"+proto]

        # Get the file_data buffer for the existing service in the pkt
        if TCP in pkt or UDP in pkt:
            transport_layer = pkt.getlayer(UDP) if pkt.getlayer(UDP) else pkt.getlayer(TCP)
            if pkt[transport_layer.name].payload:
                sport = pkt[transport_layer.name].sport
                dport = pkt[transport_layer.name].dport
                
                is_pop3 = True if sport == 110 or sport == 995 else ( True if dport == 110 or dport == 995 else False)
                is_smtp = True if sport in smtp_ports else (True if dport in smtp_ports else False) 
                is_imap = True if sport in imap_ports else (True if dport in imap_ports else False) 
                is_ftp = True if sport in ftp_ports else (True if dport in ftp_ports else False) 
                is_smb = True if sport in smb_ports else (True if dport in smb_ports else False) 
                if is_pop3 or is_smtp or is_imap or is_ftp or is_smb:
                    payload_buffers["original"]["file_data"] = payload_buffers["original"]["pkt_data_"+transport_layer.name]

        payload_buffers = self.__get_http_buffers(pkt, payload_buffers)
        
        for key in payload_buffers["original"]:
            payload_buffers["nocase"][key] = payload_buffers["original"][key].lower()

        return payload_buffers

    # Get http_* and file_data buffers for HTTP packets
    def __get_http_buffers(self, pkt, payload_buffers):
        http_type = None
        if HTTPRequest in pkt:
            http_type = HTTPRequest
        elif HTTPResponse in pkt:
            http_type = HTTPResponse

        if http_type != None:
            payload_buffers["original"]["http_client_body"] = bytes(pkt[http_type].payload).decode('utf-8', errors = 'ignore')
            payload_buffers["original"]["http_raw_body"] = payload_buffers["original"]["http_client_body"]
            payload_buffers["original"]["file_data"] = payload_buffers["original"]["http_client_body"]

            payload_buffers["original"]["http_header"] = self.__get_http_header(pkt[http_type], True)
            payload_buffers["original"]["http_raw_header"] = self.__get_http_header(pkt[http_type], False)

            payload_buffers["original"]["http_cookie"] = self.__get_http_cookie(pkt[http_type], True)
            payload_buffers["original"]["http_raw_cookie"] = self.__get_http_cookie(pkt[http_type], False)

            payload_buffers["original"]["http_param"] = bytes(pkt[http_type]).decode('utf-8', errors = 'ignore')

            if HTTPRequest in pkt:
                uri_path = self.__decode_http_field(pkt[HTTPRequest].Path)
                uri_host = self.__decode_http_field(pkt[HTTPRequest].Host)

                payload_buffers["original"]["http_uri"] = self.__normalize_http_text("http_uri", uri_path, "http://"+uri_host)
                payload_buffers["original"]["http_raw_uri"] = "http://"+uri_host+uri_path
                payload_buffers["original"]["http_method"] = self.__decode_http_field(pkt[HTTPRequest].Method)
            elif HTTPResponse in pkt:
                payload_buffers["original"]["http_stat_code"] = self.__decode_http_field(pkt[HTTPResponse].Status_Code)
                payload_buffers["original"]["http_stat_msg"] = self.__decode_http_field(pkt[HTTPResponse].Reason_Phrase)

        return payload_buffers

    # If the HTTP field is valid return the field decoded
    def __decode_http_field(self, http_field):
        return http_field.decode("utf-8") if http_field else ""

    # Returns the normalized or raw HTTP header
    def __get_http_header(self, http_header, normalized):
        http_header.remove_payload()
        return self.__normalize_http_text("http_header", bytes(http_header).decode('utf-8')) if normalized else bytes(http_header).decode('utf-8')

    # Returns the parsed HTTP Cookie field
    def __get_http_cookie(self, http_header, normalized):
        cookie = ""  
        if self.http_req_in_pkt and http_header[HTTPRequest].Cookie:
            cookie = http_header.Cookie.decode("utf-8")
        elif self.http_res_in_pkt in http_header and http_header[HTTPResponse].Set_Cookie:
            cookie = http_header.Set_Cookie.decode("utf-8")

        return self.__normalize_http_text("http_cookie", cookie) if normalized else cookie

    # Snort Normalization of HTTP fields
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
