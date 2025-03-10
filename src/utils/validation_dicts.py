# This file contains sets and dictionaries with the names of possible actions, protocol, options, classification, etc. for Snort and Suricata rules.

from typing import Any

class Dicts():
    @staticmethod
    def action(action: str) -> str:
        actions = {
            "alert",
            "log",
            "pass",
            "activate",
            "dynamic",
            "drop",
            "reject",
            "sdrop",
            "rewrite"
        }

        if action in actions:
            return action
        else:
            raise ValueError("Invalid action specified", action)

    # Validates protocols/services that are used by the Snort 3 Community and Registered rulesets, and Suricat 8.0.0
    @staticmethod
    def proto(proto: str) -> str:
        protos = {
            "ip",
            "icmp",
            "tcp",
            "udp",
            "file",
            "http",
            "http1",
            "ftp",
            "ftp-data",
            "rdp",
            "smb",
            "smtp",
            "ssh",
            "ssl",
            "dcerpc",
            "tls",
            "dns",
            "tcp-stream",
            "tcp-pkt"
        }

        if proto.lower() in protos:
            return proto
        else:
            raise ValueError("Unsupported Protocol ", proto)

    @staticmethod
    def ip_variables(ip_variable: str = None):
        ip_variables_set= { "any",
                            "$HOME_NET",
                            "$EXTERNAL_NET",
                            "$DNS_SERVERS",
                            "$SMTP_SERVERS",
                            "$HTTP_SERVERS",
                            "$SQL_SERVERS",
                            "$TELNET_SERVERS",
                            "$SSH_SERVERS",
                            "$FTP_SERVERS",
                            "$SIP_SERVERS",
                            "$AIM_SERVERS",            
                        }
        if ip_variable in ip_variables_set:
            return True
        return False
         
    @staticmethod
    def port_variables(port_variable: str = None):
        port_variables_set= {   "any", 
                                "$HTTP_PORTS",
                                "$SHELLCODE_PORTS",
                                "$MAIL_PORTS",
                                "$ORACLE_PORTS",
                                "$SSH_PORTS",
                                "$FTP_PORTS",
                                "$SIP_PORTS",
                                "$FILE_DATA_PORTS",
                                "$GTP_PORTS"
                            }

        if port_variable in port_variables_set:
            return True
        return False

    @staticmethod
    def classtypes(cltype: str = None):
        classtypes = {  "attempted-admin": "Attempted Administrator Privilege Gain",
                        "attempted-dos": "Attempted Denial of Service",
                        "attempted-recon": "Attempted Information Leak",
                        "attempted-user": "Attempted User Privilege Gain",
                        "bad-unknown": "Potentially Bad Traffic",
                        "client-side-exploit": "Known client side exploit attempt",
                        "default-login-attempt": "Attempt to Login By a Default Username and Password",
                        "denial-of-service": "Detection of a Denial of Service Attack",
                        "file-format": "Known malicious file or file based exploit",
                        "icmp-event": "Generic ICMP Event",
                        "inappropriate-content": "Inappropriate content was detected",
                        "malware-cnc": "Known malware command and control traffic",
                        "misc-activity": "Misc Activity",
                        "misc-attack": "Misc Attack",
                        "network-scan": "Detection of a Network Scan",
                        "non-standard-protocol": "Detection of a Non-Standard Protocol or Event",
                        "not-suspicious": "Not Suspicious Traffic",
                        "policy-violation": "Potential Corporate Policy Violation",
                        "protocol-command-decode": "Generic Protocol Command Decode",
                        "rpc-portmap-decode": " Decode of an RPC Query",
                        "sdf": "Sensitive Data",
                        "shellcode-detect": "Executable Code was Detected",
                        "string-detect": "A Suspicious String was Detected",
                        "successful-admin": "Successful Administrator Privilege Gain",
                        "successful-dos": "Denial of Service",
                        "successful-recon-largescale": "Large Scale Information Leak",
                        "successful-recon-limited": "Information Leak",
                        "successful-user": "Successful User Privilege Gain",
                        "suspicious-filename-detect": "A Suspicious Filename was Detected",
                        "suspicious-login": "An Attempted Login Using a Suspicious Username was Detected",
                        "system-call-detect": "A System Call was Detected",
                        "tcp-connection": "A TCP Connection was Detected",
                        "trojan-activity": "A Network Trojan was Detected",
                        "unknown": "Unknown Traffic",
                        "unsuccessful-user": "Unsuccessful User Privilege Gain",
                        "unusual-client-port-connection": "A Client was Using an Unusual Port",
                        "web-application-activity": "Access to a Potentially Vulnerable Web Application",
                        "web-application-attack": "Web Application Attack",
                        "nonstd-tcp": "Detection of a Non-Standard TCP Protocol"
                    }
        if cltype in classtypes:
            return classtypes[cltype]
        else:
            return False

    @staticmethod
    def general_options(option: str = None) -> Any:
        general_options = { "msg",           # The msg keyword tells the logging and alerting engine the message to print with the packet dump or alert.
                            "reference",     # The reference keyword allows rules to include references to external attack identificationsystems.
                            "gid",           # The gid keyword (generator id) is used to identify  what part of Snort generates the event when a particular rule fires.
                            "sid",           # The sid keyword is used to uniquely identify Snort rules.
                            "rev",           # The rev keyword is used to uniquely identify revisions of Snort rules.
                            "classtype",     # The classtype keyword is used to categorize a rule as detecting  an attack that is part of a more general type of attack class.
                            "priority",      # The priority keyword assigns a severity level to rules. "priority": "priority",
                            "metadata",      # The metadata keyword allows a rule writer to embed additional  information about the rule, typically in a key-value format.
                            "service",
                            "rem",
                            "file_meta",
                        }
        if option:
            if option in general_options:
                return option
            else:
                return False
        else:
            return general_options

    @staticmethod
    def payload_options(option: str = None) -> Any:
        payload_options = { "content",              # The content keyword allows the user to set rules that search for specific content in the packet payload and trigger response based on that data.
                            "http_uri",             # Normalized HTTP URI"
                            "http_raw_uri",         # Unnormalized HTTP URI
                            "http_header",          # Normalized HTTP headers
                            "http_raw_header",	    # Unnormalized HTTP headers
                            "http_cookie", 	        # Normalized HTTP cookies
                            "http_raw_cookie",	    # Unnormalized HTTP cookies
                            "http_client_body",     # Normalized HTTP request body"
                            "http_raw_body",	    # Unnormalized HTTP request body and response data
                            "http_param",	        # Specific HTTP parameter values
                            "http_method",	        # HTTP request methods
                            "http_version",	        # HTTP request and response versions
                            "http_stat_code",	    # HTTP response status codes
                            "http_stat_msg",	    # HTTP response status messages
                            "http_raw_request",	    # Unnormalized HTTP start lines
                            "http_raw_status",	    # Unnormalized HTTP status lines
                            "http_trailer",	        # Normalized HTTP trailers
                            "http_raw_trailer",	    # Unnormalized HTTP trailers
                            "http_true_ip",	        # Original client IP address as stored in various request proxy headers
                            "http_version_match",	# Non-sticky buffer option used to test an HTTP message's version against a list of versions
                            "http_num_headers",	    # Non-sticky buffer option used to test the number of HTTP headers against a specific value or a range of values
                            "http_num_trailers",	# Non-sticky buffer option used to test the number of HTTP trailers against a specific value or a range of values
                            "http_num_cookies",	    # Non-sticky buffer option used to test the number of HTTP cookies against a specific value or a range of values
                            "bufferlen",        	# bufferlen checks the length of a given buffer"
                            "isdataat",	            # isdataat verifies the payload data exists at a specified location
                            "dsize",	            # dsize tests packet payload size
                            "pcre",	                # pcre is used to create perl compatible regular expressions
                            "regex",	            # regex is used to create perl compatible regular expressions that are checked against payload data with the hyperscan engine
                            "pkt_data",	            # pkt_data is a sticky buffer declaration that sets the detection cursor to the beginning of the normalized packet data
                            "raw_data",	            # raw_data is a sticky buffer declaration that sets the detection cursor to the beginning of the raw packet data
                            "file_data",	        # file_data is a sticky buffer declaration that sets the detection cursor to either the HTTP response body for HTTP traffic or file data sent via other application protocols that has been processed and captured by Snort's "file API"
                            "js_data",	            # js_data is a sticky buffer declaration that sets the detection cursor to the normalized JavaScript data buffer
                            "vba_data",	            # vba_data is a sticky buffer declaration that sets the detection cursor to the buffer containing VBA macro code
                            "base64_decode",	    # base64_decode is used to decode base64-encoded data in a packet
                            "base64_data",	        # base64_data is a sticky buffer declaration that sets the detection cursor to the beginning of the base64 decoded buffer
                            "byte_extract",	        # byte_extract reads some number of bytes from packet data and stores the extracted byte or bytes into a named variable
                            "byte_test",	        # byte_test tests a byte or multiple bytes from the packet against a specific value with a specified operator
                            "byte_math",	        # byte_math extracts bytes from the packet and performs a mathematical operation on the extracted value, storing the result in a new variable
                            "byte_jump",	        # byte_jump reads some number of bytes from the packet, converts them from their numeric representation if necessary, and moves that many bytes forward
                            "ber_data",             # The ber_data option moves the detection cursor to the value portion of a specified BER element.
                            "ber_skip",             # The ber_skip option skips an entire BER element.
                            "ssl_state",            # The ssl_state rule option tracks the state of the SSL/TLS session.
                            "ssl_version",          # The ssl_version rule option tracks the specific SSL/TLS version agreed upon by the two parties. 
                            "dce_iface",            # The dce_iface option is used to specify an interface UUID that a client has bound to.   
                            "dce_opnum",            # The dce_opnum option enables users to check that a packet belongs to a specific DCE-RPC operation invocation.
                            "dce_stub_data",        # The dce_stub_data option is a sticky buffer that is used to set the detection cursor to the beginning of the DCE/RPC stub data, regardless of preceding rule options.
                            "sip_method",           # The sip_method rule option enables rule writers to check packets against a specific SIP method or multiple SIP methods.
                            "sip_header",           # The sip_header rule option is a sticky buffer that sets the detection cursor to the buffers containing extracted SIP headers from a SIP message request or response.
                            "sip_body",             # The sip_body rule option is a sticky buffer that sets the detection cursor to a SIP message body. 
                            "sip_stat_code",        # The sip_stat_code option is used to check the status code of a SIP response packet.
                            "sd_pattern",	        # sd_pattern detects sensitive data, such as credit card and social security numbers
                            "cvs",	                # cvs looks for a specific attack types
                            "md5", 
                            "sha256",  
                            "sha512",	            # md5, sha256, and sha512 check payload data against a specified hash value
                            "gtp_info",             # The gtp_info rule option is used to check the "Information Element" field of GTP packets. 
                            "gtp_type",             # The gtp_type rule option is used to check for specific GTP Message Type values.
                            "gtp_version",          # The gtp_version option is used to check GTP version numbers
                            "dnp3_func",            # The dnp3_func rule option is used to check for DNP3 function codes.
                            "dnp3_ind",             # The dnp3_ind rule option is used to check DNP3 indicator flags. 
                            "dnp3_obj",             # The dnp3_obj rule option is used to check DNP3 object headers.
                            "dnp3_data",            # The dnp3_data rule option sets the cursor to the beginning of DNP3 Application Layer data. 
                            "modbus_data",          # The modbus_data rule option is used to set the detection cursor to the start of Modbus data.
                            "modbus_func",          # The modbus_func rule option is used to check for a particular Modbus function code or function name.
                            "modbus_unit",          # The modbus_unit rule option is used to check for a particular Modbus unit identifier.
                            "rawbytes",
                        }
        if option:
            if option in payload_options:
                return option
            else:
                return False
        else:
            return payload_options

    @staticmethod
    def non_payload_options(option: str = None) -> Any:
        non_payload_detect = {  "fragoffset",         # The fragoffset keyword allows one to compare the IP fragment offset field against a decimal value.
                                "ttl",              # The ttl keyword is used to check the IP time-to-live value.
                                "tos",              # The tos keyword is used to check the IP TOS field for a specific value.
                                "id",               # The id keyword is used to check the IP ID field for a specific value.
                                "ipopts",           # The ipopts keyword is used to check if a specific IP option is present.
                                "fragbits",         # The fragbits keyword is used to check if fragmentation and reserved bits are set in the IP header.
                                "ip_proto",         # The ip proto keyword allows checks against the IP protocol header
                                "flags",            # The flags keyword is used to check if specific TCP flag bits are present.
                                "flow",             # The flow keyword allows rules to only apply to certain directions of the traffic flow. 
                                "flowbits",         # The flowbits keyword allows rules to track states during a transport protocol session.
                                "file_type",        # file_type is used to create rules that are constrained to a specific file type, a specific version of a file type
                                "seq",              # The seq keyword is used to check for a specific TCP sequence number
                                "ack",              # The ack keyword is used to check for a specific TCP acknowledge number
                                "window",           # The window keyword is used to check for a specific TCP window size
                                "itype",            # The itype keyword is used to check for a specific ICMP type value
                                "icode",            # The icode keyword is used to check for a specific ICMP code value
                                "icmp_id",          # The icmp id keyword is used to check for a specific ICMP ID value.
                                "icmp_seq",         # The icmp seq keyword is used to check or a specific ICMP sequence value.
                                "rpc",              # The rpc keyword is used to check for a RPC application, version, and procedure numbers in SUNRPC CALL requests
                                "stream_reassemble",# The stream_reassemble keyword allows a rule to enable or disable TCP stream reassembly on matching traffic.
                                "stream_size"       # The stream_size keyword allows a rule to match traffic according to the number of bytes observed, as determined by the TCP sequence numbers.
                            }
        if option:
            if option in non_payload_detect:
                return option
            else:
                return False
        else:
            return non_payload_detect

    @staticmethod
    def post_detect_options(option: str = None) -> Any:
        post_detect = { "detection_filter",
                        "replace",              # Replace the prior matching content with the given string of the same length. Available in inline mode only. 
                                                # NOTE: As mentioned above, Snort evaluates detection_filter as the last step of the detection and not in post-detection.
                        "tag",                  # The tag keyword allow rules to log more than just the single packet that triggered the rule
                    }
        if option:
            if option in post_detect:
                return option
            else:
                return False
        else:
            return post_detect

    @staticmethod
    def content_modifiers(option: str = None) -> Any:
        content_modifiers = {   "nocase",
                                "depth",
                                "offset",
                                "distance",
                                "within",
                                "fast_pattern",
                                "startswith",
                                "endswith"
                            }
        if option:
            if option in content_modifiers:
                return option
            else:
                return False
        else:
            return content_modifiers


    @staticmethod
    def sticky_buffers(option: str = None) -> Any:
        sticky_buffers = {  "http_uri",
                            "http_raw_uri",	
                            "http_header",	
                            "http_raw_header",	
                            "http_cookie",	
                            "http_raw_cookie",	
                            "http_client_body",	
                            "http_raw_body",	
                            "http_param",
                            "http_method",
                            "http_stat_code",
                            "http_stat_msg",
                            "pkt_data",	            
                            "raw_data",	            
                            "file_data",	                
                            "base64_data",
                            "json_data", 
                            "vba_data",
                            "ssh_proto",
                            "ja3_hash",
                            "ja3.hash",
                            "ja3s.hash",
                            "http.method",
                            "http.uri",
                            "http.uri.raw",
                            "http.host",
                            "http.start",
                            "http.server",
                            "http.header",
                            "http.header.raw",
                            "http.header_names",
                            "http.stat_code",
                            "http.response_body",
                            "http.user_agent",
                            "http.request_body",
                            "http.content_type",
                            "http.content_len",
                            "http.connection",
                            "http.cookie",
                            "http.request_line",
                            "http.accept_lang",
                            "http.accept_enc",
                            "http.accept",
                            "http.referer",
                            "http.location",
                            "http_header_names",
                            "http_user_agent",
                            "http_referer",
                            "dns.query",
                            "dns_query",
                            "file.data",
                            "tls.cert_subject",
                            "tls.sni",
                            "tls_sni",
                            "tls.cert_issuer",
                            "tls.cert_serial",
                            "tls.certs",
                            "tls.version",
                        }
        if option:
            if option in sticky_buffers:
                return option
            else:
                return False
        else:
            return sticky_buffers


    @staticmethod
    def supported_snort_sticky_buffers(option: str = None) -> Any:
        snort_sticky_buffers = {  
                            "http_uri",
                            "http_raw_uri",	
                            "http_header",	
                            "http_raw_header",	
                            "http_cookie",	
                            "http_raw_cookie",	
                            "http_client_body",	
                            "http_raw_body",	
                            "http_method",
                            "http_stat_code",
                            "http_stat_msg", 
                            "pkt_data",	            
                            "raw_data",
                            "file_data"               
                        }
        if option:
            if option in snort_sticky_buffers:
                return option
            else:
                return False
        else:
            return snort_sticky_buffers
        
    @staticmethod
    def supported_suricata_sticky_buffers(option: str = None) -> Any:
        suricata_sticky_buffers = {  
                            "http.method",
                            "http.uri",
                            "http.uri.raw",
                            "http.host",
                            "http.server",
                            "http.header",
                            "http.header.raw",
                            "http.header_names",
                            "http.stat_code",
                            "http.stat_msg",
                            "http.response_body",
                            "http.user_agent",
                            "http.request_body",
                            "http.content_type",
                            "http.content_len",
                            "http.connection",
                            "http.cookie",
                            "http.accept_lang",
                            "http.accept_enc",
                            "http.accept",
                            "http.referer",
                            "http.location", 
                            "http_method",
                            "http_uri",	
                            "http_raw_uri",	
                            "http_header",
                            "http_raw_header",	
                            "http_header_names",	
                            "http_stat_code",
                            "http_stat_msg",
                            "http_user_agent",
                            "http_client_body",	
                            "http_cookie",
                            "http_referer",
                            "dns.query",
                            "dns_query"
                        }
        if option:
            if option in suricata_sticky_buffers:
                return option
            else:
                return False
        else:
            return suricata_sticky_buffers


    @staticmethod
    def suricata_only_options(option: str = None) -> Any:
        suricata_only_options = {  "asn1",
                            "threshold",
                            "bsize",
                            "urilen",
                            "target",
                            "dotprefix",
                            "xbits",
                            "noalert",
                            "flowint",
                            "app-layer-event",
                            "app-layer-protocol"     
                        }
        if option:
            if option in suricata_only_options:
                return option
            else:
                return False
        else:
            return suricata_only_options
        

    # Check if a rule option is a valid option type 
    def is_option(self, option):
        if option in self.payload_options():
            return "payload", True
        if option in self.non_payload_options():
            return "non-payload", True
        if option in self.general_options():
            return "general", True
        if option in self.post_detect_options():
            return "post_detect", True
        if option in self.content_modifiers():
            return "payload", True
        if option in self.suricata_only_options():
            return "suricata_only", True
        if option in self.sticky_buffers():
            return "sticky_buffers", True
        
        return "", False