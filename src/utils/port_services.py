ip_proto_num_to_str = {1:"icmp", 6:"tcp", 17:"udp"}

file_data_ports = {110, 143} # This will be updated at the main file

port_to_service_map = {446: "drda", 447: "drda", 448: "drda", 1098:"java_rmi", 1099:"java_rmi",
                    1900: "ssdp", 1935: "rtmp", 5500: "vnc",  5800: "vnc", 5900: "vnc", 5938: "teamview"} # This will be updated at the main file

change_map = {"http-alt": "http", "microsoft-ds": "netbios-ssn", 
              "domain": "dns", "mdns":"dns", "https": "tls",
              "mysql-proxy": "mysql", "auth": "ident", "imap2": "imap",
              "imaps": "imap", "pop3s": "pop3", "telnets": "telnet",
              "ftps-data": "ftp-data", "ftps":"ftp", "dhcpv6-client": "dhcp",
              "dhcpv6-server": "dhcp", "syslog-tls": "syslog",
              "ircs-u": "irc", "radius-acct": "radius", "bgpd": "bgp",
              "sip-tls": "sip", "ms-wbt-server": "rdp", "epmap": "dcerpc"}


# file_data_ports = {20, 21, 25, 69, 110, 139, 143, 220, 445, 465, 585, 587, 993, 995, 2525, 3535, 3020,
                   # 152, 989, 990, 2100, 2811, 3305, 3535, 3721, 5402, 6086, 6619, 6622}