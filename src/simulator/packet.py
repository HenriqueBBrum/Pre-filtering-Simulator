import codecs
from socket import getservbyport



# Size in bytes
ETH_SIZE = 14

IPV4_MIN_SIZE = 20
IPV4_MAX_SIZE = 60

IPV6_SIZE = 40

ICMP_MIN_SIZE = 4
ICMPV4_MAX_SIZE = 8

TCP_MIN_SIZE = 20
UDP_SIZE = 8

# Ether type

IPV4 = 0X800
IPV6 = 0X8DD

# IP Protocol

ICMP = 0X01
TCP = 0X06
UDP = 0X11

ipproto_str_to_hex = {0x01:"icmp", 0x06:"tcp", 0x11:"udp"}
ICMP_TYPE_WITH_ID_AND_SEQ = {13, 14, 17, 18}


class Packet(object):
    def __init__(self, buffer, buffer_len) -> None:
        self.buffer_len = buffer_len

        self.hex_buffer = ""
        self.hex_buffer_lower = ""

        self.layer3_proto = None

        self.id           = None
        self.fragbits     = None
        self.ttl          = None
        self.layer4_proto = None
        self.layer4_proto_str = None

        self.src_ip       = ""
        self.dst_ip       = ""
        self.ipotps       = None

        self.icmp_itype   = None
        self.icmp_icode   = None
        self.icmp_id      = None
        self.icmp_seq     = None

        self.src_port     = None
        self.dst_port     = None

        self.tcp_flags    = None
        self.tcp_seq      = None
        self.tcp_ack      = None
        self.tcp_window   = None

        self.applayer_proto = None

        self.payload      = None
        self.payload_lower_case = b""
        self.payload_len  = None

        ether_type_hex = int(codecs.encode(buffer[12:14], "hex"), 16)
        if ether_type_hex == IPV4 or ether_type_hex == IPV6:
            self.hex_buffer = codecs.encode(buffer, "hex") # Do this only if packet is IP
            self.hex_buffer_lower = codecs.encode(buffer.lower(), "hex")
            self.__parse_eth()

    def __str__(self):
        print_str ="\n"+"-"*10+"PKT data"+"-"*10+"\n"
        print_str+=("Layer 3 proto=" + str(self.layer3_proto) + "\n")
        print_str+=("IP fields:  ID="+ str(self.id)+", Fragbits="+str(self.fragbits)+", TTL="+str(self.ttl)+", Layer 4 proto="+str(self.layer4_proto)+ "\n")
        if self.layer4_proto == TCP:
            print_str+=("TCP fields: Flags="+ str(self.tcp_flags)+", SEQ="+str(self.tcp_seq)+", ACK="+str(self.tcp_ack)+", Window="+str(self.tcp_window)+ "\n")

        if self.src_port:
            print_str+=("Src port=" + str(self.src_port) + ", Dst port=" + str(self.dst_port) + "\n")

        print_str+=("-"*14+"-"*14+"\n")
        return print_str 
    

    def __get_byte(self, index, as_int=True):
        return int(self.hex_buffer[index*2:index*2+2], 16) if as_int else self.hex_buffer[index*2:index*2+2]
    
    def __get_bytes(self, start, end, as_int=True):
        return int(self.hex_buffer[start*2:end*2], 16) if as_int else self.hex_buffer[start*2:end*2]

    def __parse_eth(self):
        if self.buffer_len < ETH_SIZE:
            return
        
        self.layer3_proto = self.__parse_ip(self.__get_bytes(12, 14))


    def __parse_ip(self, eth_type):
        if eth_type == IPV4:
            if self.buffer_len < ETH_SIZE+IPV4_MIN_SIZE:
                return None
            
            ihl = self.__get_byte(14) & 0X0F # Get only "upper" four bits
            self.id = self.__get_bytes(18, 20)
            self.fragbits =  self.__get_byte(20) >> 5 # Not all, just the first three bits
            self.ttl = self.__get_byte(22)
            self.layer4_proto = self.__get_byte(23)
            self.layer4_proto_str = ipproto_str_to_hex.get(self.layer4_proto, "")

            self.src_ip = self.__parse_ip_address(26, 30)
            self.dst_ip = self.__parse_ip_address(30, 34)

            ipv4_end = ETH_SIZE+IPV4_MIN_SIZE
            if ihl*4 > IPV4_MIN_SIZE:
                ipv4_end = 34+(ihl*4-IPV4_MIN_SIZE)
                self.ipotps = self.__get_byte(34) # Only get the type
            
            payload_start = ipv4_end
            if self.layer4_proto == 0x01:
                payload_start = self.__parse_icmp(ipv4_end)
            elif self.layer4_proto == 0x06:
                payload_start = self.__parse_tcp(ipv4_end)
            elif self.layer4_proto == 0x11:
                payload_start = self.__parse_udp(ipv4_end)

            self.applayer_proto = self.__get_applayer_proto()
 
            self.payload = self.hex_buffer[payload_start*2:]
            self.payload_lower_case = self.hex_buffer_lower[payload_start*2:]
            self.payload_len = int(len(self.payload)/2)
            return IPV4
        elif eth_type == IPV6:
            if self.buffer_len < ETH_SIZE+IPV6_SIZE:
                return None
            
            return None

        return None

    def __parse_ip_address(self, start, end):
        ip_str = ""
        ip_bytes= self.__get_bytes(start, end, False)
        for i in range(0, len(ip_bytes), 2): 
            ip_str+=(str(int(ip_bytes[i:i+2], 16)) + ".")

        return  ip_str[:-1]

    def __parse_icmp(self, layer4_start, icmp_version=4):
        if self.buffer_len < layer4_start + ICMP_MIN_SIZE:
            return
        
        self.icmp_itype = self.__get_byte(layer4_start)
        self.icmp_icode = self.__get_byte(layer4_start+1)

        icmp_end = layer4_start+4 # +4 because there are two bytes for checksum
        if icmp_version==4 and self.icmp_itype in ICMP_TYPE_WITH_ID_AND_SEQ:
            self.icmp_id = self.__get_byte(layer4_start+5)
            self.icmp_seq = self.__get_byte(layer4_start+6)
            icmp_end = layer4_start+7

        # print("icmp",  self.icmp_itype, self.icmp_icode, self.icmp_id, self.icmp_seq)

        return icmp_end


    def __parse_tcp(self, layer4_start):
        if self.buffer_len < layer4_start + TCP_MIN_SIZE:
            return
        
        self.src_port = self.__get_bytes(layer4_start, layer4_start+2)
        self.dst_port = self.__get_bytes(layer4_start+2, layer4_start+4)
        self.tcp_seq = self.__get_bytes(layer4_start+4, layer4_start+8)
        self.tcp_ack = self.__get_bytes(layer4_start+8, layer4_start+12)
        data_offset = self.__get_byte(layer4_start+12) >> 4 # Get only "lower" four bits
        self.tcp_flags= self.__get_byte(layer4_start+13, True)
        self.tcp_window = self.__get_bytes(layer4_start+14, layer4_start+16)
       
        # print("tcp", self.src_port, self.dst_port, self.tcp_seq, self.tcp_ack, self.tcp_flags, self.tcp_window)

        return layer4_start+(data_offset*4)
      


    def __parse_udp(self, layer4_start):
        if self.buffer_len < layer4_start + UDP_SIZE:
            return
        
        self.src_port = self.__get_bytes(layer4_start, layer4_start+2)
        self.dst_port = self.__get_bytes(layer4_start+2, layer4_start+4)

        # print("udp", self.src_port, self.dst_port)

        return layer4_start+UDP_SIZE


    def __get_applayer_proto(self):
        if self.layer4_proto != TCP and self.layer4_proto != UDP:
            return None
        
        proto = None
        try:
            proto = getservbyport(self.dst_port, self.layer4_proto_str)
        except:
            try:
                proto = getservbyport(self.src_port, self.layer4_proto_str)
            except:
                return None
       
        change_map = {"http-alt": "http", "microsoft-ds": "netbios-ssn", "domain": "dns", "mdns":"dns", "https": None}
        if proto:
            if proto in change_map:
                proto = change_map[proto]
                
            if not proto:
                return proto
    
        return proto