import attr

# Class representing a NIDS rule.
class Rule(object):
    def __init__(self, rule, header, options, has_negation):
        self.id = None
        self.rule = rule # Original rule string

        self.header = header
        self.options = options

        self.pkt_header = {}
        self.payload_fields = {}
        
        self.has_negation = has_negation # IP or port is negated


        self.data = {"header": self.header, "options": self.options}
        self.all = self.data

    def rule_to_string(self):
        string = ""
        for key, value in self.pkt_header.items():
            if key == "src_ip" or key == "dst_ip":
                string+=key+":["
                for rnode in value[0]:
                    string+="("+rnode.prefix+","+str(rnode.data["match"])+")"
                string+="];"
            else:
                string+=key+":"+str(value)+";"

        for key, value in self.payload_fields.items():
            string+=key+":"+str(value)

        return string
    

    def __getitem__(self, key):
        if key == 'all':
            return self.data
        else:
            return self.data[key]
        
    

# Class that aggreggates multiple rule with the same pre-filtering values in pkt_header and payload_fields
class AggregatedRule(object):
    def __init__(self, pkt_header, payload_fields, priority_list=[], sid_rev_list=[]):
        self.pkt_header = pkt_header
        self.payload_fields = payload_fields

        self.priority_list = priority_list
        self.sid_rev_list = sid_rev_list

    def sids(self):
        return list(set(self.sid_list))