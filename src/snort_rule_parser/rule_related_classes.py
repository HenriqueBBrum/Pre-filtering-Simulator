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

    def rule_id(self):
        id = ""
        for key, value in self.header.items():
            id+=str(value)

        flags = self.options.get("flags", [])
        if flags:
            flags = flags[1][0]

        return id+str(flags)
    

    def __getitem__(self, key):
        if key == 'all':
            return self.data
        else:
            return self.data[key]
        
    

# Class that aggreggates multiple rule with the same header values and tcp flag options
class AggregatedRule(object):
    def __init__(self, header={}, flags=str(), priority_list=[], sid_rev_list=[]):
        self.header = header
        self.flags = flags

        self.priority_list = priority_list
        self.sid_rev_list = sid_rev_list

    def sids(self):
        return list(set(self.sid_list))