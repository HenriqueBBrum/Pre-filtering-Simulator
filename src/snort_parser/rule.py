# Class representing a NIDS rule.
class Rule(object):
    def __init__(self, rule, header, options, has_negation):
        self.rule = rule # Original rule string

        self.header = header
        self.options = options

        self.has_negation = has_negation # IP or port is negated

        self.data = {"header": self.header, "options": self.options}
        self.all = self.data

    def rule_to_string(self):    
        return str(self.header)+str(self.options)
    
    def __getitem__(self, key):
        if key == 'all':
            return self.data
        else:
            return self.data[key]