# Methods that return statistics about the NIDS rules

from collections import Counter

class RuleStatistics:

    def __init__(self, config, parsed_rules):
        self.rules = parsed_rules

        self.protocol_stats = self.compute_protocol_stats()
        self.direction_stats = self.compute_direction_stats()
        self.src_stats = self.compute_src_stats()
        self.dst_stats = self.compute_dst_stats()
        self.src_port_stats = self.compute_src_port_stats()
        self.dst_port_stats = self.compute_dst_port_stats()

        self.negation_stats = self.compute_negation_stats(config)

        self.priorities = self.compute_priorities(config)

    def compute_protocol_stats(self):
        result = [rule.header.get('proto') for rule in self.rules]
        return Counter(result)

    def compute_direction_stats(self):
        result = [rule.header.get('direction') for rule in self.rules]
        return Counter(result)
    
    def compute_src_stats(self):
        result = [str(rule.header.get('src_ip')) for rule in self.rules]
        return Counter(result)

    def compute_dst_stats(self):
        result = [str(rule.header.get('dst_ip')) for rule in self.rules]
        return Counter(result)

    def compute_src_port_stats(self):
        result = [str(rule.header.get('src_port')) for rule in self.rules]
        return Counter(result)

    def compute_dst_port_stats(self):
        result = [str(rule.header.get('dst_port'))  for rule in self.rules]
        return Counter(result)
    
    # Negation counter should take into account config file?
    def compute_negation_stats(self, config):
        result = [rule.has_negation for rule in self.rules]
        return {'non-negation': result.count(False), 'negation': result.count(True)}

    def compute_priorities(self, config):    
        classtypes = [rule.options.get('classtype', 'unknown')[1][0] for rule in self.rules]
        priorities = [config.classification_priority[classtype] for classtype in classtypes]
        return Counter(priorities)

    def print_all(self):
        print(self.negation_stats)
        print(self.protocol_stats)
        print(self.direction_stats)
        print("Top 10 src ip: ", dict(self.src_stats.most_common(10)))
        print("Top 10 dst ip: ", dict(self.dst_stats.most_common(10)))
        print()
        print("Top 10 src port: ", dict(self.src_port_stats.most_common(10)))
        print()
        print("Top 10 dst port: ", dict(self.dst_port_stats.most_common(10)))
        print()
        print(self.priorities)

