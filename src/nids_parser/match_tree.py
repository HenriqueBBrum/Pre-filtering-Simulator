# Class represeting the matches of a protocol
class Node:
    def __init__(self, parents, name, children=set()):
        self.parents = parents
        self.name = name
        self.children = children

        self.matches = []
        self.groupped_matches = {}

class MatchTree:
    def __init__(self, base_node_names):
        self.nodes = {}
        for parents, name, children in base_node_names:
            self.nodes[name] = Node(parents, name, children)

    def add_node(self, parents, node_name):
        if node_name in self.nodes:
            raise Exception("Node already exists")
        
        for parent in parents:
            if parent not in self.nodes:
                raise Exception("No parent with this name")
          
        self.nodes[node_name] = Node(parents, node_name)
        for parent in parents:
            self.nodes[parent].children.add(node_name)
        
    def add_match(self, node_name, match):
        if node_name not in self.nodes:
            raise Exception("Node does not exist")
        else:
            self.nodes[node_name].matches.append(match)

    def safe_match_add(self, parents, node_name, match):
        if node_name not in self.nodes:
            self.add_node(parents, node_name)

        self.add_match(node_name, match)

    def get_related_matches(self, start_node, transport_node, node_name):
        if transport_node:
            if start_node.name == transport_node:
                return []
                        
        if start_node.name == node_name: # Base case: Has found the node
            return start_node.matches
            
        if len(start_node.children) == 0: # Base case: Not the desired node and it has no children
            return []
        
        matches = []
        for child in start_node.children: # Checking each node
            r = self.get_related_matches(self.nodes[child], transport_node, node_name)
            if r:
                matches = start_node.matches + r # Has found the node, return to root
                return matches

        return matches
        
    def print_nodes(self):
       for key, node in self.nodes.items():
           print(node.parents, node.name, node.children, len(node.matches))