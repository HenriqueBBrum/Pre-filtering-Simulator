# Class represeting the matches of a protocol
class Node:
    def __init__(self, parents, name, applayer=False):
        self.parents = parents
        self.name = name

        self.applayer = applayer
        self.children = set()

        self.matches = []

class MatchTree:
    def __init__(self, root, base_node_names):
        self.nodes = {}
        self.root = root
        self.nodes[root] = Node([], root)

        for parents, name in base_node_names:
            self.add_node(parents, name)


    def get_root(self):
        return self.nodes[self.root]

    def add_node(self, parents, node_name, applayer=False):
        if node_name in self.nodes:
            raise Exception(f"Node already exists: {node_name}")
        if type(parents) == str:
            parents = [parents]

        for parent in parents:
            if parent not in self.nodes:
                raise Exception(f"No parent with this name: {parent}")
        
        self.nodes[node_name] = Node(parents, node_name, applayer)
        if node_name != self.root:
            for parent in parents:
                self.nodes[parent].children.add(node_name)
        
    def add_match(self, node_name, match):
        if node_name not in self.nodes:
            raise Exception("Node does not exist")
        else:
            self.nodes[node_name].matches.append(match)

    def safe_match_add(self, parents, node_name, match, applayer):
        if node_name not in self.nodes:
            self.add_node(parents, node_name, applayer)

        self.add_match(node_name, match)

    def get_related_matches(self, start_node, wrong_transport_node, node_name):
        if wrong_transport_node:
            if start_node.name == wrong_transport_node:
                return []
                        
        if start_node.name == node_name: # Base case: Has found the node
            return start_node.matches
            
        if len(start_node.children) == 0: # Base case: Not the desired node and it has no children
            return []
        
        matches = []
        for child in start_node.children: # Checking each node
            r = self.get_related_matches(self.nodes[child], wrong_transport_node, node_name)
            if r:
                return start_node.matches + r # Has found the node, return to root

        return matches
        
    def print_nodes(self):
       for key, node in self.nodes.items():
           print(node.parents, node.name, node.children, len(node.matches))