import networkx as nx


class CFG:

    def __init__(self):

        self.graph = nx.DiGraph()
        self.graph_nodes_lookup = {}
        self.completed = 0x0

    def add_node(self, cfg_node):

        if cfg_node.label not in self.graph_nodes_lookup:
            self.graph.add_node(cfg_node)
            self.graph_nodes_lookup[cfg_node.label] = cfg_node

    def add_egde(self, node, predecessor):

        if (not self.graph.has_edge(predecessor, node)) and predecessor != node:
            self.graph.add_edge(predecessor, node)

    def has_node(self, sp=-1, value=None):
        if sp == -1 or value is None:
            return False
        elif sp and value:
            return '0x{:x}, 0x{:x}'.format(sp, value) in self.graph_nodes_lookup
        else:
            return False

    def _is_unique_predecessor(self, adj_matrix, src, dest):
        for (node, successors) in adj_matrix.iteritems():
            if src == node:
                if dest not in successors:
                    return False
            elif dest in successors:
                return False
        return True

    def _merge_node_aux(self, adj_matrix, src, dst, new_src):
        self.graph.add_node(new_src)
        incoming_edges = list(self.graph.predecessors(src))
        for pred in incoming_edges:
            self.graph.remove_edge(pred, src)
            adj_matrix[pred].remove(src)
            self.graph.add_edge(pred, new_src)
            adj_matrix[pred].append(new_src)
        self.graph.remove_edge(src, dst)
        self.graph.remove_node(src)
        del adj_matrix[src]

        for x in adj_matrix[dst]:
            self.graph.remove_edge(dst, x)
            self.graph.add_edge(new_src, x)

        adj_matrix[new_src] = adj_matrix[dst]
        del adj_matrix[dst]
        self.graph.remove_node(dst)

    def _merge_nodes(self, sequences_only):
        adj_matrix = {}  # manual won over nx.convert.to_dict_of_lists(G)
        for node in self.graph.nodes:
            adj_matrix[node] = []
        for (a, b) in self.graph.edges:
            adj_matrix[a].append(b)
        changed = True
        while changed is True:
            changed = False
            for (src, successors) in adj_matrix.iteritems():
                if len(successors) is 0 or len(successors) > 1:
                    continue
                dst = next(iter(successors))
                if src == dst or src.label == '==== START ====':
                    continue
                if not self._is_unique_predecessor(adj_matrix, src, dst):
                    continue
                if sequences_only:
                    # Assumption: can only be called before clusters are created
                    value_src = src.value[0] if isinstance(src, SequenceNode) else src.value
                    value_dst = dst.value[0] if isinstance(dst, SequenceNode) else dst.value
                    if value_src == value_dst:
                        new_src = SequenceNode(src, dst)
                        self._merge_node_aux(adj_matrix, src, dst, new_src)
                        changed = True
                        break
                else:
                    new_src = ClusterNode(src, dst)
                    self._merge_node_aux(adj_matrix, src, dst, new_src)
                    changed = True
                    break

    def merge_gadget_sequence(self, G, root):
        self._merge_nodes(sequences_only=True)

    def merge_clusters(self, G, root):
        self._merge_nodes(sequences_only=False)

    def _save_graph(self, empty=False):

        from graphviz import Digraph

        to_render = Digraph(node_attr={'shape': 'box'})

        if self.completed != 0x3:
            # this will merge repetitions of the same gadgets
            self.merge_gadget_sequence(self.graph, BaseNode())
            # this will assemble basic blocks
            self.merge_clusters(self.graph, BaseNode())

        for node in self.graph.nodes:
            if node.label != '==== START ====':
                node_n = node.label
                if empty:
                    to_render.node(node_n, ' ')
                else:
                    to_render.node(node_n, str(node))
            else:
                to_render.node(node.label)
        for edge in self.graph.edges:
            l = self.graph.edges[edge]['label'] if 'label' in self.graph.edges[edge] else ''
            to_render.edge(edge[0].label, edge[1].label, label=l)

        if empty:
            to_render.save('output/empty_graph.gv')
        else:
            to_render.save('output/graph.gv')

    def render_graph(self):

        if self.completed & 0x1:
            return

        self.completed |= 0x1

        self._save_graph(empty=False)

    def render_empty_graph(self):

        if self.completed & 0x2:
            return

        self.completed |= 0x2

        self._save_graph(empty=True)

    def combine_with(self, other):
        self.graph = nx.compose(self.graph, other.graph)
        self.graph_nodes_lookup.update(other.graph_nodes_lookup)

    @staticmethod
    def combine_CFGs(cfgs):
        if cfgs:
            G = cfgs[0]
            for H in cfgs[1:]:
                G.combine_with(H)
            return G

        return None


class BaseNode:

    def __init__(self):
        self.label = '==== START ===='
        self.sp = []
        self.value = []
        self.gadget = []

    def __hash__(self):
        return hash(self.label)

    def __eq__(self, other):
        return self.label == other.label

    def __str__(self):
        return self.label


class CFGNode(BaseNode):

    def __init__(self, sp=-1, value=-1, gadget=None):
        BaseNode.__init__(self)

        if sp != -1 and value != -1:
            self.label = '0x{:x}, 0x{:x}'.format(sp, value)
        elif (sp == -1 and value != -1) or (sp != -1 and value == -1):
            raise TypeError('Got to provide both sp and value as parameters or neither.')
        else:
            self.label = '==== START ===='
        self.sp = sp
        self.value = value
        self.gadget = gadget

    def __eq__(self, other):
        return self.sp == other.sp and self.value == other.value

    def __hash__(self):
        return hash(self.sp) + hash(self.value)

    def __str__(self):
        return '== [0x{:x}]: 0x{:x} ==\n\n{}'.format(self.sp, self.value, self.gadget)


class SequenceNode(BaseNode):

    def __init__(self, merge_src, merge_dst):
        BaseNode.__init__(self)
        self.sp = []
        self.value = []   # TODO just use one
        self.gadget = []  # TODO just use one
        for node in [merge_src, merge_dst]:
            if isinstance(node, SequenceNode):
                self.sp = self.sp + node.sp
                self.value = self.value + node.value
                self.gadget = self.gadget + node.gadget
            else:
                self.sp.append(node.sp)
                self.value.append(node.value)
                self.gadget.append(node.gadget)
        self.label = '== Sequence x{} [0x{:x}, 0x{:x}] =='.format(len(self.sp), self.sp[0], self.sp[-1])

    def __str__(self):
        return '{}\n\n{}'.format(self.label, self.gadget)


class ClusterNode(BaseNode):

    def __init__(self, merge_src, merge_dst):
        BaseNode.__init__(self)
        self.label = '==== Basic Block {} ===='
        self.nodes = []
        self.sp = []
        self.value = []
        self.gadget = []
        for node in [merge_src, merge_dst]:
            if isinstance(node, ClusterNode):
                for n in node.nodes:
                    self._helper_fields(n)
            else:
                self._helper_fields(node)

    def _helper_fields(self, node):
        if isinstance(node, CFGNode):
            self.nodes.append(node)
            self.sp.append(node.sp)
            self.value.append(node.value)
            self.gadget.append(node.gadget)
            self.label = self.label + '\n0x{:x}, 0x{:x}'.format(node.sp, node.value)
        elif isinstance(node, SequenceNode):
            self.nodes.append(node)
            self.sp = self.sp + node.sp
            self.value = self.value + node.value
            self.gadget = self.gadget + node.gadget
            self.label = self.label + '\n' + node.label

    def __str__(self):
        e = '{}\n\n{}'
        ret = e
        for i, node in enumerate(self.nodes):
            end = e if i != len(self.nodes) - 1 else ''
            ret = ret.format(node, end)
        return ret

    def __hash__(self):
        return hash(self.label) + sum(hash(node) for node in self.nodes)
