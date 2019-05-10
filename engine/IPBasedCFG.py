import networkx as nx


class IPBasedCFG:

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_nodes(self, nodes):
        n = set()
        for node, _ in nodes:
            n.add(node)
        for node in n:
            self.graph.add_node(hex(node).strip('L'))

    @staticmethod
    def _create_edges(nodes):
        edges = set()
        for i in xrange(1, len(nodes)):
            edges.add((hex(nodes[i - 1][0]).strip('L'), hex(nodes[i][0]).strip('L')))
        return edges

    def add_edges(self, nodes):
        edges = self._create_edges(nodes)
        self.graph.add_edges_from(list(edges))

    def render(self):
        nx.nx_pydot.write_dot(self.graph, 'output/MP-ip.gv')
        #import graphviz
        #graphviz.render('dot', 'png', 'output/MP-ip.gv')


class IPBasedMPCFG(IPBasedCFG):

    def __init__(self):
        IPBasedCFG.__init__(self)

    def add_nodes(self, traces):
        for trace in traces:
            IPBasedCFG.add_nodes(self, trace)

    def add_edges(self, traces):
        for trace in traces:
            IPBasedCFG.add_edges(self, trace)


"""
main
    from scozzo_su_debray import ScozzoDB
    scozzo = ScozzoDB()
    scozzo.add_nodes(emu.output.gadget_sequence)
    scozzo.add_edges(emu.output.gadget_sequence)
"""
