import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import "./App.css";

type NodeData = {
  id: string;
  name: string;
  type: string;
  ip: string;
  criticality: string;
  exposed: string;
  compromised: string;
};

type EdgeData = {
  source: string;
  target: string;
  relationship: string;
  protocol: string;
};

type GraphResponse = {
  nodes: NodeData[];
  edges: EdgeData[];
};

function App() {
  const graphRef = useRef<HTMLDivElement>(null);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("http://127.0.0.1:8000/graph")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Failed to fetch graph");
        }
        return response.json();
      })
      .then((data: GraphResponse) => {
        setGraph(data);
      })
      .catch((err) => {
        console.error(err);
        setError("Could not connect to NEXAGRAPH AI backend.");
      });
  }, []);

  useEffect(() => {
    if (!graph || !graphRef.current) return;

    const elements = [
      ...graph.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.name,
          type: node.type,
          criticality: node.criticality,
        },
      })),

      ...graph.edges.map((edge, index) => ({
        data: {
          id: `edge-${index}`,
          source: edge.source,
          target: edge.target,
          label: edge.relationship,
        },
      })),
    ];

    const cy = cytoscape({
      container: graphRef.current,

      elements,

      style: [
        {
          selector: "node",
          style: {
            "background-color": "#2563eb",
            label: "data(label)",
            color: "#ffffff",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": "11px",
            width: 45,
            height: 45,
            "border-width": 2,
            "border-color": "#93c5fd",
          },
        },

        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#64748b",
            "target-arrow-color": "#64748b",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            color: "#94a3b8",
            "font-size": "8px",
          },
        },

        {
          selector: "node:selected",
          style: {
            "background-color": "#f59e0b",
            "border-color": "#fbbf24",
            "border-width": 4,
          },
        },
      ],

      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 50,
        spacingFactor: 1.3,
      },
    });

    cy.on("tap", "node", (event) => {
      const id = event.target.id();

      const node = graph.nodes.find(
        (item) => item.id === id
      );

      if (node) {
        setSelectedNode(node);
      }
    });

    return () => {
      cy.destroy();
    };
  }, [graph]);

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>NEXAGRAPH AI</h1>
          <p>Enterprise Attack Path Analysis & Threat Intelligence</p>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          SYSTEM ONLINE
        </div>
      </header>

      <main className="main">
        <section className="stats">
          <div className="stat-card">
            <span>Assets</span>
            <strong>{graph?.nodes.length ?? 0}</strong>
          </div>

          <div className="stat-card">
            <span>Connections</span>
            <strong>{graph?.edges.length ?? 0}</strong>
          </div>

          <div className="stat-card">
            <span>Critical Assets</span>
            <strong>
              {graph?.nodes.filter(
                (node) =>
                  node.criticality.toLowerCase() === "critical"
              ).length ?? 0}
            </strong>
          </div>

          <div className="stat-card">
            <span>Compromised</span>
            <strong>
              {graph?.nodes.filter(
                (node) =>
                  node.compromised.toLowerCase() === "yes"
              ).length ?? 0}
            </strong>
          </div>
        </section>

        {error && <div className="error">{error}</div>}

        <section className="workspace">
          <div className="graph-panel">
            <div className="panel-header">
              <div>
                <h2>Enterprise Attack Graph</h2>
                <p>
                  Live graph loaded from Neo4j through FastAPI
                </p>
              </div>

              <span className="live-badge">LIVE DATA</span>
            </div>

            <div ref={graphRef} className="graph-container"></div>
          </div>

          <aside className="details-panel">
            <h2>Asset Details</h2>

            {!selectedNode ? (
              <div className="empty">
                Click a node to inspect the asset.
              </div>
            ) : (
              <div className="details">
                <div className="asset-name">
                  {selectedNode.name}
                </div>

                <div className="detail-row">
                  <span>ID</span>
                  <strong>{selectedNode.id}</strong>
                </div>

                <div className="detail-row">
                  <span>Type</span>
                  <strong>{selectedNode.type}</strong>
                </div>

                <div className="detail-row">
                  <span>IP</span>
                  <strong>{selectedNode.ip}</strong>
                </div>

                <div className="detail-row">
                  <span>Criticality</span>
                  <strong>{selectedNode.criticality}</strong>
                </div>

                <div className="detail-row">
                  <span>Exposed</span>
                  <strong>{selectedNode.exposed}</strong>
                </div>

                <div className="detail-row">
                  <span>Compromised</span>
                  <strong>{selectedNode.compromised}</strong>
                </div>
              </div>
            )}
          </aside>
        </section>
      </main>
    </div>
  );
}

export default App;