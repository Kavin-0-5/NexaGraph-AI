
import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import cytoscape from "cytoscape";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

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
  protocol: string | null;
};

type GraphResponse = {
  nodes: NodeData[];
  edges: EdgeData[];
};


type AttackPath = {
  path: NodeData[];
  connections: EdgeData[];
  risk_score: number;
  risk_level: "Low" | "Medium" | "High" | "Critical";
};

type AttackPathResponse = {
  paths: AttackPath[];
  total_paths: number;
  max_paths_reached: boolean;
  scoring_note?: string;
};
type RemediationType = "isolate-asset" | "remove-connection";


type FullSimulationResponse = {
  action_type: RemediationType;
  simulated_only: boolean;
  database_modified: boolean;
  before: AttackPathResponse;
  after: AttackPathResponse;
  paths_eliminated: number;
  highest_risk_before: number;
  highest_risk_after: number;
  risk_score_reduction: number;
  scoring_note: string;
};


type AssetForm = Omit<NodeData, never>;

type ConnectionForm = {
  source: string;
  target: string;
  relationship: string;
  protocol: string;
};

const emptyAssetForm: AssetForm = {
  id: "",
  name: "",
  type: "Server",
  ip: "",
  criticality: "Medium",
  exposed: "No",
  compromised: "No",
};

const emptyConnectionForm: ConnectionForm = {
  source: "",
  target: "",
  relationship: "CONNECTS",
  protocol: "TCP",
};

async function apiRequest(path: string, options?: RequestInit) {
  const response = await fetch(`${API_URL}${path}`, options);
  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      typeof result.detail === "string"
        ? result.detail
        : `Request failed (${response.status})`
    );
  }

  return result;
}

function App() {
  const graphRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [assetForm, setAssetForm] = useState<AssetForm>(emptyAssetForm);
  const [connectionForm, setConnectionForm] =
    useState<ConnectionForm>(emptyConnectionForm);

  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState<AssetForm>(emptyAssetForm);
  const [saving, setSaving] = useState(false);
  const [formMessage, setFormMessage] = useState("");
  const [formError, setFormError] = useState("");

  
  const [attackData, setAttackData] =
    useState<AttackPathResponse | null>(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [attackError, setAttackError] = useState("");
  const [selectedPathIndex, setSelectedPathIndex] =
    useState<number | null>(null);

  const [remediationType, setRemediationType] =
    useState<RemediationType>("isolate-asset");
  const [remediationTarget, setRemediationTarget] = useState("");
  const [simulationResult, setSimulationResult] =
    useState<FullSimulationResponse | null>(null);
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [simulationError, setSimulationError] = useState("");


  async function refreshGraph(showSpinner = false) {
    try {
      if (showSpinner) setLoading(true);
      setError("");

      const data = (await apiRequest("/graph")) as GraphResponse;

      if (!Array.isArray(data.nodes) || !Array.isArray(data.edges)) {
        throw new Error("Invalid graph response");
      }

      setGraph(data);
      // Discard old analysis results when the underlying graph is refreshed.
      setAttackData(null);
      setSelectedPathIndex(null);

      setSelectedNode((previous) => {
        if (!previous) return null;
        return data.nodes.find((node) => node.id === previous.id) ?? null;
      });
    } catch (err) {
      console.error(err);
      setError(
        err instanceof Error
          ? err.message
          : "Could not load graph. Check FastAPI and Neo4j."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refreshGraph(true);
  }, []);

  // Rebuild the visualization whenever the database graph changes.
  useEffect(() => {
    if (!graph || !graphRef.current) return;

    const elements: cytoscape.ElementDefinition[] = [
      ...graph.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.name,
          type: node.type,
          ip: node.ip,
          criticality: node.criticality,
          exposed: node.exposed,
          compromised: node.compromised,
        },
      })),
      ...graph.edges
        .filter(
          (edge) =>
            graph.nodes.some((node) => node.id === edge.source) &&
            graph.nodes.some((node) => node.id === edge.target)
        )
        .map((edge, index) => ({
          data: {
            id: `edge-${index}`,
            source: edge.source,
            target: edge.target,
            label: edge.relationship,
            protocol: edge.protocol ?? "",
          },
        })),
    ];

    const cy = cytoscape({
      container: graphRef.current,
      elements,
      minZoom: 0.3,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#2563eb",
            label: "data(label)",
            color: "#ffffff",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": 11,
            width: 48,
            height: 48,
            "border-width": 2,
            "border-color": "#93c5fd",
            "text-wrap": "wrap",
            "text-max-width": 75,
            "overlay-opacity": 0,
          },
        },
        {
          selector: 'node[criticality = "Critical"]',
          style: {
            "background-color": "#991b1b",
            "border-color": "#f87171",
          },
        },
        {
          selector: 'node[exposed = "Yes"]',
          style: {
            "border-width": 4,
            "border-color": "#f59e0b",
          },
        },
        {
          selector: 'node[compromised = "Yes"]',
          style: {
            "background-color": "#7f1d1d",
            "border-color": "#ef4444",
            "border-width": 5,
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
            "font-size": 8,
            "text-background-color": "#0f172a",
            "text-background-opacity": 0.85,
            "text-background-padding": 2,
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#fbbf24",
            "border-width": 5,
          },
        },
        {
          selector: ".search-match",
          style: {
            "border-color": "#22c55e",
            "border-width": 5,
          },
        },
        {
          selector: ".search-dim",
          style: { opacity: 0.2 },
        },
        {
          selector: ".path-highlight",
          style: {
            opacity: 1,
            "overlay-opacity": 0,
          },
        },
        {
          selector: "node.path-highlight",
          style: {
            "background-color": "#d97706",
            "border-color": "#fef3c7",
            "border-width": 5,
            opacity: 1,
          },
        },
        {
          selector: "edge.path-highlight",
          style: {
            "line-color": "#fbbf24",
            "target-arrow-color": "#fbbf24",
            width: 5,
            opacity: 1,
          },
        },
        {
          selector: ".path-dim",
          style: { opacity: 0.15 },
        },
      ],
      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 45,
        spacingFactor: 1.35,
        animate: false,
      },
    });

    cyRef.current = cy;

    cy.on("tap", "node", (event) => {
      const node = graph.nodes.find(
        (item) => item.id === event.target.id()
      );

      if (node) {
        setSelectedNode(node);
        setEditing(false);
        setFormMessage("");
        setFormError("");
      }
    });

    cy.on("tap", (event) => {
      if (event.target === cy) {
        setSelectedNode(null);
        setEditing(false);
      }
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph]);

  // Search graph assets.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const query = search.trim().toLowerCase();
    cy.elements().removeClass("search-match search-dim");

    if (!query) return;

    const matches = cy.nodes().filter((node) =>
      [
        node.data("id"),
        node.data("label"),
        node.data("type"),
        node.data("ip"),
      ].some((value) =>
        String(value ?? "").toLowerCase().includes(query)
      )
    );

    cy.elements().addClass("search-dim");
    matches.removeClass("search-dim").addClass("search-match");
    matches.connectedEdges().removeClass("search-dim");

    if (matches.length) {
      cy.animate({ fit: { eles: matches, padding: 70 }, duration: 250 });
    }
  }, [search, graph]);

  async function analyzeAttackPaths() {
    setAnalyzing(true);
    setAttackError("");
    setSelectedPathIndex(null);

    try {
      const result = (await apiRequest("/attack-paths")) as AttackPathResponse;

      if (!Array.isArray(result.paths)) {
        throw new Error("The attack-path endpoint returned an unexpected response.");
      }

      setAttackData(result);

      const cy = cyRef.current;
      if (cy) {
        cy.elements().removeClass("path-highlight path-dim");
      }
    } catch (err) {
      setAttackError(
        err instanceof Error ? err.message : "Could not analyze attack paths."
      );
      setAttackData(null);
    } finally {
      setAnalyzing(false);
    }
  }

  async function runFullSimulation() {
    setSimulationError("");
    setSimulationResult(null);

    if (!remediationTarget) {
      setSimulationError(
        remediationType === "isolate-asset"
          ? "Select an asset to isolate."
          : "Select a connection to remove."
      );
      return;
    }

    setSimulationLoading(true);
    try {
      let payload: {
        action_type: RemediationType;
        target_id?: string;
        source_id?: string;
        destination_id?: string;
        relationship?: string;
      };

      if (remediationType === "isolate-asset") {
        payload = {
          action_type: "isolate-asset",
          target_id: remediationTarget,
        };
      } else {
        const edgeIndex = Number(remediationTarget);
        const edge = graph?.edges[edgeIndex];
        if (!edge) {
          throw new Error("The selected connection no longer exists. Refresh the graph and try again.");
        }
        payload = {
          action_type: "remove-connection",
          source_id: edge.source,
          destination_id: edge.target,
          relationship: edge.relationship,
        };
      }

      const result = (await apiRequest("/simulate-remediation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })) as FullSimulationResponse;

      if (!result.before || !result.after) {
        throw new Error("The simulation endpoint returned an unexpected response. Check the backend response schema.");
      }
      setSimulationResult(result);
    } catch (err) {
      setSimulationError(
        err instanceof Error ? err.message : "Full-graph simulation failed."
      );
    } finally {
      setSimulationLoading(false);
    }
  }

  function highlightAttackPath(item: AttackPath, index: number) {
    setSelectedPathIndex(index);

    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass("path-highlight path-dim");
    cy.elements().addClass("path-dim");

    item.path.forEach((node) => {
      cy.getElementById(node.id)
        .removeClass("path-dim")
        .addClass("path-highlight");
    });

    item.connections.forEach((edge) => {
      cy.edges()
        .filter(
          (candidate) =>
            candidate.data("source") === edge.source &&
            candidate.data("target") === edge.target &&
            candidate.data("label") === edge.relationship
        )
        .forEach((candidate) => {
          candidate.removeClass("path-dim").addClass("path-highlight");
        });
    });

    const highlighted = cy.elements(".path-highlight");
    if (highlighted.length) {
      cy.animate({
        fit: { eles: highlighted, padding: 70 },
        duration: 300,
      });
    }
  }

  function resetGraph() {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass(
      "search-match search-dim path-highlight path-dim"
    );
    setSelectedPathIndex(null);
    cy.layout({
      name: "breadthfirst",
      directed: true,
      padding: 45,
      spacingFactor: 1.35,
    }).run();

    cy.fit(undefined, 45);
    setSearch("");
    setSelectedNode(null);
    setEditing(false);
  }

  async function submitAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest("/assets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...assetForm,
          id: assetForm.id.trim(),
          name: assetForm.name.trim(),
          type: assetForm.type.trim(),
          ip: assetForm.ip.trim(),
        }),
      });

      await refreshGraph();
      setAssetForm({ ...emptyAssetForm });
      setFormMessage("Asset added successfully.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not add asset."
      );
    } finally {
      setSaving(false);
    }
  }

  async function submitConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest("/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(connectionForm),
      });

      await refreshGraph();
      setConnectionForm({ ...emptyConnectionForm });
      setFormMessage("Connection added successfully.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not add connection."
      );
    } finally {
      setSaving(false);
    }
  }

  function startEditing() {
    if (!selectedNode) return;

    setEditForm({ ...selectedNode });
    setEditing(true);
    setFormMessage("");
    setFormError("");
  }

  async function submitEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedNode) return;

    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest(
        `/assets/${encodeURIComponent(selectedNode.id)}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ...editForm,
            id: selectedNode.id,
            name: editForm.name.trim(),
            type: editForm.type.trim(),
            ip: editForm.ip.trim(),
          }),
        }
      );

      await refreshGraph();
      setEditing(false);
      setFormMessage("Asset updated successfully.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not update asset."
      );
    } finally {
      setSaving(false);
    }
  }

  async function removeAsset() {
    if (!selectedNode) return;

    const confirmed = window.confirm(
      `Delete "${selectedNode.name}" and ALL its connected relationships? This cannot be undone.`
    );

    if (!confirmed) return;

    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest(
        `/assets/${encodeURIComponent(selectedNode.id)}`,
        { method: "DELETE" }
      );

      setSelectedNode(null);
      setEditing(false);
      await refreshGraph();
      setFormMessage("Asset and its relationships deleted.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not delete asset."
      );
    } finally {
      setSaving(false);
    }
  }

  async function removeConnection(edge: EdgeData) {
    const sourceName =
      graph?.nodes.find((node) => node.id === edge.source)?.name ??
      edge.source;
    const targetName =
      graph?.nodes.find((node) => node.id === edge.target)?.name ??
      edge.target;

    const confirmed = window.confirm(
      `Delete connection ${sourceName} → ${targetName} (${edge.relationship})?`
    );

    if (!confirmed) return;

    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest("/connections", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: edge.source,
          target: edge.target,
          relationship: edge.relationship,
        }),
      });

      await refreshGraph();
      setFormMessage("Connection deleted successfully.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not delete connection."
      );
    } finally {
      setSaving(false);
    }
  }

  const criticalCount =
    graph?.nodes.filter(
      (node) => node.criticality.toLowerCase() === "critical"
    ).length ?? 0;

  const compromisedCount =
    graph?.nodes.filter(
      (node) => node.compromised.toLowerCase() === "yes"
    ).length ?? 0;

  const selectedConnections =
    graph?.edges.filter(
      (edge) =>
        selectedNode &&
        (edge.source === selectedNode.id || edge.target === selectedNode.id)
    ) ?? [];

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>NEXAGRAPH AI</h1>
          <p>Enterprise Attack Path Analysis &amp; Threat Intelligence</p>
        </div>

        <div className="status">
          <span className="status-dot" />
          {error ? "BACKEND UNAVAILABLE" : loading ? "CONNECTING..." : "SYSTEM ONLINE"}
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
            <strong>{criticalCount}</strong>
          </div>
          <div className="stat-card">
            <span>Compromised</span>
            <strong>{compromisedCount}</strong>
          </div>
        </section>

        {error && <div className="error">{error}</div>}
        {loading && <div className="loading">Loading enterprise graph...</div>}

        <section className="management-panel">
          <h2>Manage Enterprise Graph</h2>
          <p>Add assets and define relationships between existing assets.</p>

          {formMessage && (
            <div className="form-success" role="status">{formMessage}</div>
          )}
          {formError && (
            <div className="error" role="alert">{formError}</div>
          )}

          <div className="forms-grid">
            <form className="management-form" onSubmit={submitAsset}>
              <h3>Add Asset</h3>

              <label>
                Asset ID
                <input
                  required
                  maxLength={50}
                  value={assetForm.id}
                  onChange={(e) => setAssetForm({ ...assetForm, id: e.target.value })}
                  placeholder="e.g. A08"
                />
              </label>

              <label>
                Asset Name
                <input
                  required
                  maxLength={100}
                  value={assetForm.name}
                  onChange={(e) => setAssetForm({ ...assetForm, name: e.target.value })}
                  placeholder="e.g. Payment Server"
                />
              </label>

              <label>
                Type
                <select
                  value={assetForm.type}
                  onChange={(e) => setAssetForm({ ...assetForm, type: e.target.value })}
                >
                  {["External", "Server", "Endpoint", "Database", "Application", "Network Device"].map((type) => (
                    <option key={type}>{type}</option>
                  ))}
                </select>
              </label>

              <label>
                IP Address / Identifier
                <input
                  required
                  maxLength={100}
                  value={assetForm.ip}
                  onChange={(e) => setAssetForm({ ...assetForm, ip: e.target.value })}
                  placeholder="e.g. 10.0.0.70"
                />
              </label>

              <label>
                Criticality
                <select
                  value={assetForm.criticality}
                  onChange={(e) => setAssetForm({ ...assetForm, criticality: e.target.value })}
                >
                  {["Low", "Medium", "High", "Critical"].map((level) => (
                    <option key={level}>{level}</option>
                  ))}
                </select>
              </label>

              <label>
                Exposed
                <select
                  value={assetForm.exposed}
                  onChange={(e) => setAssetForm({ ...assetForm, exposed: e.target.value })}
                >
                  <option>No</option>
                  <option>Yes</option>
                </select>
              </label>

              <label>
                Compromised
                <select
                  value={assetForm.compromised}
                  onChange={(e) => setAssetForm({ ...assetForm, compromised: e.target.value })}
                >
                  <option>No</option>
                  <option>Yes</option>
                </select>
              </label>

              <button type="submit" disabled={saving}>
                {saving ? "Saving..." : "Add Asset"}
              </button>
            </form>

            <form className="management-form" onSubmit={submitConnection}>
              <h3>Add Connection</h3>

              <label>
                Source Asset
                <select
                  required
                  value={connectionForm.source}
                  onChange={(e) => setConnectionForm({
                    ...connectionForm,
                    source: e.target.value,
                    target: e.target.value === connectionForm.target ? "" : connectionForm.target,
                  })}
                >
                  <option value="">Select source asset</option>
                  {(graph?.nodes ?? []).map((node) => (
                    <option key={node.id} value={node.id}>{node.name} ({node.id})</option>
                  ))}
                </select>
              </label>

              <label>
                Target Asset
                <select
                  required
                  value={connectionForm.target}
                  onChange={(e) => setConnectionForm({ ...connectionForm, target: e.target.value })}
                >
                  <option value="">Select target asset</option>
                  {(graph?.nodes ?? []).filter((node) => node.id !== connectionForm.source).map((node) => (
                    <option key={node.id} value={node.id}>{node.name} ({node.id})</option>
                  ))}
                </select>
              </label>

              <label>
                Relationship
                <select
                  value={connectionForm.relationship}
                  onChange={(e) => setConnectionForm({ ...connectionForm, relationship: e.target.value })}
                >
                  {["CONNECTS", "ACCESS", "ACCESSES", "ADMIN_ACCESS", "BACKUP", "AUTHENTICATES", "DEPENDS_ON"].map((rel) => (
                    <option key={rel}>{rel}</option>
                  ))}
                </select>
              </label>

              <label>
                Protocol
                <select
                  value={connectionForm.protocol}
                  onChange={(e) => setConnectionForm({ ...connectionForm, protocol: e.target.value })}
                >
                  {["TCP", "UDP", "HTTP", "HTTPS", "SSH", "RDP", "OTHER"].map((protocol) => (
                    <option key={protocol}>{protocol}</option>
                  ))}
                </select>
              </label>

              <button type="submit" disabled={saving || !connectionForm.source || !connectionForm.target}>
                {saving ? "Saving..." : "Add Connection"}
              </button>
            </form>
          </div>
        </section>

        {/* Attack Path Analysis */}
        <section className="management-panel attack-panel">
          <div className="panel-header">
            <div>
              <h2>Attack Path Analysis</h2>
              <p>
                Find potential directed routes from exposed or compromised
                assets to critical assets.
              </p>
            </div>
            <button
              type="button"
              onClick={() => void analyzeAttackPaths()}
              disabled={analyzing || loading || !graph}
            >
              {analyzing ? "Analyzing..." : "Analyze Attack Paths"}
            </button>
          </div>

          {attackError && (
            <div className="error" role="alert">{attackError}</div>
          )}

          {!attackData && !attackError && (
            <p className="attack-note">
              Run an analysis to identify and rank potential attack paths.
            </p>
          )}

          {attackData && (
            <div className="attack-results">
              <div className="attack-summary">
                <div className="stat-card">
                  <span>Paths Found</span>
                  <strong>{attackData.total_paths}</strong>
                </div>
                <div className="stat-card">
                  <span>Highest Risk</span>
                  <strong>
                    {attackData.paths.length > 0
                      ? attackData.paths[0].risk_level
                      : "None"}
                  </strong>
                </div>
              </div>

              {attackData.max_paths_reached && (
                <p className="attack-note">
                  The 100-path limit was reached. Additional paths may exist.
                </p>
              )}

              {attackData.paths.length === 0 ? (
                <div className="empty">
                  No qualifying paths were found. Check that an exposed or
                  compromised asset has a directed route to an asset marked
                  Critical.
                </div>
              ) : (
                <div className="attack-path-list">
                  {attackData.paths.map((item, index) => (
                    <button
                      type="button"
                      key={`${item.path.map((node) => node.id).join("-")}-${index}`}
                      className={`attack-path-card ${
                        selectedPathIndex === index ? "path-selected" : ""
                      }`}
                      aria-pressed={selectedPathIndex === index}
                      onClick={() => highlightAttackPath(item, index)}
                    >
                      <div className="attack-path-heading">
                        <strong>Path {index + 1}</strong>
                        <span
                          className={`risk-pill risk-${item.risk_level.toLowerCase()}`}
                        >
                          {item.risk_level} Risk
                        </span>
                      </div>

                      <div className="risk-score">
                        Risk score: {item.risk_score}/100
                      </div>

                      <div className="path-sequence">
                        {item.path.map((node, nodeIndex) => (
                          <span className="path-node" key={`${node.id}-${nodeIndex}`}>
                            {node.name}
                            {nodeIndex < item.path.length - 1 && (
                              <span className="path-arrow"> → </span>
                            )}
                          </span>
                        ))}
                      </div>

                      <span className="path-hint">
                        Select to highlight this route in the graph
                      </span>
                    </button>
                  ))}
                </div>
              )}

              <p className="attack-note">{attackData.scoring_note}</p>
            </div>
          )}
        </section>

        <section className="management-panel full-simulation-panel">
          <div className="panel-header">
            <div>
              <h2>Remediation Simulator</h2>
              <p>
                Test a proposed fix against the full graph snapshot. This simulation
                does not modify your Neo4j database.
              </p>
            </div>
            <span className="simulation-safe-badge">SIMULATION ONLY</span>
          </div>

          <div className="simulation-controls">
            <label>
              Remediation action
              <select
                value={remediationType}
                onChange={(event) => {
                  setRemediationType(event.target.value as RemediationType);
                  setRemediationTarget("");
                  setSimulationResult(null);
                  setSimulationError("");
                }}
              >
                <option value="isolate-asset">Isolate an asset</option>
                <option value="remove-connection">Remove a connection</option>
              </select>
            </label>

            {remediationType === "isolate-asset" ? (
              <label>
                Asset to isolate
                <select
                  value={remediationTarget}
                  onChange={(event) => {
                    setRemediationTarget(event.target.value);
                    setSimulationResult(null);
                    setSimulationError("");
                  }}
                >
                  <option value="">Select an asset</option>
                  {(graph?.nodes ?? []).map((node) => (
                    <option key={node.id} value={node.id}>
                      {node.name} ({node.id})
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <label>
                Connection to remove
                <select
                  value={remediationTarget}
                  onChange={(event) => {
                    setRemediationTarget(event.target.value);
                    setSimulationResult(null);
                    setSimulationError("");
                  }}
                >
                  <option value="">Select a connection</option>
                  {(graph?.edges ?? []).map((edge, index) => {
                    const sourceName =
                      graph?.nodes.find((node) => node.id === edge.source)?.name ?? edge.source;
                    const targetName =
                      graph?.nodes.find((node) => node.id === edge.target)?.name ?? edge.target;
                    return (
                      <option key={`${edge.source}-${edge.target}-${edge.relationship}-${index}`} value={String(index)}>
                        {sourceName} → {targetName} ({edge.relationship})
                      </option>
                    );
                  })}
                </select>
              </label>
            )}

            <button
              type="button"
              onClick={() => void runFullSimulation()}
              disabled={simulationLoading || loading || !graph || !remediationTarget}
            >
              {simulationLoading ? "Recalculating full graph..." : "Run Full-Graph Simulation"}
            </button>
          </div>

          {simulationError && (
            <div className="error" role="alert">{simulationError}</div>
          )}

          {simulationResult && (
            <div className="full-simulation-results" aria-live="polite">
              <div className="panel-header">
                <h3>Simulation Results</h3>
                <span className="simulation-safe-badge">
                  {simulationResult.database_modified ? "DATABASE CHANGED" : "DATABASE UNCHANGED"}
                </span>
              </div>

              <div className="simulation-metrics">
                <div className="stat-card">
                  <span>Paths Before</span>
                  <strong>{simulationResult.before.total_paths}</strong>
                </div>
                <div className="stat-card">
                  <span>Paths After</span>
                  <strong>{simulationResult.after.total_paths}</strong>
                </div>
                <div className="stat-card">
                  <span>Paths Eliminated</span>
                  <strong>{simulationResult.paths_eliminated}</strong>
                </div>
                <div className="stat-card">
                  <span>Highest Risk After</span>
                  <strong>{simulationResult.highest_risk_after}/100</strong>
                </div>
              </div>

              <p className="attack-note">
                Highest risk before: {simulationResult.highest_risk_before}/100 ·
                Score reduction: {simulationResult.risk_score_reduction} points
              </p>

              <h4>Remaining Attack Paths</h4>
              {simulationResult.after.paths.length === 0 ? (
                <div className="form-success">
                  No qualifying attack paths were found after this simulated action.
                </div>
              ) : (
                <div className="simulation-path-list">
                  {simulationResult.after.paths.map((path, index) => (
                    <div
                      className="simulation-path-row"
                      key={`${path.path.map((node) => node.id).join("-")}-${index}`}
                    >
                      <span>{path.path.map((node) => node.name).join(" → ")}</span>
                      <strong>{path.risk_score}/100 · {path.risk_level}</strong>
                    </div>
                  ))}
                </div>
              )}

              {(simulationResult.after.max_paths_reached ||
                simulationResult.before.max_paths_reached) && (
                <p className="attack-note">
                  The 100-path limit was reached. Additional qualifying paths may exist.
                </p>
              )}
              <p className="attack-note">
                {simulationResult.scoring_note || "Risk scores are prototype heuristics, not probabilities of a real attack."}
              </p>
            </div>
          )}
        </section>

        <section className="workspace">
          <div className="graph-panel">
            <div className="panel-header">
              <div>
                <h2>Enterprise Attack Graph</h2>
                <p>Interactive asset and relationship visualization</p>
              </div>
              <span className="live-badge">
                {graph ? "GRAPH LOADED" : "WAITING FOR DATA"}
              </span>
            </div>

            <div className="graph-toolbar">
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search assets by name, ID, type or IP..."
                aria-label="Search graph assets"
              />
              <button type="button" onClick={resetGraph}>Reset graph</button>
              <button type="button" onClick={() => void refreshGraph(true)}>Refresh</button>
            </div>

            <div ref={graphRef} className="graph-container" />

            <div className="graph-legend">
              <span><i className="legend-normal" /> Normal</span>
              <span><i className="legend-critical" /> Critical</span>
              <span><i className="legend-exposed" /> Exposed</span>
              <span><i className="legend-compromised" /> Compromised</span>
            </div>
          </div>

          <aside className="details-panel">
            <h2>Asset Details</h2>

            {!selectedNode ? (
              <div className="empty">Select a node in the graph to inspect its properties.</div>
            ) : editing ? (
              <form className="management-form" onSubmit={submitEdit}>
                <h3>Edit {selectedNode.name}</h3>

                <label>
                  Asset ID (cannot change)
                  <input value={editForm.id} readOnly />
                </label>

                <label>
                  Name
                  <input required maxLength={100} value={editForm.name}
                    onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} />
                </label>

                <label>
                  Type
                  <select value={editForm.type}
                    onChange={(e) => setEditForm({ ...editForm, type: e.target.value })}>
                    {["External", "Server", "Endpoint", "Database", "Application", "Network Device"].map((type) => (
                      <option key={type}>{type}</option>
                    ))}
                  </select>
                </label>

                <label>
                  IP Address / Identifier
                  <input required maxLength={100} value={editForm.ip}
                    onChange={(e) => setEditForm({ ...editForm, ip: e.target.value })} />
                </label>

                <label>
                  Criticality
                  <select value={editForm.criticality}
                    onChange={(e) => setEditForm({ ...editForm, criticality: e.target.value })}>
                    {["Low", "Medium", "High", "Critical"].map((level) => (
                      <option key={level}>{level}</option>
                    ))}
                  </select>
                </label>

                <label>
                  Exposed
                  <select value={editForm.exposed}
                    onChange={(e) => setEditForm({ ...editForm, exposed: e.target.value })}>
                    <option>No</option><option>Yes</option>
                  </select>
                </label>

                <label>
                  Compromised
                  <select value={editForm.compromised}
                    onChange={(e) => setEditForm({ ...editForm, compromised: e.target.value })}>
                    <option>No</option><option>Yes</option>
                  </select>
                </label>

                <button type="submit" disabled={saving}>
                  {saving ? "Saving..." : "Save Changes"}
                </button>
                <button type="button" disabled={saving} onClick={() => setEditing(false)}>
                  Cancel
                </button>
              </form>
            ) : (
              <>
                <div className="details">
                  <div className="asset-name">{selectedNode.name}</div>

                  {[
                    ["ID", selectedNode.id],
                    ["Type", selectedNode.type],
                    ["IP Address", selectedNode.ip],
                    ["Criticality", selectedNode.criticality],
                    ["Exposed", selectedNode.exposed],
                    ["Compromised", selectedNode.compromised],
                  ].map(([label, value]) => (
                    <div className="detail-row" key={label}>
                      <span>{label}</span>
                      <strong>{value}</strong>
                    </div>
                  ))}
                </div>

                <div className="asset-actions">
                  <button type="button" disabled={saving} onClick={startEditing}>
                    Edit Asset
                  </button>
                  <button type="button" className="danger-button" disabled={saving} onClick={() => void removeAsset()}>
                    Delete Asset
                  </button>
                </div>

                <div className="connection-list">
                  <h3>Connected Relationships ({selectedConnections.length})</h3>

                  {selectedConnections.length === 0 ? (
                    <p className="empty">No connections for this asset.</p>
                  ) : selectedConnections.map((edge, index) => {
                    const sourceName = graph?.nodes.find((node) => node.id === edge.source)?.name ?? edge.source;
                    const targetName = graph?.nodes.find((node) => node.id === edge.target)?.name ?? edge.target;

                    return (
                      <div className="connection-item" key={`${edge.source}-${edge.target}-${edge.relationship}-${index}`}>
                        <p><strong>{sourceName}</strong> → <strong>{targetName}</strong></p>
                        <p>{edge.relationship} · {edge.protocol || "No protocol"}</p>
                        <button
                          type="button"
                          className="danger-button"
                          disabled={saving}
                          onClick={() => void removeConnection(edge)}
                        >
                          Delete Connection
                        </button>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </aside>
        </section>
      </main>
    </div>
  );
}

export default App;
