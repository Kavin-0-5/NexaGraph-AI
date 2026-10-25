"""Unit tests for NexaGraph AI's shared attack-path scoring logic.

Run from the backend directory with:
    python -m pytest -q test_attack_paths.py

These tests exercise the in-memory analyzer and do not require a running Neo4j
server, although the project's Python dependencies must be installed.
"""

from main import analyze_graph_snapshot


def asset(
    asset_id: str,
    *,
    criticality: str = "Medium",
    exposed: str = "No",
    compromised: str = "No",
):
    return {
        "id": asset_id,
        "name": asset_id,
        "type": "Server",
        "ip": "127.0.0.1",
        "criticality": criticality,
        "exposed": exposed,
        "compromised": compromised,
    }


def edge(source: str, target: str, relationship: str = "CONNECTS"):
    return {
        "source": source,
        "target": target,
        "relationship": relationship,
        "protocol": "TCP",
    }


def test_finds_directed_path_from_exposed_asset_to_critical_asset():
    nodes = [
        asset("internet", exposed="Yes"),
        asset("database", criticality="Critical"),
    ]
    result = analyze_graph_snapshot(nodes, [edge("internet", "database")])

    assert result["total_paths"] == 1
    assert [node["id"] for node in result["paths"][0]["path"]] == [
        "internet",
        "database",
    ]
    # Exposed source (+30) and critical destination (+30).
    assert result["paths"][0]["risk_score"] == 60
    assert result["paths"][0]["risk_level"] == "High"


def test_intermediate_asset_contributes_to_risk_score():
    nodes = [
        asset("internet", exposed="Yes"),
        asset("app", criticality="Medium"),
        asset("database", criticality="Critical"),
    ]
    result = analyze_graph_snapshot(
        nodes,
        [edge("internet", "app"), edge("app", "database")],
    )

    path = result["paths"][0]
    # Exposed source (+30), critical destination (+30), medium intermediate (+5).
    assert path["risk_score"] == 65
    assert path["risk_level"] == "High"


def test_compromised_source_score_is_capped_at_100():
    nodes = [
        asset("host", exposed="Yes", compromised="Yes"),
        asset("database", criticality="Critical"),
    ]
    result = analyze_graph_snapshot(nodes, [edge("host", "database")])

    assert result["paths"][0]["risk_score"] == 100
    assert result["paths"][0]["risk_level"] == "Critical"


def test_unreachable_critical_asset_produces_no_path():
    nodes = [
        asset("internet", exposed="Yes"),
        asset("database", criticality="Critical"),
    ]
    result = analyze_graph_snapshot(nodes, [])

    assert result["paths"] == []
    assert result["total_paths"] == 0


def test_removing_a_connection_can_eliminate_a_path_without_mutating_original():
    nodes = [
        asset("internet", exposed="Yes"),
        asset("app"),
        asset("database", criticality="Critical"),
    ]
    original_edges = [edge("internet", "app"), edge("app", "database")]

    before = analyze_graph_snapshot(nodes, original_edges)
    simulated_edges = [e for e in original_edges if not (
        e["source"] == "app" and e["target"] == "database"
    )]
    after = analyze_graph_snapshot(nodes, simulated_edges)

    assert before["total_paths"] == 1
    assert after["total_paths"] == 0
    assert len(original_edges) == 2  # Original snapshot remains unchanged.


def test_cycles_do_not_repeat_nodes_inside_a_path():
    nodes = [
        asset("internet", exposed="Yes"),
        asset("app"),
        asset("database", criticality="Critical"),
    ]
    edges = [
        edge("internet", "app"),
        edge("app", "internet"),
        edge("app", "database"),
    ]
    result = analyze_graph_snapshot(nodes, edges)

    assert result["total_paths"] == 1
    ids = [node["id"] for node in result["paths"][0]["path"]]
    assert len(ids) == len(set(ids))


def test_results_include_scoring_explanation_and_path_cap_metadata():
    nodes = [
        asset("internet", exposed="Yes"),
        asset("database", criticality="Critical"),
    ]
    result = analyze_graph_snapshot(nodes, [edge("internet", "database")])

    assert result["max_paths_reached"] is False
    assert "not a probability" in result["scoring_note"].lower()
