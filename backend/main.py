
from contextlib import asynccontextmanager
import os
import re

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase
from pydantic import BaseModel, Field

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

driver = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global driver

    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD]):
        raise RuntimeError("Neo4j environment variables are missing.")

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASSWORD),
    )
    driver.verify_connectivity()

    yield

    driver.close()


app = FastAPI(title="NexaGraph AI", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AssetInput(BaseModel):
    id: str = Field(min_length=1, max_length=50)
    name: str = Field(min_length=1, max_length=100)
    type: str = Field(min_length=1, max_length=50)
    ip: str = Field(min_length=1, max_length=100)
    criticality: str
    exposed: str
    compromised: str


class ConnectionInput(BaseModel):
    source: str = Field(min_length=1, max_length=50)
    target: str = Field(min_length=1, max_length=50)
    relationship: str = Field(min_length=1, max_length=40)
    protocol: str = Field(default="TCP", max_length=30)


def graph_data():
    with driver.session() as session:
        nodes_result = session.run("""
            MATCH (a:Asset)
            RETURN collect({
                id: a.id,
                name: a.name,
                type: a.type,
                ip: a.ip,
                criticality: a.criticality,
                exposed: a.exposed,
                compromised: a.compromised
            }) AS nodes
        """).single()

        edges_result = session.run("""
            MATCH (a:Asset)-[r]->(b:Asset)
            RETURN collect({
                source: a.id,
                target: b.id,
                relationship: type(r),
                protocol: r.protocol
            }) AS edges
        """).single()

        return {
            "nodes": nodes_result["nodes"],
            "edges": edges_result["edges"],
        }


@app.get("/")
def home():
    return {"message": "NexaGraph AI Backend Running"}


@app.get("/health")
def health():
    try:
        driver.verify_connectivity()
        return {"status": "healthy", "neo4j": "connected"}
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Neo4j is unavailable.",
        ) from exc


@app.get("/graph")
def get_graph():
    try:
        return graph_data()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not load graph from Neo4j.",
        ) from exc


@app.post("/assets", status_code=201)
def add_asset(asset: AssetInput):
    asset_id = asset.id.strip()
    if not asset_id:
        raise HTTPException(400, "Asset ID cannot be blank.")

    if asset.criticality not in ["Low", "Medium", "High", "Critical"]:
        raise HTTPException(400, "Invalid criticality.")

    if asset.exposed not in ["Yes", "No"]:
        raise HTTPException(400, "Exposed must be Yes or No.")

    if asset.compromised not in ["Yes", "No"]:
        raise HTTPException(400, "Compromised must be Yes or No.")

    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (existing:Asset {id: $id})
                RETURN existing
            """, id=asset_id).single()

            if result:
                raise HTTPException(
                    status_code=409,
                    detail=f"Asset ID '{asset_id}' already exists.",
                )

            session.run("""
                CREATE (a:Asset {
                    id: $id,
                    name: $name,
                    type: $type,
                    ip: $ip,
                    criticality: $criticality,
                    exposed: $exposed,
                    compromised: $compromised
                })
            """, **{
                **asset.model_dump(),
                "id": asset_id,
                "name": asset.name.strip(),
                "type": asset.type.strip(),
                "ip": asset.ip.strip(),
            })

        return {"message": "Asset added successfully.", "graph": graph_data()}

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Failed to save asset to Neo4j.") from exc


@app.post("/connections", status_code=201)
def add_connection(connection: ConnectionInput):
    source = connection.source.strip()
    target = connection.target.strip()
    relationship = connection.relationship.strip().upper()

    # Only allow safe relationship names for the Cypher query.
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,39}", relationship):
        raise HTTPException(400, "Use letters, numbers and underscores for the relationship.")

    if source == target:
        raise HTTPException(400, "Source and target must be different assets.")

    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (a:Asset {id: $source})
                MATCH (b:Asset {id: $target})
                RETURN a.id AS source, b.id AS target
            """, source=source, target=target).single()

            if not result:
                raise HTTPException(
                    status_code=404,
                    detail="Source or target asset was not found.",
                )

            # Relationship type is interpolated only after strict validation.
            session.run(f"""
                MATCH (a:Asset {{id: $source}})
                MATCH (b:Asset {{id: $target}})
                CREATE (a)-[r:{relationship} {{
                    protocol: $protocol
                }}]->(b)
            """, source=source, target=target, protocol=connection.protocol.strip())

        return {
            "message": "Connection added successfully.",
            "graph": graph_data(),
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Failed to save connection to Neo4j.") from exc


# Update an existing asset
@app.put("/assets/{asset_id}")
def update_asset(asset_id: str, asset: AssetInput):
    if asset.id.strip() != asset_id:
        raise HTTPException(
            status_code=400,
            detail="Asset ID cannot be changed."
        )

    if asset.criticality not in ["Low", "Medium", "High", "Critical"]:
        raise HTTPException(status_code=400, detail="Invalid criticality.")

    if asset.exposed not in ["Yes", "No"]:
        raise HTTPException(status_code=400, detail="Invalid exposed value.")

    if asset.compromised not in ["Yes", "No"]:
        raise HTTPException(status_code=400, detail="Invalid compromised value.")

    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (a:Asset {id: $id})
                SET a.name = $name,
                    a.type = $type,
                    a.ip = $ip,
                    a.criticality = $criticality,
                    a.exposed = $exposed,
                    a.compromised = $compromised
                RETURN a.id AS id
            """, **asset.model_dump()).single()

            if not result:
                raise HTTPException(status_code=404, detail="Asset not found.")

        return {
            "message": "Asset updated successfully.",
            "graph": graph_data()
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Failed to update asset."
        ) from exc


# Delete an asset and its connected relationships
@app.delete("/assets/{asset_id}")
def delete_asset(asset_id: str):
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (a:Asset {id: $id})
                DETACH DELETE a
                RETURN count(*) AS deleted
            """, id=asset_id).single()

            if not result or result["deleted"] == 0:
                raise HTTPException(status_code=404, detail="Asset not found.")

        return {
            "message": "Asset and its connections deleted successfully.",
            "graph": graph_data()
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Failed to delete asset."
        ) from exc


# Delete connections between two assets for a specified relationship type
class DeleteConnectionInput(BaseModel):
    source: str
    target: str
    relationship: str


@app.delete("/connections")
def delete_connection(connection: DeleteConnectionInput):
    import re

    relationship = connection.relationship.strip().upper()

    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,39}", relationship):
        raise HTTPException(
            status_code=400,
            detail="Invalid relationship type."
        )

    try:
        with driver.session() as session:
            result = session.run(f"""
                MATCH (a:Asset {{id: $source}})
                MATCH (b:Asset {{id: $target}})
                MATCH (a)-[r:{relationship}]->(b)
                WITH collect(r) AS relationships
                FOREACH (rel IN relationships | DELETE rel)
                RETURN size(relationships) AS deleted
            """,
                source=connection.source,
                target=connection.target
            ).single()

            if not result or result["deleted"] == 0:
                raise HTTPException(
                    status_code=404,
                    detail="Connection not found."
                )

        return {
            "message": "Connection deleted successfully.",
            "graph": graph_data()
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Failed to delete connection."
        ) from exc

@app.get("/attack-paths")
def get_attack_paths():
    """
    Find directed paths from exposed or compromised assets
    to critical assets. Uses a simple prototype risk heuristic.
    """
    try:
        data = graph_data()
        nodes = data["nodes"]
        edges = data["edges"]

        node_map = {node["id"]: node for node in nodes}
        adjacency = {node["id"]: [] for node in nodes}

        for edge in edges:
            source = edge["source"]
            target = edge["target"]

            if source in adjacency and target in node_map:
                adjacency[source].append(edge)

        sources = [
            node for node in nodes
            if node.get("exposed") == "Yes"
            or node.get("compromised") == "Yes"
        ]

        targets = {
            node["id"] for node in nodes
            if str(node.get("criticality", "")).lower() == "critical"
        }

        paths = []
        max_depth = 8
        max_paths = 100

        def explore(current_id, path_ids, path_edges):
            if len(paths) >= max_paths:
                return

            if current_id in targets and len(path_ids) > 1:
                path_nodes = [node_map[node_id] for node_id in path_ids]

                score = 0

                # Starting-point risk
                if path_nodes[0].get("exposed") == "Yes":
                    score += 30
                if path_nodes[0].get("compromised") == "Yes":
                    score += 40

                # Critical destination
                score += 30

                # Risk from intermediate assets
                for node in path_nodes[1:-1]:
                    level = str(node.get("criticality", "")).lower()
                    score += {
                        "low": 2,
                        "medium": 5,
                        "high": 10,
                        "critical": 15,
                    }.get(level, 0)

                    if node.get("compromised") == "Yes":
                        score += 10

                score = min(score, 100)

                paths.append({
                    "path": path_nodes,
                    "connections": path_edges,
                    "risk_score": score,
                    "risk_level": (
                        "Critical" if score >= 80
                        else "High" if score >= 60
                        else "Medium" if score >= 35
                        else "Low"
                    ),
                })
                return

            if len(path_ids) >= max_depth:
                return

            for edge in adjacency.get(current_id, []):
                next_id = edge["target"]

                # Prevent cycles within a path.
                if next_id in path_ids:
                    continue

                explore(
                    next_id,
                    path_ids + [next_id],
                    path_edges + [edge],
                )

        for source in sources:
            explore(source["id"], [source["id"]], [])

            if len(paths) >= max_paths:
                break

        paths.sort(key=lambda item: item["risk_score"], reverse=True)

        return {
            "paths": paths,
            "total_paths": len(paths),
            "max_paths_reached": len(paths) >= max_paths,
            "scoring_note": (
                "Prototype heuristic based on exposure, compromise, "
                "asset criticality, and path structure. Not a probability "
                "of a real attack."
            ),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not analyze attack paths."
        ) from exc

class RemediationSimulationInput(BaseModel):
    action_type: str = Field(
        description="isolate-asset or remove-connection"
    )
    target_id: str | None = None
    source_id: str | None = None
    destination_id: str | None = None
    relationship: str | None = None


def analyze_graph_snapshot(nodes, edges, max_depth=8, max_paths=100):
    """Analyze a graph snapshot without writing to Neo4j."""
    node_map = {node["id"]: node for node in nodes}
    adjacency = {node["id"]: [] for node in nodes}

    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")

        if source in adjacency and target in node_map:
            adjacency[source].append(edge)

    sources = [
        node for node in nodes
        if node.get("exposed") == "Yes"
        or node.get("compromised") == "Yes"
    ]

    targets = {
        node["id"] for node in nodes
        if str(node.get("criticality", "")).lower() == "critical"
    }

    paths = []

    def calculate_score(path_nodes):
        score = 0

        if path_nodes[0].get("exposed") == "Yes":
            score += 30
        if path_nodes[0].get("compromised") == "Yes":
            score += 40

        score += 30

        for node in path_nodes[1:-1]:
            level = str(node.get("criticality", "")).lower()
            score += {
                "low": 2,
                "medium": 5,
                "high": 10,
                "critical": 15,
            }.get(level, 0)

            if node.get("compromised") == "Yes":
                score += 10

        return min(score, 100)

    def explore(current_id, path_ids, path_edges):
        if len(paths) >= max_paths:
            return

        if current_id in targets and len(path_ids) > 1:
            path_nodes = [node_map[node_id] for node_id in path_ids]
            score = calculate_score(path_nodes)

            paths.append({
                "path": path_nodes,
                "connections": path_edges,
                "risk_score": score,
                "risk_level": (
                    "Critical" if score >= 80 else
                    "High" if score >= 60 else
                    "Medium" if score >= 35 else "Low"
                ),
            })
            return

        if len(path_ids) >= max_depth:
            return

        for edge in adjacency.get(current_id, []):
            next_id = edge["target"]

            if next_id not in path_ids:
                explore(
                    next_id,
                    path_ids + [next_id],
                    path_edges + [edge],
                )

                if len(paths) >= max_paths:
                    return

    for source in sources:
        explore(source["id"], [source["id"]], [])
        if len(paths) >= max_paths:
            break

    paths.sort(key=lambda item: item["risk_score"], reverse=True)

    return {
        "paths": paths,
        "total_paths": len(paths),
        "max_paths_reached": len(paths) >= max_paths,
    }


@app.post("/simulate-remediation")
def simulate_remediation(request: RemediationSimulationInput):
    """
    Simulate a remediation action on a temporary graph snapshot.
    Never changes Neo4j.
    """
    try:
        data = graph_data()
        original_nodes = data["nodes"]
        original_edges = data["edges"]

        # Copy the graph so the simulation cannot mutate the source data.
        simulated_nodes = [dict(node) for node in original_nodes]
        simulated_edges = [dict(edge) for edge in original_edges]

        if request.action_type == "isolate-asset":
            if not request.target_id:
                raise HTTPException(
                    status_code=400,
                    detail="target_id is required to isolate an asset.",
                )

            if not any(
                node["id"] == request.target_id
                for node in simulated_nodes
            ):
                raise HTTPException(
                    status_code=404,
                    detail="Asset to isolate was not found.",
                )

            # Remove the asset and all its incident connections
            # from this temporary graph only.
            simulated_nodes = [
                node for node in simulated_nodes
                if node["id"] != request.target_id
            ]
            simulated_edges = [
                edge for edge in simulated_edges
                if edge["source"] != request.target_id
                and edge["target"] != request.target_id
            ]

        elif request.action_type == "remove-connection":
            if not all([
                request.source_id,
                request.destination_id,
                request.relationship,
            ]):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "source_id, destination_id and relationship "
                        "are required."
                    ),
                )

            relationship = request.relationship.strip().upper()

            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,39}", relationship):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid relationship type.",
                )

            matching = [
                edge for edge in simulated_edges
                if edge["source"] == request.source_id
                and edge["target"] == request.destination_id
                and str(edge.get("relationship", "")).upper()
                    == relationship
            ]

            if not matching:
                raise HTTPException(
                    status_code=404,
                    detail="The specified connection was not found.",
                )

            # Remove matching directed relationships from the snapshot.
            simulated_edges = [
                edge for edge in simulated_edges
                if not (
                    edge["source"] == request.source_id
                    and edge["target"] == request.destination_id
                    and str(edge.get("relationship", "")).upper()
                        == relationship
                )
            ]

        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    "action_type must be isolate-asset "
                    "or remove-connection."
                ),
            )

        before = analyze_graph_snapshot(original_nodes, original_edges)
        after = analyze_graph_snapshot(simulated_nodes, simulated_edges)

        before_max = max(
            (path["risk_score"] for path in before["paths"]),
            default=0,
        )
        after_max = max(
            (path["risk_score"] for path in after["paths"]),
            default=0,
        )

        return {
            "action_type": request.action_type,
            "simulated_only": True,
            "database_modified": False,
            "before": before,
            "after": after,
            "paths_eliminated": max(
                0, before["total_paths"] - after["total_paths"]
            ),
            "highest_risk_before": before_max,
            "highest_risk_after": after_max,
            "risk_score_reduction": before_max - after_max,
            "scoring_note": (
                "Scores are prototype heuristics, not probabilities "
                "of a real attack. Path enumeration is limited to "
                "depth 8 and 100 paths."
            ),
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Remediation simulation failed.",
        ) from exc
