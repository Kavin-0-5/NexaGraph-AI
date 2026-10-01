from fastapi import FastAPI
from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="NexaGraph AI")

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASSWORD)
)


@app.get("/")
def home():
    return {
        "message": "NexaGraph AI Backend Running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.get("/graph")
def get_graph():

    nodes = []
    edges = []

    with driver.session() as session:

        node_result = session.run(
            """
            MATCH (n:Asset)
            RETURN n
            """
        )

        for record in node_result:

            node = record["n"]

            nodes.append({
                "id": node["id"],
                "name": node["name"],
                "type": node["type"],
                "ip": node["ip"],
                "criticality": node["criticality"],
                "exposed": node["exposed"],
                "compromised": node["compromised"]
            })

        edge_result = session.run(
            """
            MATCH (a:Asset)-[r]->(b:Asset)
            RETURN a.id AS source,
                   b.id AS target,
                   type(r) AS relationship
            """
        )

        for record in edge_result:

            edges.append({
                "source": record["source"],
                "target": record["target"],
                "relationship": record["relationship"]
            })

    return {
        "nodes": nodes,
        "edges": edges
    }