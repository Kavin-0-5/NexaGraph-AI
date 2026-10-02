from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="NexaGraph AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
        """)

        edges_result = session.run("""
            MATCH (a:Asset)-[r]->(b:Asset)
            RETURN collect({
                source: a.id,
                target: b.id,
                relationship: type(r),
                protocol: r.protocol
            }) AS edges
        """)

        nodes = nodes_result.single()["nodes"]
        edges = edges_result.single()["edges"]

        return {
            "nodes": nodes,
            "edges": edges
        }