import os
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from neo4j import GraphDatabase


# Project root
ROOT = Path(__file__).resolve().parents[1]

# Load .env
load_dotenv(ROOT / ".env")

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# CSV files
ASSETS_FILE = ROOT / "data" / "assets.csv"
CONNECTIONS_FILE = ROOT / "data" / "connections.csv"


# Connect to Neo4j
driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASSWORD)
)


def clear_database():
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")


def load_assets():
    assets = pd.read_csv(ASSETS_FILE)

    with driver.session() as session:
        for _, row in assets.iterrows():
            session.run(
                """
                MERGE (a:Asset {id: $id})
                SET
                    a.name = $name,
                    a.type = $type,
                    a.ip = $ip,
                    a.criticality = $criticality,
                    a.exposed = $exposed,
                    a.compromised = $compromised
                """,
                id=row["id"],
                name=row["name"],
                type=row["type"],
                ip=row["ip"],
                criticality=row["criticality"],
                exposed=row["exposed"],
                compromised=row["compromised"]
            )


def load_connections():
    connections = pd.read_csv(CONNECTIONS_FILE)

    allowed = {
        "CONNECTS",
        "ACCESSES",
        "ADMIN_ACCESS",
        "BACKUP"
    }

    with driver.session() as session:
        for _, row in connections.iterrows():

            relationship = row["relationship"].strip().upper()

            if relationship not in allowed:
                raise ValueError(
                    f"Invalid relationship: {relationship}"
                )

            query = f"""
            MATCH (a:Asset {{id: $source}})
            MATCH (b:Asset {{id: $target}})
            MERGE (a)-[r:{relationship}]->(b)
            SET r.protocol = $protocol
            """

            session.run(
                query,
                source=row["source"],
                target=row["target"],
                protocol=row["protocol"]
            )


def verify_graph():
    with driver.session() as session:

        result = session.run(
            """
            MATCH (a:Asset)
            OPTIONAL MATCH (a)-[r]->(b:Asset)
            RETURN count(DISTINCT a) AS assets,
                   count(r) AS relationships
            """
        )

        record = result.single()

        print()
        print("Graph loaded successfully!")
        print("Assets:", record["assets"])
        print("Relationships:", record["relationships"])


if __name__ == "__main__":

    print("Starting NexaGraph AI graph builder...")

    clear_database()

    print("Loading assets...")
    load_assets()

    print("Loading connections...")
    load_connections()

    verify_graph()

    driver.close()

    print()
    print("Done!")