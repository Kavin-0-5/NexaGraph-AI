
from main import build_remediation_recommendations


def sample_nodes():
    return [
        {"id": "A01", "name": "Internet"},
        {"id": "A02", "name": "Web-Server"},
        {"id": "A03", "name": "App-Server"},
        {"id": "A06", "name": "Customer-DB"},
    ]


def sample_path(risk, connections):
    return {
        "risk_score": risk,
        "connections": connections,
    }


def connection(source, target, relationship="CONNECTS"):
    return {
        "source": source,
        "target": target,
        "relationship": relationship,
    }


def test_empty_paths_return_no_recommendations():
    result = build_remediation_recommendations([], sample_nodes())

    assert result == []


def test_recommendations_rank_highest_risk_first():
    paths = [
        sample_path(60, [connection("A01", "A02")]),
        sample_path(95, [connection("A02", "A03")]),
    ]

    result = build_remediation_recommendations(paths, sample_nodes())

    assert result[0]["source_id"] == "A02"
    assert result[0]["highest_path_risk"] == 95


def test_repeated_connection_is_counted_once_per_path():
    paths = [
        sample_path(
            80,
            [
                connection("A02", "A03"),
                connection("A02", "A03"),
            ],
        ),
    ]

    result = build_remediation_recommendations(paths, sample_nodes())

    assert len(result) == 1
    assert result[0]["paths_affected"] == 1
    assert result[0]["priority_score"] == 80


def test_connection_appearing_in_multiple_paths_gets_higher_count():
    paths = [
        sample_path(80, [connection("A02", "A03")]),
        sample_path(70, [connection("A02", "A03")]),
        sample_path(60, [connection("A01", "A02")]),
    ]

    result = build_remediation_recommendations(paths, sample_nodes())

    assert result[0]["source_id"] == "A02"
    assert result[0]["paths_affected"] == 2
    assert result[0]["priority_score"] == 150


def test_recommendation_limit_is_respected():
    paths = [
        sample_path(
            80,
            [
                connection("A01", "A02"),
                connection("A02", "A03"),
                connection("A03", "A06"),
            ],
        ),
    ]

    result = build_remediation_recommendations(
        paths, sample_nodes(), limit=2
    )

    assert len(result) == 2


def test_recommendation_limit_zero_returns_empty_list():
    paths = [
        sample_path(90, [connection("A02", "A03")]),
    ]

    result = build_remediation_recommendations(
        paths, sample_nodes(), limit=0
    )

    assert result == []


def test_missing_node_names_use_asset_ids():
    paths = [
        sample_path(85, [connection("UNKNOWN1", "UNKNOWN2")]),
    ]

    result = build_remediation_recommendations(paths, [])

    assert result[0]["source_name"] == "UNKNOWN1"
    assert result[0]["destination_name"] == "UNKNOWN2"


def test_missing_relationship_defaults_to_connects():
    paths = [
        sample_path(
            75,
            [{"source": "A02", "target": "A03"}],
        ),
    ]

    result = build_remediation_recommendations(paths, sample_nodes())

    assert result[0]["relationship"] == "CONNECTS"


def test_invalid_risk_score_defaults_to_zero():
    paths = [
        sample_path(
            "invalid",
            [connection("A02", "A03")],
        ),
    ]

    result = build_remediation_recommendations(paths, sample_nodes())

    assert result[0]["highest_path_risk"] == 0
    assert result[0]["priority_score"] == 0
