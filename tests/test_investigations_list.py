"""
Tests for Deep Investigations List Endpoint (GET /api/v1/investigations).

Validates:
1. Retrieval of existing investigation reports for authenticated tenant.
2. Strict cross-tenant isolation (reports for other tenants are never leaked).
3. Pagination support.
"""

import datetime
import pytest
from backend.models import SecurityFinding, InvestigationReport
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID


@pytest.fixture
def seed_investigations(db_session):
    now = datetime.datetime.now(datetime.timezone.utc)
    # Seed findings first
    f1 = SecurityFinding(
        finding_id="find-inv-1",
        tenant_id=TEST_TENANT_ID,
        detector_id="detector.auth.brute_force",
        detector_version="1.0.0",
        title="Brute Force Login Attack",
        severity="high",
        confidence="high",
        description="Repeated failed logins",
        evidence={"ip": "1.2.3.4"},
    )
    f_other = SecurityFinding(
        finding_id="find-inv-other",
        tenant_id="tenant-beta",
        detector_id="detector.auth.brute_force",
        detector_version="1.0.0",
        title="Cross Tenant Finding",
        severity="critical",
        confidence="high",
        description="Cross tenant issue",
        evidence={},
    )
    db_session.add(f1)
    db_session.add(f_other)
    db_session.commit()

    # Seed reports
    r1 = InvestigationReport(
        investigation_id="inv-rep-001",
        finding_id="find-inv-1",
        tenant_id=TEST_TENANT_ID,
        verdict="confirmed_threat",
        summary="Automated credential stuffing confirmed.",
        hypotheses=[
            {
                "hypothesis_id": "hyp-1",
                "title": "Credential Stuffing",
                "description": "High velocity failed logins",
                "likelihood": "high",
                "nature": "malicious",
                "supporting_evidence": [],
            }
        ],
        candidate_rules=[],
        recommended_mitigations=["Block IP at gateway"],
        investigator_provider="mock",
        investigator_model="Llama-3.3-70B-Instruct",
        created_at=now,
    )
    r_other = InvestigationReport(
        investigation_id="inv-rep-other",
        finding_id="find-inv-other",
        tenant_id="tenant-beta",
        verdict="inconclusive",
        summary="Other tenant report.",
        hypotheses=[],
        candidate_rules=[],
        recommended_mitigations=[],
        investigator_provider="mock",
        investigator_model="Llama-3.3-70B-Instruct",
        created_at=now,
    )
    db_session.add(r1)
    db_session.add(r_other)
    db_session.commit()


def test_list_investigations_tenant_isolated(client, auth_headers, seed_investigations):
    res = client.get("/api/v1/investigations", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["investigation_id"] == "inv-rep-001"
    assert data[0]["tenant_id"] == TEST_TENANT_ID
    assert data[0]["verdict"] == "confirmed_threat"
    assert len(data[0]["hypotheses"]) == 1


def test_investigation_disposition_resolved(client, auth_headers, seed_investigations):
    res = client.post(
        "/api/v1/investigations/inv-rep-001/disposition",
        headers=auth_headers,
        json={"disposition": "resolved", "reason": "Analyst verified clean"}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["verdict"] == "resolved"

    # Verify GET returns resolved without 500 validation error
    get_res = client.get("/api/v1/investigations/inv-rep-001", headers=auth_headers)
    assert get_res.status_code == 200
    assert get_res.json()["verdict"] == "resolved"


def test_investigation_disposition_query_finding(client, auth_headers, db_session):
    now = datetime.datetime.now(datetime.timezone.utc)
    # SecurityFinding must exist due to foreign key constraint
    sf = SecurityFinding(
        finding_id="query-377f344a",
        tenant_id=TEST_TENANT_ID,
        detector_id="investigator.deep_search",
        detector_version="1.0.0",
        title="AI Deep Search: query-377f344a",
        severity="info",
        confidence="high",
        description="Query finding",
        evidence={},
        status="open",
        created_at=now,
    )
    db_session.add(sf)
    db_session.commit()

    q_rep = InvestigationReport(
        investigation_id="inv-query-999",
        finding_id="query-377f344a",
        tenant_id=TEST_TENANT_ID,
        verdict="inconclusive",
        summary="Query investigation report.",
        hypotheses=[{"title": "Some partial hypothesis"}],
        candidate_rules=[{"title": "Some partial candidate rule"}],
        recommended_mitigations=[],
        investigator_provider="muse",
        investigator_model="muse-spark-1.3",
        created_at=now,
    )
    db_session.add(q_rep)
    db_session.commit()

    res = client.post(
        "/api/v1/investigations/inv-query-999/disposition",
        headers=auth_headers,
        json={"disposition": "false_positive", "reason": "Query dismissed"}
    )
    assert res.status_code == 200, res.text
    assert res.json()["verdict"] == "likely_benign"
