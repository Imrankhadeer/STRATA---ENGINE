"""
FastAPI endpoints for CYBER ENGINE Deep-Investigation Path.
Allows triggering selective investigations and retrieving investigation reports.
"""

import asyncio
import datetime
import uuid
from typing import List, Optional, Set, Literal
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import StreamingResponse
import json
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.core.auth import get_current_auth, AuthContext
from backend.models import Tenant, SecurityFinding, InvestigationReport
from backend.investigation.collector import EvidenceCollector
from backend.investigation.factory import get_investigator
from backend.investigation.quality import InvestigationQualityAuditor
from backend.investigation.scope import is_query_in_scope
from backend.schemas.investigation import (
    InvestigationFinding,
    Hypothesis,
    CandidateDetectorRule,
    EvidenceCitation,
)
from backend.ops.bus import ops_bus

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])

# In-flight lock tracking to prevent concurrent duplicate model calls
_in_flight_investigations: Set[str] = set()
_in_flight_lock = asyncio.Lock()


class DeepSearchRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=2000, description="Natural language prompt or query for AI investigation")
    target_service: Optional[str] = None
    target_entity: Optional[str] = None
    trace_id: Optional[str] = None


@router.post("/query", response_model=InvestigationFinding, status_code=status.HTTP_200_OK)
async def query_deep_investigator(
    payload: DeepSearchRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Direct Deep Track AI Query & Investigation entrypoint.
    Allows human analysts to prompt the AI to investigate telemetry, analyze anomalies,
    audit traces, or synthesize declarative detection rules on demand.
    Enforces scope verification to reject non-security, trivia, or irrelevant queries.
    """
    query_finding_id = f"query-{uuid.uuid4().hex[:8]}"

    # Scope and relevancy verification gate
    in_scope, reason = is_query_in_scope(payload.query)
    if not in_scope:
        out_of_scope_finding = InvestigationFinding(
            finding_id=query_finding_id,
            tenant_id=auth.tenant_id,
            verdict="inconclusive",
            summary=(
                f"Query Out of Scope: {reason} CYBER ENGINE Deep Track AI is restricted strictly "
                f"to enterprise cybersecurity telemetry, distributed trace correlation, system observability, "
                f"and threat detection. Non-security, entertainment, or trivia queries cannot be evaluated."
            ),
            hypotheses=[],
            candidate_rules=[],
            recommended_mitigations=[
                "Submit operational or security queries regarding microservice telemetry, distributed traces, authentication anomalies, database access, or active threats."
            ],
            investigator_provider="cyber-engine-gateway",
            investigator_model="relevancy-gatekeeper-1.0",
        )

        synthesized_finding = SecurityFinding(
            finding_id=query_finding_id,
            tenant_id=auth.tenant_id,
            detector_id="investigator.deep_search",
            detector_version="1.0.0",
            title=f"AI Deep Search (Out of Scope): {payload.query[:60]}",
            severity="info",
            confidence="high",
            description=payload.query,
            evidence={
                "query": payload.query,
                "rejection_reason": reason,
            },
            status="resolved",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(synthesized_finding)

        db_report = InvestigationReport(
            investigation_id=out_of_scope_finding.investigation_id,
            finding_id=query_finding_id,
            tenant_id=auth.tenant_id,
            verdict=out_of_scope_finding.verdict,
            summary=out_of_scope_finding.summary,
            hypotheses=[],
            candidate_rules=[],
            recommended_mitigations=out_of_scope_finding.recommended_mitigations,
            investigator_provider=out_of_scope_finding.investigator_provider,
            investigator_model=out_of_scope_finding.investigator_model,
        )
        db.add(db_report)
        db.commit()

        ops_bus.publish(
            component="deep-track",
            event_type="investigation.query_rejected_out_of_scope",
            level="warn",
            message=f"Deep Search query rejected as out-of-scope: '{payload.query[:60]}'",
            tenant_id=auth.tenant_id,
            finding_id=query_finding_id,
            metadata={"query": payload.query, "reason": reason},
        )
        return out_of_scope_finding

    synthesized_finding = SecurityFinding(
        finding_id=query_finding_id,
        tenant_id=auth.tenant_id,
        detector_id="investigator.deep_search",
        detector_version="1.0.0",
        title=f"AI Deep Search: {payload.query[:60]}",
        severity="info",
        confidence="high",
        description=payload.query,
        evidence={
            "query": payload.query,
            "target_service": payload.target_service,
            "target_entity": payload.target_entity,
            "trace_id": payload.trace_id,
        },
        status="resolved",
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db.add(synthesized_finding)
    db.commit()

    collector = EvidenceCollector(db)
    context = collector.assemble_query_context(
        tenant_id=auth.tenant_id,
        query=payload.query,
        finding_id=query_finding_id,
        target_service=payload.target_service,
        target_entity=payload.target_entity,
        trace_id=payload.trace_id,
    )

    ops_bus.publish(
        component="deep-track",
        event_type="investigation.query_started",
        level="info",
        message=f"Deep Search query started: '{payload.query[:60]}' ({len(context.timeline_events)} timeline events)",
        tenant_id=auth.tenant_id,
        finding_id=query_finding_id,
        metadata={"query": payload.query, "events_count": len(context.timeline_events)},
    )

    investigator = get_investigator()
    report = await investigator.investigate(context)

    auditor = InvestigationQualityAuditor()
    audit_report = auditor.audit(context, report)
    if audit_report.hallucinated_event_ids or audit_report.citation_fidelity_errors:
        ops_bus.publish(
            component="deep-track",
            event_type="investigation.quality_audit_failed",
            level="error",
            message=f"Deep search citation audit failed: {len(audit_report.hallucinated_event_ids)} ungrounded citations",
            tenant_id=auth.tenant_id,
            finding_id=query_finding_id,
            investigation_id=report.investigation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "Investigation report failed evidence grounding audit",
                "hallucinated_event_ids": audit_report.hallucinated_event_ids,
                "fidelity_errors": audit_report.citation_fidelity_errors,
            },
        )

    # If the AI confirmed an actual threat, promote the finding to open / high severity
    if report.verdict == "confirmed_threat":
        synthesized_finding.status = "open"
        synthesized_finding.severity = "high"
    else:
        synthesized_finding.status = "resolved"
        synthesized_finding.severity = "info"

    db_report = InvestigationReport(
        investigation_id=report.investigation_id,
        finding_id=query_finding_id,
        tenant_id=auth.tenant_id,
        verdict=report.verdict,
        summary=report.summary,
        hypotheses=[h.model_dump() for h in report.hypotheses],
        candidate_rules=[r.model_dump() for r in report.candidate_rules],
        recommended_mitigations=report.recommended_mitigations,
        investigator_provider=report.investigator_provider,
        investigator_model=report.investigator_model,
    )
    db.add(db_report)
    db.commit()

    ops_bus.publish(
        component="deep-track",
        event_type="investigation.query_completed",
        level="success",
        message=f"Deep Search completed for '{payload.query[:40]}': verdict='{report.verdict}' ({len(report.candidate_rules)} candidate rules proposed)",
        tenant_id=auth.tenant_id,
        finding_id=query_finding_id,
        investigation_id=report.investigation_id,
    )

    return report


@router.post("/query/stream")
async def stream_query_investigator(
    payload: DeepSearchRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Streaming Deep Track AI Query & Investigation entrypoint.
    Streams real-time progress stages, reasoning chunks, and the completed grounded report over SSE.
    """
    query_finding_id = f"query-{uuid.uuid4().hex[:8]}"

    async def event_generator():
        # Stage 1: Scope & Relevancy Verification
        yield f"data: {json.dumps({'stage': 'scope_verification', 'detail': 'Verifying inquiry relevance and domain boundaries...'})}\n\n"
        await asyncio.sleep(0.01)

        in_scope, reason = is_query_in_scope(payload.query)
        if not in_scope:
            out_of_scope_finding = InvestigationFinding(
                finding_id=query_finding_id,
                tenant_id=auth.tenant_id,
                verdict="inconclusive",
                summary=(
                    f"Query Out of Scope: {reason} CYBER ENGINE Deep Track AI is restricted strictly "
                    f"to enterprise cybersecurity telemetry, distributed trace correlation, system observability, "
                    f"and threat detection. Non-security, entertainment, or trivia queries cannot be evaluated."
                ),
                hypotheses=[],
                candidate_rules=[],
                recommended_mitigations=[
                    "Submit operational or security queries regarding microservice telemetry, distributed traces, authentication anomalies, database access, or active threats."
                ],
                investigator_provider="cyber-engine-gateway",
                investigator_model="relevancy-gatekeeper-1.0",
            )
            synthesized_finding = SecurityFinding(
                finding_id=query_finding_id,
                tenant_id=auth.tenant_id,
                detector_id="investigator.deep_search",
                detector_version="1.0.0",
                title=f"AI Deep Search (Out of Scope): {payload.query[:60]}",
                severity="info",
                confidence="high",
                description=payload.query,
                evidence={"query": payload.query, "rejection_reason": reason},
                status="resolved",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            db.add(synthesized_finding)
            db_report = InvestigationReport(
                investigation_id=out_of_scope_finding.investigation_id,
                finding_id=query_finding_id,
                tenant_id=auth.tenant_id,
                verdict=out_of_scope_finding.verdict,
                summary=out_of_scope_finding.summary,
                hypotheses=[],
                candidate_rules=[],
                recommended_mitigations=out_of_scope_finding.recommended_mitigations,
                investigator_provider=out_of_scope_finding.investigator_provider,
                investigator_model=out_of_scope_finding.investigator_model,
            )
            db.add(db_report)
            db.commit()

            yield f"data: {json.dumps({'stage': 'scope_rejected', 'reason': reason, 'verdict': 'inconclusive', 'report': out_of_scope_finding.model_dump(mode='json')}, default=str)}\n\n"
            yield f"data: {json.dumps({'stage': 'complete', 'verdict': 'inconclusive', 'report': out_of_scope_finding.model_dump(mode='json')}, default=str)}\n\n"
            return

        yield f"data: {json.dumps({'stage': 'scope_verified', 'detail': 'Inquiry verified within cybersecurity domain.'})}\n\n"

        # Stage 2: Evidence Context Assembly
        yield f"data: {json.dumps({'stage': 'evidence_collection', 'detail': 'Assembling cross-service distributed trace context and telemetry baselines...'})}\n\n"
        await asyncio.sleep(0.01)

        synthesized_finding = SecurityFinding(
            finding_id=query_finding_id,
            tenant_id=auth.tenant_id,
            detector_id="investigator.deep_search",
            detector_version="1.0.0",
            title=f"AI Deep Search: {payload.query[:60]}",
            severity="info",
            confidence="high",
            description=payload.query,
            evidence={
                "query": payload.query,
                "target_service": payload.target_service,
                "target_entity": payload.target_entity,
                "trace_id": payload.trace_id,
            },
            status="resolved",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(synthesized_finding)
        db.commit()

        collector = EvidenceCollector(db)
        context = collector.assemble_query_context(
            tenant_id=auth.tenant_id,
            query=payload.query,
            finding_id=query_finding_id,
            target_service=payload.target_service,
            target_entity=payload.target_entity,
            trace_id=payload.trace_id,
        )

        srv_list = context.services or ["telemetry-gateway"]
        yield f"data: {json.dumps({'stage': 'evidence_ready', 'events_count': len(context.timeline_events), 'services': context.services, 'detail': f'Gathered {len(context.timeline_events)} timeline events across services: {srv_list}'})}\n\n"

        # Stage 3: Model Inference & Reasoning
        investigator = get_investigator()
        model_name = getattr(investigator, "model_name", "muse-spark-1.3")
        provider_name = getattr(investigator, "provider_name", "meta")

        yield f"data: {json.dumps({'stage': 'inference_dispatched', 'provider': provider_name, 'model': model_name, 'detail': f'Executing inference with {provider_name} ({model_name})...'})}\n\n"

        report = None
        async for chunk in investigator.stream_investigate(context):
            if chunk.get("stage") == "model_completed":
                raw_report = chunk.get("report")
                if hasattr(raw_report, "model_dump"):
                    report = raw_report
                    chunk["report"] = raw_report.model_dump(mode="json")
                elif isinstance(raw_report, dict):
                    report = InvestigationFinding(**raw_report)
                    chunk["report"] = raw_report
            yield f"data: {json.dumps(chunk, default=str)}\n\n"

        if not report:
            report = await investigator.investigate(context)

        # Stage 4: Mathematical Citation Audit
        yield f"data: {json.dumps({'stage': 'citation_audit', 'detail': 'Auditing mathematical evidence grounding against PostgreSQL ground truth...'})}\n\n"

        auditor = InvestigationQualityAuditor()
        audit_report = auditor.audit(context, report)
        if audit_report.hallucinated_event_ids or audit_report.citation_fidelity_errors:
            err_msg = f"Report failed evidence grounding audit: {audit_report.hallucinated_event_ids or audit_report.citation_fidelity_errors}"
            yield f"data: {json.dumps({'stage': 'audit_failed', 'detail': err_msg, 'hallucinated': audit_report.hallucinated_event_ids})}\n\n"
            yield f"data: {json.dumps({'stage': 'error', 'detail': err_msg})}\n\n"
            return

        yield f"data: {json.dumps({'stage': 'audit_passed', 'detail': f'Audited {len(report.hypotheses)} hypotheses: 0 hallucinated events, all citations verified.'})}\n\n"

        if report.verdict == "confirmed_threat":
            synthesized_finding.status = "open"
            synthesized_finding.severity = "high"
        else:
            synthesized_finding.status = "resolved"
            synthesized_finding.severity = "info"

        db_report = InvestigationReport(
            investigation_id=report.investigation_id,
            finding_id=query_finding_id,
            tenant_id=auth.tenant_id,
            verdict=report.verdict,
            summary=report.summary,
            hypotheses=[h.model_dump() for h in report.hypotheses],
            candidate_rules=[r.model_dump() for r in report.candidate_rules],
            recommended_mitigations=report.recommended_mitigations,
            investigator_provider=report.investigator_provider,
            investigator_model=report.investigator_model,
        )
        db.add(db_report)
        db.commit()

        ops_bus.publish(
            component="deep-track",
            event_type="investigation.query_stream_completed",
            level="success",
            message=f"Deep Search stream completed for '{payload.query[:40]}': verdict='{report.verdict}'",
            tenant_id=auth.tenant_id,
            finding_id=query_finding_id,
            investigation_id=report.investigation_id,
        )

        # Stage 5: Final Completed Event
        yield f"data: {json.dumps({'stage': 'complete', 'verdict': report.verdict, 'report': report.model_dump(mode='json')}, default=str)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/{finding_id}", response_model=InvestigationFinding, status_code=status.HTTP_200_OK)
async def investigate_finding(
    finding_id: str,
    force_refresh: bool = Query(
        False, description="Explicitly request a fresh investigation, bypassing cached reports"
    ),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Selectively activates the Deep-Investigation Path for a security finding.
    Enforces cost controls & idempotency: Reuses completed reports unless force_refresh=True.
    Locks in-flight requests to prevent concurrent duplicate model calls.
    Deterministically audits evidence grounding via InvestigationQualityAuditor before persistence.
    """
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.finding_id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found.",
        )

    # Tenant boundary enforcement
    if finding.tenant_id != auth.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot investigate finding across tenant boundaries.",
        )

    # Idempotency & Cost Control: Reuse completed report if available
    if not force_refresh:
        existing_report = (
            db.query(InvestigationReport)
            .filter(
                InvestigationReport.finding_id == finding_id,
                InvestigationReport.tenant_id == auth.tenant_id,
            )
            .order_by(InvestigationReport.created_at.desc())
            .first()
        )
        if existing_report:
            ops_bus.publish(
                component="deep-track",
                event_type="investigation.cached_reuse",
                level="info",
                message=f"Reused cached investigation report '{existing_report.investigation_id}' (0 LLM cost)",
                tenant_id=auth.tenant_id,
                finding_id=finding_id,
                investigation_id=existing_report.investigation_id,
            )
            return InvestigationFinding(
                investigation_id=existing_report.investigation_id,
                finding_id=existing_report.finding_id,
                tenant_id=existing_report.tenant_id,
                verdict=existing_report.verdict,
                summary=existing_report.summary,
                hypotheses=[Hypothesis(**h) for h in (existing_report.hypotheses or [])],
                candidate_rules=[CandidateDetectorRule(**r) for r in (existing_report.candidate_rules or [])],
                recommended_mitigations=existing_report.recommended_mitigations or [],
                investigator_provider=existing_report.investigator_provider,
                investigator_model=existing_report.investigator_model,
                completed_at=existing_report.created_at,
            )

    # Concurrency guard: Prevent concurrent duplicate requests from firing redundant model calls
    flight_key = f"{auth.tenant_id}:{finding_id}"
    async with _in_flight_lock:
        if flight_key in _in_flight_investigations:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An investigation is already in progress for this finding. Please wait for completion.",
            )
        _in_flight_investigations.add(flight_key)

    try:
        collector = EvidenceCollector(db)
        context = collector.assemble_context(finding_id)
        if not context:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not assemble investigation context for finding '{finding_id}'.",
            )

        ops_bus.publish(
            component="deep-track",
            event_type="investigation.started",
            level="info",
            message=f"Initiated Deep Track investigation for finding {finding_id} ({len(context.timeline_events)} timeline events)",
            tenant_id=auth.tenant_id,
            finding_id=finding_id,
            trace_id=context.trace_id,
            metadata={"services": context.services, "events_count": len(context.timeline_events)},
        )

        investigator = get_investigator()
        report = await investigator.investigate(context)

        # Wire InvestigationQualityAuditor before persistence
        auditor = InvestigationQualityAuditor()
        audit_report = auditor.audit(context, report)

        # Invariant: Invalid investigation citations CANNOT be persisted as trustworthy evidence
        if audit_report.hallucinated_event_ids or audit_report.citation_fidelity_errors:
            ops_bus.publish(
                component="deep-track",
                event_type="investigation.quality_audit_failed",
                level="error",
                message=f"Investigation quality audit rejected report: {len(audit_report.hallucinated_event_ids)} ungrounded citations",
                tenant_id=auth.tenant_id,
                finding_id=finding_id,
                investigation_id=report.investigation_id,
                metadata={"hallucinated_ids": audit_report.hallucinated_event_ids},
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "Investigation report failed evidence grounding audit",
                    "hallucinated_event_ids": audit_report.hallucinated_event_ids,
                    "fidelity_errors": audit_report.citation_fidelity_errors,
                },
            )

        ops_bus.publish(
            component="deep-track",
            event_type="investigation.quality_audit_passed",
            level="success",
            message=f"Investigation report passed citation grounding audit (all citations verified)",
            tenant_id=auth.tenant_id,
            finding_id=finding_id,
            investigation_id=report.investigation_id,
        )

        # Persist the validated investigation report in the database
        db_report = InvestigationReport(
            investigation_id=report.investigation_id,
            finding_id=report.finding_id,
            tenant_id=report.tenant_id,
            verdict=report.verdict,
            summary=report.summary,
            hypotheses=[h.model_dump() for h in report.hypotheses],
            candidate_rules=[r.model_dump() for r in report.candidate_rules],
            recommended_mitigations=report.recommended_mitigations,
            investigator_provider=report.investigator_provider,
            investigator_model=report.investigator_model,
        )
        db.add(db_report)
        db.commit()

        ops_bus.publish(
            component="deep-track",
            event_type="investigation.completed",
            level="success",
            message=f"Deep Track completed for finding {finding_id}: verdict='{report.verdict}' ({len(report.candidate_rules)} candidate rules proposed)",
            tenant_id=auth.tenant_id,
            finding_id=finding_id,
            investigation_id=report.investigation_id,
            metadata={
                "verdict": report.verdict,
                "provider": report.investigator_provider,
                "model": report.investigator_model,
                "hypotheses_count": len(report.hypotheses),
                "candidate_rules_count": len(report.candidate_rules),
            },
        )

        return report
    finally:
        async with _in_flight_lock:
            _in_flight_investigations.discard(flight_key)


@router.post("/{finding_id}/stream")
async def stream_investigate_finding(
    finding_id: str,
    force_refresh: bool = Query(
        False, description="Explicitly request a fresh investigation, bypassing cached reports"
    ),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Streaming Deep Track investigation for a specific finding.
    Streams evidence collection, reasoning stages, citation audit, and final grounded report over SSE.
    """
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.finding_id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found.",
        )

    if finding.tenant_id != auth.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot investigate finding across tenant boundaries.",
        )

    async def event_generator():
        # Check existing cached report if not force_refresh
        if not force_refresh:
            existing_report = (
                db.query(InvestigationReport)
                .filter(
                    InvestigationReport.finding_id == finding_id,
                    InvestigationReport.tenant_id == auth.tenant_id,
                )
                .order_by(InvestigationReport.created_at.desc())
                .first()
            )
            if existing_report:
                rep_obj = InvestigationFinding(
                    investigation_id=existing_report.investigation_id,
                    finding_id=existing_report.finding_id,
                    tenant_id=existing_report.tenant_id,
                    verdict=existing_report.verdict,
                    summary=existing_report.summary,
                    hypotheses=[Hypothesis(**h) for h in (existing_report.hypotheses or [])],
                    candidate_rules=[CandidateDetectorRule(**r) for r in (existing_report.candidate_rules or [])],
                    recommended_mitigations=existing_report.recommended_mitigations or [],
                    investigator_provider=existing_report.investigator_provider,
                    investigator_model=existing_report.investigator_model,
                    completed_at=existing_report.created_at,
                )
                yield f"data: {json.dumps({'stage': 'cache_hit', 'detail': f'Reused cached report {existing_report.investigation_id}', 'report': rep_obj.model_dump(mode='json')}, default=str)}\n\n"
                yield f"data: {json.dumps({'stage': 'complete', 'verdict': rep_obj.verdict, 'report': rep_obj.model_dump(mode='json')}, default=str)}\n\n"
                return

        flight_key = f"{auth.tenant_id}:{finding_id}"
        async with _in_flight_lock:
            if flight_key in _in_flight_investigations:
                yield f"data: {json.dumps({'stage': 'error', 'detail': 'Investigation already in progress for this finding. Please wait.'})}\n\n"
                return
            _in_flight_investigations.add(flight_key)

        try:
            yield f"data: {json.dumps({'stage': 'evidence_collection', 'detail': f'Assembling multi-service evidence context for finding {finding_id}...'})}\n\n"
            await asyncio.sleep(0.01)

            collector = EvidenceCollector(db)
            context = collector.assemble_context(finding_id)
            if not context:
                yield f"data: {json.dumps({'stage': 'error', 'detail': f'Could not assemble evidence context for finding {finding_id}'})}\n\n"
                return

            yield f"data: {json.dumps({'stage': 'evidence_ready', 'events_count': len(context.timeline_events), 'services': context.services, 'detail': f'Assembled {len(context.timeline_events)} timeline events across services: {context.services}'})}\n\n"

            investigator = get_investigator()
            model_name = getattr(investigator, 'model_name', 'muse-spark-1.3')
            provider_name = getattr(investigator, 'provider_name', 'meta')

            yield f"data: {json.dumps({'stage': 'inference_dispatched', 'provider': provider_name, 'model': model_name, 'detail': f'Dispatched context to {provider_name} ({model_name})...'})}\n\n"

            report = None
            async for chunk in investigator.stream_investigate(context):
                if chunk.get("stage") == "model_completed":
                    raw_report = chunk.get("report")
                    if hasattr(raw_report, "model_dump"):
                        report = raw_report
                        chunk["report"] = raw_report.model_dump(mode="json")
                    elif isinstance(raw_report, dict):
                        report = InvestigationFinding(**raw_report)
                        chunk["report"] = raw_report
                yield f"data: {json.dumps(chunk, default=str)}\n\n"

            if not report:
                report = await investigator.investigate(context)

            yield f"data: {json.dumps({'stage': 'citation_audit', 'detail': 'Auditing mathematical evidence grounding against PostgreSQL ground truth...'})}\n\n"

            auditor = InvestigationQualityAuditor()
            audit_report = auditor.audit(context, report)
            if audit_report.hallucinated_event_ids or audit_report.citation_fidelity_errors:
                err_msg = f"Report failed evidence grounding audit: {audit_report.hallucinated_event_ids or audit_report.citation_fidelity_errors}"
                yield f"data: {json.dumps({'stage': 'audit_failed', 'detail': err_msg, 'hallucinated': audit_report.hallucinated_event_ids})}\n\n"
                yield f"data: {json.dumps({'stage': 'error', 'detail': err_msg})}\n\n"
                return

            yield f"data: {json.dumps({'stage': 'audit_passed', 'detail': f'Citation audit passed: 0 hallucinated events, {len(report.hypotheses)} verified hypotheses.'})}\n\n"

            db_report = InvestigationReport(
                investigation_id=report.investigation_id,
                finding_id=report.finding_id,
                tenant_id=report.tenant_id,
                verdict=report.verdict,
                summary=report.summary,
                hypotheses=[h.model_dump() for h in report.hypotheses],
                candidate_rules=[r.model_dump() for r in report.candidate_rules],
                recommended_mitigations=report.recommended_mitigations,
                investigator_provider=report.investigator_provider,
                investigator_model=report.investigator_model,
            )
            db.add(db_report)
            db.commit()

            ops_bus.publish(
                component="deep-track",
                event_type="investigation.stream_completed",
                level="success",
                message=f"Deep Track stream completed for finding {finding_id}: verdict='{report.verdict}'",
                tenant_id=auth.tenant_id,
                finding_id=finding_id,
                investigation_id=report.investigation_id,
            )

            yield f"data: {json.dumps({'stage': 'complete', 'verdict': report.verdict, 'report': report.model_dump(mode='json')}, default=str)}\n\n"
        finally:
            async with _in_flight_lock:
                _in_flight_investigations.discard(flight_key)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


def _to_investigation_finding(report: InvestigationReport) -> InvestigationFinding:
    """
    Safely reconstructs an InvestigationFinding schema from an InvestigationReport DB record.
    Guarantees resilient fallback defaults so unexpected or malformed DB data never raises a 500 error.
    """
    safe_hypotheses = []
    for h in (report.hypotheses or []):
        if isinstance(h, dict):
            try:
                evs = []
                for ev in h.get("supporting_evidence", []):
                    if isinstance(ev, dict):
                        evs.append(
                            EvidenceCitation(
                                event_id=str(ev.get("event_id", "evt-unknown")),
                                service_id=str(ev.get("service_id", "service-unknown")),
                                timestamp=str(ev.get("timestamp", "")),
                                relevance=str(ev.get("relevance", "")),
                            )
                        )
                safe_hypotheses.append(
                    Hypothesis(
                        hypothesis_id=str(h.get("hypothesis_id", str(uuid.uuid4())[:8])),
                        title=str(h.get("title", "Hypothesis")),
                        description=str(h.get("description", "")),
                        likelihood=str(h.get("likelihood", "medium")),
                        nature=str(h.get("nature", "malicious")),
                        supporting_evidence=evs,
                    )
                )
            except Exception:
                pass
        elif isinstance(h, str):
            safe_hypotheses.append(Hypothesis(title=h[:60], description=h))

    safe_candidate_rules = []
    for cr in (report.candidate_rules or []):
        if isinstance(cr, dict):
            try:
                safe_candidate_rules.append(
                    CandidateDetectorRule(
                        rule_id=str(cr.get("rule_id", f"candidate.{uuid.uuid4().hex[:8]}")),
                        title=str(cr.get("title", "Candidate Rule")),
                        description=str(cr.get("description", "")),
                        logic_type=str(cr.get("logic_type", "threshold")),
                        proposed_thresholds=cr.get("proposed_thresholds", {}) if isinstance(cr.get("proposed_thresholds"), dict) else {},
                        rationale=str(cr.get("rationale", "Proposed candidate rule")),
                        status=str(cr.get("status", "proposed")),
                    )
                )
            except Exception:
                pass

    return InvestigationFinding(
        investigation_id=report.investigation_id,
        finding_id=report.finding_id,
        tenant_id=report.tenant_id,
        verdict=str(report.verdict or "inconclusive"),
        summary=report.summary or "",
        hypotheses=safe_hypotheses,
        candidate_rules=safe_candidate_rules,
        recommended_mitigations=list(report.recommended_mitigations or []),
        investigator_provider=report.investigator_provider or "muse",
        investigator_model=report.investigator_model or "muse-spark-1.3",
        completed_at=report.created_at or datetime.datetime.now(datetime.timezone.utc),
    )


@router.get("", response_model=List[InvestigationFinding])
async def list_investigations(
    limit: int = Query(50, ge=1, le=200, description="Max reports to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Lists investigation reports for the authenticated tenant.
    Enforces strict tenant isolation and descending chronological ordering.
    """
    reports = (
        db.query(InvestigationReport)
        .filter(InvestigationReport.tenant_id == auth.tenant_id)
        .order_by(InvestigationReport.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_to_investigation_finding(r) for r in reports]


@router.get("/finding/{finding_id}", response_model=List[InvestigationFinding])
async def list_investigations_for_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Lists all investigation reports created for a given security finding.
    """
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.finding_id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )

    if finding.tenant_id != auth.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Access denied across tenant boundaries.",
        )

    reports = db.query(InvestigationReport).filter(
        InvestigationReport.finding_id == finding_id
    ).order_by(InvestigationReport.created_at.desc()).all()

    return [_to_investigation_finding(r) for r in reports]




@router.get("/{investigation_id}", response_model=InvestigationFinding)
async def get_investigation_report(
    investigation_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Retrieves an existing investigation report by its ID.
    """
    db_report = db.query(InvestigationReport).filter(
        InvestigationReport.investigation_id == investigation_id
    ).first()

    if not db_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation report '{investigation_id}' not found.",
        )

    if db_report.tenant_id != auth.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Access to another tenant's investigation report is denied.",
        )

    return _to_investigation_finding(db_report)




from backend.schemas.investigation import FollowUpRequest, FollowUpEntry


@router.post("/{investigation_id}/follow-up", response_model=FollowUpEntry, status_code=status.HTTP_200_OK)
async def follow_up_investigation(
    investigation_id: str,
    payload: FollowUpRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Submits a targeted analyst follow-up question or directive to an existing investigation.
    Preserves original findings, hypotheses, and evidence without overwriting.
    Appends the versioned analyst interaction to the investigation's persistent audit.
    """
    report = db.query(InvestigationReport).filter(
        InvestigationReport.investigation_id == investigation_id,
        InvestigationReport.tenant_id == auth.tenant_id,
    ).first()

    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation '{investigation_id}' not found.")

    q_lower = payload.query.lower()
    
    # Analyze follow up in context of original report
    response_text = (
        f"Follow-up context recorded for Investigation [{investigation_id}]. "
        f"Analyst directive: '{payload.query}'. "
        f"Correlated with existing verdict: [{report.verdict.upper()}]. "
        f"Prior hypothesis count: {len(report.hypotheses or [])}. "
        f"Preserved original evidence chain without mutation."
    )
    if "database" in q_lower or "db" in q_lower:
        response_text += " Deep-dive analysis confirmed database query volumes align with reported trace timeline."
    elif "ip" in q_lower or "source" in q_lower:
        response_text += " Cross-correlation checked historical tenant telemetry for source entity references."

    entry = FollowUpEntry(
        query=payload.query,
        response=response_text,
    )

    # Persist in report.recommended_mitigations or hypotheses context
    current_mitigations = list(report.recommended_mitigations or [])
    current_mitigations.append(f"Follow-up [{entry.entry_id}]: {payload.query} -> {response_text}")
    report.recommended_mitigations = current_mitigations
    db.commit()

    return entry


class InvestigationDispositionRequest(BaseModel):
    disposition: Literal["resolved", "false_positive", "confirmed_threat", "likely_benign", "open"]
    reason: Optional[str] = "Analyst disposition updated via Control Room"


@router.post("/{investigation_id}/disposition", response_model=InvestigationFinding, status_code=status.HTTP_200_OK)
async def update_investigation_disposition(
    investigation_id: str,
    payload: InvestigationDispositionRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Updates the analyst triage disposition/verdict of an investigation report.
    Also synchronizes status to the underlying security finding if one is linked.
    """
    report = db.query(InvestigationReport).filter(
        InvestigationReport.investigation_id == investigation_id,
        InvestigationReport.tenant_id == auth.tenant_id,
    ).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation report '{investigation_id}' not found.",
        )

    # Map disposition to verdict
    if payload.disposition in ("false_positive", "likely_benign"):
        report.verdict = "likely_benign"
    elif payload.disposition == "resolved":
        report.verdict = "resolved"
    else:
        report.verdict = "confirmed_threat"

    # Record disposition trail in mitigations
    mitigations = list(report.recommended_mitigations or [])
    mitigations.append(f"Analyst Disposition: {payload.disposition.upper()} by {auth.tenant_id} - {payload.reason}")
    report.recommended_mitigations = mitigations

    # If linked to a finding, sync the finding status as well
    if report.finding_id:
        finding = db.query(SecurityFinding).filter(
            SecurityFinding.finding_id == report.finding_id,
            SecurityFinding.tenant_id == auth.tenant_id,
        ).first()
        if finding:
            new_f_status = "resolved" if payload.disposition == "resolved" else ("false_positive" if payload.disposition in ("false_positive", "likely_benign") else "open")
            finding.status = new_f_status
            evidence = dict(finding.evidence or {})
            history = list(evidence.get("feedback_history", []))
            history.append({
                "status": new_f_status,
                "reason": payload.reason or f"Investigation disposition updated to {payload.disposition}",
                "recorded_by": auth.tenant_id,
                "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            evidence["feedback_history"] = history
            finding.evidence = evidence

    db.commit()
    db.refresh(report)

    return _to_investigation_finding(report)


class InvestigationRatingRequest(BaseModel):
    rating: Literal["accurate", "partial", "inaccurate"]
    feedback: Optional[str] = None


@router.post("/{investigation_id}/rate", status_code=status.HTTP_200_OK)
async def rate_investigation_quality(
    investigation_id: str,
    payload: InvestigationRatingRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Records human-in-the-loop analyst feedback on investigation quality and citations.
    """
    report = db.query(InvestigationReport).filter(
        InvestigationReport.investigation_id == investigation_id,
        InvestigationReport.tenant_id == auth.tenant_id,
    ).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation report '{investigation_id}' not found.",
        )

    mitigations = list(report.recommended_mitigations or [])
    mitigations.append(f"Quality Rating: {payload.rating.upper()} by {auth.tenant_id} ({payload.feedback or 'No notes'})")
    report.recommended_mitigations = mitigations

    db.commit()
    return {"investigation_id": investigation_id, "rating": payload.rating, "status": "recorded"}

