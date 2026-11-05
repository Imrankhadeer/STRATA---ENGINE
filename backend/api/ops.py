"""
FastAPI Router for Ternline Operational Observability & Live Console.

Provides:
- GET /api/v1/ops/overview — Real-time security posture, pipeline health, and aggregate telemetry
- POST /api/v1/ops/stream-ticket — Generates a short-lived, single-use ticket for browser EventSource
- GET /api/v1/ops/events/stream — Authenticated Server-Sent Events (SSE) live operational event stream
- GET /api/v1/ops/events/recent — Returns recent buffered operational events
"""

import asyncio
import datetime
import json
import logging
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Security, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, text
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from backend.config import settings
from backend.core.auth import (
    get_current_auth,
    AuthContext,
    Permission,
    hash_api_key,
    require_permission,
)
from backend.db.session import get_db
from backend.models import (
    ApiKey,
    EventModel,
    SecurityFinding,
    InvestigationReport,
    DeclarativeRuleModel,
    Tenant,
    UserModel,
)
from backend.ops.bus import ops_bus, OpsEvent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ops", tags=["Operations & Observability"])
security_bearer = HTTPBearer(auto_error=False)


# --- Response Models ---

class FindingsPosture(BaseModel):
    total_findings: int
    open_findings: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]


class InvestigationPosture(BaseModel):
    total_investigations: int
    by_verdict: Dict[str, int]
    provider: str
    model: str
    provider_status: str
    status: str = "operational"
    average_duration_ms: Optional[float] = None


class RulesPosture(BaseModel):
    total_rules: int
    by_status: Dict[str, int]
    active_count: int
    pending_validation_count: int
    pending_approval_count: int


class PipelineHealth(BaseModel):
    database_status: str
    database_latency_ms: Optional[float]
    database_version: Optional[str]
    total_events_ingested: int
    recent_events_1h: int
    fast_track_engine_status: str
    fast_track_detection_latency: str
    live_subscribers_connected: int
    redis_status: str = "operational"
    redis_latency_ms: Optional[float] = None


class RecentFindingSummary(BaseModel):
    finding_id: str
    title: str
    severity: str
    status: str
    detector_id: str
    created_at: str
    services: List[str]


class OverviewResponse(BaseModel):
    tenant_id: str
    timestamp: str
    security_posture: FindingsPosture
    investigations: InvestigationPosture
    rules: RulesPosture
    pipeline_health: PipelineHealth
    recent_findings: List[RecentFindingSummary]
    uninstrumented_metrics: Dict[str, Optional[str]] = Field(
        default_factory=lambda: {
            "network_packet_drops": "Not instrumented (requires eBPF/host agent)",
            "kafka_queue_lag": "Not applicable (process-local architecture)",
            "disk_io_saturation": "Not instrumented",
        }
    )


class StreamTicketResponse(BaseModel):
    ticket: str
    expires_in_seconds: int


# --- Helper: Authenticate SSE using Bearer or Single-Use Ticket ---

async def get_stream_auth(
    request: Request,
    ticket: Optional[str] = Query(default=None, description="Short-lived single-use stream ticket"),
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    db: Session = Depends(get_db),
) -> AuthContext:
    """
    Authenticates the live operations event stream:
    1. First checks for a valid single-use stream ticket (preferred for browser EventSource).
    2. Falls back to Authorization: Bearer <key> header if provided.
    Rejects long-lived API keys passed directly in query parameters.
    """
    # 1. Single-use short-lived stream ticket
    if ticket:
        consumed = ops_bus.consume_stream_ticket(ticket)
        if not consumed:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, expired, or previously consumed stream ticket. Obtain a new ticket via POST /api/v1/ops/stream-ticket.",
            )
        tenant = db.query(Tenant).filter(
            Tenant.id == consumed.tenant_id,
            Tenant.is_active == True,
        ).first()
        if not tenant:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ticket tenant is inactive.")

        if consumed.auth_type == "jwt":
            user = db.query(UserModel).filter(
                UserModel.email == consumed.operator_principal,
                UserModel.tenant_id == consumed.tenant_id,
                UserModel.is_active == True,
            ).first()
            if not user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ticket operator is inactive.")
        else:
            api_key = db.query(ApiKey).filter(
                ApiKey.id == consumed.key_id,
                ApiKey.tenant_id == consumed.tenant_id,
                ApiKey.is_active == True,
            ).first()
            expires_at = api_key.expires_at if api_key else None
            if expires_at and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
            if not api_key or (expires_at and expires_at < datetime.datetime.now(datetime.timezone.utc)):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ticket API key is inactive.")
        return AuthContext(
            tenant_id=consumed.tenant_id,
            app_id=consumed.app_id,
            key_id=consumed.key_id or "stream-ticket",
            operator_principal=consumed.operator_principal,
            auth_type=consumed.auth_type,
        )

    # 2. Standard Bearer Authorization header
    if credentials and credentials.credentials:
        raw_key = credentials.credentials
        key_hash = hash_api_key(raw_key)
        api_key_rec = (
            db.query(ApiKey)
            .filter(ApiKey.key_hash == key_hash, ApiKey.is_active == True)
            .first()
        )
        if api_key_rec:
            return AuthContext(
                tenant_id=api_key_rec.tenant_id,
                app_id=api_key_rec.app_id,
                key_id=api_key_rec.id,
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: SSE connection requires a valid stream ticket (?ticket=) or Authorization Bearer header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# --- Endpoints ---

@router.get("/overview", response_model=OverviewResponse)
async def get_operations_overview(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Returns live security posture, pipeline health, and aggregate operations data
    computed strictly for the authenticated tenant using efficient PostgreSQL queries.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    t_1h_ago = now - datetime.timedelta(hours=1)

    # 0. Redis Health Check & Latency
    redis_status = "operational"
    redis_latency_ms = None
    if settings.REDIS_URL:
        t_red_start = time.time()
        try:
            import redis
            r_client = redis.from_url(settings.REDIS_URL, socket_timeout=0.5)
            if r_client.ping():
                redis_status = "connected"
                redis_latency_ms = round((time.time() - t_red_start) * 1000, 2)
            else:
                redis_status = "degraded"
        except Exception:
            redis_status = "in-memory (fallback)" if settings.ENVIRONMENT == "development" else "unreachable"
    else:
        redis_status = "in-memory"

    # 1. Database Health Check & Latency
    db_status = "connected"
    db_latency_ms = None
    db_version = "PostgreSQL"
    t_db_start = time.time()
    try:
        raw_ver = db.execute(text("SELECT version()")).scalar()
        if raw_ver:
            db_version = str(raw_ver).split(",")[0]
        db_latency_ms = round((time.time() - t_db_start) * 1000, 2)
    except Exception as e:
        logger.error("Overview DB query failed: %s", e)
        db_status = "degraded"

    # 2. Findings Aggregations (tenant-scoped)
    findings_q = db.query(SecurityFinding).filter(SecurityFinding.tenant_id == auth.tenant_id)
    total_findings = findings_q.count()

    # Severity distribution
    sev_rows = (
        db.query(SecurityFinding.severity, func.count(SecurityFinding.finding_id))
        .filter(SecurityFinding.tenant_id == auth.tenant_id)
        .group_by(SecurityFinding.severity)
        .all()
    )
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s, count in sev_rows:
        normalized_severity = str(s or "").strip().lower()
        if normalized_severity in by_severity:
            by_severity[normalized_severity] += count
        else:
            by_severity[normalized_severity] = count

    # Status distribution
    status_rows = (
        db.query(SecurityFinding.status, func.count(SecurityFinding.finding_id))
        .filter(SecurityFinding.tenant_id == auth.tenant_id)
        .group_by(SecurityFinding.status)
        .all()
    )
    by_status = {"open": 0, "resolved": 0, "false_positive": 0}
    for st, count in status_rows:
        normalized_status = str(st or "").strip().lower()
        if normalized_status in by_status:
            by_status[normalized_status] += count
        else:
            by_status[normalized_status] = count

    open_findings = by_status.get("open", 0)

    # Recent 5 findings
    recent_findings_raw = (
        findings_q.order_by(SecurityFinding.created_at.desc())
        .limit(5)
        .all()
    )
    recent_findings = []
    for f in recent_findings_raw:
        evidence = f.evidence or {}
        stages = evidence.get("stages", {})
        services = []
        if isinstance(stages, dict):
            for stage_info in stages.values():
                if isinstance(stage_info, dict) and "service_id" in stage_info:
                    services.append(stage_info["service_id"])
        if not services and "service_id" in evidence:
            services.append(evidence["service_id"])
        if not services:
            services = ["api-service"]

        recent_findings.append(
            RecentFindingSummary(
                finding_id=f.finding_id,
                title=f.title,
                severity=f.severity,
                status=f.status,
                detector_id=f.detector_id,
                created_at=f.created_at.isoformat() if f.created_at else now.isoformat(),
                services=list(set(services)),
            )
        )

    # 3. Investigations Aggregations (tenant-scoped)
    inv_rows = (
        db.query(InvestigationReport.verdict, func.count(InvestigationReport.investigation_id))
        .filter(InvestigationReport.tenant_id == auth.tenant_id)
        .group_by(InvestigationReport.verdict)
        .all()
    )
    by_verdict = {"confirmed_threat": 0, "likely_benign": 0, "inconclusive": 0}
    total_investigations = 0
    for v, c in inv_rows:
        total_investigations += c
        if v in by_verdict:
            by_verdict[v] = c
        else:
            by_verdict[v] = c

    # 4. Declarative Rules Aggregations (tenant-scoped)
    rule_rows = (
        db.query(DeclarativeRuleModel.status, func.count(DeclarativeRuleModel.rule_id))
        .filter(DeclarativeRuleModel.tenant_id == auth.tenant_id)
        .group_by(DeclarativeRuleModel.status)
        .all()
    )
    by_rule_status = {
        "proposed": 0,
        "validated": 0,
        "approved": 0,
        "active": 0,
        "disabled": 0,
        "rolled_back": 0,
    }
    total_rules = 0
    for rst, count in rule_rows:
        total_rules += count
        if rst in by_rule_status:
            by_rule_status[rst] = count
        else:
            by_rule_status[rst] = count

    # 5. Ingested Events Count (tenant-scoped)
    total_events = (
        db.query(func.count(EventModel.event_id))
        .filter(EventModel.tenant_id == auth.tenant_id)
        .scalar()
        or 0
    )
    recent_events_1h = (
        db.query(func.count(EventModel.event_id))
        .filter(
            EventModel.tenant_id == auth.tenant_id,
            EventModel.timestamp >= t_1h_ago.replace(tzinfo=None),
        )
        .scalar()
        or 0
    )

    return OverviewResponse(
        tenant_id=auth.tenant_id,
        timestamp=now.isoformat(),
        security_posture=FindingsPosture(
            total_findings=total_findings,
            open_findings=open_findings,
            by_severity=by_severity,
            by_status=by_status,
        ),
        investigations=InvestigationPosture(
            total_investigations=total_investigations,
            by_verdict=by_verdict,
            provider=settings.INVESTIGATOR_PROVIDER,
            model=settings.INVESTIGATOR_MODEL,
            provider_status="configured" if settings.INVESTIGATOR_API_KEY else "fallback",
            status="operational" if settings.INVESTIGATOR_API_KEY else "fallback",
        ),
        rules=RulesPosture(
            total_rules=total_rules,
            by_status=by_rule_status,
            active_count=by_rule_status.get("active", 0),
            pending_validation_count=by_rule_status.get("proposed", 0),
            pending_approval_count=by_rule_status.get("validated", 0),
        ),
        pipeline_health=PipelineHealth(
            database_status=db_status,
            database_latency_ms=db_latency_ms,
            database_version=db_version,
            total_events_ingested=total_events,
            recent_events_1h=recent_events_1h,
            fast_track_engine_status=(
                "degraded"
                if db_status != "connected"
                or ((settings.REDIS_REQUIRED or settings.WORKERS > 1 or settings.ENVIRONMENT.lower() in ("production", "staging"))
                    and redis_status != "connected")
                else "operational"
            ),
            fast_track_detection_latency="< 10ms (deterministic)",
            live_subscribers_connected=ops_bus.subscriber_count(auth.tenant_id),
            redis_status=redis_status,
            redis_latency_ms=redis_latency_ms,
        ),
        recent_findings=recent_findings,
    )


@router.post("/stream-ticket", response_model=StreamTicketResponse)
async def create_stream_ticket(auth: AuthContext = Depends(get_current_auth)):
    """
    Generates a secure, cryptographically random, short-lived (60s) single-use stream ticket.
    Enables the browser to connect to the SSE endpoint without exposing long-lived API keys
    in URL query parameters.
    """
    ticket = ops_bus.create_stream_ticket(
        tenant_id=auth.tenant_id,
        app_id=auth.app_id,
        key_id=auth.key_id,
        auth_type=auth.auth_type,
        operator_principal=auth.operator_principal,
    )
    return StreamTicketResponse(
        ticket=ticket,
        expires_in_seconds=60,
    )


@router.get("/events/recent", response_model=List[OpsEvent])
async def get_recent_events(
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Returns recent operational events buffered in memory for the authenticated tenant.
    Hydrates from persistent security records if memory buffer is cold (e.g. after container spin-up).
    """
    buffered = ops_bus.get_buffered_events(tenant_id=auth.tenant_id, limit=limit)
    if len(buffered) >= 5:
        return buffered

    audit_events = list(buffered)
    existing_ids = {e.event_id for e in audit_events}

    # 1. From DefenseAuditLogModel
    try:
        from backend.models import DefenseAuditLogModel
        def_logs = db.query(DefenseAuditLogModel).filter(
            DefenseAuditLogModel.tenant_id == auth.tenant_id
        ).order_by(DefenseAuditLogModel.timestamp.desc()).limit(20).all()
        for d in def_logs:
            if d.log_id not in existing_ids:
                audit_events.append(OpsEvent(
                    event_id=d.log_id,
                    timestamp=d.timestamp,
                    component="defense",
                    event_type=f"defense.{d.action_type}",
                    level="info",
                    message=f"Defense action '{d.action_id}': {d.reason or d.action_type}",
                    tenant_id=d.tenant_id,
                    metadata={"target_entity": d.target_entity, "executed_by": d.executed_by}
                ))
                existing_ids.add(d.log_id)
    except Exception:
        pass

    # 2. From InvestigationReport
    try:
        from backend.models import InvestigationReport
        invs = db.query(InvestigationReport).filter(
            InvestigationReport.tenant_id == auth.tenant_id
        ).order_by(InvestigationReport.created_at.desc()).limit(20).all()
        for inv in invs:
            eid = f"inv-audit-{inv.investigation_id[:12]}"
            if eid not in existing_ids:
                audit_events.append(OpsEvent(
                    event_id=eid,
                    timestamp=inv.created_at,
                    component="deep-investigator",
                    event_type="investigation.completed",
                    level="info" if inv.verdict != "confirmed_threat" else "warn",
                    message=f"Deep Track completed for finding {inv.finding_id}: verdict='{inv.verdict}' ({inv.investigator_model})",
                    tenant_id=inv.tenant_id,
                    metadata={"verdict": inv.verdict, "investigation_id": inv.investigation_id}
                ))
                existing_ids.add(eid)
    except Exception:
        pass

    # 3. From DeclarativeRuleModel
    try:
        from backend.models import DeclarativeRuleModel
        rules = db.query(DeclarativeRuleModel).filter(
            DeclarativeRuleModel.tenant_id == auth.tenant_id
        ).limit(10).all()
        for r in rules:
            eid = f"rule-audit-{r.rule_id[:12]}"
            if eid not in existing_ids:
                audit_events.append(OpsEvent(
                    event_id=eid,
                    timestamp=datetime.datetime.now(datetime.timezone.utc),
                    component="rules",
                    event_type="rule.registered",
                    level="info",
                    message=f"Declarative rule registered: '{r.title}' (status: {r.status}, detector: {r.target_detector})",
                    tenant_id=r.tenant_id,
                    metadata={"status": r.status, "target_detector": r.target_detector}
                ))
                existing_ids.add(eid)
    except Exception:
        pass

    audit_events.sort(key=lambda x: x.timestamp, reverse=True)
    return audit_events[:limit]


@router.get("/events/stream")
async def stream_operations_events(
    request: Request,
    max_events: Optional[int] = Query(default=None, description="Optional limit of events before cleanly closing stream"),
    auth: AuthContext = Depends(get_stream_auth),
):
    """
    Real-time Server-Sent Events (SSE) stream of internal engine operational events.
    - Tenant-isolated: only events belonging to the client's tenant are delivered.
    - Replays recent events from bounded memory buffer on connect.
    - Emits ': ping' keep-alive comments every 15 seconds.
    - Clean disconnection and queue cleanup on client exit.
    """
    tenant_id = auth.tenant_id

    async def event_generator():
        # Inform subscriber of connection
        yield f"event: connected\ndata: {json.dumps({'message': 'Connected to Ternline Live Operations Stream', 'tenant_id': tenant_id})}\n\n"
        emitted = 1
        if max_events is not None and emitted >= max_events:
            return

        async for item in ops_bus.subscribe(tenant_id=tenant_id, replay_limit=50):
            # Check client disconnection
            if await request.is_disconnected():
                break

            if item is None:
                # Keep-alive heartbeat ping
                yield ": ping\n\n"
            else:
                payload = item.model_dump(mode="json")
                yield f"event: ops_event\ndata: {json.dumps(payload)}\n\n"
                emitted += 1
                if max_events is not None and emitted >= max_events:
                    break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/metrics")
def get_ops_metrics(
    auth: AuthContext = Depends(require_permission(Permission.METRICS_READ)),
    db: Session = Depends(get_db),
):
    """Standard Prometheus metrics export endpoint for operations."""
    from backend.ops.metrics import metrics_registry
    from fastapi.responses import Response
    content = metrics_registry.export_prometheus(db, tenant_id=auth.tenant_id)
    return Response(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")
