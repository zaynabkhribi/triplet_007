"""Pydantic models for typed responses and internal objects.

Inbound readings are validated against shared/schema/reading.json (the contract),
then parsed into `Reading` for internal use. Response models keep the OpenAPI /
describe surface stable.
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class Result(BaseModel):
    value: float
    unit: str


class Provenance(BaseModel):
    firmware: str
    cal: str
    seq: Optional[int] = None


class Reading(BaseModel):
    batch_id: str
    sensor_id: str
    zone: str
    observed_property: str
    phenomenon_time: str
    result: Result
    digest: str
    signature: str
    provenance: Provenance
    reading_id: Optional[str] = None
    received_at: Optional[str] = None


class ReadingAck(BaseModel):
    accepted: bool
    code: str
    message: str
    reading_id: str
    batch_id: str
    event_id: Optional[int] = None


class DescribeEndpoints(BaseModel):
    readings: str
    passport: str
    verdict: str
    witness: str
    healthz: str


class DescribeResponse(BaseModel):
    layer: str = "guardian"
    version: str
    protocol: str
    optional_faces: List[str] = Field(default_factory=list)
    endpoints: DescribeEndpoints
    auth: str
    accepts_sensor_types: List[str]
    emits_dispositions: List[str]
    max_latency_s: float
    policy_version: str


class HealthResponse(BaseModel):
    status: str
    layer: str
    version: str
    policy_version: str
    uptime_s: float


class VerdictTailResponse(BaseModel):
    count: int
    events: List[dict]


class GenericAck(BaseModel):
    accepted: bool
    code: str
    message: Optional[str] = None
    event_id: Optional[int] = None
