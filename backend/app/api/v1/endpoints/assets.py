"""Assets endpoints — CRUD + graph topology."""

import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import Asset, Service, AssetType, Severity

router = APIRouter()


class ServiceOut(BaseModel):
    id: str
    port: int
    protocol: str
    name: Optional[str]
    product: Optional[str]
    version: Optional[str]
    state: str
    tls: bool
    model_config = {"from_attributes": True}


class AssetOut(BaseModel):
    id: str
    name: str
    asset_type: str
    value: str
    os: Optional[str]
    criticality: str
    tags: List[str]
    is_active: bool
    last_seen: Optional[datetime]
    services: List[ServiceOut] = []
    parent_id: Optional[str]
    model_config = {"from_attributes": True}


class AssetCreate(BaseModel):
    name: str
    asset_type: AssetType
    value: str
    description: Optional[str] = None
    os: Optional[str] = None
    criticality: Severity = Severity.MEDIUM
    tags: List[str] = []
    parent_id: Optional[str] = None


@router.get("", response_model=List[AssetOut])
async def list_assets(
    asset_type: Optional[AssetType] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Asset).order_by(desc(Asset.created_at)).limit(limit).offset(offset)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if search:
        stmt = stmt.where(
            Asset.value.ilike(f"%{search}%") | Asset.name.ilike(f"%{search}%")
        )
    result = await db.execute(stmt)
    assets = result.scalars().all()
    out = []
    for a in assets:
        svc_result = await db.execute(select(Service).where(Service.asset_id == a.id))
        svcs = svc_result.scalars().all()
        out.append(AssetOut(
            id=str(a.id), name=a.name, asset_type=a.asset_type.value, value=a.value,
            os=a.os, criticality=a.criticality.value, tags=a.tags or [],
            is_active=a.is_active, last_seen=a.last_seen,
            parent_id=str(a.parent_id) if a.parent_id else None,
            services=[ServiceOut(id=str(s.id), port=s.port, protocol=s.protocol,
                                  name=s.name, product=s.product, version=s.version,
                                  state=s.state, tls=s.tls) for s in svcs],
        ))
    return out


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(payload: AssetCreate, db: AsyncSession = Depends(get_db)):
    asset = Asset(
        id=uuid.uuid4(), name=payload.name, asset_type=payload.asset_type,
        value=payload.value, description=payload.description,
        os=payload.os, criticality=payload.criticality, tags=payload.tags,
        parent_id=uuid.UUID(payload.parent_id) if payload.parent_id else None,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return AssetOut(
        id=str(asset.id), name=asset.name, asset_type=asset.asset_type.value,
        value=asset.value, os=asset.os, criticality=asset.criticality.value,
        tags=asset.tags or [], is_active=asset.is_active, last_seen=asset.last_seen,
        parent_id=str(asset.parent_id) if asset.parent_id else None, services=[],
    )


@router.get("/graph")
async def get_asset_graph(db: AsyncSession = Depends(get_db)):
    """Return nodes + edges for the network topology graph."""
    result = await db.execute(select(Asset).where(Asset.is_active == True))
    assets = result.scalars().all()
    nodes = []
    edges = []
    for a in assets:
        svc_result = await db.execute(select(Service).where(Service.asset_id == a.id))
        svcs = svc_result.scalars().all()
        nodes.append({
            "id": str(a.id),
            "label": a.name or a.value,
            "type": a.asset_type.value,
            "ip": a.value,
            "os": a.os,
            "criticality": a.criticality.value,
            "services": [{"port": s.port, "name": s.name} for s in svcs],
        })
        if a.parent_id:
            edges.append({"source": str(a.parent_id), "target": str(a.id)})
    return {"nodes": nodes, "edges": edges}


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == uuid.UUID(asset_id)))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    svc_result = await db.execute(select(Service).where(Service.asset_id == asset.id))
    svcs = svc_result.scalars().all()
    return AssetOut(
        id=str(asset.id), name=asset.name, asset_type=asset.asset_type.value,
        value=asset.value, os=asset.os, criticality=asset.criticality.value,
        tags=asset.tags or [], is_active=asset.is_active, last_seen=asset.last_seen,
        parent_id=str(asset.parent_id) if asset.parent_id else None,
        services=[ServiceOut(id=str(s.id), port=s.port, protocol=s.protocol,
                              name=s.name, product=s.product, version=s.version,
                              state=s.state, tls=s.tls) for s in svcs],
    )
