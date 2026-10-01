"""Network discovery endpoints — trigger Nmap scans, ARP discovery."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.workers.celery_app import celery_app

router = APIRouter()


class NetworkScanRequest(BaseModel):
    targets: List[str]         # ["192.168.1.0/24", "10.0.0.1"]
    scan_type: str = "full"    # quick | full | stealth | udp | os | version
    ports: Optional[str] = None
    timing: int = 3            # Nmap -T flag (0-5)


@router.post("/discover")
async def discover_network(payload: NetworkScanRequest):
    """Launch an Nmap-based network discovery scan."""
    task = celery_app.send_task(
        "app.workers.tasks.run_nmap_scan",
        args=[payload.targets, payload.scan_type, payload.ports, payload.timing],
        queue="red_queue",
    )
    return {"task_id": task.id, "status": "queued", "targets": payload.targets}


@router.post("/topology")
async def discover_topology(targets: List[str]):
    """Build network topology via traceroute + ARP."""
    task = celery_app.send_task(
        "app.workers.tasks.discover_topology",
        args=[targets],
        queue="red_queue",
    )
    return {"task_id": task.id, "status": "queued"}


@router.post("/pcap/upload")
async def upload_pcap(filename: str):
    """Queue a PCAP file for Zeek/Suricata analysis."""
    task = celery_app.send_task(
        "app.workers.tasks.analyze_pcap",
        args=[filename],
        queue="blue_queue",
    )
    return {"task_id": task.id, "status": "queued"}
