"""Celery application configuration for SPAIDER workers."""

from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "spaider",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.workers.tasks.run_nmap_scan": {"queue": "red_queue"},
        "app.workers.tasks.run_nuclei_scan": {"queue": "red_queue"},
        "app.workers.tasks.run_scan": {"queue": "red_queue"},
        "app.workers.tasks.analyze_malware": {"queue": "blue_queue"},
        "app.workers.tasks.analyze_pcap": {"queue": "blue_queue"},
        "app.workers.tasks.purple_validate": {"queue": "blue_queue"},
        "app.workers.tasks.discover_topology": {"queue": "red_queue"},
    },
    beat_schedule={
        "threat-intel-refresh": {
            "task": "app.workers.tasks.refresh_threat_intel",
            "schedule": 3600.0,  # every hour
        },
    },
)
