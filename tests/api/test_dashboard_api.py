"""
Tests for the built-in SIEM Web Dashboard and FastAPI API endpoints.
"""

from fastapi.testclient import TestClient
from app.api.routes import app
from app.core.pipeline import default_pipeline


def test_dashboard_html_endpoints():
    """Verify that / and /dashboard return the SOC dashboard HTML page."""
    with TestClient(app) as client:
        for path in ["/", "/dashboard"]:
            response = client.get(path)
            assert response.status_code == 200
            assert "text/html" in response.headers["content-type"]
            assert "CYBER OPERATIONS & SIEM DASHBOARD" in response.text
            assert "Chart.js" in response.text


def test_dashboard_stats_endpoint():
    """Verify that /api/v1/dashboard/stats returns aggregated metrics."""
    with TestClient(app) as client:
        # Ingest a sample event first
        ingest_payload = {
            "raw_event": '{"src_ip": "10.0.0.99", "dst_ip": "192.168.1.1", "action": "deny", "severity": "high", "vendor": "DashboardTest"}',
            "format": "json"
        }
        ingest_res = client.post("/api/v1/events", json=ingest_payload)
        assert ingest_res.status_code == 200

        # Query stats
        stats_res = client.get("/api/v1/dashboard/stats")
        assert stats_res.status_code == 200
        stats = stats_res.json()
        assert "total_events" in stats
        assert stats["total_events"] >= 1
        assert "action_distribution" in stats
        assert "severity_distribution" in stats
        assert "top_sources" in stats
        assert "top_destinations" in stats
        assert "top_vendors" in stats
        assert "throughput_eps" in stats
        assert "average_latency_ms" in stats


def test_events_filtering():
    """Verify that /api/v1/events supports search queries, action, and severity filtering."""
    with TestClient(app) as client:
        # Query with specific query filter
        res = client.get("/api/v1/events?query=DashboardTest")
        assert res.status_code == 200
        events = res.json()
        assert isinstance(events, list)
        assert len(events) >= 1
        assert events[0]["device"]["vendor"] == "DashboardTest"

        # Query with action filter
        res_action = client.get("/api/v1/events?action=deny")
        assert res_action.status_code == 200
        events_action = res_action.json()
        assert all(e["event"]["action"].lower() == "deny" for e in events_action)


def test_lifespan_plugin_loading():
    """Verify that the FastAPI lifespan hook automatically loads dynamic plugins on startup."""
    with TestClient(app) as client:
        res = client.get("/api/v1/plugins")
        assert res.status_code == 200
        plugins = res.json().get("plugins", [])
        assert len(plugins) >= 1
        plugin_names = [p["name"] for p in plugins]
        assert "acme_guard_plugin" in plugin_names
