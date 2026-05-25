import pytest
from browser_handoff_service.main import app
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_healthz_supports_kubernetes_probe_path():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        healthz = await client.get("/healthz")

    assert healthz.status_code == 200
    assert healthz.json()["ok"] is True
