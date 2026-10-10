"""Start the gateway:  python run_gateway.py  (then open http://127.0.0.1:8000)."""
import os

import uvicorn

if __name__ == "__main__":
    host = os.environ.get("GATEWAY_HOST", "127.0.0.1")
    port = int(os.environ.get("GATEWAY_PORT", "8000"))
    os.environ.setdefault("GATEWAY_PUBLIC_URL", f"http://{host}:{port}")
    uvicorn.run("app.main:create_app", factory=True, host=host, port=port, log_level="info")
