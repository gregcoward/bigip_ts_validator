#!/usr/bin/env python3
"""Run the FastAPI server (API + optional built React UI from frontend/dist)."""

import uvicorn

if __name__ == "__main__":
    print("Starting API on http://0.0.0.0:8000  (try http://127.0.0.1:8000/ locally)")
    print("If the UI shows 'not built', run: cd frontend && npm install && npm run build")
    print("Dev UI with hot reload: cd frontend && npm run dev  →  http://127.0.0.1:5173/")
    print(
        "Behind nginx (or similar): set a long read timeout for /api (e.g. proxy_read_timeout 900s;) — "
        "remediate can run many minutes while RPMs install / AS3 / TS post."
    )
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["server", "bigip_ts_validator.py", "as3_services.py", "ts_declaration_builder.py"],
    )
