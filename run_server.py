#!/usr/bin/env python3
"""Run the FastAPI server (API + optional built React UI from frontend/dist)."""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["server", "bigip_ts_validator.py", "as3_services.py", "ts_declaration_builder.py"],
    )
