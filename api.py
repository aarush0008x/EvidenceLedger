from fastapi import FastAPI, UploadFile, File, HTTPException
import hashlib
import sqlite3
import secrets
import os
from datetime import datetime, timezone


app = FastAPI(
    title="EvidenceLedger API",
    description="Digital Evidence Integrity & Verification API",
    version="1.0.0"
)


# =========================================================
# CONFIGURATION
# =========================================================

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "evidence.db"
)

BASE_URL = os.getenv(
    "BASE_URL",
    "http://127.0.0.1:8000"
)


# =========================================================
# DATABASE
# =========================================================

def init_database():
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_database()


# =========================================================
# SHA-256
# =========================================================

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():
    return {
        "project": "EvidenceLedger",
        "status": "online",
        "endpoints": {
            "hash": "POST /hash",
            "verify": "POST /verify/{evidence_id}",
            "get_evidence": "GET /evidence/{evidence_id}",
            "docs": "/docs"
        }
    }


# =========================================================
# HASH + REGISTER EVIDENCE
# =========================================================

@app.post("/hash")
async def hash_file(file: UploadFile = File(...)):

    file_bytes = await file.read()

    if not file_bytes:
        raise HTTPException(
            status_code=400,
            detail="Empty file"
        )

    sha256_hash = calculate_sha256(file_bytes)

    # Generate unique evidence ID
    evidence_id = "EV-" + secrets.token_hex(4).upper()

    created_at = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DATABASE)

    conn.execute(
        """
        INSERT INTO evidence
        (id, filename, sha256, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            evidence_id,
            file.filename or "unknown",
            sha256_hash,
            created_at
        )
    )

    conn.commit()
    conn.close()

    verification_url = f"{BASE_URL}/verify/{evidence_id}"

    return {
        "success": True,
        "evidence_id": evidence_id,
        "filename": file.filename,
        "algorithm": "SHA-256",
        "hash": sha256_hash,
        "created_at": created_at,
        "verification_url": verification_url,
        "message": "Evidence registered successfully"
    }


# =========================================================
# VERIFY EVIDENCE
# =========================================================

@app.post("/verify/{evidence_id}")
async def verify_file(
    evidence_id: str,
    file: UploadFile = File(...)
):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.execute(
        """
        SELECT filename, sha256, created_at
        FROM evidence
        WHERE id = ?
        """,
        (evidence_id,)
    )

    record = cursor.fetchone()

    conn.close()

    if not record:
        raise HTTPException(
            status_code=404,
            detail="Evidence ID not found"
        )

    original_filename, stored_hash, created_at = record

    file_bytes = await file.read()

    if not file_bytes:
        raise HTTPException(
            status_code=400,
            detail="Empty file"
        )

    actual_hash = calculate_sha256(file_bytes)

    verified = (
        actual_hash.lower() ==
        stored_hash.lower()
    )

    return {
        "success": True,
        "evidence_id": evidence_id,
        "original_filename": original_filename,
        "uploaded_filename": file.filename,
        "algorithm": "SHA-256",
        "stored_hash": stored_hash,
        "actual_hash": actual_hash,
        "verified": verified,
        "status": "VERIFIED" if verified else "TAMPERED",
        "message": (
            "Evidence is authentic. Hash matches."
            if verified
            else "Evidence may have been modified. Hash does not match."
        ),
        "registered_at": created_at
    }


# =========================================================
# GET EVIDENCE INFORMATION
# =========================================================

@app.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.execute(
        """
        SELECT id, filename, sha256, created_at
        FROM evidence
        WHERE id = ?
        """,
        (evidence_id,)
    )

    record = cursor.fetchone()

    conn.close()

    if not record:
        raise HTTPException(
            status_code=404,
            detail="Evidence ID not found"
        )

    return {
        "evidence_id": record[0],
        "filename": record[1],
        "algorithm": "SHA-256",
        "hash": record[2],
        "registered_at": record[3],
        "verification_url": f"{BASE_URL}/verify/{record[0]}"
    }
