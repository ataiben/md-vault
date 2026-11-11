from __future__ import annotations

import uuid
from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


def generate_entry_id() -> str:
    """Generate a short, readable, unique account entry ID."""
    return f"acc_{uuid.uuid4().hex[:8]}"


def now_timestamp() -> str:
    """Return formatted local timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M")


class SecurityQA(BaseModel):
    question: str = ""
    answer: str = ""


class AccountEntry(BaseModel):
    id: str = Field(default_factory=generate_entry_id)
    category: str = "未分类"
    title: str
    platform: str = ""
    tags: List[str] = Field(default_factory=list)
    favorite: bool = False
    username: str = ""
    password: str = ""
    phone: str = ""
    recovery_email: str = ""
    url: str = ""
    security_questions: List[SecurityQA] = Field(default_factory=list)
    two_fa_recovery: str = ""
    notes: str = ""
    custom_fields: Dict[str, str] = Field(default_factory=dict)
    updated_at: str = Field(default_factory=now_timestamp)


class VaultHeader(BaseModel):
    vault_version: int = 1
    vault_name: str = "我的账号密码库"
    kdf: str = "pbkdf2-sha256"
    kdf_iterations: int = 600000
    salt: str = ""
    verifier: str = ""
    saved_tags: Optional[Dict[str, List[str]]] = None
    updated_at: str = Field(default_factory=now_timestamp)


class VaultDocument(BaseModel):
    header: VaultHeader = Field(default_factory=VaultHeader)
    categories: List[str] = Field(default_factory=list)
    entries: List[AccountEntry] = Field(default_factory=list)
