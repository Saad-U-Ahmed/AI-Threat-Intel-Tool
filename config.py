"""
Centralized application configuration.

All values are sourced from environment variables (or a local .env file).
Nothing here is a secret default worth relying on in production -- always
set OPENAI_API_KEY and TI_API_KEY via your environment / secrets manager.
"""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- OpenAI / LangChain ---
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_temperature: float = 0.1

    # --- App ---
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "INFO"

    # --- Simple shared-secret auth for the API ---
    ti_api_key: str = "change-me"

    # --- MITRE ATT&CK ---
    attack_stix_url: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    )
    attack_cache_path: str = "./data/enterprise-attack.json"
    attack_cache_max_age_days: int = 7

    # --- OSINT gathering ---
    request_timeout_seconds: int = 15
    max_articles_per_run: int = 8

    @property
    def attack_cache_file(self) -> Path:
        """Returns the cache file path, ensuring the parent folder exists."""
        p = Path(self.attack_cache_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
