"""Application configuration using Pydantic Settings for type-safe configuration management."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogConfig(BaseSettings):
    """Logging configuration."""
    model_config = SettingsConfigDict(env_prefix="LOG_", case_sensitive=False)
    
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: str = "json"  # json or console
    file_path: Path = Path("logs/app.log")
    max_bytes: int = 10_485_760  # 10MB
    backup_count: int = 5


class LogAnalyzerConfig(BaseSettings):
    """Log analyzer configuration."""
    model_config = SettingsConfigDict(env_prefix="ANALYZER_", case_sensitive=False)
    
    log_file_path: Path = Path("sample.log")
    failed_login_pattern: str = r"\[(\d+\.\d+\.\d+\.\d+)\] FAILED LOGIN"
    threat_thresholds: dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 5,
            "high": 3,
            "medium": 1,
        }
    )
    severity_labels: dict[str, str] = Field(
        default_factory=lambda: {
            "critical": "Critical",
            "high": "High", 
            "medium": "Medium",
            "low": "Low",
        }
    )


class FlaskConfig(BaseSettings):
    """Flask application configuration."""
    model_config = SettingsConfigDict(env_prefix="FLASK_", case_sensitive=False)
    
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    secret_key: str = Field(default="dev-secret-change-in-production", min_length=32)
    json_sort_keys: bool = False
    jsonify_prettyprint_regular: bool = False


class PrometheusConfig(BaseSettings):
    """Prometheus metrics configuration."""
    model_config = SettingsConfigDict(env_prefix="PROMETHEUS_", case_sensitive=False)
    
    enabled: bool = True
    port: int = 9090
    path: str = "/metrics"


class Settings(BaseSettings):
    """Main application settings."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    app_name: str = "SIEM Log Analyzer"
    environment: Literal["development", "staging", "production"] = "development"
    
    log: LogConfig = LogConfig()
    analyzer: LogAnalyzerConfig = LogAnalyzerConfig()
    flask: FlaskConfig = FlaskConfig()
    prometheus: PrometheusConfig = PrometheusConfig()


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# For backward compatibility and easy imports
settings = get_settings()
log_config = settings.log
analyzer_config = settings.analyzer
flask_config = settings.flask
prometheus_config = settings.prometheus