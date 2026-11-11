"""
ZDay Scanner - Configuration Management
"""
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path

# Optional YAML support
try:
    import yaml
    HAS_YAML = True
except ImportError:
    yaml = None
    HAS_YAML = False

# Optional .env support
try:
    from dotenv import load_dotenv
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False
    def load_dotenv(path: str = None, override: bool = False):
        pass


@dataclass
class ScannerConfig:
    """Scanner configuration with YAML, ENV, and CLI precedence"""

    # Network
    timeout: int = 30
    rate_limit: float = 10.0
    max_concurrent: int = 10
    verify_ssl: bool = True
    follow_redirects: bool = True
    proxy: Optional[str] = None

    # Crawling
    max_pages: int = 100
    crawl_depth: int = 2
    respect_robots_txt: bool = True

    # Fingerprinting
    enable_headless_fingerprinting: bool = True
    enable_version_detection: bool = True
    enable_cve_matching: bool = True

    # Detection modules
    enable_injection_tests: bool = True
    enable_deserialization_tests: bool = True
    enable_auth_bypass_tests: bool = True
    enable_logic_tests: bool = True
    enable_race_condition_tests: bool = True
    enable_crypto_tests: bool = True
    enable_intrusive_tests: bool = False

    # Reporting
    output_formats: List[str] = field(default_factory=lambda: ["html", "json"])
    min_severity: str = "info"
    include_evidence: bool = True

    # Custom
    custom_headers: Dict[str, str] = field(default_factory=dict)
    custom_cookies: Dict[str, str] = field(default_factory=dict)
    auth_headers: Dict[str, str] = field(default_factory=dict)

    # Browser / Playwright
    headless: bool = True
    browser_timeout: int = 30
    browser_wait_until: str = "networkidle"
    enable_stealth: bool = True
    browser_executable_path: Optional[str] = "auto"  # "auto", "/path/to/chrome", "", None
    browser_channel: str = ""                      # "chrome", "msedge", "chromium", "brave"
    browser_args: List[str] = field(default_factory=list)
    cdp_endpoint: str = ""                          # CDP endpoint for existing browser

    # Advanced
    user_agent: str = "ZDay Scanner/1.0"
    debug: bool = False

    @classmethod
    def from_yaml(cls, path: str) -> "ScannerConfig":
        """Load configuration from YAML file"""
        if not HAS_YAML:
            raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")

        with open(path, 'r') as f:
            data = yaml.safe_load(f)

        return cls(**data) if data else cls()

    @classmethod
    def from_env(cls, env_file: str = None) -> "ScannerConfig":
        """Load configuration from environment variables and .env file"""
        # Load .env file if available
        if env_file and HAS_DOTENV:
            load_dotenv(env_file, override=True)
        elif HAS_DOTENV:
            # Try default locations
            for path in [
                Path.cwd() / ".env",
                Path.cwd() / ".env.local",
                Path(__file__).parent.parent.parent / ".env",
            ]:
                if path.exists():
                    load_dotenv(path, override=True)
                    break

        config = cls()

        # Map env vars to config fields
        env_map = {
            "ZDAY_TIMEOUT": ("timeout", int),
            "ZDAY_RATE_LIMIT": ("rate_limit", float),
            "ZDAY_MAX_CONCURRENT": ("max_concurrent", int),
            "ZDAY_VERIFY_SSL": ("verify_ssl", lambda x: x.lower() == "true"),
            "ZDAY_FOLLOW_REDIRECTS": ("follow_redirects", lambda x: x.lower() == "true"),
            "ZDAY_PROXY": ("proxy", str),
            "ZDAY_MAX_PAGES": ("max_pages", int),
            "ZDAY_CRAWL_DEPTH": ("crawl_depth", int),
            "ZDAY_RESPECT_ROBOTS": ("respect_robots_txt", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_HEADLESS": ("enable_headless_fingerprinting", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_VERSION_DETECTION": ("enable_version_detection", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_CVE_MATCHING": ("enable_cve_matching", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_INJECTION": ("enable_injection_tests", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_DESERIALIZATION": ("enable_deserialization_tests", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_AUTH_BYPASS": ("enable_auth_bypass_tests", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_LOGIC": ("enable_logic_tests", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_RACE": ("enable_race_condition_tests", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_CRYPTO": ("enable_crypto_tests", lambda x: x.lower() == "true"),
            "ZDAY_ENABLE_INTRUSIVE": ("enable_intrusive_tests", lambda x: x.lower() == "true"),
            "ZDAY_MIN_SEVERITY": ("min_severity", str),
            "ZDAY_USER_AGENT": ("user_agent", str),
            "ZDAY_DEBUG": ("debug", lambda x: x.lower() == "true"),
        }

        # Browser / Playwright env vars
        browser_env_map = {
            "ZDAY_HEADLESS": ("headless", lambda x: x.lower() == "true"),
            "ZDAY_BROWSER_TIMEOUT": ("browser_timeout", int),
            "ZDAY_BROWSER_WAIT_UNTIL": ("browser_wait_until", str),
            "ZDAY_ENABLE_STEALTH": ("enable_stealth", lambda x: x.lower() == "true"),
            "ZDAY_BROWSER_EXECUTABLE_PATH": ("browser_executable_path", str),
            "ZDAY_BROWSER_CHANNEL": ("browser_channel", str),
            "ZDAY_BROWSER_ARGS": ("browser_args", lambda x: x.split(",") if x else []),
            "ZDAY_CDP_ENDPOINT": ("cdp_endpoint", str),
        }

        for env_var, (attr, converter) in env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    setattr(config, attr, converter(value))
                except Exception:
                    pass

        for env_var, (attr, converter) in browser_env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    setattr(config, attr, converter(value))
                except Exception:
                    pass

        return config

    def merge(self, other: "ScannerConfig") -> "ScannerConfig":
        """Merge another config into this one (other takes precedence)"""
        for field_name in self.__dataclass_fields__:
            other_value = getattr(other, field_name)
            default_value = self.__dataclass_fields__[field_name].default
            if other_value != default_value:
                setattr(self, field_name, other_value)
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {f.name: getattr(self, f.name) for f in self.__dataclass_fields__.values()}

    def save_yaml(self, path: str):
        """Save configuration to YAML file"""
        if not HAS_YAML:
            raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")

        with open(path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
