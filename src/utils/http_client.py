"""
ZDay Scanner - HTTP Client with Rate Limiting
Uses requests library with asyncio thread pool for async operations
"""
import asyncio
import random
import time
import ssl
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Callable, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup


@dataclass
class HTTPResponse:
    """HTTP Response wrapper"""
    status: int
    text: str
    content: bytes
    headers: Dict[str, str]
    cookies: Dict[str, str]
    url: str
    duration: float


class HTTPClient:
    """Async HTTP client with rate limiting, retries, and connection pooling"""

    def __init__(
        self,
        timeout: int = 30,
        rate_limit: float = 10.0,
        max_concurrent: int = 10,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        proxy: Optional[str] = None,
        user_agent: str = "ZDay Scanner/1.0",
    ):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.max_concurrent = max_concurrent
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.user_agent = user_agent

        # Rate limiting
        self._last_request_time = 0.0
        self._min_interval = 1.0 / rate_limit if rate_limit > 0 else 0

        # Connection pool via requests session
        self._session = self._create_session()

        # Thread pool for async operations
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent)

        # Semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(max_concurrent)

        # Crawler state
        self._visited: Set[str] = set()
        self._to_visit: List[str] = []

    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()

        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.max_concurrent,
            pool_maxsize=self.max_concurrent,
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Default headers
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}

        return session

    async def _rate_limit(self):
        """Apply rate limiting"""
        if self._min_interval <= 0:
            return

        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)

    def _request_sync(self, method: str, url: str, **kwargs) -> HTTPResponse:
        """Synchronous request (runs in thread pool)"""
        start = time.time()

        # Apply defaults
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        kwargs.setdefault("allow_redirects", self.follow_redirects)

        resp = self._session.request(method, url, **kwargs)

        duration = time.time() - start

        return HTTPResponse(
            status=resp.status_code,
            text=resp.text,
            content=resp.content,
            headers=dict(resp.headers),
            cookies=dict(resp.cookies),
            url=resp.url,
            duration=duration,
        )

    async def request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        """Async request with rate limiting and concurrency control"""
        await self._rate_limit()

        async with self._semaphore:
            self._last_request_time = time.time()

            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self._executor,
                lambda: self._request_sync(method, url, **kwargs)
            )

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("HEAD", url, **kwargs)

    async def get_with_browser_headers(self, url: str, **kwargs) -> HTTPResponse:
        """GET with browser-like headers"""
        headers = kwargs.pop("headers", {})
        headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        })
        return await self.get(url, headers=headers, **kwargs)

    async def close(self):
        """Close connections"""
        self._session.close()
        self._executor.shutdown(wait=True)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


# Alias for backward compatibility
AsyncHTTPClient = HTTPClient

class Crawler:
    """Simple web crawler for discovering pages"""

    def __init__(self, http_client: HTTPClient, max_pages: int = 100, max_depth: int = 2):
        self.http_client = http_client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited: Set[str] = set()
        self.urls: List[Dict[str, Any]] = []

    async def crawl(self, start_url: str) -> List[Dict[str, Any]]:
        """Crawl website starting from URL"""
        self.visited.clear()
        self.urls.clear()

        queue = [(start_url, 0)]

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.pop(0)

            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)

            try:
                resp = await self.http_client.get_with_browser_headers(url)

                self.urls.append({
                    "url": url,
                    "depth": depth,
                    "status": resp.status,
                    "title": self._extract_title(resp.text),
                    "links": [],
                })

                # Extract links
                if depth < self.max_depth:
                    links = self._extract_links(resp.text, url)
                    for link in links:
                        if link not in self.visited:
                            queue.append((link, depth + 1))

            except Exception as e:
                self.urls.append({
                    "url": url,
                    "depth": depth,
                    "status": 0,
                    "error": str(e),
                    "links": [],
                })

        return self.urls

    def _extract_title(self, html: str) -> str:
        try:
            soup = BeautifulSoup(html, "html.parser")
            title = soup.find("title")
            return title.get_text().strip() if title else ""
        except Exception:
            return ""

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_domain = urlparse(base_url).netloc

            for a in soup.find_all("a", href=True):
                href = a["href"]
                absolute = urljoin(base_url, href)
                parsed = urlparse(absolute)

                # Only same domain
                if parsed.netloc == base_domain:
                    # Remove fragment
                    clean = parsed._replace(fragment="").geturl()
                    links.append(clean)
        except Exception:
            pass
        return links
