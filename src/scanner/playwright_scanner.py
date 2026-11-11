"""
ZDay Scanner - Main Playwright-based Scanner Module
Uses Playwright to fetch pages and extract technology fingerprints from:
- HTTP Response Headers
- HTML Content (meta tags, scripts, comments, patterns)
- JavaScript (global variables, frameworks, libraries)
- Cookies
- TLS/SSL Certificate info
"""
import asyncio
import re
import ssl
import json
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from pathlib import Path

# Optional imports
try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Response
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    # Type stubs for when Playwright is not available
    Browser = object
    BrowserContext = object
    Page = object
    Response = object

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

from src.core.config import ScannerConfig
from src.core.models import (
    Target, Technology, Fingerprint, ScanResult, Severity
)
from src.technologies.fingerprint_db import FingerprintDB
from src.technologies.version_detector import VersionDetector
from src.technologies.cve_matcher import CVEMatcher
from src.fingerprinting.aggregator import FingerprintAggregator
from src.fingerprinting.http_fingerprinter import HTTPFingerprinter
from src.fingerprinting.headless_browser import HeadlessBrowserFingerprinter
from src.utils.http_client import AsyncHTTPClient


@dataclass
class PageData:
    """Collected data from a single page"""
    url: str
    status_code: int
    headers: Dict[str, str]
    html: str
    cookies: List[Dict[str, Any]]
    scripts: List[Dict[str, Any]]  # {src, content, inline}
    meta_tags: Dict[str, str]
    links: List[str]
    forms: List[Dict[str, Any]]
    technologies: List[Technology] = field(default_factory=list)
    tls_info: Optional[Dict[str, Any]] = None
    response_chain: List[Dict[str, Any]] = field(default_factory=list)


class PlaywrightScanner:
    """
    Main scanner using Playwright for dynamic fingerprinting.
    Combines HTTP-based and browser-based detection.
    """
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.fp_db = FingerprintDB()
        self.version_detector = VersionDetector()
        self.cve_matcher = CVEMatcher()
        self.aggregator = FingerprintAggregator()
        self.http_fingerprinter = HTTPFingerprinter(config)
        self.headless_fingerprinter = HeadlessBrowserFingerprinter(config)
        self.http_client = AsyncHTTPClient(config)
        
        # State
        self._playwright = None
        self._browser = None
        self._context = None
        self.visited_urls: Set[str] = set()
        self.page_data: List[PageData] = []
        self.all_technologies: List[Technology] = []
        
        # Compile regex patterns for performance
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for technology detection"""
        self.patterns = {
            'generator': re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE),
            'csrf_token': re.compile(r'<meta\s+name=["\']csrf[-_]?token["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE),
            'viewport': re.compile(r'<meta\s+name=["\']viewport["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE),
            'theme_color': re.compile(r'<meta\s+name=["\']theme-color["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE),
            'script_src': re.compile(r'<script\s+src=["\']([^"\']+)["\']', re.IGNORECASE),
            'script_inline': re.compile(r'<script[^>]*>([\s\S]*?)</script>', re.IGNORECASE),
            'link_href': re.compile(r'<link\s+[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE),
            'form_action': re.compile(r'<form\s+[^>]*action=["\']([^"\']*)["\']', re.IGNORECASE),
            'input_name': re.compile(r'<input\s+[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE),
            'wp_json': re.compile(r'wp-json|wp\.com|wordpress', re.IGNORECASE),
            'drupal': re.compile(r'Drupal|drupal', re.IGNORECASE),
            'joomla': re.compile(r'Joomla|joomla', re.IGNORECASE),
            'react': re.compile(r'react|_reactRootContainer|__REACT_DEVTOOLS_GLOBAL_HOOK__', re.IGNORECASE),
            'vue': re.compile(r'vue\.js|__VUE__|Vue\.version', re.IGNORECASE),
            'angular': re.compile(r'angular|ng-version|getAngularTestability', re.IGNORECASE),
            'jquery': re.compile(r'jquery|jQuery', re.IGNORECASE),
            'bootstrap': re.compile(r'bootstrap', re.IGNORECASE),
            'analytics': re.compile(r'google-analytics|gtag|ga\(|_gaq|Matomo|matomo', re.IGNORECASE),
            'recaptcha': re.compile(r'recaptcha|grecaptcha', re.IGNORECASE),
            'cloudflare': re.compile(r'cloudflare|__cfduid|cf-ray', re.IGNORECASE),
            'akamai': re.compile(r'akamai|akamaized', re.IGNORECASE),
        }
    
    async def __aenter__(self):
        await self.http_client.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_client.__aexit__(exc_type, exc_val, exc_tb)
        await self._cleanup_browser()
    
    async def _cleanup_browser(self):
        """Clean up browser resources"""
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._context = None
        self._browser = None
        self._playwright = None
    
    async def _init_browser(self):
        """Initialize Playwright browser"""
        if not HAS_PLAYWRIGHT:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install chromium")
        
        if self._browser:
            return
        
        self._playwright = await async_playwright().start()
        self._browser = await self.headless_fingerprinter._launch_browser(self._playwright)
        self._context = await self._browser.new_context(
            user_agent=self.config.user_agent,
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=not self.config.verify_ssl,
        )
        
        if self.config.enable_stealth:
            await self.headless_fingerprinter._inject_stealth(self._context)
    
    async def scan(self, target: Target) -> ScanResult:
        """
        Main scan entry point.
        Performs comprehensive fingerprinting using both HTTP and Playwright.
        """
        import time
        start_time = time.time()
        
        try:
            # Phase 1: HTTP-based fingerprinting (fast, no browser)
            http_techs = await self._http_scan(target)
            
            # Phase 2: Playwright-based fingerprinting (deep, dynamic)
            if self.config.enable_headless_fingerprinting and HAS_PLAYWRIGHT:
                await self._init_browser()
                browser_techs = await self._playwright_scan(target)
                
                # Phase 3: Crawl additional pages if configured
                if self.config.crawl_depth > 0 and self.config.max_pages > 1:
                    await self._crawl(target)
                    # Fingerprint crawled pages
                    for page_data in self.page_data[1:]:  # Skip first (already done)
                        page_techs = await self._analyze_page_data(page_data)
                        self.all_technologies.extend(page_techs)
                
                all_techs = http_techs + browser_techs
            else:
                all_techs = http_techs
            
            # Deduplicate and aggregate
            unique_techs = self.aggregator.aggregate(all_techs)
            
            # Phase 4: Version detection
            if self.config.enable_version_detection:
                for tech in unique_techs:
                    version = self.version_detector.detect_version(tech, self.page_data)
                    if version:
                        tech.version = version
            
            # Phase 5: CVE matching
            if self.config.enable_cve_matching:
                for tech in unique_techs:
                    cves = self.cve_matcher.match(tech)
                    tech.cves = cves
            
            # Create fingerprints
            fingerprints = []
            for tech in unique_techs:
                fp = Fingerprint(
                    technology=tech,
                    matches=list(tech.evidence),
                    confidence=tech.confidence,
                    source="combined",
                    metadata={"pages_scanned": len(self.page_data)}
                )
                fingerprints.append(fp)
            
            # Build result
            from datetime import datetime
            result = ScanResult(
                target=target,
                started_at=datetime.now(),
                fingerprints=fingerprints,
                technologies=unique_techs,
                duration=time.time() - start_time,
                pages_scanned=len(self.page_data),
                errors=[]
            )
            
            return result
            
        except Exception as e:
            from datetime import datetime
            return ScanResult(
                target=target,
                started_at=datetime.now(),
                fingerprints=[],
                technologies=[],
                duration=time.time() - start_time,
                pages_scanned=len(self.page_data),
                errors=[str(e)]
            )
        finally:
            await self._cleanup_browser()
    
    async def _http_scan(self, target: Target) -> List[Technology]:
        """Fast HTTP-based fingerprinting without browser"""
        technologies = []
        
        try:
            # Fetch main page
            response = await self.http_client.get(str(target.url))
            if not response:
                return technologies
            
            # Analyze HTTP response
            http_techs = await self.http_fingerprinter.fingerprint(target, self.http_client)
            technologies.extend(http_techs)
            
            # Parse HTML for additional signals
            page_data = self._parse_http_response(str(target.url), response)
            self.page_data.append(page_data)
            
            # Extract technologies from parsed data
            html_techs = self._extract_technologies_from_html(page_data)
            technologies.extend(html_techs)
            
            # Analyze cookies
            cookie_techs = self._analyze_cookies(page_data.cookies)
            technologies.extend(cookie_techs)
            
            # Analyze headers
            header_techs = self._analyze_headers(page_data.headers)
            technologies.extend(header_techs)
            
        except Exception:
            pass
        
        return technologies
    
    def _parse_http_response(self, url: str, response) -> PageData:
        """Parse aiohttp response into PageData"""
        html = response.text if hasattr(response, 'text') else ""
        headers = dict(response.headers) if hasattr(response, 'headers') else {}
        status = response.status if hasattr(response, 'status') else 200
        
        # Extract cookies
        cookies = []
        if hasattr(response, 'cookies'):
            for name, cookie in response.cookies.items():
                cookies.append({
                    'name': name,
                    'value': cookie.value,
                    'domain': cookie.get('domain', ''),
                    'path': cookie.get('path', '/'),
                    'secure': cookie.get('secure', False),
                    'httponly': cookie.get('httponly', False),
                    'samesite': cookie.get('samesite', ''),
                })
        
        # Parse HTML
        scripts = self._extract_scripts(html)
        meta_tags = self._extract_meta_tags(html)
        links = self._extract_links(html, url)
        forms = self._extract_forms(html)
        
        return PageData(
            url=url,
            status_code=status,
            headers=headers,
            html=html,
            cookies=cookies,
            scripts=scripts,
            meta_tags=meta_tags,
            links=links,
            forms=forms,
        )
    
    async def _playwright_scan(self, target: Target) -> List[Technology]:
        """Deep browser-based fingerprinting using Playwright"""
        technologies = []
        
        try:
            page = await self._context.new_page()
            
            # Set up response listener for headers
            responses = []
            
            async def handle_response(response: Response):
                responses.append({
                    'url': response.url,
                    'status': response.status,
                    'headers': dict(response.headers),
                })
            
            page.on("response", handle_response)
            
            # Navigate
            await page.goto(
                str(target.url),
                wait_until=self.config.browser_wait_until,
                timeout=self.config.browser_timeout * 1000
            )
            
            # Get page content
            html = await page.content()
            url = page.url
            
            # Extract data
            page_data = await self._extract_page_data(page, url, responses)
            self.page_data.append(page_data)
            
            # Run headless fingerprinter
            headless_techs = await self.headless_fingerprinter.fingerprint(target, self.http_client)
            technologies.extend(headless_techs)
            
            # Analyze page data
            html_techs = self._extract_technologies_from_html(page_data)
            technologies.extend(html_techs)
            
            await page.close()
            
        except Exception:
            pass
        
        return technologies
    
    async def _extract_page_data(self, page: Page, url: str, responses: List) -> PageData:
        """Extract comprehensive data from Playwright page"""
        
        # Get HTML
        html = await page.content()
        
        # Get cookies
        cookies = await self._context.cookies()
        
        # Execute JS to get more data
        js_data = await page.evaluate("""() => {
            return {
                // Global variables that indicate frameworks
                globals: Object.keys(window).filter(k => 
                    k.includes('React') || k.includes('Vue') || k.includes('angular') ||
                    k.includes('jQuery') || k.includes('webpack') || k.includes('require') ||
                    k.includes('define') || k.includes('module') || k.includes('exports')
                ),
                // Meta tags
                meta: Array.from(document.querySelectorAll('meta')).map(m => ({
                    name: m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv'),
                    content: m.getAttribute('content')
                })).filter(m => m.name && m.content),
                // Scripts
                scripts: Array.from(document.querySelectorAll('script')).map(s => ({
                    src: s.src,
                    type: s.type,
                    async: s.async,
                    defer: s.defer,
                    inline: s.textContent?.substring(0, 500) || ''
                })),
                // Links
                links: Array.from(document.querySelectorAll('link')).map(l => ({
                    rel: l.rel,
                    href: l.href,
                    type: l.type
                })),
                // Forms
                forms: Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.querySelectorAll('input')).map(i => ({
                        name: i.name,
                        type: i.type,
                        value: i.value
                    }))
                })),
                // Cookies from document.cookie
                documentCookie: document.cookie,
                // LocalStorage keys (sample)
                localStorageKeys: Object.keys(localStorage).slice(0, 20),
                // SessionStorage keys (sample)
                sessionStorageKeys: Object.keys(sessionStorage).slice(0, 20),
            };
        }""")
        
        # Parse scripts
        scripts = []
        for s in js_data.get('scripts', []):
            scripts.append({
                'src': s.get('src', ''),
                'inline': s.get('inline', ''),
                'type': s.get('type', ''),
            })
        
        # Parse meta tags
        meta_tags = {}
        for m in js_data.get('meta', []):
            if m['name']:
                meta_tags[m['name']] = m['content']
        
        # Parse links
        links = [l['href'] for l in js_data.get('links', []) if l.get('href')]
        
        # Parse forms
        forms = []
        for f in js_data.get('forms', []):
            forms.append({
                'action': f.get('action', ''),
                'method': f.get('method', 'GET'),
                'inputs': f.get('inputs', []),
            })
        
        # Get response headers from first response
        headers = {}
        if responses:
            headers = responses[0].get('headers', {})
        
        return PageData(
            url=url,
            status_code=responses[0].get('status', 200) if responses else 200,
            headers=headers,
            html=html,
            cookies=[{
                'name': c['name'],
                'value': c['value'],
                'domain': c.get('domain', ''),
                'path': c.get('path', '/'),
                'secure': c.get('secure', False),
                'httponly': c.get('httpOnly', False),
                'samesite': c.get('sameSite', ''),
            } for c in cookies],
            scripts=scripts,
            meta_tags=meta_tags,
            links=links,
            forms=forms,
        )
    
    async def _crawl(self, target: Target):
        """Crawl additional pages up to max_pages and crawl_depth"""
        base_domain = urlparse(str(target.url)).netloc
        to_visit = [(str(target.url), 0)]
        
        while to_visit and len(self.page_data) < self.config.max_pages:
            url, depth = to_visit.pop(0)
            
            if url in self.visited_urls or depth > self.config.crawl_depth:
                continue
            
            self.visited_urls.add(url)
            
            try:
                page = await self._context.new_page()
                await page.goto(
                    url,
                    wait_until=self.config.browser_wait_until,
                    timeout=self.config.browser_timeout * 1000
                )
                
                # Extract links
                links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith('http'));
                }""")
                
                # Filter same-domain links
                for link in links:
                    parsed = urlparse(link)
                    if parsed.netloc == base_domain and link not in self.visited_urls:
                        to_visit.append((link, depth + 1))
                
                # Get page data
                html = await page.content()
                cookies = await self._context.cookies()
                
                page_data = PageData(
                    url=url,
                    status_code=200,
                    headers={},
                    html=html,
                    cookies=[{
                        'name': c['name'], 'value': c['value'],
                        'domain': c.get('domain', ''), 'path': c.get('path', '/'),
                        'secure': c.get('secure', False), 'httponly': c.get('httpOnly', False),
                        'samesite': c.get('sameSite', ''),
                    } for c in cookies],
                    scripts=[], meta_tags={}, links=[], forms=[],
                )
                
                self.page_data.append(page_data)
                await page.close()
                
            except Exception:
                continue
    
    async def _analyze_page_data(self, page_data: PageData) -> List[Technology]:
        """Analyze a single page's data for technologies"""
        technologies = []
        
        # HTML-based detection
        technologies.extend(self._extract_technologies_from_html(page_data))
        
        # Cookie-based detection
        technologies.extend(self._analyze_cookies(page_data.cookies))
        
        # Header-based detection
        technologies.extend(self._analyze_headers(page_data.headers))
        
        return technologies
    
    def _extract_technologies_from_html(self, page_data: PageData) -> List[Technology]:
        """Extract technology fingerprints from HTML content"""
        from src.core.models import Technology
        
        technologies = []
        html = page_data.html
        scripts = page_data.scripts
        meta_tags = page_data.meta_tags
        
        # Check meta tags
        generator = meta_tags.get('generator', '')
        if generator:
            technologies.append(Technology(
                name="CMS/Framework",
                category="cms",
                version=self._extract_version(generator),
                confidence=0.9,
                evidence=[f"Generator meta tag: {generator}"],
            ))
        
        # Check for specific CMS/framework patterns in HTML
        checks = [
            ('wp-json', 'WordPress', 'cms', ['wp-json endpoint found']),
            ('drupal', 'Drupal', 'cms', ['Drupal references found']),
            ('joomla', 'Joomla', 'cms', ['Joomla references found']),
            ('react', 'React', 'framework', ['React references found']),
            ('vue', 'Vue.js', 'framework', ['Vue.js references found']),
            ('angular', 'Angular', 'framework', ['Angular references found']),
            ('jquery', 'jQuery', 'library', ['jQuery references found']),
            ('bootstrap', 'Bootstrap', 'library', ['Bootstrap references found']),
            ('google-analytics', 'Google Analytics', 'analytics', ['GA tracking code found']),
            ('gtag', 'Google Tag Manager', 'analytics', ['GTM code found']),
            ('recaptcha', 'reCAPTCHA', 'security', ['reCAPTCHA found']),
            ('cloudflare', 'Cloudflare', 'cdn', ['Cloudflare headers/JS found']),
            ('akamai', 'Akamai', 'cdn', ['Akamai references found']),
        ]
        
        html_lower = html.lower()
        for pattern, name, category, evidence in checks:
            if self.patterns.get(pattern, re.compile(pattern, re.IGNORECASE)).search(html):
                technologies.append(Technology(
                    name=name,
                    category=category,
                    confidence=0.7,
                    evidence=evidence,
                ))
        
        # Check script sources
        for script in scripts:
            src = script.get('src', '').lower()
            inline = script.get('inline', '').lower()
            content = src + ' ' + inline
            
            script_checks = [
                ('react', 'React', 'framework'),
                ('vue', 'Vue.js', 'framework'),
                ('angular', 'Angular', 'framework'),
                ('jquery', 'jQuery', 'library'),
                ('webpack', 'Webpack', 'build'),
                ('require.js', 'RequireJS', 'library'),
                ('modernizr', 'Modernizr', 'library'),
                ('lodash', 'Lodash', 'library'),
                ('moment', 'Moment.js', 'library'),
                ('axios', 'Axios', 'library'),
                ('fetch', 'Fetch API', 'api'),
            ]
            
            for pattern, name, category in script_checks:
                if pattern in content:
                    version = self._extract_version_from_url(src) if src else None
                    technologies.append(Technology(
                        name=name,
                        category=category,
                        version=version,
                        confidence=0.8,
                        evidence=[f"Script reference: {src[:100]}" if src else "Inline script"],
                    ))
        
        # Check for CMS-specific paths
        if '/wp-content/' in html or '/wp-includes/' in html:
            technologies.append(Technology(
                name='WordPress', category='cms', confidence=0.85,
                evidence=['WordPress paths found in HTML']
            ))
        
        if '/sites/default/' in html or 'drupal-settings-json' in html:
            technologies.append(Technology(
                name='Drupal', category='cms', confidence=0.85,
                evidence=['Drupal paths found in HTML']
            ))
        
        return technologies
    
    def _analyze_cookies(self, cookies: List[Dict]) -> List[Technology]:
        """Analyze cookies for technology fingerprints"""
        from src.core.models import Technology
        
        technologies = []
        cookie_names = [c['name'].lower() for c in cookies]
        cookie_str = ' '.join(cookie_names)
        
        cookie_signatures = {
            'wordpress': ('WordPress', 'cms', ['wordpress', 'wp-', 'wp_']),
            'drupal': ('Drupal', 'cms', ['drupal', 'sess', 'session']),
            'joomla': ('Joomla', 'cms', ['joomla', 'jsession']),
            'magento': ('Magento', 'ecommerce', ['mage', 'frontend', 'adminhtml']),
            'shopify': ('Shopify', 'ecommerce', ['shopify', '_shopify']),
            'laravel': ('Laravel', 'framework', ['laravel_session', 'xsrf-token']),
            'django': ('Django', 'framework', ['csrftoken', 'sessionid']),
            'flask': ('Flask', 'framework', ['session', 'remember_token']),
            'rails': ('Ruby on Rails', 'framework', ['_session', 'csrf_token']),
            'asp.net': ('ASP.NET', 'framework', ['asp.net', '__requestverificationtoken']),
            'php': ('PHP', 'language', ['phpsessid']),
            'cloudflare': ('Cloudflare', 'cdn', ['__cfduid', 'cf_clearance', 'cf_chl']),
            'akamai': ('Akamai', 'cdn', ['akamai']),
            'incapsula': ('Incapsula', 'waf', ['incap_ses', 'visid_incap']),
            'aws': ('AWS', 'cloud', ['aws', 'awselb', 'awsalb']),
        }
        
        for tech_name, (display_name, category, patterns) in cookie_signatures.items():
            for pattern in patterns:
                if any(pattern in cn for cn in cookie_names):
                    technologies.append(Technology(
                        name=display_name,
                        category=category,
                        confidence=0.75,
                        evidence=[f"Cookie pattern: {pattern}"],
                    ))
                    break
        
        return technologies
    
    def _analyze_headers(self, headers: Dict[str, str]) -> List[Technology]:
        """Analyze HTTP headers for technology fingerprints"""
        from src.core.models import Technology
        
        technologies = []
        header_str = ' '.join(f"{k}: {v}" for k, v in headers.items()).lower()
        
        header_signatures = {
            'server': ('Web Server', 'server', ['server']),
            'x-powered-by': ('Backend', 'backend', ['x-powered-by']),
            'x-generator': ('CMS', 'cms', ['x-generator']),
            'x-drupal-cache': ('Drupal', 'cms', ['x-drupal-cache']),
            'x-wordpress': ('WordPress', 'cms', ['x-wordpress']),
            'cf-ray': ('Cloudflare', 'cdn', ['cf-ray']),
            'cf-cache-status': ('Cloudflare', 'cdn', ['cf-cache-status']),
            'x-amz-cf-id': ('AWS CloudFront', 'cdn', ['x-amz-cf-id']),
            'x-varnish': ('Varnish', 'cache', ['x-varnish']),
            'via': ('Proxy/CDN', 'proxy', ['via']),
            'x-frame-options': ('Security Headers', 'security', ['x-frame-options']),
            'content-security-policy': ('CSP', 'security', ['content-security-policy']),
            'strict-transport-security': ('HSTS', 'security', ['strict-transport-security']),
            'x-content-type-options': ('Security Headers', 'security', ['x-content-type-options']),
            'referrer-policy': ('Referrer Policy', 'security', ['referrer-policy']),
            'permissions-policy': ('Permissions Policy', 'security', ['permissions-policy']),
        }
        
        for header_key, (name, category, patterns) in header_signatures.items():
            if header_key in headers:
                value = headers[header_key]
                technologies.append(Technology(
                    name=name,
                    category=category,
                    confidence=0.9,
                    evidence=[f"Header {header_key}: {value[:200]}"],
                ))
        
        # Server header version detection
        server = headers.get('Server', '') or headers.get('server', '')
        if server:
            technologies.append(Technology(
                name='Web Server',
                category='server',
                version=self._extract_version(server),
                confidence=0.95,
                evidence=[f"Server header: {server}"],
            ))
        
        # X-Powered-By
        powered = headers.get('X-Powered-By', '') or headers.get('x-powered-by', '')
        if powered:
            technologies.append(Technology(
                name='Backend Technology',
                category='backend',
                version=self._extract_version(powered),
                confidence=0.9,
                evidence=[f"X-Powered-By: {powered}"],
            ))
        
        return technologies
    
    def _extract_version(self, text: str) -> Optional[str]:
        """Extract version from string"""
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+(?:[-.]\w+)?)',  # 1.2.3, 1.2.3-beta
            r'(\d+\.\d+)',                     # 1.2
            r'v(\d+\.\d+\.\d+)',               # v1.2.3
            r'version[:\s]+(\d+\.\d+\.\d+)',   # version: 1.2.3
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _extract_version_from_url(self, url: str) -> Optional[str]:
        """Extract version from script URL"""
        # Common patterns: /js/app.1.2.3.js, /vendor/jquery-3.6.0.min.js
        patterns = [
            r'[.-](\d+\.\d+\.\d+)(?:[-.]\w+)?\.',  # .1.2.3. or -1.2.3-
            r'[.-](\d+\.\d+)\.',                     # .1.2.
            r'v(\d+\.\d+\.\d+)',                     # v1.2.3
            r'/(\d+\.\d+\.\d+)/',                    # /1.2.3/
        ]
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None
    
    def _extract_scripts(self, html: str) -> List[Dict[str, Any]]:
        """Extract script tags from HTML"""
        scripts = []
        for match in self.patterns['script_src'].finditer(html):
            scripts.append({'src': match.group(1), 'inline': '', 'type': 'external'})
        for match in self.patterns['script_inline'].finditer(html):
            content = match.group(1).strip()
            if content:
                scripts.append({'src': '', 'inline': content, 'type': 'inline'})
        return scripts
    
    def _extract_meta_tags(self, html: str) -> Dict[str, str]:
        """Extract meta tags from HTML"""
        meta = {}
        for match in re.finditer(r'<meta\s+([^>]+)>', html, re.IGNORECASE):
            attrs = match.group(1)
            name_match = re.search(r'(?:name|property|http-equiv)=["\']([^"\']+)["\']', attrs)
            content_match = re.search(r'content=["\']([^"\']+)["\']', attrs)
            if name_match and content_match:
                meta[name_match.group(1).lower()] = content_match.group(1)
        return meta
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        for match in self.patterns['link_href'].finditer(html):
            href = match.group(1)
            links.append(urljoin(base_url, href))
        return links
    
    def _extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        for form_match in re.finditer(r'<form\s+([^>]*)>([\s\S]*?)</form>', html, re.IGNORECASE):
            attrs = form_match.group(1)
            content = form_match.group(2)
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs)
            method_match = re.search(r'method=["\']([^"\']+)["\']', attrs)
            inputs = []
            for input_match in re.finditer(r'<input\s+([^>]*)>', content, re.IGNORECASE):
                input_attrs = input_match.group(1)
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_attrs)
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_attrs)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_attrs)
                inputs.append({
                    'name': name_match.group(1) if name_match else '',
                    'type': type_match.group(1) if type_match else 'text',
                    'value': value_match.group(1) if value_match else '',
                })
            forms.append({
                'action': action_match.group(1) if action_match else '',
                'method': method_match.group(1).upper() if method_match else 'GET',
                'inputs': inputs,
            })
        return forms


async def scan_target(url: str, config: ScannerConfig = None) -> ScanResult:
    """
    Convenience function to scan a single target.
    
    Args:
        url: Target URL to scan
        config: Optional ScannerConfig (uses defaults if not provided)
    
    Returns:
        ScanResult with fingerprints, technologies, and metadata
    """
    if config is None:
        config = ScannerConfig()
    
    target = Target(url=url)
    
    async with PlaywrightScanner(config) as scanner:
        return await scanner.scan(target)


# CLI entry point
if __name__ == "__main__":
    import sys
    import asyncio
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python -m scanner.playwright_scanner <url>")
            sys.exit(1)
        
        url = sys.argv[1]
        config = ScannerConfig.from_env()
        
        print(f"Scanning {url}...")
        result = await scan_target(url, config)
        
        print(f"\nScan completed in {result.duration:.2f}s")
        print(f"Pages scanned: {result.pages_scanned}")
        print(f"Technologies found: {len(result.technologies)}")
        
        for tech in result.technologies:
            print(f"  - {tech.name} ({tech.category}) - confidence: {tech.confidence:.0%}")
            if tech.version:
                print(f"    Version: {tech.version}")
            if tech.cves:
                print(f"    CVEs: {', '.join(c.id for c in tech.cves)}")
    
    asyncio.run(main())