"""
ZDay Scanner - Headless Browser Fingerprinter
Uses Playwright for: Canvas, WebGL, Fonts, Screen, Navigator, Audio, Battery, HTTP/2, TLS, Automation detection
"""
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.fingerprinting.base import FingerprinterBase, register_fingerprinter
from src.core.config import ScannerConfig
from src.core.models import Technology


@register_fingerprinter("headless")
class HeadlessBrowserFingerprinter(FingerprinterBase):
    """Headless browser fingerprinting using Playwright"""

    def __init__(self, config: ScannerConfig):
        super().__init__(config)
        self._playwright = None
        self._browser = None

    def _load_signatures(self):
        # Headless fingerprinting uses dynamic detection
        self.signatures = []

    async def fingerprint(self, target, http_client) -> List:
        """Perform headless browser fingerprinting"""
        from src.core.models import Fingerprint, Technology

        results = []

        if not self.config.enable_headless_fingerprinting:
            return results

        try:
            # Try to import playwright
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                self._playwright = p
                browser = await self._launch_browser(p)
                self._browser = browser

                context = await browser.new_context(
                    user_agent=self.config.user_agent,
                    viewport={"width": 1920, "height": 1080},
                    ignore_https_errors=not self.config.verify_ssl,
                )

                # Add stealth scripts
                if self.config.enable_stealth:
                    await self._inject_stealth(context)

                page = await context.new_page()

                try:
                    await page.goto(
                        target.url,
                        wait_until=self.config.browser_wait_until,
                        timeout=self.config.browser_timeout * 1000
                    )

                    # Collect fingerprint data
                    fp_data = await self._collect_fingerprint(page)

                    # Analyze and create fingerprints
                    techs = self._analyze_fingerprint(fp_data)
                    for tech in techs:
                        fp = Fingerprint(
                            technology=tech,
                            matches=list(tech.evidence),
                            confidence=tech.confidence,
                            source="headless",
                            metadata=fp_data,
                        )
                        results.append(fp)

                finally:
                    await page.close()
                    await context.close()
                    await browser.close()

        except ImportError:
            # Playwright not available
            pass
        except Exception:
            pass

        return results

    async def _launch_browser(self, playwright):
        """Launch browser with configured executable path or CDP connection"""
        import sys
        from pathlib import Path

        # If CDP endpoint is configured, connect to existing browser
        if self.config.cdp_endpoint:
            return await playwright.chromium.connect_over_cdp(self.config.cdp_endpoint)

        # Build launch arguments
        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-setuid-sandbox",
        ]
        # Add custom browser args from config
        if self.config.browser_args:
            launch_args.extend(self.config.browser_args)

        # Determine executable path
        executable_path = self._resolve_browser_path()
        channel = self.config.browser_channel if self.config.browser_channel else None

        # Launch browser
        if executable_path and executable_path != "auto":
            # Explicit path provided
            return await playwright.chromium.launch(
                headless=self.config.headless,
                executable_path=executable_path,
                args=launch_args,
            )
        elif channel:
            # Use channel (chrome, msedge, chromium, brave)
            return await playwright.chromium.launch(
                headless=self.config.headless,
                channel=channel,
                args=launch_args,
            )
        else:
            # Auto-detect or use Playwright bundled
            if executable_path == "auto":
                auto_path = self._auto_detect_browser()
                if auto_path:
                    return await playwright.chromium.launch(
                        headless=self.config.headless,
                        executable_path=auto_path,
                        args=launch_args,
                    )
            # Fallback to Playwright's bundled browser
            return await playwright.chromium.launch(
                headless=self.config.headless,
                args=launch_args,
            )

    def _resolve_browser_path(self) -> Optional[str]:
        """Resolve browser executable path from config"""
        path = self.config.browser_executable_path
        if not path or path == "auto":
            return "auto"
        # Expand user directory
        from pathlib import Path
        expanded = Path(path).expanduser()
        if expanded.exists():
            return str(expanded)
        return None

    def _auto_detect_browser(self) -> Optional[str]:
        """Auto-detect system Chrome/Chromium/Edge/Brave across platforms"""
        import sys
        from pathlib import Path

        candidates = []

        if sys.platform == "darwin":  # macOS
            candidates = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
            ]
        elif sys.platform == "win32":  # Windows
            import os
            program_files = os.environ.get("PROGRAMFILES", "C:\\Program Files")
            program_files_x86 = os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
            local_app_data = os.environ.get("LOCALAPPDATA", "")

            candidates = [
                f"{program_files}\\Google\\Chrome\\Application\\chrome.exe",
                f"{program_files_x86}\\Google\\Chrome\\Application\\chrome.exe",
                f"{local_app_data}\\Google\\Chrome\\Application\\chrome.exe",
                f"{program_files}\\Microsoft\\Edge\\Application\\msedge.exe",
                f"{program_files_x86}\\Microsoft\\Edge\\Application\\msedge.exe",
                f"{program_files}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
                f"{local_app_data}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
                f"{program_files}\\Vivaldi\\Application\\vivaldi.exe",
            ]
        else:  # Linux
            candidates = [
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/usr/bin/microsoft-edge",
                "/usr/bin/microsoft-edge-stable",
                "/usr/bin/brave-browser",
                "/usr/bin/brave-browser-stable",
                "/usr/bin/vivaldi",
                "/usr/bin/vivaldi-stable",
            ]

        for path in candidates:
            if Path(path).exists():
                return path
        return None

    async def _inject_stealth(self, context):
        """Inject stealth scripts to avoid detection"""
        stealth_script = """
        // Overwrite navigator.webdriver
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
        });

        // Mock chrome object
        window.chrome = {
            runtime: {},
            loadTimes: () => {},
            csi: () => {},
            app: {}
        };

        // Mock permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );

        // Mock plugins
        Object.defineProperty(navigator, 'plugins', {
            get: () => [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                { name: 'Native Client', filename: 'internal-nacl-plugin' }
            ],
        });

        // Mock languages
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
        });
        """
        await context.add_init_script(stealth_script)

    async def _collect_fingerprint(self, page) -> Dict[str, Any]:
        """Collect comprehensive browser fingerprint"""

        # Canvas fingerprint
        canvas_fp = await page.evaluate("""
            () => {
                const canvas = document.createElement('canvas');
                canvas.width = 200;
                canvas.height = 50;
                const ctx = canvas.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(10, 10, 100, 30);
                ctx.fillStyle = '#069';
                ctx.fillText('ZDay Scanner Fingerprint', 2, 15);
                return canvas.toDataURL();
            }
        """)

        # WebGL fingerprint
        webgl_fp = await page.evaluate("""
            () => {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) return null;
                return {
                    vendor: gl.getParameter(gl.VENDOR),
                    renderer: gl.getParameter(gl.RENDERER),
                    version: gl.getParameter(gl.VERSION),
                    shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                    extensions: gl.getSupportedExtensions(),
                };
            }
        """)

        # Fonts
        fonts = await page.evaluate("""
            () => {
                const testFonts = [
                    'Arial', 'Helvetica', 'Times New Roman', 'Courier New',
                    'Verdana', 'Georgia', 'Palatino', 'Garamond',
                    'Comic Sans MS', 'Trebuchet MS', 'Arial Black',
                    'Impact', 'Lucida Console', 'Tahoma', 'Calibri',
                    'Roboto', 'Open Sans', 'Lato', 'Montserrat'
                ];
                const detected = [];
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                ctx.font = '72px monospace';
                const baseWidth = ctx.measureText('mmmmmmmmmmlli').width;

                for (const font of testFonts) {
                    ctx.font = `72px "${font}", monospace`;
                    if (ctx.measureText('mmmmmmmmmmlli').width !== baseWidth) {
                        detected.push(font);
                    }
                }
                return detected;
            }
        """)

        # Screen
        screen = await page.evaluate("""
            () => ({
                width: screen.width,
                height: screen.height,
                availWidth: screen.availWidth,
                availHeight: screen.availHeight,
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth,
                devicePixelRatio: window.devicePixelRatio,
            })
        """)

        # Navigator
        navigator = await page.evaluate("""
            () => ({
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                languages: navigator.languages,
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory,
                maxTouchPoints: navigator.maxTouchPoints,
                cookieEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack,
            })
        """)

        # Audio
        audio = await page.evaluate("""
            () => {
                try {
                    const ctx = new (window.AudioContext || window.webkitAudioContext)();
                    const oscillator = ctx.createOscillator();
                    const analyser = ctx.createAnalyser();
                    const gainNode = ctx.createGain();
                    gainNode.gain.value = 0;
                    oscillator.connect(analyser);
                    analyser.connect(gainNode);
                    gainNode.connect(ctx.destination);
                    oscillator.frequency.value = 10000;
                    oscillator.type = 'triangle';
                    oscillator.start(0);
                    const buffer = new Float32Array(analyser.frequencyBinCount);
                    analyser.getFloatFrequencyData(buffer);
                    oscillator.stop(0);
                    ctx.close();
                    const sum = buffer.reduce((a, b) => a + Math.abs(b), 0);
                    return { fingerprint: sum.toFixed(10) };
                } catch (e) {
                    return { error: String(e) };
                }
            }
        """)

        # Battery
        battery = await page.evaluate("""
            () => {
                return navigator.getBattery ? navigator.getBattery().then(b => ({
                    charging: b.charging,
                    level: b.level,
                    chargingTime: b.chargingTime,
                    dischargingTime: b.dischargingTime,
                })) : Promise.resolve({ unavailable: true });
            }
        """)

        # HTTP/2 and protocol
        protocol = await page.evaluate("""
            () => {
                const entries = performance.getEntriesByType('navigation');
                if (entries.length > 0) {
                    return {
                        nextHopProtocol: entries[0].nextHopProtocol,
                        type: entries[0].type,
                    };
                }
                return {};
            }
        """)

        # Automation detection
        automation = await page.evaluate("""
            () => ({
                webdriver: navigator.webdriver,
                automationControlled: 'automationControlled' in navigator,
                chrome: !!window.chrome,
                phantom: !!window._phantom,
                selenium: !!window.__selenium_unwrapped,
                domAutomation: !!window.domAutomation,
            })
        """)

        # TLS info
        tls = await page.evaluate("""
            () => {
                try {
                    return {
                        protocol: document.location.protocol,
                        // Note: TLS details not directly accessible from JS
                    };
                } catch { return {}; }
            }
        """)

        return {
            "canvas": canvas_fp,
            "webgl": webgl_fp,
            "fonts": fonts,
            "screen": screen,
            "navigator": navigator,
            "audio": audio,
            "battery": battery,
            "protocol": protocol,
            "automation": automation,
            "tls": tls,
        }

    def _analyze_fingerprint(self, data: Dict[str, Any]) -> List[Technology]:
        """Analyze fingerprint data and identify technologies"""
        from src.core.models import Technology

        techs = []

        # Detect automation/headless
        automation = data.get("automation", {})
        if automation.get("webdriver") or automation.get("automationControlled"):
            techs.append(Technology(
                name="Automation Detected",
                category="client",
                confidence=0.9,
                evidence=["navigator.webdriver=true" if automation.get("webdriver") else "automationControlled present"],
            ))

        # WebGL renderer detection
        webgl = data.get("webgl")
        if webgl:
            renderer = webgl.get("renderer", "").lower()
            vendor = webgl.get("vendor", "").lower()

            if "swiftshader" in renderer or "llvmpipe" in renderer or "mesa" in renderer:
                techs.append(Technology(
                    name="Software Rendering (Headless)",
                    category="client",
                    confidence=0.85,
                    evidence=[f"WebGL Renderer: {renderer}", f"Vendor: {vendor}"],
                ))
            elif "angle" in renderer:
                techs.append(Technology(
                    name="ANGLE (Windows/Chrome)",
                    category="client",
                    confidence=0.7,
                    evidence=[f"WebGL Renderer: {renderer}"],
                ))

        # Canvas fingerprint uniqueness
        canvas = data.get("canvas", "")
        if canvas:
            techs.append(Technology(
                name="Canvas Fingerprint",
                category="client",
                confidence=0.6,
                evidence=[f"Canvas hash: {canvas[:50]}..."],
            ))

        # Font fingerprint
        fonts = data.get("fonts", [])
        if fonts:
            techs.append(Technology(
                name="Font Fingerprint",
                category="client",
                confidence=0.6,
                evidence=[f"Detected fonts: {', '.join(fonts[:10])}"],
            ))

        # Screen resolution
        screen = data.get("screen", {})
        if screen.get("width") and screen.get("height"):
            techs.append(Technology(
                name="Screen Resolution",
                category="client",
                confidence=0.5,
                evidence=[f"{screen['width']}x{screen['height']}, DPR: {screen.get('devicePixelRatio')}"],
            ))

        # Audio fingerprint
        audio = data.get("audio", {})
        if audio.get("fingerprint"):
            techs.append(Technology(
                name="Audio Fingerprint",
                category="client",
                confidence=0.5,
                evidence=[f"Audio hash: {audio['fingerprint']}"],
            ))

        # Battery API
        battery = data.get("battery", {})
        if battery and not battery.get("unavailable"):
            techs.append(Technology(
                name="Battery API",
                category="client",
                confidence=0.4,
                evidence=[f"Level: {battery.get('level')}, Charging: {battery.get('charging')}"],
            ))

        # HTTP/2
        protocol = data.get("protocol", {})
        if protocol.get("nextHopProtocol") == "h2":
            techs.append(Technology(
                name="HTTP/2",
                category="protocol",
                confidence=0.9,
                evidence=["nextHopProtocol: h2"],
            ))

        return techs
