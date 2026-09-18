"""
Fingerprinting Engine — Stage 1 of LLM-EduAttackGraph

Implements the fingerprinting procedure described in Algorithm 1 of the paper:

    procedure SCAN_TARGET(target_ip):
        open_ports ← PORT_SCAN(target_ip, port_scanner)
        for each port in open_ports:
            service ← SERVICE_IDENTIFY(target_ip:port, service_scanner)
            if service ∈ {http, https}:
                url ← BUILD_URL(service, target_ip, port)
                fingerprint ← WEB_FINGERPRINT(url, fingerprint_tool)
                if fingerprint ≠ null:
                    vulnerability ← AI_ANALYZE(fingerprint, ai_model)  [optional]
        GENERATE_REPORT(target_ip, service_map)

Tools in paper:
    - port-go.exe  → PortScanner (Python-native + exe adapter)
    - server-go.exe → ServiceIdentifier (Python-native + exe adapter)
    - finger.exe → WebFingerprintProvider (Python-native + exe adapter)
    - spark-api → SparkAPIAdapter (optional)
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any

import httpx

from app.core.authorization import auth_manager, AuthorizationError
from app.config import settings


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class ServiceInfo:
    """Service identified on an open port."""
    port: int
    name: str                   # http, https, ftp, ssh, mysql, redis, etc.
    version: Optional[str] = None
    product: Optional[str] = None
    banner: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebFingerprint:
    """Web application fingerprint."""
    url: str
    framework: Optional[str] = None
    cms: Optional[str] = None
    server: Optional[str] = None
    server_version: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    status_code: Optional[int] = None


@dataclass
class PortRecord:
    """One entry in the service_map from Algorithm 1."""
    port: int
    service: Optional[ServiceInfo] = None
    url: Optional[str] = None
    fingerprint: Optional[WebFingerprint] = None
    spark_vulnerability: Optional[str] = None     # From spark-api (optional)


@dataclass
class StructuredFingerprint:
    """
    Final structured fingerprint — output of Stage 1.
    Paper: "aggregated into a structured CSV report that reflects the site's technical footprint"
    Implementation uses JSON internally.
    """
    target: str
    scan_id: str
    timestamp: str
    port_records: List[PortRecord] = field(default_factory=list)

    # Aggregated summary
    web_framework: Optional[str] = None
    web_application: Optional[str] = None
    server_software: Optional[str] = None
    server_version: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    cms: Optional[str] = None

    def to_text(self) -> str:
        """
        Convert to text for embedding (becomes the RAG query).
        This text is fed to the BGE embedding model.
        """
        lines = [f"Target: {self.target}"]

        if self.web_framework:
            lines.append(f"Web Framework: {self.web_framework}")
        if self.web_application:
            lines.append(f"Web Application: {self.web_application}")
        if self.server_software:
            lines.append(f"Server: {self.server_software} {self.server_version or ''}")
        if self.cms:
            lines.append(f"CMS: {self.cms}")
        if self.technologies:
            lines.append(f"Technologies: {', '.join(self.technologies)}")

        for pr in self.port_records:
            lines.append(f"\nPort {pr.port}:")
            if pr.service:
                lines.append(f"  Service: {pr.service.name}")
                if pr.service.version:
                    lines.append(f"  Version: {pr.service.version}")
            if pr.fingerprint:
                fp = pr.fingerprint
                if fp.framework:
                    lines.append(f"  Framework: {fp.framework}")
                if fp.server:
                    lines.append(f"  Server: {fp.server} {fp.server_version or ''}")
                if fp.technologies:
                    lines.append(f"  Technologies: {', '.join(fp.technologies)}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for storage."""
        return asdict(self)


# ==============================================================================
# Port Scanner (implements port-go.exe behavior)
# ==============================================================================

class PortScanner:
    """
    Python-native TCP port scanner.
    Equivalent to port-go.exe from Algorithm 1.

    From Algorithm 1:
        PORT_SCAN(ip, scanner):
            raw_data ← EXECUTE(scanner, ["-d", ip])
            ports ← EXTRACT_BRACKET_CONTENT(raw_data)
            return ports
    """

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        timeout: int = None,
        max_concurrent: int = None,
        exe_path: Optional[str] = None,
    ):
        self.ports = ports or settings.port_scan_ports
        self.timeout = timeout or settings.PORT_SCAN_TIMEOUT
        self.max_concurrent = max_concurrent or settings.PORT_SCAN_THREADS
        self.exe_path = exe_path or settings.PORT_GO_EXE_PATH

    async def scan(self, target: str) -> List[int]:
        """
        Scan target for open TCP ports.
        Returns list of open port numbers.

        Implementation:
        - If port-go.exe is available, uses it (paper's tool)
        - Otherwise, uses Python socket-based scanning
        """
        if self.exe_path:
            return await self._scan_with_exe(target)
        return await self._scan_python(target)

    async def _scan_python(self, target: str) -> List[int]:
        """Python socket-based TCP connect scan."""
        open_ports = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_port(port: int) -> Optional[int]:
            async with semaphore:
                try:
                    conn = asyncio.open_connection(target, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                    writer.close()
                    await writer.wait_closed()
                    return port
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        tasks = [check_port(p) for p in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, int):
                open_ports.append(r)

        return sorted(open_ports)

    async def _scan_with_exe(self, target: str) -> List[int]:
        """Use port-go.exe if available (paper's tool)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.exe_path, "-d", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            raw = stdout.decode("utf-8", errors="replace")
            # Extract bracket content as described in Algorithm 1
            matches = re.findall(r'\[([^\]]+)\]', raw)
            ports = []
            for m in matches:
                try:
                    ports.append(int(m.strip()))
                except ValueError:
                    pass
            return sorted(set(ports))
        except Exception:
            # Fall back to Python implementation
            return await self._scan_python(target)


# ==============================================================================
# Service Identifier (implements server-go.exe behavior)
# ==============================================================================

class ServiceIdentifier:
    """
    Service and version identification via banner grabbing.
    Equivalent to server-go.exe from Algorithm 1.

    Implements:
        SERVICE_IDENTIFY(target_ip:port, service_scanner)
    """

    # Known service signatures
    SERVICE_SIGNATURES = {
        "SSH": re.compile(r'^SSH-', re.IGNORECASE),
        "FTP": re.compile(r'^220.*(FTP|FileZilla|Pure-FTP|ProFTPD|vsftpd)', re.IGNORECASE),
        "SMTP": re.compile(r'^220\s+\S+\s+SMTP', re.IGNORECASE),
        "HTTP": re.compile(r'^HTTP/[12]', re.IGNORECASE),
        "MySQL": re.compile(r'mysql', re.IGNORECASE),
        "Redis": re.compile(r'^\+PONG|^\-ERR.*Redis', re.IGNORECASE),
        "Elasticsearch": re.compile(r'elastic', re.IGNORECASE),
    }

    # Known port-to-service mappings
    WELL_KNOWN_PORTS = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 3306: "mysql", 5432: "postgresql",
        6379: "redis", 8080: "http", 8443: "https",
        8888: "http", 9200: "elasticsearch", 27017: "mongodb",
        3000: "http", 4848: "http", 9090: "http",
    }

    def __init__(
        self,
        timeout: int = None,
        exe_path: Optional[str] = None,
    ):
        self.timeout = timeout or settings.SERVICE_BANNER_TIMEOUT
        self.exe_path = exe_path or settings.SERVER_GO_EXE_PATH

    async def identify(self, target: str, port: int) -> ServiceInfo:
        """
        Identify service running on target:port.
        Returns ServiceInfo with name, version, banner.
        """
        if self.exe_path:
            return await self._identify_with_exe(target, port)
        return await self._identify_python(target, port)

    async def _identify_python(self, target: str, port: int) -> ServiceInfo:
        """Python-native service identification via banner grabbing."""
        # Start with well-known port assumption
        service_name = self.WELL_KNOWN_PORTS.get(port, "unknown")

        try:
            # Try to grab banner
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )

            # Send HTTP probe for potential web services
            if service_name in ("http", "unknown") or port in (80, 8080, 8888, 3000):
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                await writer.drain()

            # Read banner
            try:
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                banner = banner_bytes.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                banner = ""

            writer.close()
            await writer.wait_closed()

            # Parse banner for service/version
            return self._parse_banner(port, service_name, banner)

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return ServiceInfo(
                port=port,
                name=service_name,
                evidence={"method": "well-known-port-fallback"},
            )

    def _parse_banner(self, port: int, assumed_service: str, banner: str) -> ServiceInfo:
        """Parse banner to extract service name and version."""
        evidence = {"banner": banner[:200] if banner else None}
        service_name = assumed_service
        version = None
        product = None

        if not banner:
            return ServiceInfo(port=port, name=service_name, evidence=evidence)

        # HTTP response
        if banner.startswith("HTTP/") or "Server:" in banner:
            service_name = "https" if port == 443 or port == 8443 else "http"
            server_match = re.search(r'Server:\s*(.+)', banner, re.IGNORECASE)
            if server_match:
                server_header = server_match.group(1).strip()
                product, version = self._parse_server_header(server_header)
                evidence["server_header"] = server_header

        # SSH banner
        elif banner.startswith("SSH-"):
            service_name = "ssh"
            ssh_match = re.match(r'SSH-[\d.]+-(OpenSSH[\w._-]+)', banner)
            if ssh_match:
                version = ssh_match.group(1)
                product = "OpenSSH"

        # MySQL
        elif re.search(r'mysql|MariaDB', banner, re.IGNORECASE):
            service_name = "mysql"
            ver_match = re.search(r'([\d]+\.[\d]+\.[\d]+)', banner)
            if ver_match:
                version = ver_match.group(1)
            product = "MariaDB" if "MariaDB" in banner else "MySQL"

        # Redis
        elif "+PONG" in banner or "redis" in banner.lower():
            service_name = "redis"
            product = "Redis"

        return ServiceInfo(
            port=port,
            name=service_name,
            version=version,
            product=product,
            banner=banner[:500],
            evidence=evidence,
        )

    def _parse_server_header(self, server_header: str) -> tuple[Optional[str], Optional[str]]:
        """Parse Server HTTP header for product and version."""
        # Common patterns: "Apache/2.4.41", "nginx/1.18.0", "Microsoft-IIS/10.0"
        match = re.match(r'([^/]+)/?([\d.]+)?', server_header)
        if match:
            product = match.group(1).strip()
            version = match.group(2)
            return product, version
        return server_header, None

    async def _identify_with_exe(self, target: str, port: int) -> ServiceInfo:
        """Use server-go.exe if available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.exe_path, f"{target}:{port}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            raw = stdout.decode("utf-8", errors="replace")
            # Extract bracket content from exe output
            matches = re.findall(r'\[([^\]]+)\]', raw)
            if matches:
                service_name = matches[0] if len(matches) > 0 else "unknown"
                version = matches[1] if len(matches) > 1 else None
                return ServiceInfo(port=port, name=service_name, version=version)
        except Exception:
            pass
        # Fall back to Python
        return await self._identify_python(target, port)


# ==============================================================================
# Web Fingerprint Provider (implements finger.exe behavior)
# ==============================================================================

class WebFingerprintProvider:
    """
    Web application fingerprinting.
    Equivalent to finger.exe from Algorithm 1.

    From Algorithm 1:
        WEB_FINGERPRINT(url, tool):
            response ← EXECUTE(tool, ["-u", url])
            features ← EXTRACT_BRACKET_CONTENT(response)
            if features ≠ ∅:
                return features[0]  # Primary fingerprint
            return null
    """

    # Framework/CMS detection signatures
    FRAMEWORK_SIGNATURES = {
        # Java frameworks
        "RuoYi": [
            re.compile(r'若依|RuoYi|ruoyi', re.IGNORECASE),
            re.compile(r'ruoyi-ui|ry-system', re.IGNORECASE),
        ],
        "Spring Boot": [
            re.compile(r'Whitelabel Error Page', re.IGNORECASE),
            re.compile(r'spring.*boot', re.IGNORECASE),
        ],
        "Shiro": [re.compile(r'rememberMe=|shiro', re.IGNORECASE)],
        "Struts2": [re.compile(r'struts|\.action\b', re.IGNORECASE)],
        "Nacos": [re.compile(r'nacos', re.IGNORECASE)],
        "FastJSON": [re.compile(r'fastjson', re.IGNORECASE)],
        "Log4j": [re.compile(r'log4j', re.IGNORECASE)],
        # PHP
        "ThinkPHP": [re.compile(r'thinkphp|think\.js', re.IGNORECASE)],
        "Laravel": [re.compile(r'laravel', re.IGNORECASE)],
        "WordPress": [re.compile(r'wp-content|wp-includes|WordPress', re.IGNORECASE)],
        "Joomla": [re.compile(r'joomla', re.IGNORECASE)],
        "Drupal": [re.compile(r'drupal', re.IGNORECASE)],
        # Python
        "Django": [re.compile(r'django|csrftoken', re.IGNORECASE)],
        "Flask": [re.compile(r'flask', re.IGNORECASE)],
        # Node.js
        "Express": [re.compile(r'express', re.IGNORECASE)],
        # CMS/Platforms
        "Druid": [re.compile(r'druid/index|druid-monitor', re.IGNORECASE)],
        "Swagger": [re.compile(r'swagger-ui|api-docs', re.IGNORECASE)],
        "MinIO": [re.compile(r'minio', re.IGNORECASE)],
        "Kibana": [re.compile(r'kibana', re.IGNORECASE)],
    }

    SERVER_SIGNATURES = {
        "Apache": re.compile(r'Apache', re.IGNORECASE),
        "Nginx": re.compile(r'nginx', re.IGNORECASE),
        "IIS": re.compile(r'Microsoft-IIS', re.IGNORECASE),
        "Tomcat": re.compile(r'Apache-Coyote|Tomcat', re.IGNORECASE),
        "Jetty": re.compile(r'Jetty', re.IGNORECASE),
        "Lighttpd": re.compile(r'lighttpd', re.IGNORECASE),
    }

    def __init__(
        self,
        timeout: int = 10,
        exe_path: Optional[str] = None,
    ):
        self.timeout = timeout
        self.exe_path = exe_path or settings.FINGER_EXE_PATH

    async def fingerprint(self, url: str) -> Optional[WebFingerprint]:
        """
        Perform web fingerprinting on the given URL.
        Returns WebFingerprint or None if fingerprinting fails.
        """
        if self.exe_path:
            return await self._fingerprint_with_exe(url)
        return await self._fingerprint_python(url)

    async def _fingerprint_python(self, url: str) -> Optional[WebFingerprint]:
        """HTTP-based web fingerprinting."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,       # Educational sites may have invalid certs
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Security Analysis)"},
            ) as client:
                response = await client.get(url)

            return self._analyze_response(url, response)

        except Exception as e:
            return WebFingerprint(
                url=url,
                evidence=[f"Fingerprinting failed: {str(e)}"],
            )

    def _analyze_response(self, url: str, response: httpx.Response) -> WebFingerprint:
        """Analyze HTTP response to extract fingerprint."""
        headers = dict(response.headers)
        body = response.text[:10000]  # First 10KB

        fp = WebFingerprint(
            url=url,
            headers={k.lower(): v for k, v in headers.items()},
            status_code=response.status_code,
        )

        # Detect server
        server_header = headers.get("server", "")
        for server_name, pattern in self.SERVER_SIGNATURES.items():
            if pattern.search(server_header):
                fp.server = server_name
                ver_match = re.search(r'/([\d.]+)', server_header)
                if ver_match:
                    fp.server_version = ver_match.group(1)
                break

        # Detect framework/CMS
        search_text = body + " " + str(headers)
        for framework_name, patterns in self.FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if pattern.search(search_text):
                    if not fp.framework:
                        fp.framework = framework_name
                    if framework_name not in fp.technologies:
                        fp.technologies.append(framework_name)
                    fp.evidence.append(f"Detected {framework_name} pattern")
                    break

        # Detect technology from headers
        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            fp.technologies.append(x_powered)
            fp.evidence.append(f"X-Powered-By: {x_powered}")

        x_generator = headers.get("x-generator", "")
        if x_generator and x_generator not in fp.technologies:
            fp.technologies.append(x_generator)

        return fp

    async def _fingerprint_with_exe(self, url: str) -> Optional[WebFingerprint]:
        """Use finger.exe if available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.exe_path, "-u", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            raw = stdout.decode("utf-8", errors="replace")
            # Extract bracket content as described in Algorithm 1
            matches = re.findall(r'\[([^\]]+)\]', raw)
            if matches:
                return WebFingerprint(
                    url=url,
                    framework=matches[0],
                    evidence=[f"finger.exe: {matches[0]}"],
                )
        except Exception:
            pass
        return await self._fingerprint_python(url)


# ==============================================================================
# Fingerprint Engine — Main Orchestrator
# ==============================================================================

class FingerprintEngine:
    """
    Main orchestrator implementing Algorithm 1 from the paper.

    procedure SCAN_TARGET(target_ip):
        open_ports ← PORT_SCAN(target_ip, port_scanner)
        service_map ← INIT_MAP
        for each port in open_ports:
            service ← SERVICE_IDENTIFY(target_ip:port, service_scanner)
            service_map[port] ← [port, service, "-", "-", ""]
            if service ∈ {http, https}:
                url ← BUILD_URL(service, target_ip, port)
                fingerprint ← WEB_FINGERPRINT(url, fingerprint_tool)
                service_map[port][2] ← url
                service_map[port][3] ← fingerprint
                if fingerprint ≠ null:
                    vulnerability ← AI_ANALYZE(fingerprint, ai_model)
                    service_map[port][4] ← vulnerability
        GENERATE_REPORT(target_ip, service_map)
    """

    def __init__(
        self,
        port_scanner: Optional[PortScanner] = None,
        service_identifier: Optional[ServiceIdentifier] = None,
        web_fingerprint_provider: Optional[WebFingerprintProvider] = None,
        spark_adapter=None,
    ):
        self.port_scanner = port_scanner or PortScanner()
        self.service_identifier = service_identifier or ServiceIdentifier()
        self.web_fingerprint_provider = web_fingerprint_provider or WebFingerprintProvider()
        self.spark_adapter = spark_adapter  # Optional, from Algorithm 1

    async def scan_target(
        self,
        target: str,
        scan_id: str,
        authorize: bool = True,
    ) -> StructuredFingerprint:
        """
        Execute Algorithm 1: full fingerprinting of target.

        Returns StructuredFingerprint — input to Stage 2 (RAG pipeline).
        """
        # Step 0: Authorization check (safety requirement)
        if authorize:
            auth_manager.validate_target(target)

        timestamp = datetime.utcnow().isoformat()

        # Step 1: PORT_SCAN — active TCP probing
        open_ports = await self.port_scanner.scan(target)

        service_map: Dict[int, PortRecord] = {}

        # Step 2: For each open port
        for port in open_ports:
            # SERVICE_IDENTIFY
            service = await self.service_identifier.identify(target, port)
            pr = PortRecord(port=port, service=service)

            # Step 3: Web fingerprinting (only for HTTP/HTTPS)
            if service.name in ("http", "https"):
                scheme = service.name
                url = f"{scheme}://{target}:{port}"

                # WEB_FINGERPRINT
                fingerprint = await self.web_fingerprint_provider.fingerprint(url)
                pr.url = url
                pr.fingerprint = fingerprint

                # Optional: AI_ANALYZE via spark-api (Algorithm 1, line 19)
                if fingerprint and self.spark_adapter:
                    try:
                        vulnerability = await self.spark_adapter.analyze(fingerprint)
                        pr.spark_vulnerability = vulnerability
                    except Exception:
                        pass  # spark-api is optional

            service_map[port] = pr

        # Step 4: GENERATE_REPORT
        return self._generate_report(target, scan_id, timestamp, service_map)

    def _generate_report(
        self,
        target: str,
        scan_id: str,
        timestamp: str,
        service_map: Dict[int, PortRecord],
    ) -> StructuredFingerprint:
        """
        Generate structured fingerprint report from service_map.
        Paper: "integrate all the acquired information to generate a comprehensive scanning report"
        """
        port_records = list(service_map.values())

        # Aggregate web-level information
        web_framework = None
        web_application = None
        server_software = None
        server_version = None
        technologies = []
        cms = None

        for pr in port_records:
            if pr.fingerprint:
                fp = pr.fingerprint
                if fp.framework and not web_framework:
                    web_framework = fp.framework
                if fp.cms and not cms:
                    cms = fp.cms
                if fp.server and not server_software:
                    server_software = fp.server
                    server_version = fp.server_version
                for tech in fp.technologies:
                    if tech not in technologies:
                        technologies.append(tech)

        return StructuredFingerprint(
            target=target,
            scan_id=scan_id,
            timestamp=timestamp,
            port_records=port_records,
            web_framework=web_framework,
            web_application=web_application or web_framework,
            server_software=server_software,
            server_version=server_version,
            technologies=technologies,
            cms=cms,
        )
