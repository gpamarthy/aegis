import abc
from aegis.connectors.base_llm import BaseConnector
from aegis.core.scan_config import ScanConfig
from aegis.core.findings import Finding, OWASPCategory, Severity, ComplianceMapping
from aegis.core.cost_tracker import CostTracker
from aegis.core.rate_limiter import RateLimiter
from aegis.core.session import ConversationSession, Role


class BaseScanner(abc.ABC):
    name: str = "base"
    description: str = ""
    category: OWASPCategory = OWASPCategory.LLM01

    def __init__(self, connector: BaseConnector, config: ScanConfig, cost_tracker: CostTracker, rate_limiter: RateLimiter):
        self.connector = connector
        self.config = config
        self.cost_tracker = cost_tracker
        self.rate_limiter = rate_limiter
        self.findings: list[Finding] = []

    @abc.abstractmethod
    async def run(self) -> list[Finding]:
        ...

    def add_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        technique: str,
        payload: str,
        response: str,
        evidence: str = "",
        remediation: str = "",
        compliance: ComplianceMapping | None = None,
        tokens_used: int = 0,
        cost_usd: float = 0.0,
    ) -> Finding:
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            category=self.category,
            technique=technique,
            payload=payload,
            response=response,
            evidence=evidence,
            remediation=remediation,
            compliance=compliance or self._default_compliance(),
            scanner_name=self.name,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
        )
        self.findings.append(finding)
        return finding

    def _default_compliance(self) -> ComplianceMapping:
        return ComplianceMapping(owasp=self.category)

    async def _send(self, prompt: str, system: str | None = None):
        # TODO: add retry with exponential backoff on transient failures
        if self.cost_tracker.over_budget:
            return None
        await self.rate_limiter.acquire()
        resp = await self.connector.send_single(prompt, system=system)
        self.cost_tracker.record(
            model=self.connector.config.model,
            input_tokens=resp.input_tokens,
            output_tokens=resp.output_tokens,
            scanner=self.name,
        )
        return resp

    async def _send_conversation(self, session: ConversationSession, prompt: str):
        """Send a message as part of a multi-turn conversation.

        Appends the user message to the session, sends the full history
        to the connector, appends the assistant response, and returns it.
        """
        if self.cost_tracker.over_budget:
            return None
        await self.rate_limiter.acquire()
        session.add_message(Role.USER, prompt)
        resp = await self.connector.send(session.get_messages_for_api())
        session.add_message(Role.ASSISTANT, resp.content, tokens=resp.output_tokens)
        self.cost_tracker.record(
            model=self.connector.config.model,
            input_tokens=resp.input_tokens,
            output_tokens=resp.output_tokens,
            scanner=self.name,
        )
        session.total_tokens += resp.input_tokens + resp.output_tokens
        return resp

    def _new_session(self) -> ConversationSession:
        """Create a fresh conversation session for multi-turn attacks."""
        return ConversationSession(target=self.config.target.endpoint, scanner=self.name)
