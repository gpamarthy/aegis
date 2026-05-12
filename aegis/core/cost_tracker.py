from dataclasses import dataclass, field

# TODO: per-model pricing table instead of flat rate
COST_PER_1K = {
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "claude-sonnet-4-6": {"input": 0.003, "output": 0.015},
    "claude-haiku-4-5-20251001": {"input": 0.0008, "output": 0.004},
    "claude-opus-4-6": {"input": 0.015, "output": 0.075},
}


@dataclass
class CostTracker:
    budget_usd: float = 5.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost: float = 0.0
    requests: int = 0
    _cost_log: list[dict] = field(default_factory=list)

    def record(self, model: str, input_tokens: int, output_tokens: int, scanner: str = "") -> float:
        costs = COST_PER_1K.get(model, {"input": 0.002, "output": 0.006})
        cost = (input_tokens / 1000 * costs["input"]) + (output_tokens / 1000 * costs["output"])
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost += cost
        self.requests += 1
        self._cost_log.append({"model": model, "input": input_tokens, "output": output_tokens, "cost": cost, "scanner": scanner})
        return cost

    @property
    def budget_remaining(self) -> float:
        return max(0, self.budget_usd - self.total_cost)

    @property
    def over_budget(self) -> bool:
        return self.total_cost >= self.budget_usd

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens
