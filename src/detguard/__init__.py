"""detguard — policy-as-code guardrails for AI agent tool calls.

Two products, one engine:

* a runtime enforcement library, called at four canonical hooks in an agent
  loop (``before_input``, ``before_tool``, ``after_tool``, ``before_output``);
* an adversarial regression suite — role-parameterised attack templates that
  instantiate against a client's tool manifest, a runner, a baseline and a
  CI gate.

Enforcement is 100% deterministic in v1. No LLM sits in the enforcement path.

    >>> from detguard import engine, policy
    >>> policy_set = policy.load("policy.yaml")
    >>> verdict = engine.before_tool(calls, policy_set, user_prompt=prompt)
    >>> verdict.allow, verdict.requires_approval
"""

from . import engine, policy, registry, roles
from .events import (
    HOOKS,
    SEVERITIES,
    Decision,
    GuardContext,
    ToolCall,
    Verdict,
)
from .policy import PolicyError, PolicySet, Rule
from .roles import GATED_BY_DEFAULT, ROLES

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # modules
    "engine",
    "policy",
    "registry",
    "roles",
    # event model
    "HOOKS",
    "SEVERITIES",
    "Decision",
    "GuardContext",
    "ToolCall",
    "Verdict",
    # policy
    "PolicyError",
    "PolicySet",
    "Rule",
    # roles
    "ROLES",
    "GATED_BY_DEFAULT",
]
