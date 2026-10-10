"""Authorization model: permissions, roles and the Policy Decision Point (PDP).

The permission set is derived directly from Ollama's REST API surface
(server/routes.go). Every Ollama route is mapped to exactly one permission;
anything not in the table is denied by default.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum


class Perm(str, Enum):
    SYSTEM_READ = "system:read"      # version, health, running models
    MODEL_LIST = "model:list"        # list / show models
    MODEL_RUN = "model:run"          # inference: generate, chat, embed, OpenAI/Anthropic-compatible
    MODEL_PULL = "model:pull"        # download from a registry
    MODEL_PUSH = "model:push"        # upload to a registry
    MODEL_MANAGE = "model:manage"    # create, copy, delete, blobs
    AUDIT_READ = "audit:read"
    IAM_ADMIN = "iam:admin"


ROLES: dict[str, dict] = {
    "admin": {
        "label": "Administrator",
        "about": "Full control of models and users.",
        "perms": set(Perm),
    },
    "operator": {
        "label": "Model operator",
        "about": "Pulls, creates and deletes models; reads the audit log.",
        "perms": {Perm.SYSTEM_READ, Perm.MODEL_LIST, Perm.MODEL_RUN, Perm.MODEL_PULL,
                  Perm.MODEL_MANAGE, Perm.AUDIT_READ},
    },
    "developer": {
        "label": "Developer",
        "about": "Runs inference on the models they are allowed to use.",
        "perms": {Perm.SYSTEM_READ, Perm.MODEL_LIST, Perm.MODEL_RUN},
    },
    "viewer": {
        "label": "Viewer",
        "about": "Sees which models exist; cannot run them.",
        "perms": {Perm.SYSTEM_READ, Perm.MODEL_LIST},
    },
}


@dataclass(frozen=True)
class RouteRule:
    method: str
    pattern: re.Pattern
    perm: Perm
    model_from: str = "body"   # body | path | none


def _r(method: str, path: str, perm: Perm, model_from: str = "body") -> RouteRule:
    regex = "^" + re.sub(r":(\w+)", r"(?P<\1>[^/]+)", path) + "$"
    return RouteRule(method, re.compile(regex), perm, model_from)


# Mirrors Ollama's router. Order matters only for readability; patterns don't overlap.
ROUTE_RULES: list[RouteRule] = [
    _r("GET", "/", Perm.SYSTEM_READ, "none"),
    _r("HEAD", "/", Perm.SYSTEM_READ, "none"),
    _r("GET", "/api/version", Perm.SYSTEM_READ, "none"),
    _r("GET", "/api/status", Perm.SYSTEM_READ, "none"),
    _r("GET", "/api/ps", Perm.SYSTEM_READ, "none"),
    _r("GET", "/api/tags", Perm.MODEL_LIST, "none"),
    _r("POST", "/api/show", Perm.MODEL_LIST),
    _r("GET", "/v1/models", Perm.MODEL_LIST, "none"),
    _r("GET", "/v1/models/:model", Perm.MODEL_LIST, "path"),
    _r("POST", "/api/generate", Perm.MODEL_RUN),
    _r("POST", "/api/chat", Perm.MODEL_RUN),
    _r("POST", "/api/embed", Perm.MODEL_RUN),
    _r("POST", "/api/embeddings", Perm.MODEL_RUN),
    _r("POST", "/v1/chat/completions", Perm.MODEL_RUN),
    _r("POST", "/v1/completions", Perm.MODEL_RUN),
    _r("POST", "/v1/embeddings", Perm.MODEL_RUN),
    _r("POST", "/v1/responses", Perm.MODEL_RUN),
    _r("POST", "/v1/messages", Perm.MODEL_RUN),
    _r("POST", "/api/pull", Perm.MODEL_PULL),
    _r("POST", "/api/push", Perm.MODEL_PUSH),
    _r("POST", "/api/create", Perm.MODEL_MANAGE),
    _r("POST", "/api/copy", Perm.MODEL_MANAGE),
    _r("DELETE", "/api/delete", Perm.MODEL_MANAGE),
    _r("POST", "/api/blobs/:digest", Perm.MODEL_MANAGE, "none"),
    _r("HEAD", "/api/blobs/:digest", Perm.MODEL_MANAGE, "none"),
]


def match_route(method: str, path: str) -> tuple[RouteRule, dict] | None:
    for rule in ROUTE_RULES:
        if rule.method == method:
            m = rule.pattern.match(path)
            if m:
                return rule, m.groupdict()
    return None


@dataclass
class Principal:
    """Who is calling: a signed-in user."""
    user_id: int
    username: str
    display_name: str
    roles: list[str]
    model_allow: list[str]
    kind: str = "session"
    session_id: str | None = None
    csrf: str | None = None

    @property
    def perms(self) -> set[Perm]:
        granted: set[Perm] = set()
        for role in self.roles:
            granted |= ROLES.get(role, {}).get("perms", set())
        return granted

    def can(self, perm: Perm | str) -> bool:
        return Perm(perm) in self.perms

    def may_use_model(self, model: str | None) -> bool:
        if model is None:
            return True
        name = normalize_model(model)
        return any(fnmatch.fnmatchcase(name, normalize_pattern(p)) for p in self.model_allow)

    @property
    def actor(self) -> str:
        return self.username


def normalize_model(name: str) -> str:
    """'llama3.2' -> 'llama3.2:latest', drop the default registry host."""
    name = name.strip().lower()
    for host in ("registry.ollama.ai/library/", "ollama.com/library/"):
        if name.startswith(host):
            name = name[len(host):]
    if ":" not in name.rsplit("/", 1)[-1]:
        name += ":latest"
    return name


def normalize_pattern(pattern: str) -> str:
    p = pattern.strip().lower()
    if p == "*" or ":" in p.rsplit("/", 1)[-1] or p.endswith("*"):
        return p
    return p + ":*"


@dataclass
class Decision:
    allowed: bool
    status: int
    reason: str
    perm: Perm | None = None
    models: list[str] = field(default_factory=list)


def decide(principal: Principal | None, method: str, path: str, models: list[str]) -> Decision:
    """The single place where access decisions are made (PDP)."""
    matched = match_route(method, path)
    if matched is None:
        return Decision(False, 404, "Route is not exposed through the gateway.")
    rule, _ = matched
    if principal is None:
        return Decision(False, 401, "Authentication required.", rule.perm)
    if not principal.can(rule.perm):
        return Decision(False, 403, f"Missing permission {rule.perm.value}.", rule.perm)
    blocked = [m for m in models if not principal.may_use_model(m)]
    if blocked:
        return Decision(False, 403, f"Not allowed to use model {blocked[0]}.", rule.perm, models)
    return Decision(True, 200, "ok", rule.perm, models)
