"""Framework adapters.

An adapter translates one agent framework's call shape into detguard's
canonical model and back. Adapters may import core; **core must never import
an adapter**, and adapters must never import each other.

Concrete adapters (``generic``, ``langgraph``, ``openai_agents``) are added in
build steps 6, 8 and 9. Optional third-party imports are guarded inside the
adapter modules so that ``pip install detguard`` with zero extras still works.
"""

__all__: list[str] = []
