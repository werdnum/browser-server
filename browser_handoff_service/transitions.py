from __future__ import annotations

from dataclasses import dataclass

from .models import TERMINAL_STATES, LeaseOwner, SessionState


class TransitionError(ValueError):
    pass


@dataclass(frozen=True)
class Transition:
    from_state: SessionState
    to_state: SessionState
    from_owner: LeaseOwner
    to_owner: LeaseOwner


ALLOWED_TRANSITIONS = {
    (SessionState.AGENT_ACTIVE, SessionState.HANDOFF_REQUESTED): LeaseOwner.SERVICE,
    (SessionState.AGENT_RESUMABLE, SessionState.HANDOFF_REQUESTED): LeaseOwner.SERVICE,
    (SessionState.HANDOFF_REQUESTED, SessionState.HUMAN_ACTIVE): LeaseOwner.HUMAN,
    (SessionState.HUMAN_ACTIVE, SessionState.HUMAN_SENSITIVE): LeaseOwner.HUMAN,
    (SessionState.HUMAN_ACTIVE, SessionState.AGENT_ACTIVE): LeaseOwner.AGENT,
    (SessionState.HUMAN_ACTIVE, SessionState.COMPLETED): LeaseOwner.NONE,
    (SessionState.HUMAN_SENSITIVE, SessionState.COMPLETED): LeaseOwner.NONE,
    (SessionState.HANDOFF_REQUESTED, SessionState.CANCELLED): LeaseOwner.NONE,
    (SessionState.HUMAN_ACTIVE, SessionState.CANCELLED): LeaseOwner.NONE,
    (SessionState.HUMAN_SENSITIVE, SessionState.CANCELLED): LeaseOwner.NONE,
    (SessionState.HUMAN_ACTIVE, SessionState.SANITIZE_PENDING): LeaseOwner.SERVICE,
    (SessionState.SANITIZE_PENDING, SessionState.AGENT_RESUMABLE): LeaseOwner.AGENT,
}


def transition(state: SessionState, owner: LeaseOwner, to_state: SessionState) -> LeaseOwner:
    if state in TERMINAL_STATES:
        raise TransitionError(f"terminal session cannot transition from {state}")
    if to_state in {SessionState.EXPIRED, SessionState.FAILED}:
        return LeaseOwner.NONE
    next_owner = ALLOWED_TRANSITIONS.get((state, to_state))
    if next_owner is None:
        raise TransitionError(f"invalid transition {state} -> {to_state}")
    if state in {SessionState.AGENT_ACTIVE, SessionState.AGENT_RESUMABLE} and owner != LeaseOwner.AGENT:
        raise TransitionError("agent-owned transition requires agent lease")
    if state in {SessionState.HUMAN_ACTIVE, SessionState.HUMAN_SENSITIVE} and owner != LeaseOwner.HUMAN:
        raise TransitionError("human-owned transition requires human lease")
    if state == SessionState.HANDOFF_REQUESTED and owner != LeaseOwner.SERVICE:
        raise TransitionError("handoff claim requires service lease")
    return next_owner
