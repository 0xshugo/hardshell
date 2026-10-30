"""Executable boundary: trusted readback, signed gate, then finite typed handlers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from uuid import uuid4

from hardshell.adapters.base import ExecutionReceipt, ExecutionStatus, ResourceKind, ResourceRef
from hardshell.executor.contract import AuthorizedPlan, SignedExecutorPlan
from hardshell.executor.replay import PersistentReplayStore
from hardshell.executor.verify import ExecutorDenied, ExecutorVerifier

TypedOperation = Callable[[AuthorizedPlan], Awaitable[list[str]]]


class BoundedExecutor:
    """Keep keys, readback, replay ledger and operation handlers local.

    This is a reference dispatcher, not a hardened system service. In production,
    put it in an independently sandboxed process with a privileged local owner.
    """

    def __init__(
        self,
        verifier: ExecutorVerifier,
        replay: PersistentReplayStore,
        observe_digest: Callable[[AuthorizedPlan], Awaitable[str]],
        handlers: Mapping[str, TypedOperation],
    ) -> None:
        self.verifier = verifier
        self.replay = replay
        self.observe_digest = observe_digest
        self.handlers = dict(handlers)

    async def execute(self, request: SignedExecutorPlan) -> ExecutionReceipt:
        # Use a deep copy, not a caller-owned mutable parameters dictionary.
        plan = request.plan.model_copy(deep=True)
        # Reading current provider state is mandatory and owned by this executor.
        current_digest = await self.observe_digest(plan)
        self.verifier.authorize(request, current_digest)
        if plan != request.plan:
            raise ExecutorDenied("request mutated during authorization")
        handler = self.handlers.get(plan.operation)
        if handler is None:
            raise ExecutorDenied("no trusted handler for the approved operation")
        # Claim once, durably, before contacting the provider.
        self.replay.claim(plan)
        started = datetime.now(UTC)
        status = ExecutionStatus.ACCEPTED
        change_ids: list[str] = []
        try:
            change_ids = await handler(plan)
            if not isinstance(change_ids, list) or not all(isinstance(x, str) for x in change_ids):
                raise TypeError("handler returned invalid receipt identifiers")
        except Exception:
            # After claim, we cannot safely infer whether the provider acted.
            status = ExecutionStatus.UNKNOWN
        self.replay.record_outcome(plan, status.value, change_ids)
        return ExecutionReceipt(
            receipt_id=f"executor-{uuid4()}",
            adapter_id=plan.adapter_id,
            plan_id=str(plan.plan_id),
            resource=ResourceRef(
                provider=plan.adapter_id,
                kind=ResourceKind(plan.resource_kind),
                external_id=plan.resource_id,
                environment=plan.environment,
            ),
            status=status,
            started_at=started,
            external_change_ids=change_ids,
            message="Provider readback is required before marking execution verified.",
        )
