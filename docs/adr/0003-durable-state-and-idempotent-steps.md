# ADR-0003: Durable state, centralized transitions, idempotent steps
All run status changes go through `core.services.transition_run`: validated against `domain/states.py`, compare-and-swap
on the expected status, and written in one transaction with an event, an audit row and (where relevant) a notification.
Every step handler first checks the run is in the status it expects, so a replayed job after a crash is a no-op or a clean
continuation. Jobs have leases; a dead worker's job is re-queued after the lease expires. Retries use an idempotency key.
