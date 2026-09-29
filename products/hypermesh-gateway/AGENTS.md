# hypermesh-gateway package context

## Ownership
The hypermesh-gateway product implementation, its routes and tests. Use the package README for route, state, and OpenAPI details; do not infer another service owns this behavior.

## Public interface
Allowed shared imports and cross-package exceptions are defined in [`scripts/import_boundaries.json`](../../scripts/import_boundaries.json). No unrelated product may import this implementation. Event integration uses typed `controlplane_events` payloads on `controlplane.events.v1`; consult the package README and events module for publishers/consumers.
The contract is exact-module based, not permission to import every descendant.

## Source of truth
Start with [README.md](README.md) and the package's source/tests. Repository dependency policy: [../../AGENTS.md](../../AGENTS.md).

## Stop reading here
Start inside this package. Follow another package's context file only when the task crosses its interface; do not sweep unrelated product docs. Shared database migrations belong in `core/lib/controlplane-db`, shared API helpers in `core/lib/controlplane-core`, and event contracts in `core/events`. Cross-package edits must be justified by the requested change.
