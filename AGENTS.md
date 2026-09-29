<!-- markdownlint-disable MD025 -->
<!-- BEGIN rules:spec:common -->

# Shared Rules

- Keep one coherent task per worktree, use worktree-local tool environments, and remove temporary worktrees and branches after landing.
- Maintain a real gitignored `<worktree>/tmp/` for scratch and task-local state. Managed-goal artifact bundles are owned and initialized by `$goal-prompt-optimizer`; do not create placeholder planning or goal files as a generic worktree preflight.
- Keep heavy or generated scratch assets outside the repository or in ignored `tmp/`; never commit `temp`, `tmp`, `_temp`, `_tmp`, `.tmp`, or `.temp` paths.
- Run relevant tests, builds, and checks before landing.
- **User-facing messages:** During substantive work, remain silent unless user input or approval is required. Do not announce starts or narrate routine actions, tool calls, or intermediate progress. Final reports should state only the outcome, relevant checks, and unresolved issues. Reduced narration must not reduce reasoning, investigation, execution, or verification.

<!-- END rules:spec:common -->
<!-- BEGIN rules:spec:coding -->

# Coding Baseline

- Default to `mre`: prefer no code when it safely satisfies the proven need; when existing code must change, make the smallest surgical, coherent change and preserve repo conventions, safeguards, and risk-proportional verification.
- Organize new production code into cohesive, idiomatic modules, packages, classes, or functions with clear ownership. Prefer feature/domain-first folders when no stronger convention exists; avoid flat dumps and generic catch-alls (`utils`, `helpers`, `common`, `misc`). Shared code needs a specific owner and purpose.
- Give modules narrow public entry points, private internals, acyclic dependencies, and shallow imports. Separate domain/policy logic from UI, transport, persistence, and integrations when they change or test independently.
- Use SOLID, separation of concerns, Clean Architecture, and established patterns when they reduce coupling or testing cost; do not add speculative layers or abstractions.
- For touched legacy code, improve boundaries when safe and proportional, never deepen structural debt, and reserve broad restructuring for explicit refactor scope.
- Prefer TDD/BDD. Follow repo test conventions; otherwise co-locate unit/component tests with their module and place integration/contract/E2E tests in dedicated suites. Keep fixtures/helpers near consumers until shared.
- **Integration tests must use isolated live environments** (sandboxed databases, test accounts, ephemeral services). Never run integration tests against a production runtime or data store.
- Prefer cohesive files ~300–500 lines; review 500+ and consider splitting 1,000+ unless generated, declarative, or inherently cohesive. Split by semantic boundary; keep co-changing code together.

<!-- END rules:spec:coding -->
<!-- BEGIN rules:local -->
<!-- END rules:local -->

Load on-demand specs: [`code-review`](~/.agents/skills/agent-md/assets/specs/code-review.md), [`sharia`](~/.agents/skills/agent-md/assets/specs/sharia.md), [`ts`](~/.agents/skills/agent-md/assets/specs/ts.md)
