<!-- markdownlint-disable MD025 -->
<!-- BEGIN rules:spec:common -->

# Shared Rules

- **Worktree isolation:** Never edit, stage, or commit directly on `main`; switch into a dedicated `<repo>/worktrees/<name>/`, keep `/worktrees/*` ignored, and follow runtime skill naming, branching, and reconcile rules.
- Keep one coherent task per worktree, use worktree-local tool environments, and remove temporary worktrees and branches after landing.
- Maintain a real gitignored `<worktree>/tmp/`; before editing, ensure `tmp/tasks.md` and `tmp/plan.md` exist and are ignored, creating or updating them before implementation. Keep `tmp/plan.md` nonempty and `tmp/tasks.md` as the canonical ledger with no incomplete items before landing.
- Keep heavy or generated scratch assets outside the repository or in ignored `tmp/`; never commit `temp`, `tmp`, `_temp`, `_tmp`, `.tmp`, or `.temp` paths.
- **Git operation consent:** Routine completion does not authorize review, commit, merge, push, or landing; perform them only when explicitly requested or when a repository rule requires them.
- Run relevant tests, builds, and checks before landing.
- **User-facing messages:** At substantive start, briefly state what/why/how. Then communicate only for changed direction or needed input, approval, or awareness. Final reports should state outcome, checks, and unresolved issues; omit routine narration, logs, diffs, and repetition unless needed or requested.

<!-- END rules:spec:common -->
<!-- BEGIN rules:spec:coding -->

# Coding Baseline

- Default to `mre`: solve the proven need with the smallest safe rung—no change, deletion, reuse, platform/stdlib, installed dependency, new code, then new dependency. Keep edits scoped and follow repo idioms.
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
