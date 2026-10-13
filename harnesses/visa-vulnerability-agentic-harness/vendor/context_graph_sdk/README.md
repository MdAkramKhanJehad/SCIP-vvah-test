<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Context Graph SDK

A synchronous, Python-native SDK that analyzes local repositories into
immutable physical code-graph snapshots and queries them with strictly
read-only Cypher and bounded structured operations.

- One `Workspace` directory holds one physical graph database per accepted
  project snapshot plus one correlation/catalog database.
- `Workspace.analyze(repository, project_id)` extracts 17 Tree-sitter
  languages, resolves imports/calls/heritage/MRO, derives communities and
  processes, applies trusted plugins, and publishes atomically.
- `CodeGraph` offers `cypher()`, `schema()`, `context()`, `impact()`, and
  `correlations()` against the latest accepted snapshot.
- Raw Cypher executes in killable query-worker subprocesses with hard
  wall-clock, memory, row, and byte limits.
- Evidence-backed cross-project correlations are computed by workspace
  correlation providers and stored as lightweight endpoint references.

## Installation

This SDK ships inside the `vvaharness` distribution. Install vvaharness, then
`import context_graph_sdk`. Do not install the SDK separately: vvaharness
pins its runtime dependencies, so a separate install can resolve different
versions.

```python
from context_graph_sdk import Workspace
from context_graph_sdk.backends.arcadedb import ArcadeDBBackendFactory


def main() -> None:
    with Workspace("/path/to/workspace", ArcadeDBBackendFactory()) as workspace:
        graph = workspace.analyze("/path/to/repo", "my-service")
        print(graph.schema().labels)
        print(graph.context("main").callees)
        rows = graph.cypher(
            "MATCH (f:File)-[:DEFINES]->(s) RETURN f.filePath AS path, s.name AS name"
            " ORDER BY path, name"
        ).rows
        print(rows)


if __name__ == "__main__":
    main()
```

Symbol line numbers (`startLine`, `endLine`, and a selector's `line`) are
zero-based.

## Documentation

In vvaharness, [the architecture guide](../../docs/architecture.md#code-graph)
explains how a scan builds and queries the graph, and
[the integrations guide](../../docs/integrations.md) explains plugins.

## Backend dependency policy

The SDK pins `arcadedb-embedded`, `tree-sitter` and every Tree-sitter grammar
to exact versions, because its bundled queries are conformance-tested against
those versions.
Version changes require the complete backend and all-language conformance
suites. Inside vvaharness, the root `pyproject.toml` restates these pins and
governs what installs. Keep `tree-sitter` on its pinned release: a newer
release has caused native crashes while parsing larger source files.

## Deferred scope

BM25/regex/vector search, Neo4j, remote cloning, a packaged MCP server or CLI,
workspace-global or federated Cypher, built-in correlation heuristics,
incremental analysis, and a separate async API are explicitly deferred; the
backend, plugin, correlation, and index seams exist for them.
