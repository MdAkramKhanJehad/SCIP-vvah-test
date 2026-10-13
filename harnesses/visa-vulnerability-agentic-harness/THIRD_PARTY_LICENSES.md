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
# Third-Party License Inventory

vvaharness is licensed under Apache-2.0 (see `LICENSE`). It depends on the
third-party packages listed below. Most are installed from PyPI at install
time (`pipx install .` / `pip install .`). The Apache-2.0 context-graph-sdk
is vendored under `vendor/context_graph_sdk` and included in the project wheel;
its license text is retained there. The arcadedb-embedded dependency bundles
Java libraries and a runtime. This inventory is provided for transparency and
compliance review.

**Source:** the SPDX 2.3 SBOM generated on 2026-10-08 and the project's
`[project].dependencies` declarations. The snapshot contains **166 unique
third-party components**: 103 Python packages and 63 Maven components. The
scanner application record is excluded. The table lists the 37 direct runtime
dependencies with project version constraints and the SBOM's `licenseConcluded`
expressions; optional development and build dependencies are not included.
The remaining 129 components are 66 transitive Python packages and 63 bundled
Java components. This snapshot represents macOS/Python 3.14 artifacts, not
every supported platform. The vendored SDK and bundled JRE are not separate
package records in this SBOM and need separate notice review.

### Direct runtime dependencies

| Package                   | Version        | License      |
| ------------------------- | -------------- | ------------ |
| pydantic                  | >=2.13.5,<3    | MIT          |
| pydantic-settings         | >=2.15.0,<3    | MIT          |
| PyYAML                    | >=6.0.3,<7     | MIT          |
| anthropic                 | >=1.11.0,<2.0  | MIT          |
| openai                    | >=3.22.1,<4    | Apache-2.0   |
| httpx                     | >=0.28.1,<1    | BSD-3-Clause |
| httpx2                    | >=2.13.1,<3    | BSD-3-Clause |
| urllib3                   | >=2.8.0,<3     | MIT          |
| python-dotenv             | >=1.2.4,<2     | BSD-3-Clause |
| structlog                 | >=25.1.0,<27   | Apache-2.0 AND MIT AND (Apache-2.0 OR MIT) |
| typer                     | >=0.15.0,<1    | MIT          |
| rich                      | >=13.9.0,<15   | MIT          |
| typing_extensions         | >=4.16.0,<5    | PSF-2.0      |
| claude-agent-sdk          | >=0.2.163,<0.3 | MIT          |
| tree-sitter               | ==0.25.2       | MIT          |
| tree-sitter-language-pack | ==1.15.8       | MIT          |
| arcadedb-embedded          | ==26.10.1      | Apache-2.0   |
| tree-sitter-go             | ==0.25.0       | MIT          |
| tree-sitter-python         | ==0.25.0       | MIT          |
| tree-sitter-javascript     | ==0.25.0       | MIT          |
| tree-sitter-typescript     | ==0.23.2       | MIT          |
| tree-sitter-java           | ==0.23.5       | MIT          |
| tree-sitter-c-sharp        | ==0.23.5       | MIT          |
| tree-sitter-scala          | ==0.26.2       | MIT          |
| tree-sitter-c              | ==0.24.2       | MIT          |
| tree-sitter-cpp            | ==0.23.4       | MIT          |
| tree-sitter-rust           | ==0.24.2       | MIT          |
| tree-sitter-ruby           | ==0.23.1       | MIT          |
| tree-sitter-php            | ==0.24.1       | MIT          |
| tree-sitter-swift          | ==0.7.3        | MIT          |
| tree-sitter-dart           | ==0.1.0        | MIT          |
| tree-sitter-solidity       | ==1.2.13       | MIT          |
| deepagents                | >=0.7.21,<0.8  | MIT          |
| langchain                 | >=1.4.3,<2     | MIT          |
| langchain-anthropic       | >=1.7.5,<2     | MIT          |
| langchain-openai          | >=1.6.7,<2     | MIT          |
| langgraph                 | >=1.2.12,<2    | MIT          |

The remaining 129 components include transitive Python and bundled Java dependencies
(e.g. `anyio`, `annotated-types`, `h11`, `httpcore`, `idna`, `sniffio`,
`distro`, `pydantic-core`, `packaging`, `requests`, `starlette`, and
`websockets`). JPype1 1.7.1 (Apache-2.0) supplies the native JVM bridge.
Bundled Java components include ArcadeDB 26.10.1, Micrometer
core/commons/observation 1.17.1, Lucene 10.5.1, and GraalVM SDK artifacts
25.2.4. Recorded expressions are mostly permissive: MIT, MIT-0, BSD,
Apache-2.0, PSF-2.0, CNRI-Python, ISC, ICU, Python-2.0, 0BSD, and UPL-1.0.
`certifi` and `orjson` include MPL-2.0 terms; JTS includes EPL/EDL terms.
ArcadeDB Studio includes CC-BY-4.0 and OFL-1.1 alongside code licenses.
`LicenseRef-*` identifiers require their associated extracted license text.
Declared and concluded expressions differ for 108 package records; many
declared expressions contain `LicenseRef-Not-Supported`. Scanner conclusions
are evidence for review, not legal approval or proof that all notices are met.

The installed arcadedb-embedded 26.10.1 runtime reports OpenJDK 25.0.4.1.
Its `arcadedb_embedded/jre/legal/java.base/LICENSE` contains GPL v2 with the
Classpath Exception. The OpenJDK Assembly Exception, additional license
information, and third-party notices under each `jre/legal/` module also
apply. These runtime terms are not represented by the Python wheel's Apache-2.0
package label or the SBOM's Maven records. Preserve and review those notices
before redistribution; the SBOM alone is not a complete runtime-license review.

The `deepagents` declaration additionally requires `python_version >= '3.11'`,
which is already the project's supported Python floor.
