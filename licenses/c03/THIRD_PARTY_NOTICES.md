# AiDA C03 Third-Party Notices

This ledger is the source-controlled aggregation index for C03 dependencies. `aida_c03_stage_notices` copies pinned production license files and extracts the hash-bound managed package notice entries into the customer notice directory. `aida_c03_stage_evidence_notices` copies evidence-only notices into a separate developer evidence notice directory. A source, archive-entry, or license hash mismatch is a fatal packaging error.

| Component | Version | Decision | License | Pinned local license source |
|---|---|---|---|---|
| Zydis | 4.1.1 | production | MIT | `.deps/zydis-4.1.1/LICENSE` |
| Zycore | bundled with Zydis 4.1.1 | production | MIT | `.deps/zydis-4.1.1/dependencies/zycore/LICENSE` |
| Capstone | 5.0.9 | production | BSD-style | `.deps/capstone/capstone-5.0.9/LICENSE.TXT` |
| Taskflow | local pinned source | production | MIT | `.deps/taskflow/LICENSE` |
| Ghidra decompiler components | local pinned source | production worker | Apache-2.0 | `src/standalone/third_party_notices/Ghidra-LICENSE.txt` and `Ghidra-NOTICE.txt` |
| Triton | local pinned source | production thorough-only | Apache-2.0 | `sources/Triton/LICENSE.txt` |
| Z3 | 4.13.4 | production thorough-only | MIT | `.deps/z3/z3-4.13.4-x64-win/LICENSE.txt` |
| SQLite | 3.53.3 | production | public domain | `SQLite-Public-Domain.txt` and `.deps/sqlite-amalgamation-3530300/sqlite3.c` provenance header |
| Dear ImGui | local pinned source | production | MIT | `.deps/imgui-src/LICENSE.txt` |
| zlib | 1.3.2 | production | zlib | `.deps/zlib-1.3.2/LICENSE` |
| Zstandard | 1.5.7 | production | BSD-3-Clause | `.deps/zstd-1.5.7/LICENSE` |
| liblzma minimal subset | 5.8.3 | production | 0BSD | `.deps/xz-5.8.3/COPYING.0BSD` |
| minizip-ng | 4.2.2 | production read-only | zlib | `.deps/minizip-ng-4.2.2/LICENSE` |
| PCRE2 | 10.47 | production 8-bit no-JIT | BSD-3-Clause WITH PCRE2-exception | `.deps/pcre2-10.47/LICENCE.md` |
| nlohmann JSON | 3.12.0 | production | MIT | `.deps/licenses/nlohmann-json-3.12.0-LICENSE.MIT` |
| nlohmann JSON Schema Validator | 2.4.0 | production | MIT | `.deps/json-schema-validator-2.4.0/LICENSE` |
| LLVM Demangle and Support | 22.1.8 | production | Apache-2.0 WITH LLVM-exception | `.deps/llvm-project-llvmorg-22.1.8/LICENSE.TXT` |
| Microsoft.NETCore.App | 10.0.9 win-x64 | production managed worker runtime | Microsoft .NET Library License plus third-party notices | `.deps/dotnet-sdk-10.0.301-win-x64/LICENSE.txt` and `.deps/dotnet-sdk-10.0.301-win-x64/ThirdPartyNotices.txt` |
| .NET SDK | 10.0.301 | build-only | Microsoft .NET Library License | `.deps/dotnet-sdk-10.0.301-win-x64/LICENSE.txt` |
| PyInstaller | 6.21.0 | build-only frozen Camoufox reverse-MCP freezer | GPL-2.0-or-later with bootloader exception | `.deps/.camoufox-reverse-mcp-build-venv/Lib/site-packages/pyinstaller-6.21.0.dist-info/licenses/COPYING.txt` |
| ICSharpCode.Decompiler | 10.1.0.8386 | production managed worker | MIT | `.deps/nuget-offline/ICSharpCode.Decompiler.10.1.0.8386.nupkg` package metadata declares `MIT` |
| System.Collections.Immutable | 9.0.0 | production managed worker | MIT plus third-party notices | `.deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg::LICENSE.TXT` and `.deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg::THIRD-PARTY-NOTICES.TXT` |
| System.Reflection.Metadata | 9.0.0 | production managed worker | MIT plus third-party notices | `.deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg::LICENSE.TXT` and `.deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg::THIRD-PARTY-NOTICES.TXT` |
| LIEF | 0.17.6 | evidence-only | Apache-2.0 | `.deps/LIEF-0.17.6/LICENSE` |
| Remill | 6.0.1 | evidence-only | Apache-2.0 | `.deps/remill-6.0.1/remill-6.0.1/LICENSE` |

LMDB and Unicorn are C03 non-use decisions. Neither is linked by C03 targets, shipped by C03 packaging, or included in customer notices. LIEF and Remill remain evidence-only and their notices are staged only through `aida_c03_stage_evidence_notices`. Camoufox and the frozen Camoufox reverse-MCP executable remain existing protected customer sidecars; their established notice chain remains unchanged and their pinned artifact hashes are preserved in `packaging/c03_worker_manifest.lock.json`.
