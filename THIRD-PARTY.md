# AWS asm-exec provenance and retained terms

The files `scripts/repro/scripts/resolver/asm-exec.original` and `asm-exec-compat` include AWS upstream software under **Apache-2.0**. These upstream terms apply to this component; no repository-wide license grant is implied.

| Field | Verified source |
|---|---|
| Project | [AWS Agent Toolkit for AWS](https://github.com/aws/agent-toolkit-for-aws) |
| Source revision | [`af9a95cce54248a338f9be95f8ebd41ceafa3b73`](https://github.com/aws/agent-toolkit-for-aws/commit/af9a95cce54248a338f9be95f8ebd41ceafa3b73) |
| Source path | [`plugins/aws-core/skills/aws-secrets-manager/references/asm-exec`](https://github.com/aws/agent-toolkit-for-aws/blob/af9a95cce54248a338f9be95f8ebd41ceafa3b73/plugins/aws-core/skills/aws-secrets-manager/references/asm-exec) |
| Upstream identity | Amazon Web Services, as declared in [the plugin metadata](https://github.com/aws/agent-toolkit-for-aws/blob/af9a95cce54248a338f9be95f8ebd41ceafa3b73/plugins/aws-core/.claude-plugin/plugin.json) |
| Upstream plugin version at that revision | 1.1.0; this is plugin metadata, not a standalone script release |
| Original source bytes | 14,904 bytes; SHA-256 `38399ce2a9a2b5e69fc9179815d90669e80612ea1dfc4dc2d399db9608488035` |
| License | [Apache License 2.0, complete retained copy](LICENSES/Apache-2.0-aws-agent-toolkit.txt), from [this revision](https://github.com/aws/agent-toolkit-for-aws/blob/af9a95cce54248a338f9be95f8ebd41ceafa3b73/LICENSE) |
| Copyright notice | [Complete retained upstream NOTICE](LICENSES/NOTICE-aws-agent-toolkit.txt), from [this revision](https://github.com/aws/agent-toolkit-for-aws/blob/af9a95cce54248a338f9be95f8ebd41ceafa3b73/NOTICE) |

The distributed `asm-exec.original` is byte-identical to the pinned upstream source. The original has not been upgraded or modified in this edition. The local compatibility derivative is a separate file. Its pre-existing changes use the `run_script` MCP backend and asynchronous polling, response checks, a process-local cache, timeouts and sanitized diagnostics. Those differences do not represent an AWS-maintained release. This provenance check does not assign their authorship to a person.

Edition 4 adds only a prominent modification/provenance comment to `asm-exec-compat`; its executable Python AST is unchanged from the supplied edition 3. Both files retain the upstream Apache-2.0 terms and the applicable Amazon notice. No other repository notice replaces those terms.

The curated distribution's package version and the script's protocol/User-Agent strings are distinct from the pinned source revision. The source identity is repository, path, commit and byte hash. The pinned revision is not asserted to be the latest upstream version.

The upstream revision and byte hash above identify the original component. Historical review receipts are not included in this supporting-code edition.
