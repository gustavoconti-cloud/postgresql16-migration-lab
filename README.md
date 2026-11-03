# PostgreSQL 16 migration laboratory

Supporting code for a synthetic PostgreSQL migration laboratory using Amazon RDS and AWS DMS. The laboratory explores full load, change data capture, controlled row mismatches, writer barriers, cutover evidence, and the limits of returning to the source after exclusive target writes.

## Scope

This repository is a curated supporting-code edition. It does not include the article manuscript, editorial correspondence, invoices, historical AWS exports, or private audit notes. Examples use synthetic identifiers and start without environment bindings. It is not a production migration product or a guarantee of recovery time, throughput or cost.

Start with [the reproduction guide](scripts/repro/README-repro.md). The guide distinguishes historical laboratory observations, offline control revisions and work an operator must validate in a new environment.

## Safety and cost

Use only a disposable, explicitly authorized non-production AWS account and synthetic data. Review every generated template and command. Some scripts create billable resources or delete laboratory resources; none should be run merely to browse this repository. Empty example configuration deliberately refuses execution.

The inherited budget values are validation settings, not spending approval or a billing cap. The rates file is an October 2026 historical snapshot, not a current quotation. Check current service availability, prices, permissions, expiry and cleanup before running anything. Do not commit filled configuration, credentials, generated readbacks or exports.

No AWS infrastructure was created or tested for this publication. Offline checks do not establish production readiness. Prepared transactions, other writer identities and ambiguous commit outcomes require explicit validation beyond the historical demonstrations.

## Local checks

Use a disposable copy and an isolated Python environment with the dependencies in `scripts/repro/requirements-local.txt`. The regression suite writes synthetic fixtures and receipts.

```sh
python -B scripts/repro/qa/test_cutover_revision.py
python -B scripts/repro/qa/test_repro.py
```

The scripts target the runtime documented in the reproduction guide. Preserve assertions: do not use Python `-O`.

## Rights and third-party components

No new open-source or Creative Commons license is granted by this repository pending the author's licensing decision. Public visibility alone is not a repository-wide reuse license. Existing third-party terms remain applicable: see [THIRD-PARTY.md](THIRD-PARTY.md), [NOTICE](NOTICE), and `LICENSES/`. The AWS resolver retains Apache-2.0 and its original copyright notice. The bundled RDS PEM is public CA trust material, not a private key.
