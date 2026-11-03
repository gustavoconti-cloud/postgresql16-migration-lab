# PostgreSQL 16 migration laboratory

Supporting code for a synthetic PostgreSQL migration laboratory using Amazon RDS and AWS DMS. The laboratory explores full load, change data capture, controlled row mismatches, writer barriers, cutover evidence, and the limits of returning to the source after exclusive target writes.

## Scope

This repository is a curated supporting-code edition. It does not include the article manuscript, editorial correspondence, invoices, historical AWS exports, or private audit notes. Examples use synthetic identifiers and start without environment bindings. It is not a production migration product or a guarantee of recovery time, throughput or cost.

Start with [the reproduction guide](scripts/repro/README-repro.md). The guide distinguishes historical laboratory observations, offline control revisions and work an operator must validate in a new environment.

## Safety and cost

Use only a disposable, explicitly authorized non-production AWS account and synthetic data. Review every generated template and command. Some scripts create billable resources or delete laboratory resources; none should be run merely to browse this repository. Empty example configuration deliberately refuses execution.

The inherited budget values are validation settings, not spending approval or a billing cap. The rates file is an October 2026 historical snapshot, not a current quotation. The runtime estimator also contains auxiliary rate constants; review both `scripts/repro/rates/cost-scenarios.json` and `scripts/repro/scripts/verification/estimate_runtime_cost.py` before using a new cost estimate. Check current service availability, prices, permissions, expiry and cleanup before running anything. Do not commit filled configuration, credentials, generated readbacks or exports.

No AWS infrastructure was created or tested for this publication. Offline checks do not establish production readiness. Prepared transactions, other writer identities and ambiguous commit outcomes require explicit validation beyond the historical demonstrations.

## Quick start: local checks only

Prerequisites: Git and Python 3.12. Clone into a disposable working directory; the tests write synthetic fixtures and receipts. Installing the pinned dependencies requires internet access. The tests themselves run offline and do not need AWS credentials, an AWS account or the AWS CLI.

```sh
git clone https://github.com/gustavoconti-cloud/postgresql16-migration-lab.git
cd postgresql16-migration-lab
python3.12 -m venv .venv
.venv/bin/python -m pip install -r scripts/repro/requirements-local.txt
.venv/bin/python -B scripts/repro/qa/test_cutover_revision.py
.venv/bin/python -B scripts/repro/qa/test_repro.py
```

On Windows PowerShell, replace the last four commands with:

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r scripts/repro/requirements-local.txt
& .\.venv\Scripts\python.exe -B scripts/repro/qa/test_cutover_revision.py
& .\.venv\Scripts\python.exe -B scripts/repro/qa/test_repro.py
```

Both suites should finish with `OK`: 19 cutover-regression methods and 19 reproduction-regression methods. These include additional nested checks and template linting. Preserve assertions: do not use Python `-O`. These results validate the local checks, not a live migration.

## Repository layout

- `scripts/repro/README-repro.md`: operator guide for a separately authorized AWS laboratory run, including cleanup.
- `scripts/repro/*.example.json`: unbound example configurations; do not use them as evidence of a real environment.
- `scripts/repro/scripts/`: infrastructure builders, migration controls, harness, resolver, cleanup and verification code.
- `scripts/repro/qa/`: offline regression suites.
- `scripts/repro/rates/`: dated public-rate snapshot and hypothetical cost scenarios.
- `LICENSES/`, `NOTICE` and `THIRD-PARTY.md`: retained third-party terms and provenance.

## Rights and third-party components

No new open-source or Creative Commons license is granted by this repository pending the author's licensing decision. Public visibility alone is not a repository-wide reuse license. Existing third-party terms remain applicable: see [THIRD-PARTY.md](THIRD-PARTY.md), [NOTICE](NOTICE), and `LICENSES/`. The AWS resolver retains Apache-2.0 and its original copyright notice. The bundled RDS PEM is public CA trust material, not a private key.
