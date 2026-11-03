# Supporting-code edition notice

This directory contains a curated subset of the editor-review package. The manuscript, historical evidence, editorial reviews and original package manifests are intentionally not included. References below to historical runs describe the original laboratory and are not a claim that this repository was deployed or revalidated on AWS. No new license grant is made by this publication; third-party terms remain in force.

# Reproducing the PostgreSQL 16 migration laboratory

This reproduction copy contains the laboratory's CloudFormation builders, harness and controls, with targets declared in one local configuration file. It contains no credentials, AWS profile, account ID or ARN from the original execution. Source hashes and diffs are retained in the private provenance record.

The original reproduction copy was validated **offline** using two synthetic account/prefix contexts, barrier tests, import/help checks, deterministic generation and cfn-lint. This edition adds local corrections to approval-time metric freshness and the treatment of an unresolved DML outcome during return. The actual R01/R02 laboratory runs remain historical evidence; the revised controls were tested offline, without another AWS deployment. See the revision notes (not distributed in this supporting-code edition) for the boundary between those results.

See runtime-notes.md (not distributed in this supporting-code edition) for the observed local and remote versions, and provenance-summary.json (not distributed in this supporting-code edition) for source and reproduction-copy hashes.

## 1. Environment and explicit configuration

All commands in this guide assume the current working directory is `scripts/repro`. From the repository root, run `Set-Location scripts/repro` in PowerShell first. The root README uses repository-root paths for its separate offline quick start.

Use Windows/PowerShell, Python 3.12, AWS CLI v2 and a valid temporary session in the authorized POC/HML account. The region remains `us-east-1`. Install dependencies in a dedicated virtual environment; no cache or runtime is distributed.

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r .\requirements-local.txt
Copy-Item .\config.example.json .\config.json
$env:PG_LAB_CONTEXT = (Resolve-Path .\config.json).Path
$LabPython = (Resolve-Path .\.venv\Scripts\python.exe).Path
```

Fill in `profile`, `expected_account_id`, `prefix`, `resource_run_id`, `expires_at` and `owner` in `config.json`. Null values are rejected. The UTC expiry must be in the future and no more than 72 hours away. The source contains a US$1,000 validation ceiling and a lower operating envelope. These are inherited laboratory settings, not authorization to spend; obtain your own budget approval and configure a lower limit when appropriate. Financial alerts are delayed and do not impose an exact billing cap.

`resource_run_id` identifies resource ownership and remains unchanged throughout the reproduction. `run_id` identifies the test ledger and changes from `RUN-01` to `RUN-02`. `evidence_run_ids` lists those two ledgers. Changing the ledger does not change ownership tags.

`bindings` starts with no targets. Populate it from readbacks of the new execution, never from example evidence. For resources that already exist, the scripts check the account, region, prefix, immutable ARN and ownership tags; they do not automatically select an account or production environment. Use `python -B`, without `-O`, to preserve the controllers' original assertions.

```powershell
& $LabPython -B .\scripts\control\aws_context.py validate
$Lab = Get-Content $env:PG_LAB_CONTEXT -Raw | ConvertFrom-Json
$LabIdentity = aws sts get-caller-identity --profile $Lab.profile --region $Lab.region | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $LabIdentity.Account -ne $Lab.expected_account_id -or $LabIdentity.Arn -match ':root$') { throw 'AWS identity mismatch.' }
```

Repeat this check before every write phase. Always pass the profile and region to the CLI. Importing local modules neither authenticates nor calls AWS; controllers that use AWS create a session only when needed.

## 2. New private infrastructure

Recheck the availability of PostgreSQL 16.15, DMS 3.6.1, instance classes, the Canonical AMI and Availability Zones. The template retains the tested scenario: Ubuntu 24.04 on EC2 `t3.small`, RDS `db.t4g.small`, DMS `dms.t3.medium`, a dedicated VPC, Single-AZ deployment, two private subnet groups, temporary NAT/EIP resources and SSM. Review the scope and record the change before substituting versions.

Check the standard `dms-vpc-role` and `dms-cloudwatch-logs-role` roles. If they already exist and are suitable, set `create_dms_vpc_role=false` and/or `create_dms_logs_role=false`; this copy neither adopts them into the stack nor deletes them later. If a flag is `true`, the corresponding role must be absent. Preserve shared resources.

```powershell
& $LabPython -B .\scripts\infra\build_template.py
& .\.venv\Scripts\cfn-lint.exe -t .\scripts\infra\postgres-migration-lab.template.json -r us-east-1
```

Create a Change Set for stack `$Lab.prefix` using the generated template, `CAPABILITY_NAMED_IAM` and all six tags: `Environment=HML`, `Project=postgresql-migration-lab`, `Owner`, `ManagedBy=migration-lab-toolkit`, `RunId=resource_run_id` and `ExpiresAt`. Review resources, permissions, cost and exclusions before executing the Change Set. These are AWS operations performed by an authorized operator; the builders only write local files.

Save the complete `describe-stacks` readback, containing exactly one stack in `CREATE_COMPLETE`/`UPDATE_COMPLETE`, its tags and its outputs. A value map with no recorded origin is insufficient.

```powershell
aws cloudformation describe-stacks --stack-name $Lab.prefix --profile $Lab.profile --region $Lab.region --output json | Set-Content .\main-readback.json -Encoding utf8
& $LabPython -B .\scripts\control\aws_context.py bind --kind main --readback .\main-readback.json --output .\config.json
```

The local binding step imports the stack ARN, private IP addresses, RDS DNS name, four secret ARNs, EC2 role and DMS instance. Check SSM `Online` status and `/var/lib/postgresql-migration-lab/bootstrap.ready.json`; stack completion alone does not prove that bootstrap is ready.

## 3. Certificate, migration and guardrail

`scripts/control/us-east-1-bundle.pem` is the public regional CA bundle, never a private key. Confirm its origin and currency before importing it into DMS. Use identifier `${prefix}-rds-ca` and the same tags, then save the returned ARN in `bindings.certificate_arn`.

```powershell
$Lab = Get-Content $env:PG_LAB_CONTEXT -Raw | ConvertFrom-Json
& $LabPython -B .\scripts\migration\build_migration.py --main-outputs .\main-readback.json --certificate-arn $Lab.bindings.certificate_arn --prefix $Lab.prefix
```

Create and review the `${prefix}-migration` Change Set using `migration.template.json` and `migration.parameters.json`. The task is created without starting automatically. After the Change Set executes and completes, save that stack's `describe-stacks` output and import it:

```powershell
& $LabPython -B .\scripts\control\aws_context.py bind --kind migration --readback .\migration-readback.json --output .\config.json
& $LabPython -B .\scripts\control\aws_context.py policy --output .\scripts\guardrails\teardown.bootstrap.policy.json
```

Generate the separate `${prefix}-guardrail` stack with `build_guardrail.py`, passing the main stack's `--target-stack-arn`, `--run-id resource_run_id`, `--expires-at`, `--deletion-policy-file`, `--migration-stack-arn`, `--certificate-arn` and `--replication-task-arn`. Use `--help` for the complete option names. Validate with cfn-lint and a Change Set. The bootstrap policy is provisional: `tighten_policy.py` narrows it to the exact IDs in complete CloudFormation inventories. Do not assume an inventory needs no pagination. Review and apply the restricted version before the rehearsals.

After the guardrail completes, save its `describe-stacks` output and run `aws_context.py bind --kind guardrail`. Check the Lambda with `operation=probe`; the probe is read-only and does not demonstrate deletion. An optional budget must not be described as a spending block.

## 4. Remote installation and database preparation

Generate the remote configuration without secrets:

```powershell
& $LabPython -B .\scripts\control\aws_context.py runtime --output .\scripts\control\runtime-config.json
& $LabPython -B .\scripts\control\stage_actions.py install-runtime --install-runtime
```

The second command generates `scripts/control/install-runtime.sh`; it does not submit it. Review the script and submit it with `ssm_runtime.py submit ... --label install-runtime`. The target is obtained from the main stack, and its tags are checked. Installation copies the harness, wrapper and approved resolver, runs bootstrap on EC2 and prints hashes for comparison. The compatibility copy is installed as `/opt/pg-lab/harness/asm-exec`. The original is distributed separately for provenance; it is not a silent fallback.

The wrapper retains the approved in-memory resolution of dynamic references, account/role guard, child-only environment, timeout and sanitized errors. Do not replace it with manual `SecretString` retrieval, print the environment or send passwords.

A remote action can be prepared, reviewed, submitted and read back as follows:

```powershell
& $LabPython -B .\scripts\control\stage_actions.py RUN-01-prepare '[["prepare-source"],["prepare-target"],["configure-hba"]]'
& $LabPython -B .\scripts\control\ssm_runtime.py submit .\scripts\control\RUN-01-prepare.sh --label RUN-01-prepare
& $LabPython -B .\scripts\control\read_stage.py RUN-01-prepare '<returned-command-id>' --compact
```

`stage_actions.py` only generates a script; `ssm_runtime.py submit` and `run_stage.py` write remotely. Labels must be unique and identify the ledger, for example `RUN-01`. Each batch permits at most eight actions. Read the child process's exit code and every receipt as well as the SSM status.

Confirm eight source rows, an empty target, matching catalogs and primary keys, TLS, logical replication parameters, the DMS `/32` HBA rule and a blocked target writer returning `42501` inside a rolled-back transaction. Confirm effective `rds.force_ssl` in the applied parameter group, or test that a connection without TLS is rejected. The runtime uses `require` for the source and `verify-full` for RDS; these are different assurance levels.

Test the endpoints with `dms_step.py test-connections --label ...` and wait until both report `successful`. Use `start` only when the task is `ready`, the target is empty and the correct barriers are in place. Read `inspect` until full load and native validation complete. Run the harness's `inspect`/`compare` actions and retain evidence of full equality. This is G3.

## 5. CDC, divergence, two cutovers and return

Run one action and its observation at a time: `t01`/`observe --test T01`, then `t02`/T02 and `t03`/T03. Compare every column. Expected changes are an INSERT of ID 201, an UPDATE of ID 102 and a DELETE of ID 103, leaving eight rows with a total of 937.31 after all three operations.

Run `diverge-target` and `compare`, request `dms_step.py revalidate`, and retain a new native mismatch result. The `note` column for ID 106 differs while the count and sum remain equal. Repair it with `correct-divergence` on the source, observe the change, compare, and request a new clean validation. An old `Validated` state cannot approve a new snapshot.

For G6a, run `marker-901`, `freeze-source`, `freeze-target` and `observe --test T05-marker-901`. Request revalidation after the marker. Collect two new metric samples with `dms_step.py metrics`, a native `inspect` result and complete logs with `collect_dms_logs.py --since <freeze-UTC>`. Wait for fresh metrics, drained queues, zero failures or pending records and full equality. Missing data is not zero.

The G6 metric contract uses 60-second periods and `Maximum` statistics for `CDCIncomingChanges`, `CDCLatencySource` and `CDCLatencyTarget`. All three metrics must share two distinct timestamps after both the writer freeze and marker observation. `CDCIncomingChanges/Maximum` must be zero: this means zero captured events waiting to be applied to the target in the selected samples, not zero source transaction activity. Source and target latency maxima must each be at most 5 seconds, with a change of at most 1 second between samples. Native validation must follow the new revalidation request, and complete, paginated logs must cover the gate window. Clean G6 windows do not establish an error-free entire DMS history.

**Historical timing:** in R01/R02, the proof generator checked the two sample ages against 240 seconds. The harness then checked only that the proof itself was no more than 600 seconds old; it did not recalculate each sample's age. The oldest sample exceeded 240 seconds at approval in three of the four recorded gates. The historical timing review (not distributed in this supporting-code edition) preserves the timestamps and calculations.

**Revised local control:** this edition also checks both selected sample timestamps against the exact timestamp recorded for G6 approval. Both must still be within 240 seconds; missing, malformed, duplicate or excessively future timestamps fail. The 600-second proof limit remains an additional check. The revised rule and its tests do not retroactively change the historical approvals. Regenerate expired evidence before retrying a future gate.

Copy `g6-inputs.example.json` into `scripts/evidence/`, then fill in the run/task and the actual names of all eleven receipts. `make_g6_proof.py --inputs ... --output ...` checks timestamps, markers, counters, paginated logs and hashes. The proof must be recent and belong to the same run/task. Transfer it without changing its bytes:

```powershell
& $LabPython -B .\scripts\control\stage_actions.py RUN-01-g6a-record '[["record-g6","--proof","/opt/pg-lab/evidence/RUN-01-g6a-proof.json"],["compare"]]' --proof .\scripts\evidence\RUN-01-g6a-proof.json
```

Submit and read back that stage. Stop the task with `dms_step.py stop`, confirm `stopped`, and run `prewrite-return`. Failure of the read-only smoke test is explicitly simulated. Only the source is reopened, and it receives ID 211. The revised return entrypoint refuses any unresolved `pending_dml` before checking an earlier receipt or changing writer permissions. With no pending outcome, an idempotent response for an earlier T07 return is explicitly historical; it is not a fresh authorization to reopen the source.

Continue with `dms_step.py resume` (`resume-processing`), observe ID 211, write marker 902, and repeat the entire G6 sequence with a new proof. Stop the task, confirm `stopped`, and run `open-target`. Run `postwrite-insert`, compare, run `postwrite-update` and `postwrite-delete`, compare again, then run `freeze-target`. Preserve the first commit of row 301 and differences involving IDs 104/105/301; the source remains frozen. `prewrite-return` must be refused after that commit. Exit code 2 in this attempt is the expected negative result, not authorization to repeat the preceding commits.

## 6. Export, clean replay and teardown

`export_evidence.py prepare --tag R01 --directory <new-directory>` generates a self-contained remote script. Submit its `build.sh`, then read the descriptor and every chunk with the `read --kind descriptor`/`read --kind part` subcommands before running `finish`. The helper documents its options in `--help`; it checks lengths, hashes, JSON/UTF-8, the allowlist and the absence of secret fields/values. The export retains complete data and ledgers, not just counts.

For example, use a new local directory for R01. Review each generated script before submitting it through the existing SSM workflow; use unique labels and the command IDs returned by those submissions:

```powershell
$R01Export = '.\exports\RUN-01'
& $LabPython -B .\scripts\control\export_evidence.py prepare --tag R01 --directory $R01Export
& $LabPython -B .\scripts\control\ssm_runtime.py submit "$R01Export\build.sh" --label RUN-01-export-build
& $LabPython -B .\scripts\control\export_evidence.py read --tag R01 --directory $R01Export --kind descriptor --command-id '<build-command-id>'
& $LabPython -B .\scripts\control\ssm_runtime.py submit "$R01Export\commands\part-0000.sh" --label RUN-01-export-part-0000
& $LabPython -B .\scripts\control\export_evidence.py read --tag R01 --directory $R01Export --kind part --part 0 --command-id '<part-0000-command-id>'
```

The descriptor declares `part_count` and generates `commands/part-0000.sh` onward. Repeat the submission and `read --kind part` step for **every** index from zero through `part_count - 1`, using its corresponding generated script, unique label and command ID. Only after every part is present, run:

```powershell
& $LabPython -B .\scripts\control\export_evidence.py finish --tag R01 --directory $R01Export
```

Repeat with tag R02, a new directory and labels for `RUN-02`. If `read_stage.py` reports pending chunk transport, retain the manifest and use the complete export to recover the receipts; compact output alone is insufficient. Open the external copy and verify its hashes before any reset or teardown. This supporting-code edition includes no historical export receipts, private export files or transport. Preserve and verify your own execution evidence, as explained in the [package README](../../README.md).

For R02, change **only** `run_id` to `RUN-02` in the local context and regenerate `runtime-config.json`. Preserve `resource_run_id`, stacks, tags and R01 evidence. Use `reset-for-replay --archived-evidence <preserved-remote-JSON> --acknowledge-discard-synthetic-data`; this discards only the authorized synthetic dataset. The target must become empty. Deliberately run `dms_step.py reload`, confirm G3 and run `open-source-for-replay`, then repeat the core sequence with new labels. Export R02 as well. This reset is not a rollback that preserves exclusive target commits, and no reverse replication is supplied.

Before teardown, run `verification/verify_cleanup.py --mode full-baseline --output ...` and add exact external resources with `extra-resources.example.json`: the certificate and log groups. If the account created GuardDuty auxiliaries in the dedicated VPC, bind their IDs/ENIs/subnets from the inventory in `bindings`. If none exist, empty lists still require evidence. Deletion targets are never discovered through wildcards.

```powershell
& $LabPython -B .\scripts\verification\verify_cleanup.py --mode full-baseline --extra-manifest .\extra-resources.json --output .\scripts\verification\before-teardown.json
& $LabPython -B .\scripts\control\cleanup_lab.py --step probe --baseline .\scripts\verification\before-teardown.json
```

`extra-resources.json` is a completed copy of the example. Also copy `cleanup-evidence-receipt.example.json` to create a reviewed receipt: `account` is the configured account, `run_id` is **resource_run_id**, the timestamp is recent UTC, and every external file must exist, open correctly and match its SHA-256. Explicitly configure `preserved_evidence_root` in `config.json`; relative paths are resolved from that configuration file's directory. For example, under `scripts/repro/`, `../../evidence` identifies the package's evidence directory. Receipt paths are relative to that root or absolute within it; any escape is rejected. Mark gates/captures only after reviewing the corresponding R01/R02 evidence. The example's null values and false gates prevent deletion.

`cleanup_lab.py` starts with `--step probe`, which does not write. Executing each step requires `--execute`, a complete baseline and `--evidence-receipt` with externally preserved gates, files and hashes. Follow this order: stop the task, delete the migration stack and certificate, terminate the source, remove dedicated auxiliaries, delete the main stack and DMS logs, and delete the guardrail last. Wait for each dependency to be deleted. There is no `all` mode, forced detach or GuardDuty configuration change.

A `terminated` instance may remain as a tombstone and omit `VpcId`. This branch is accepted only with the exact ID, all six ownership tags frozen in the baseline, the stack ARN/CloudFormation logical ID and expected disks. If `Code` is present, its low byte must be 48, as defined by the [EC2 InstanceState API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceState.html). The receipt retains an unknown VPC as `null`. A present but incorrect VPC, or a live/`shutting-down` instance without the exact VPC, still blocks dependent steps.

Confirm absence with `verify_cleanup.py --mode final --baseline ... --output ...`, by service and tag. Any retained resources need a declared retention period and cost. `estimate_runtime_cost.py` calculates an estimate from runtime duration. `rates/cost-scenarios.json` is the snapshot from October 15, 2026 and must be refreshed before a future execution. An estimate, currently available cost data and the final invoice remain separate.

When binding `--cleanup-inventory`, the estimator requires a `final` receipt with the same account, region, **resource_run_id**, identity and three stack ARNs as the context. It also requires boolean `cleanup_verified=true`, explicitly empty errors/residuals, a complete baseline with resources, and checks containing neither unknown states nor live resources. Strings such as `"false"`/`"true"`, a receipt from another scope or a partial inventory are rejected; they do not produce `lab_deleted_verified=true`. Without an accepted final receipt, the estimate continues to flag possible ongoing cost.

Supply `--nat-gb` and `--vpce-gb` only when those volumes have been measured. If they are unknown, omit the flags and disclose the gap: this estimator defaults omitted volumes to numeric zero for calculation, **not** as evidence of zero traffic. Its auxiliary reserve is an allowance rather than measured usage. Preserve that distinction when reporting the estimate; do not fill unknown measurements with observed zeros or present the result as a verified invoice.

## Verification checklist

Use this single checklist alongside the procedure above. Rows 1–13 cover the workflow exercised in R01/R02, with the later local corrections explicitly identified for G6 recording and return. Their pass criteria describe this edition's procedure, not a claim that the original runs used the revised controls. Row 14 covers offline tests; the final two rows distinguish untested runtime scenarios from local guards. The article (not distributed in this supporting-code edition), evidence matrix (not distributed in this supporting-code edition) and claims matrix (not distributed in this supporting-code edition) provide the historical results and their limits.

Run commands from this README's directory. Table references to control entrypoints use `scripts/control/` and the `& $LabPython -B` invocation shown above. Harness actions follow the prepare → review → SSM submission → readback workflow in [Section 4](#4-remote-installation-and-database-preparation). Give every remote operation a unique label. Entries describing future checks do not report that those checks have been run.

| Verification | Why it matters | How to run | Pass criterion |
| --- | --- | --- | --- |
| Account, region and ownership — new context required | Prevents a write or deletion in the wrong account or run. | Follow [Section 1](#1-environment-and-explicit-configuration): [aws_context.py](scripts/control/aws_context.py) `validate`, then `aws sts get-caller-identity --profile $Lab.profile --region $Lab.region`. Bind complete stack readbacks after creation. | Configured account, non-root principal, `us-east-1`, future expiry within 72 hours and authorized ceiling no higher than US$1,000. Existing targets match immutable bindings and ownership tags; initial bindings are empty. |
| Private infrastructure, bootstrap and database prerequisites | Stack completion alone does not prove a usable, restricted database. | Run [build_template.py](scripts/infra/build_template.py) and cfn-lint as in [Section 2](#2-new-private-infrastructure). Check SSM `Online`/bootstrap readiness; stage `prepare-source`, `prepare-target`, `configure-hba` and `inspect`. | Supported versions, private endpoints and completed bootstrap; correct logical replication/HBA configuration; source TLS `require`, RDS `verify-full`; initial target writer returns `42501` and rolls back. |
| Full load and independent equality, G3 | A running task or matching counts can conceal different data. | Run [dms_step.py](scripts/control/dms_step.py) `inspect --label <unique-label>` and the harness `inspect`/`compare` actions. See [Section 4](#4-remote-installation-and-database-preparation). | Eight ordered rows, six columns, matching primary key/catalog and full content; total 839.60; full load complete, clean native validation and no load errors. |
| Ordered INSERT/UPDATE/DELETE, T01–T03 | Confirms each covered change reaches the target before the next action. | Stage `t01`, then `observe --test T01`; repeat for T02 and T03, then `compare`. See [Section 5](#5-cdc-divergence-two-cutovers-and-return). | INSERT of ID 201, UPDATE of ID 102 and DELETE of ID 103 observed; eight rows totaling 937.31; every column, key and catalog equal. |
| Divergence detection and repair, T04/G5 | Equal counts and sums do not prove row equality. | Stage `diverge-target` and `compare`; request `dms_step.py revalidate --label <label>`, then inspect. Stage `correct-divergence`, observe, compare and request another validation. | Initially only `note` for ID 106 differs, and a fresh native result reports the mismatch. After repair, full equality and a newly requested clean native result; an old `Validated` snapshot does not pass. |
| Business writer barriers, T05 — scoped identities | Comparison at cutover requires a stable business state. | Stage marker 901/902, `freeze-source`, `freeze-target` and the matching `observe`; inspect the [harness](scripts/harness/lab_harness.py) role reports. | No effective table/column write privilege, membership/ownership/admin path or active session for the two tested business writers; both negative probes return `42501` and roll back. This is not a global transaction audit. |
| Current drain evidence, T06/G6 — regenerate for each cutover | Stale validation or absent metrics cannot prove a drained current state. | Make separate `dms_step.py revalidate`, `metrics` and `inspect` calls with unique `--label` values. Run [collect_dms_logs.py](scripts/control/collect_dms_logs.py) `--label <label> --since <freeze-UTC>`, then [make_g6_proof.py](scripts/control/make_g6_proof.py) `--inputs <inputs.json> --output <proof.json>`. | Same run/task and marker; fresh native `Validated`, with pending/failed/suspended records zero. Two shared 60-second metric points, both at most 240 seconds old; `CDCIncomingChanges/Maximum=0`, latency limits and complete fresh logs as specified in [Section 5](#5-cdc-divergence-two-cutovers-and-return). Missing input fails. |
| Record the accepted G6 gate — revised local control | Evidence can expire between proof generation and approval. | Stage `record-g6 --proof /opt/pg-lab/evidence/<proof.json>` through [stage_actions.py](scripts/control/stage_actions.py), with `--proof <local-proof.json>`, then `compare`. | Live frozen roles, native state, rows/catalog and marker agree. The same-run/task proof is at most 600 seconds old and both selected sample timestamps are at most 240 seconds old at the recorded approval instant. The harness rechecks ages, not CloudWatch values or log contents. This additional age check was validated offline after R01/R02. |
| Prewrite return and checkpoint continuation, T07 — simulated trigger | Tests return before an exclusive target business commit is accepted. | After G6a, run `dms_step.py stop --label <label>` and inspect until `stopped`; stage `prewrite-return`. Run `dms_step.py resume --label <label>`, observe `T07-return-write`, then write marker 902 and repeat G6. | Fresh reader identities; target writer remains blocked; only the source reopens and commits ID 211. Checkpoint continuation delivers ID 211. The trigger is a declared simulation, not an actual outage test. |
| Refuse simple return after target writes, T08 | Returning to the old source would lose accepted target changes. | After new G6b and confirmed stop, run the following actions in separate stages: `open-target`, `postwrite-insert`, `compare`, `postwrite-update`, `postwrite-delete`, `compare`, `freeze-target` and `prewrite-return`. See the final comparison (not distributed in this supporting-code edition). | First commit of row 301 retained. Final counts are 11/11, but totals are 1148.32/1343.83 with differences involving IDs 104/105/301. Return exits with code 2 and the source stays frozen; earlier native validation is not current equality. |
| External export and clean replay — raw private exports omitted | Reset/deletion must not destroy the only evidence; replay is not reverse migration. | Use the [export helper](scripts/control/export_evidence.py) `prepare`, `read` and `finish` subcommands with the full flags in [Section 6](#6-export-clean-replay-and-teardown), for R01 and R02. Reset only after verified export, with the archive acknowledgment; change only the ledger `run_id`, then reload. | Descriptor, every chunk and source files pass length/SHA/UTF-8/JSON checks; original R01 files remain preserved. R02 begins with an empty target and repeats expected results. Public historical receipts do not contain the omitted private export files. |
| Scoped teardown and absence verification | A deletion request or permission error does not prove removal. | Run [verify_cleanup.py](scripts/verification/verify_cleanup.py) `--mode full-baseline`; [cleanup_lab.py](scripts/control/cleanup_lab.py) `--step probe`; execute reviewed steps individually. Finish with `verify_cleanup.py --mode final --baseline <baseline.json> --output <after.json>`. | Complete same-scope baseline and external evidence; `cleanup_verified=true`, empty `coverage_errors`/`residuals`, complete checks. Accepted terminated tombstones are distinguished from live resources; shared resources are preserved. |
| Cost envelope and cleanup binding — estimate; invoice unverified | Delayed budget alerts and estimates are not final invoices. | Run [estimate_runtime_cost.py](scripts/verification/estimate_runtime_cost.py) `--start-utc <UTC> --end-utc <UTC> --cleanup-inventory <after.json> --output <cost.json>`. Add traffic flags only for measured volumes. See [Section 6](#6-export-clean-replay-and-teardown). | Refresh rates for future runs; stay within the authorized envelope. Final inventory matches account, region, `resource_run_id` and all three stack ARNs, with complete clean checks. Disclose unmeasured traffic; the estimator's omitted-input zero is not observed usage. |
| Reproduction-copy regression checks — offline only | Tests guards and generated templates without claiming an AWS deployment. | In a disposable copy, run `& $LabPython -B .\qa\test_repro.py` and `& $LabPython -B .\qa\test_cutover_revision.py`. Compare the result with the edition 3 local test receipt (not distributed in this supporting-code edition). | All 19 outer regression tests and all 19 cutover-revision test methods pass separately, including the incorporated semantic suites, resolver checks and three cfn-lint templates; no failures, errors, skips or AWS calls. Synthetic fixtures are not runtime evidence. |
| Prepared and other in-flight transactions — coverage gap | Known writer sessions do not rule out prepared transactions or other capable identities. | No bundled gate demonstrates this. Before production adaptation, run `SHOW max_prepared_transactions;` on both servers and record the effective values. A value of zero disables prepared transactions. Where enabled, inspect `pg_prepared_xacts`. Inspect relevant writer transactions in `pg_stat_activity` on both databases regardless of that setting. | R01/R02 did not record `max_prepared_transactions` or demonstrate 2PC handling; do not infer that it was disabled. Production acceptance requires an explicit inventory and resolution of relevant outstanding transactions; zero sessions for the tested writer alone is insufficient. |
| Ambiguous commit after connection/crash failure — local guard and runtime coverage gap | A client timeout does not prove that a commit failed; an old return receipt does not authorize a current transition. | Inspect `ledger.pending_dml` and the exact expected before/after state. Run the local return regression tests referenced in the revision notes (not distributed in this supporting-code edition). No AWS crash/network fault injection was performed. | Any pending DML blocks `prewrite-return` before an idempotent response or writer change. A clean historical response explicitly grants no current return authorization. Local tests cover these branches; R01/R02 do not validate crash/network failure at commit or general exactly-once behavior. |

## QA and failures

```powershell
& $LabPython -B .\qa\test_repro.py
& $LabPython -B .\qa\test_cutover_revision.py
```

Run these commands in a disposable copy of this reproduction tree: the original regression runner writes fixtures and `qa/offline-qa-receipt.json`. Generated receipts are local test outputs, not historical AWS evidence. Edition 3 results are recorded separately in qa/offline-qa-v3-receipt.json (not distributed in this supporting-code edition).

The tests block network connections in child processes. They use two fictitious accounts and check guards, the private template, preservation of existing roles, an installer smaller than 50KB, self-contained exports, G6, the resolver and cleanup/verification. The cutover-revision suite additionally loads the actual harness definitions without platform or SDK imports, uses a fixed clock and in-memory substitutes, and blocks socket connections. Its 19 methods test metric freshness at approval and unresolved DML before return. Synthetic snapshots under `qa/` are not evidence of the actual laboratory.

On error, stop at the first affected gate. A timeout or unknown effect requires readback/ledger reconciliation before retry. Authentication or permission failures do not establish resource absence. Sanitized output identifies the error class; never print provider payloads, credentials or a traceback containing password SQL. Preserve the failed attempt and use a new label for the correction. A test cannot pass merely because the task is `running`, a file exists or transport succeeded.
