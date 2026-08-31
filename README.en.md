# Financial Planning SDK Brasil

[Português](README.md) | [English](README.en.md)

Local Python SDK and CLI for validating and reproducing a deterministic BRL cash-flow ledger.

> **Project status:** technical pre-release (`0.1.0.dev0`). The current scope is `draft`, carries no professional or regulatory authority, and is not authorized for registry publication, financial recommendations, or deployment.

## What exists today

The repository implements one vertical: `deterministic_cashflow_ledger`. The SDK and CLI share the same parser and use case to:

- validate JSON requests against a closed JSON Schema Draft 2020-12 profile;
- calculate present value using discount factors supplied by the caller;
- reproduce accounts, postings, and internal transfers in exact cents;
- distinguish `price_return` from `total_return`;
- emit canonical, bounded, machine-readable results and diagnostics;
- run a local Reference Acceptance Pack with three synthetic cases.

The kernel does not open HTTP or DNS connections, send telemetry, or persist data implicitly.

## Usage boundaries

The project does not yet implement:

- IRPF, pensions, insurance, inflation, mortality, or current Brazilian rules;
- account ingestion, Open Finance, Open Insurance, or personal data;
- recommendations, product ranking, suitability, or transaction execution;
- independent scientific, actuarial, legal, or regulatory validation;
- external authentication of test reports;
- an authorized package or release.

`computed` only means that arithmetic completed. The response remains `draft`, with `authority=none` and `deployment_eligibility=not_authorized`.

Read the [disclaimer](DISCLAIMER.md), [model risk statement](MODEL_RISK.md), [privacy policy](PRIVACY.md), and [data and licensing rules](DATA_LICENSES.md) before evaluating any use.

## Requirements

- Python 3.11 or later;
- Windows PowerShell 5.1 or PowerShell 7 for the documented Windows gates;
- `setuptools==84.0.0` for the locally reproduced editable installation.

## Quick start

From the repository root in PowerShell:

```powershell
$FinPlanBrVenv = Join-Path $env:LOCALAPPDATA 'finplanbr\venvs\dev'
$FinPlanBrBootstrap = (py -3.12 -c "import sys; print(sys.executable)").Trim()
& $FinPlanBrBootstrap -m venv $FinPlanBrVenv
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install setuptools==84.0.0
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install --no-deps --no-build-isolation --editable .
```

The bootstrap uses a regular CPython 3.12 installation discovered by the Python Launcher. This avoids the filesystem redirection observed with the Microsoft Store alias; if 3.12 is unavailable, use a regular Python 3.11 through 3.14 installation. The environment stays outside the checkout because the `Structure` gate deliberately inspects the entire repository tree. Do not create `.venv`, `build`, or `dist` inside the repository.

Validate and compute the synthetic example:

```powershell
& "$FinPlanBrVenv\Scripts\finplanbr.exe" validate .\examples\deterministic-cashflow-ledger.json
& "$FinPlanBrVenv\Scripts\finplanbr.exe" compute deterministic .\examples\deterministic-cashflow-ledger.json
& "$FinPlanBrVenv\Scripts\finplanbr.exe" reference run
```

Through the SDK:

```python
import json
from pathlib import Path

from financial_planning_sdk_br import compute_deterministic

request = json.loads(
    Path("examples/deterministic-cashflow-ledger.json").read_text(encoding="utf-8")
)
result = compute_deterministic(request).to_dict()

print(result["valuation"]["present_value"])
print(result["authority"])
```

The executable contract is documented in [deterministic-cashflow-ledger.md](docs/specification/deterministic-cashflow-ledger.md) in Portuguese.

## Architecture at a glance

```text
JSON request
    -> parser and closed schema profile
    -> opaque value objects
    -> deterministic_cashflow_ledger use case
    -> immutable result
    -> canonical JSON or closed diagnostic
```

The main boundaries are:

- **local kernel:** `src/financial_planning_sdk_br`, with no network clients;
- **contracts:** schemas, manifest, and reason-code catalog;
- **technical evidence:** vectors, properties, mutations, and acceptance pack;
- **governance:** `draft` states, fail-closed gates, and explicit absence of authority;
- **portability:** installed artifacts in disposable cells, without treating a local test as a release.

See the [full architecture](docs/architecture.md) and [documentation index](docs/README.md), currently maintained in Portuguese.

## Local validation

For the complete suite, install the development extra in the same venv and make this session resolve Python commands to it:

```powershell
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install --no-build-isolation --editable '.[dev]'
$env:PATH = "$FinPlanBrVenv\Scripts;$env:PATH"
```

The current normative commands are:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_docs.ps1 -Mode Structure
python .\scripts\validate_contracts.py
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_math_vectors.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_sdk_conformance.ps1 -OutputFormat Json
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m unittest discover -s .\tests\sdk -p 'test_*.py' -v
python -m ruff check .\src .\tests\sdk
python -m mypy --strict .\src\financial_planning_sdk_br
python .\scripts\smoke_local_package.py
```

Most recent local evidence:

| Surface | Observed result | Evidence boundary |
| --- | ---: | --- |
| contracts | 10 schemas, 33 cases, 62 reason codes | local diagnostic, no approval |
| mathematical corpus | 21 vectors, 14 of 14 mutations killed | full SUT remains `not_evaluated` |
| SDK conformance | 71 properties, 23 of 23 mutations killed | seven supported vectors out of 21 |
| SDK tests | 112 tests passed | local execution |
| SDK coverage | 80% branch floor configured | subprocesses, C#, PowerShell, and live probes remain outside this metric |
| portability | 195 tests passed, 2 opt-in live tests skipped | does not authenticate external execution |
| installed Linux matrix | Python 3.11 through 3.14 observed on an earlier snapshot | current source not rerun as a matrix; Windows remains `not_observed` without an elevated runner |
| release gates | `F0`, `Release00`, and `Release01` fail | intentional until external authority exists |

A green gate proves only its named surface. It does not prove professional correctness, regulatory compliance, complete security, or release authorization.

## Documentation

| Document | Purpose |
| --- | --- |
| [Technical index](docs/README.md) | map of specifications, ADRs, research, and governance |
| [Runbook](docs/runbook.md) | commands, result interpretation, and local operation |
| [Architecture](docs/architecture.md) | modules, flows, and trust boundaries |
| [Compatibility](docs/compatibility.md) | versions, schema scope, and change policy |
| [Threat model](docs/security/threat-model.md) | assets, attackers, controls, and limits |
| [v1 scorecard](docs/v1-scorecard.md) | open gates and pending evidence |
| [ADRs](docs/decisions/) | architectural decisions and contract changes |
| [Technical progress](docs/progress.md) | detailed builder and critic history |
| [Support](SUPPORT.md) | support channels, scope, and absence of an SLA |

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. Changes to public contracts, mathematics, policy, privacy, licensing, or deployment require tests, documentation, and review proportionate to their risk.

Follow [SECURITY.md](SECURITY.md) for vulnerability reports. Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md), and usage questions should follow [SUPPORT.md](SUPPORT.md). Never publish real PII, credentials, or client material in issues, fixtures, or logs.

## License

The source code and original documentation in this repository are licensed under [Apache-2.0](LICENSE). This does not grant rights to third-party datasets, snapshots, trademarks, or resources; see [DATA_LICENSES.md](DATA_LICENSES.md) and the applicable manifests.

## Release status

There is no authorized release, published package, or stable tag. The `finplanbr` name is provisional. The accurate description is: a local deterministic draft implementation with internal technical evidence and open professional gates.
