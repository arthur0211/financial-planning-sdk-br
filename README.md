# Financial Planning SDK Brasil

[Português](README.md) | [English](README.en.md)

[![Qualidade técnica](https://github.com/arthur0211/financial-planning-sdk-br/actions/workflows/technical-quality.yml/badge.svg?branch=main)](https://github.com/arthur0211/financial-planning-sdk-br/actions/workflows/technical-quality.yml)
[![CodeQL](https://github.com/arthur0211/financial-planning-sdk-br/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/arthur0211/financial-planning-sdk-br/actions/workflows/codeql.yml)
[![Autoverificação matemática](https://github.com/arthur0211/financial-planning-sdk-br/actions/workflows/math-conformance.yml/badge.svg?branch=main)](https://github.com/arthur0211/financial-planning-sdk-br/actions/workflows/math-conformance.yml)

SDK e CLI Python locais para validar e reproduzir um ledger determinístico de fluxos de caixa em BRL.

> **Estado do projeto:** pré-release técnico (`0.1.0.dev0`). O corte atual é `draft`, não possui autoridade profissional ou regulatória e não está autorizado para publicação em registry, recomendação financeira ou deployment.

## O que existe hoje

O repositório implementa um único vertical: `deterministic_cashflow_ledger`. SDK e CLI usam o mesmo parser e o mesmo caso de uso para:

- validar requests JSON sob um perfil fechado de JSON Schema Draft 2020-12;
- calcular valor presente com fatores de desconto fornecidos pelo chamador;
- reproduzir contas, postagens e transferências internas em centavos exatos;
- separar `price_return` de `total_return`;
- emitir resultados e diagnósticos canônicos, limitados e machine-readable;
- executar um Reference Acceptance Pack local com três casos sintéticos.

O kernel não abre HTTP ou DNS, não envia telemetria e não persiste dados implicitamente.

## Limites de uso

O projeto ainda não implementa:

- IRPF, previdência, seguros, inflação, mortalidade ou regras brasileiras vigentes;
- ingestão de contas, Open Finance, Open Insurance ou dados pessoais;
- recomendação, ranking de produtos, suitability ou execução de operações;
- validação científica, atuarial, jurídica ou regulatória independente;
- autenticação externa dos relatórios de teste;
- package ou release autorizado.

`computed` significa somente que a aritmética terminou. A resposta permanece `draft`, com `authority=none` e `deployment_eligibility=not_authorized`.

Leia o [disclaimer](DISCLAIMER.md), o [modelo de risco](MODEL_RISK.md), a [política de privacidade](PRIVACY.md) e as [regras de dados e licenças](DATA_LICENSES.md) antes de avaliar qualquer uso.

## Requisitos

- Python 3.11 ou posterior;
- PowerShell 5.1 ou PowerShell 7 para os gates Windows documentados;
- `setuptools==84.0.0` para a instalação editável reproduzida localmente.

## Início rápido

No PowerShell, a partir da raiz do repositório:

```powershell
$FinPlanBrVenv = Join-Path $env:LOCALAPPDATA 'finplanbr\venvs\dev'
$FinPlanBrBootstrap = (py -3.12 -c "import sys; print(sys.executable)").Trim()
& $FinPlanBrBootstrap -m venv $FinPlanBrVenv
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install setuptools==84.0.0
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install --no-deps --no-build-isolation --editable .
```

O bootstrap usa uma instalação regular do CPython 3.12 descoberta pelo Python Launcher. Isso evita o redirecionamento de filesystem observado no alias da Microsoft Store; se 3.12 não estiver instalado, use uma instalação regular de Python 3.11 a 3.14. O ambiente fica fora do checkout porque o gate `Structure` inspeciona deliberadamente toda a árvore. Não crie `.venv`, `build` ou `dist` dentro do repositório.

Valide e calcule o exemplo sintético:

```powershell
& "$FinPlanBrVenv\Scripts\finplanbr.exe" validate .\examples\deterministic-cashflow-ledger.json
& "$FinPlanBrVenv\Scripts\finplanbr.exe" compute deterministic .\examples\deterministic-cashflow-ledger.json
& "$FinPlanBrVenv\Scripts\finplanbr.exe" reference run
```

Pelo SDK:

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

O contrato executável está em [deterministic-cashflow-ledger.md](docs/specification/deterministic-cashflow-ledger.md).

## Arquitetura resumida

```text
request JSON
    -> parser e perfil fechado de schema
    -> value objects opacos
    -> caso de uso deterministic_cashflow_ledger
    -> resultado imutável
    -> JSON canônico ou diagnóstico fechado
```

As fronteiras principais são:

- **kernel local:** `src/financial_planning_sdk_br`, sem clientes de rede;
- **contratos:** schemas, manifesto e catálogo de reason codes;
- **evidência técnica:** vetores, propriedades, mutações e acceptance pack;
- **governança:** estados `draft`, gates fail-closed e ausência explícita de authority;
- **portabilidade:** artefatos instalados em células descartáveis, sem converter um teste local em release.

Veja a [arquitetura completa](docs/architecture.md) e o [índice da documentação](docs/README.md).

## Validação local

Para a suíte completa, instale o extra de desenvolvimento na mesma venv e faça os comandos Python desta sessão resolverem para ela:

```powershell
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install --no-build-isolation --editable '.[dev]'
$env:PATH = "$FinPlanBrVenv\Scripts;$env:PATH"
```

Os comandos normativos atuais são:

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

Evidência local mais recente:

| Superfície | Resultado observado | Limite da evidência |
| --- | ---: | --- |
| contratos | 10 schemas, 33 casos, 62 reason codes | diagnóstico local, sem aprovação |
| corpus matemático | 21 vetores, 14 de 14 mutantes mortos | SUT integral permanece `not_evaluated` |
| conformidade do SDK | 71 propriedades, 23 de 23 mutantes mortos | sete vetores suportados de um corpus de 21 |
| testes do SDK | 112 testes aprovados | execução local |
| cobertura do SDK | piso de 80% de branches configurado | subprocessos, C#, PowerShell e lives ficam fora dessa métrica |
| portabilidade | 195 testes coletados: 193 aprovados e 2 lives opt-in ignorados | não autentica execução externa |
| matriz instalada Linux | Python 3.11 a 3.14 observados em snapshot anterior | source atual ainda não foi reexecutado na matriz; Windows permanece `not_observed` sem runner elevado |
| gates de release | `F0`, `Release00` e `Release01` falham | comportamento intencional até existir authority externa |

Um gate verde prova apenas a superfície nomeada. Não prova correção profissional, conformidade regulatória, segurança integral ou autorização para release.

A CI pública exercita o SDK em Python 3.11, 3.12, 3.13 e 3.14. Os badges acima mostram somente o estado técnico da branch `main`; não conferem autoridade profissional nem autorização de package/release.

## Documentação

| Documento | Finalidade |
| --- | --- |
| [Índice técnico](docs/README.md) | mapa de especificações, ADRs, pesquisa e governança |
| [Runbook](docs/runbook.md) | comandos, interpretação de resultados e operação local |
| [Arquitetura](docs/architecture.md) | módulos, fluxos e fronteiras de confiança |
| [Compatibilidade](docs/compatibility.md) | versões, escopo de schema e política de mudança |
| [Threat model](docs/security/threat-model.md) | ativos, atacantes, controles e limites |
| [Scorecard v1](docs/v1-scorecard.md) | gates abertos e evidência pendente |
| [ADRs](docs/decisions/) | decisões arquiteturais e mudanças de contrato |
| [Progresso técnico](docs/progress.md) | histórico detalhado dos ciclos builder e critic |
| [Suporte](SUPPORT.md) | canais, escopo de ajuda e ausência de SLA |

## Contribuir

Leia [CONTRIBUTING.md](CONTRIBUTING.md) antes de abrir uma issue ou pull request. Mudanças em contrato público, matemática, política, privacidade, licença ou deployment exigem testes, documentação e revisão compatíveis com o risco.

Relatos de vulnerabilidade devem seguir [SECURITY.md](SECURITY.md). O convívio no projeto segue o [Código de Conduta](CODE_OF_CONDUCT.md), e dúvidas de uso devem observar [SUPPORT.md](SUPPORT.md). Nunca publique PII real, credenciais ou material de clientes em issues, fixtures ou logs.

## Licença

O código-fonte e a documentação original deste repositório são licenciados sob [Apache-2.0](LICENSE). Isso não concede direitos sobre datasets, snapshots, marcas ou recursos de terceiros; consulte [DATA_LICENSES.md](DATA_LICENSES.md) e os manifestos aplicáveis.

## Estado de release

Não existe release autorizado, pacote publicado ou tag estável. O nome `finplanbr` é provisório. A descrição correta é: implementação determinística local e draft, com evidência técnica interna e gates profissionais ainda abertos.
