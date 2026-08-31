# Como contribuir

Obrigado por avaliar o Financial Planning SDK Brasil. O projeto aceita contribuições técnicas dentro do escopo local e determinístico atual.

## Antes de começar

1. Leia o [README](README.md), a [arquitetura](docs/architecture.md) e o [contrato implementado](docs/specification/deterministic-cashflow-ledger.md).
2. Confirme que a proposta não adiciona recomendação, integração de contas, PII real, rede no kernel ou regra brasileira sem autoridade versionada.
3. Para mudanças de API, matemática, policy, privacidade, licença, dependency boundary ou deployment, abra primeiro uma proposta e descreva o ADR necessário.

O repositório é licenciado sob [Apache-2.0](LICENSE). Salvo declaração explícita em contrário, uma contribuição enviada intencionalmente para inclusão segue os termos da seção 5 dessa licença. Não copie código, fixtures ou dados de terceiros sem permissão compatível.

## Ambiente local

```powershell
$FinPlanBrVenv = Join-Path $env:LOCALAPPDATA 'finplanbr\venvs\dev'
$FinPlanBrBootstrap = (py -3.12 -c "import sys; print(sys.executable)").Trim()
& $FinPlanBrBootstrap -m venv $FinPlanBrVenv
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install setuptools==84.0.0
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install --no-deps --no-build-isolation --editable .
```

Mantenha ambientes, caches e builds fora do checkout: o gate `Structure` percorre a árvore inteira e trata conteúdo local não versionável como parte da superfície observada.

Para os caches das ferramentas locais:

```powershell
$FinPlanBrToolState = Join-Path $env:LOCALAPPDATA 'finplanbr\tool-state'
$env:COVERAGE_FILE = Join-Path $FinPlanBrToolState 'coverage'
$env:MYPY_CACHE_DIR = Join-Path $FinPlanBrToolState 'mypy'
$env:RUFF_CACHE_DIR = Join-Path $FinPlanBrToolState 'ruff'
```

Dependências de desenvolvimento pinadas:

```powershell
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install build==1.4.0 coverage==7.16.0 jsonschema==4.26.0 mypy==1.19.1 ruff==0.14.14
$env:PATH = "$FinPlanBrVenv\Scripts;$env:PATH"
```

## Checks obrigatórios

Execute na raiz:

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

Use o [runbook](docs/runbook.md) para interpretar RCs e gates deliberadamente fechados.

## Regras de mudança

- Preserve JSON-only no MVP e a ausência de rede, telemetria e persistência implícita no kernel.
- Adicione testes SDK e CLI para qualquer mudança pública.
- Atualize schemas, manifesto, reason codes e fixtures como uma unidade coerente.
- Não transforme comparadores internos em oráculos independentes.
- Não relaxe um gate para fazer uma fixture passar.
- Nunca inclua PII real, segredo, credencial ou dado sem licença manifestada.
- Atualize `docs/runbook.md`, `docs/architecture.md` e `docs/changelog-codex.md` em mudanças substanciais.
- Registre um ADR quando a mudança afetar contrato público, matemática, policy, licença, dependência ou trust boundary.

## Pull requests

Um pull request deve explicar:

- problema e escopo;
- comportamento anterior e novo;
- riscos e limites;
- testes executados, com RC e contagens;
- impacto em API, schema, reason codes, dados, privacidade e documentação;
- gates que permanecem abertos.

Prefira mudanças pequenas e revisáveis. Não combine refatoração ampla, mudança matemática e alteração de contrato sem necessidade demonstrada.

## Issues

Use os templates do GitHub. Para vulnerabilidades, siga [SECURITY.md](SECURITY.md) e não publique detalhes exploráveis em issue aberta.

Ao participar, siga o [Código de Conduta](CODE_OF_CONDUCT.md). Para dúvidas de uso, consulte também [SUPPORT.md](SUPPORT.md).

## Critério de aceite

Merge, build verde ou acceptance local não autorizam release. O mantenedor ainda precisa verificar escopo, evidência, revisão e os blockers de governança aplicáveis.
