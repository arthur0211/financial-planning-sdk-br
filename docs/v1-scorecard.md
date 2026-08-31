# V1 live scorecard

Última atualização: 2026-08-30
Estado do programa: `github_public_source_hardening`
Autoridade: `technical_evaluation_only`
Publicação: `public_source_only_release_blocked`

Este é o painel curto do loop. Evidência detalhada permanece em [progress.md](progress.md); a barra e a regra de vitória estão em [v1-quality-bar.md](v1-quality-bar.md). Nenhum estado desta página equivale a PASS independente ou autorização de release.

## Barra atual

| Gate | Estado | Evidência atual | Maior gap |
| --- | --- | --- | --- |
| correção matemática | `partial` | PV/ledger usam Context explícito, centavos inteiros, ties por sinal e bound 4.096; suites locais e pack passam | SUT oficial de 21 vetores permanece `not_evaluated`; falta validação matemática humana/independente |
| API/CLI | `partial` | parser único, `JsonObject` exato e quatro value objects com binding identidade+tipo e guarda não virtual passaram ao reataque independente em source/wheel/sdist-wheel | método público substituído pelo caller e código arbitrário no mesmo processo não são isolados; a superfície v1 além do ledger ainda não está completa |
| determinismo | `partial` | writers próprios `STORED` fecham wheel/sdist; com `setuptools==84.0.0`, o build local descartável pós-publicação convergiu a wheel `da7a0161…` e sdist `9edd73cc…` | igualdade Linux/Windows no mesmo freeze atual e quatro células Windows isoladas ainda não foram observadas; artifacts brutos do backend não são claim bit-reproduzível |
| packaging | `partial` | roster 18/24/29+4; binding v2 liga SHA raw intra/cross-cell; metadata v5 fecha backend, SPDX, autoria e licença source-bound | reexecutar a matriz no source atual, obter crítica fresca, origem autenticada e supply-chain authority |
| explicabilidade | `partial` | PV, ledger, warnings, assertions e diagnostics expõem decomposição fechada | pack é local/untrusted e não constitui derivação independente ou validação profissional |
| documentação | `partial` | README PT-BR/EN, ADR 0012, Apache-2.0, mantenedor, governança, checklist, Community Profile 100% e publicação do source estão reconciliados | reviewer independente não existe; documentação não cria validação profissional |
| segurança/offline | `partial` | Actions por SHA, permissões mínimas, checkout sem credencial, Dependabot, PVR, secret scanning e push protection ativos; CI, CodeQL e dependency review públicos verdes; ruleset ativo sem bypass | Windows permanece `not_observed`; assinatura verificada e reviewer independente seguem abertos; ruleset não substitui authority |
| mutação | `partial` | regressões incluem CRLF gerado, authored não normalizado, header/encoding/boundary gzip e ZIP, oito hashes sdist divergentes e 23/23 mutantes de conformance | campanha permanece candidata e sem matriz final, Windows isolado ou attestation externa |
| plataforma | `fail` | a matriz histórica observou Linux e falhou fechado em Windows; o novo backend possui apenas build local candidato | executar Linux/Windows 3.11–3.14 no mesmo freeze atual sob as boundaries documentadas; reports continuam self-issued e o agregador retorna RC1 |
| autoridade/release | `blocked_by_design` | F0/00/01 falham fechado; nenhum workflow ou verde local os promove | licença/governança do source existem, mas reviewer independente e autoridade externa não; não são resolvidos por automação |

## Sprints

| Sprint | Fatia | Builder | Crítico fresco | Estado | Maior gap devolvido |
| --- | --- | --- | --- | --- | --- |
| baseline | PV + ledger + conformance local | concluído | auditorias R1–R20 | `local_draft` | harness não observava boundary pública/contexto Decimal |
| 1 | Reference Acceptance Pack bundled, SDK/CLI | 37/37 + package smoke | 3/3 `major_revision` | `revision_required` | pack inválido pouco acionável; JSON profundo vazava traceback; contexto Decimal quebrava paridade |
| 1.1 | JSON bounded + diagnóstico estrutural acionável do pack | 48/48 + wheel smoke | 2/2 `major_revision` | `revision_required` | surrogate/Pointer vazavam traceback; report admitia estados contraditórios e conteúdo controlado |
| 1.2 | totalidade, budget, redação e consistência relacional do report | 66/66 + smoke triplo | `pass` após 41/41 e 46 mutações | `local_technical_pass` | corte fechado; pack continua local/untrusted e sem authority |
| 2 | isolamento Decimal + fechamento de entrada pública | 78/78 + 19/19 mutantes + smoke 4.096 | 2/2 `major_revision` | `revision_required` | half-even negativo/38→39 sobreviviam; erro máximo e Mapping divergiam |
| 2.1 R2 | mutação integrada + ValidationReport bounded/schema-válido | 92/92 + 23/23 + smoke triplo | `major_revision` | `revision_required` | LF divergia; factories mínimas e `tuple.__new__` contornavam o contrato público |
| 2.1 R3 | value objects opacos + perfil fechado dos quatro schemas | 103/103 + 23/23 + smoke triplo | `major_revision` | `revision_required` | left-MRO/custom MRO contornavam o hook; identifiers aninhados, percent refs e ciclos escapavam |
| 2.1 R4 | binding de tipo exato + admissão/topologia fechada | 107/107 + 23/23 + smoke 4 schemas/16 recusas/4 objetos | `pass` no snapshot congelado | `local_technical_pass` | nenhum finding no bar R4; isolamento same-process, build reproduzível, matriz multiplataforma e authority continuam fora |
| 3 R1 | package instalado/offline | Linux 3.11–3.14 no mesmo freeze + Windows fail-closed local | `major_revision` | `revision_required` | oito parities distintos e package extra podiam passar o agregador |
| 3 R2 | binding de artifacts + pins imutáveis | 22/22 + Linux 3.11–3.14 no freeze final + Windows fail-closed local | pendente | `partial_observed_global_fail` | Windows real + receipt externo autenticável; oito JSON coerentes continuam RC1 |
| 3 R3 | ZIP32 wheel canônico + SHA raw cross-cell | 25/25 + Ruff + Linux 3.11 preliminar | pendente | `builder_complete_pending_independent_critic` | reexecutar quatro Linux no freeze final; depois atacar serializer/binding e manter Windows/authentication fail-closed |
| 3 R4 | metadata gerada LF source-bound | 10/10 focado + 27/27 portabilidade + Ruff; Windows 3.13 build/install diagnóstico converge a `598a31b7…` | pendente | `builder_in_progress_global_fail` | executar quatro Linux no freeze final e crítica fresca; quatro Windows isolados/authentication seguem abertos |
| 3 R5 | sdist RFC1952/STORED + binding raw | 28/28 focado + 33/33 portabilidade + Ruff; Windows 3.11–3.14 diagnóstico converge a `fde397d5…` | pendente | `builder_complete_pending_final_matrix_and_independent_critic_global_fail` | executar Linux/Windows no freeze final; Windows isolado e authentication externa seguem abertos |
| preparação GitHub | onboarding, supply chain, CI e documentação pública | venv externa regular, setuptools 84/metadata v5, Apache-2.0, governança, CI/CodeQL/dependency review, source público, PVR, secret scanning e ruleset | reviewer independente ausente | `public_source_hardening` | resolver assinatura, hashes transitivos e reviewer real sem ampliar claims de release |

## Próximo julgamento

O último recorte AppContainer permanece wrapper v23/helper v17/failure receipt v6. O oitavo live histórico terminou RC1 sem crédito, e não existe autorização para um nono live. A crítica ZERO-LIVE P0=0/P1=0/P2=0 cobre source, compilação, reflection/IL, fakes e 17 categorias de mutação; não prova conclusão no sistema operacional, authority, portabilidade ou release.

O próximo julgamento técnico deve reproduzir os artifacts metadata v5, executar a matriz Windows/Linux × Python 3.11–3.14 no mesmo source freeze e submeter o resultado a crítica fresca. O código-fonte já está público após CI verde e ativação verificada do canal privado; package/release continuam separados e bloqueados pelos gates externos inexistentes.
