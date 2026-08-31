# Índice da documentação

Este diretório separa contratos executáveis, decisões, evidência de pesquisa, operação e histórico de auditoria. Nem todo documento tem o mesmo peso normativo.

## Comece aqui

| Documento | Público principal | Papel |
| --- | --- | --- |
| [README do projeto](../README.md) | avaliadores e contribuidores | visão geral, início rápido e limites |
| [Runbook](runbook.md) | operadores locais | comandos e interpretação dos gates |
| [Arquitetura](architecture.md) | engenharia e revisão | componentes, fluxos e fronteiras |
| [Compatibilidade](compatibility.md) | integradores | versões, estabilidade e política de mudança |
| [Scorecard v1](v1-scorecard.md) | mantenedor e revisores | estado dos gates e trabalho pendente |
| [Checklist GitHub](github-publication-checklist.md) | mantenedor | separação entre preparação, staging, source público e release |

## Contratos normativos

- [Deterministic cashflow ledger](specification/deterministic-cashflow-ledger.md): contrato do vertical implementado.
- [Motor matemático](specification/mathematical-engine.md): semântica, unidades e corpus de validação.
- [Policy packs](specification/policy-packs.md): proposta bitemporal para futuras regras externas.
- [Catálogo de erros](specification/error-catalog.md): reason codes e remediações.
- [`schemas/`](../schemas/): schemas JSON e manifesto de casos.

Código, schemas e testes prevalecem quando uma descrição histórica divergir do comportamento corrente. Divergência entre contrato público e implementação exige correção explícita e, quando aplicável, ADR.

## Decisões arquiteturais

Os [ADRs](decisions/) registram decisões que alteram escopo, API, matemática, dependências, portabilidade ou trust boundary. Os documentos 0001 a 0012 cobrem a fundação, o vertical local, o acceptance pack, o perfil de schema, a matriz instalada, a fronteira Windows AppContainer, o backend de build seguro e a publicação do source sob Apache-2.0.

## Operação e segurança

- [Runbook](runbook.md)
- [Threat model](security/threat-model.md)
- [Fronteira de release e trust](governance/release-trust.md)
- [Classificação de deployment](governance/deployment-classification.md)
- [Modelo de risco](../MODEL_RISK.md)
- [Privacidade](../PRIVACY.md)
- [Dados e licenças](../DATA_LICENSES.md)
- [Política de segurança](../SECURITY.md)
- [Suporte](../SUPPORT.md)
- [Como contribuir](../CONTRIBUTING.md)
- [Código de Conduta](../CODE_OF_CONDUCT.md)
- [Mantenedores](../MAINTAINERS.md)
- [Governança](../GOVERNANCE.md)
- [Licença Apache-2.0](../LICENSE)
- [Checklist de publicação no GitHub](github-publication-checklist.md)

## Pesquisa e revisão

- [Estudo fundacional](research/financial-planning-sdk-br-sota.md)
- [Protocolo de revisão](research/review-protocol.md)
- [Ledger de evidências](research/evidence-ledger.csv)
- [Manifesto de comparadores](research/software-comparator-manifest.csv)
- [Parecer adversarial](reviews/adversarial-review-2026-08-08.md)

Esses materiais documentam fontes, hipóteses e challenges internos. Eles não substituem validação independente do domínio.

## Histórico

- [Progresso técnico](progress.md): cronologia detalhada dos ciclos builder e critic.
- [Changelog Codex](changelog-codex.md): mudanças locais assistidas, sem equivalência a changelog de release.
- [Histórico de trust superado](history/trust-r2-r11-superseded.md): desenhos rejeitados e razões de rejeição.

## Como interpretar o status

- `draft`: contrato ou artefato ainda sem aprovação profissional.
- `computed`: aritmética concluída, sem autoridade adicional.
- `local_technical_acceptance_passed`: expected bytes locais reproduzidos.
- `not_observed`: a célula ou controle exigido não foi observado.
- `authority=none`: nenhum resultado autoriza recomendação, deployment ou release.

Consulte sempre o documento mais específico e preserve a distinção entre evidência, inferência, hipótese e decisão.
