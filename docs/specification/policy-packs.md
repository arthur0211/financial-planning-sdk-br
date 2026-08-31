# Contrato bitemporal de policy packs

_Especificação jurídica e de proveniência proposta · 8 de agosto de 2026_

---

## 📋 Problema

Uma regra não pode ser selecionada apenas por `effective_from` e `effective_until`. Edição, publicação, produção de efeitos, conhecimento pelo sistema, alteração, suspensão, restauração, decisão provisória e retroatividade são eventos distintos.

O caso IOF/VGBL de 2025–2026 — decreto, sustação legislativa, suspensão cautelar de ambos, restauração parcial declarada `ex tunc` e esclarecimento posterior que afastou cobrança no período suspenso — demonstra por que uma linha do tempo simples pode fornecer resposta fiscal errada.[^1][^2][^3][^4]

Policy pack é um artefato declarativo, assinado e revisado. Não contém código, `eval`, template executável ou regra baixada durante `compute`.

## 📝 Entidades

### AuthoritySource

```text
authority_id
issuer
jurisdiction
instrument_type
instrument_number
issued_at
issued_at_precision: day | year | unknown
published_at
published_at_precision: day | year | unknown
official_url
official_pinpoint
legal_status:
  not_yet_effective | in_force | partially_in_force |
  suspended | revoked | expired | unknown
legal_certainty:
  final | provisional | contested | unknown
policy_output_mode:
  definitive | scenario_only | blocked
source_artifact_path
source_checksum
retrieved_at
reviewed_by
reviewed_on
review_expires_at
artifact_status: draft | approved
```

### LegalEvent

```text
event_id
authority_id
event_type:
  enact | amend | revoke | suspend | restore |
  court_order | court_clarification | interpretive_guidance | correct
announced_at
announced_at_precision: day | year | datetime | unknown
published_at
published_at_precision: day | year | datetime | unknown
valid_effect_from
valid_effect_from_precision: day | year | datetime | unknown
valid_effect_until
valid_effect_until_precision: day | year | datetime | unknown | not_applicable
known_from
known_from_precision: day | year | datetime | unknown
known_until
known_until_precision: day | year | datetime | unknown | not_applicable
retroactivity:
  none | ex_nunc | ex_tunc | custom
affected_rule_ids[]
amends[]
supersedes[]
clarifies[]
suspends[]
restores[]
controlling_case_id
decision_stage:
  final | provisional | ad_referendum | administrative_guidance
source_url
source_artifact_path
source_checksum
reviewed_by
reviewed_on
review_expires_at
artifact_status: draft | approved
```

### PolicyRule

```text
rule_id
domain
jurisdiction
scope_predicate
authority_refs[]
legal_status:
  not_yet_effective | in_force | partially_in_force |
  suspended | revoked | expired | unknown
legal_certainty:
  final | provisional | contested | unknown
policy_output_mode:
  definitive | scenario_only | blocked
valid_time
knowledge_time
parameters
reviewed_by
counsel_opinion_id
approved_at
review_expires_at
authority_tests[]
artifact_status: draft | approved
```

### CalculationContext

```text
economic_data_as_of
legal_effect_at
policy_known_at
transaction_date
tax_year
filing_exercise
tax_residence
governance_envelope
```

`legal_effect_at` responde “qual regra produz efeitos para o fato?”. `policy_known_at` responde “o que o sistema conhecia naquela execução?”. Essa separação permite reproduzir cálculo histórico sem usar revisão futura.

## 🔍 Resolução

O resolver:

1. valida assinatura, checksum e reviewer;
2. seleciona fontes oficiais e eventos conhecidos em `policy_known_at`;
3. avalia o predicado de escopo sobre os fatos;
4. aplica relações explícitas de alteração/suspensão/restauração;
5. preserva status provisório/contestado; `legal_certainty=contested` exige `policy_output_mode=scenario_only` e jamais produz resposta definitiva;
6. retorna uma regra, um conjunto de cenários ou um reason code;
7. nunca escolhe silenciosamente a versão com maior timestamp.

Competência, especialidade e decisão judicial não são reduzidas a um número universal de “hierarquia”. Conflito não resolvido requer counsel e falha fechada.

## ❌ Reason codes

- `LEGAL_AUTHORITY_MISSING` — sem dispositivo oficial/pinpoint/checksum;
- `LEGAL_STATUS_UNKNOWN` — status não determinável;
- `LEGAL_STATUS_CONTESTED` — decisão provisória ou controvérsia material;
- `POLICY_REVIEW_EXPIRED` — aprovação humana vencida;
- `RULE_UNSUPPORTED_CASE` — fatos fora do escopo;
- `AUTHORITY_CONFLICT` — regras incompatíveis sem resolução;
- `POLICY_SIGNATURE_INVALID` — autenticidade falhou;
- `POLICY_KNOWLEDGE_GAP` — versão não existia no tempo de conhecimento;
- `RETROACTIVITY_UNMODELED` — efeito retroativo não representado.

Nenhum reason code é convertido para zero, alíquota anterior ou regra “mais conservadora” sem cenário explicitamente solicitado. `artifact_status=draft`, marker não resolvido, reviewer ausente ou revisão vencida mantém o pack bloqueado.

## 📊 Saídas contestadas

Quando houver status jurídico contestado, o motor pode calcular cenários:

```text
scenario_id
assumed_legal_event_path
authority_refs
result
not_a_definitive_tax_or_legal_determination: true
```

O relatório não seleciona qual cenário é juridicamente correto sem aprovação atual.

Os enums acima são fechados. Datas usam ISO 8601 conforme a precisão declarada; `unknown`, `open` e `not_applicable` são markers distintos e não podem ser tratados como datas. Precisão maior não pode ser inferida de um texto anual. Relações `amends`, `supersedes`, `suspends` e `restores` referenciam IDs existentes de autoridade ou evento. `clarifies` referencia obrigatoriamente um evento anterior; um `court_clarification` não pode, na mesma linha, alterar, substituir, suspender ou restaurar autoridade/evento.

`source_artifact_path` é o caminho relativo de um arquivo-fonte local regular e sem link. Em `draft`, pode permanecer `unknown`; em `approved`, deve existir e seu conteúdo deve produzir exatamente o `source_checksum` SHA-256 não nulo registrado. URL, diretório, nome de arquivo ou checksum autodeclarado não substituem essa verificação.

## 🔐 Autenticidade e revisão

- checksum detecta alteração; assinatura vincula o artefato a trust root;
- trust root e reviewer são allowlisted por deployment;
- aprovação tem prazo e escopo;
- pack expirado não continua por disponibilidade;
- rollback preserva artefato anterior e motivo;
- release registra policy BOM.

## 🧪 Casos de aceite

- regra futura não é aplicada antes do efeito;
- regra publicada hoje com efeito retroativo aparece somente quando conhecida;
- suspensão interrompe aplicação no intervalo correto;
- restauração `ex_tunc` respeita exceções e esclarecimentos posteriores, sem inferir cobrança no intervalo;
- esclarecimento judicial é `court_clarification`, não orientação administrativa;
- Decreto Legislativo 176 distingue promulgação em 2025-06-26 de publicação no DOU em 2025-06-27;
- dois instrumentos conflitantes retornam `AUTHORITY_CONFLICT`;
- pack expirado retorna `POLICY_REVIEW_EXPIRED`;
- replay com `policy_known_at` histórico não usa consolidação posterior;
- fato fora do escopo retorna `RULE_UNSUPPORTED_CASE`.

## 🔗 Referências

[^1]: Brasil. (2025). “Decreto 12.499.” <https://planalto.gov.br/ccivil_03/_ato2023-2026/2025/decreto/d12499.htm>

[^2]: Congresso Nacional. (2025). “Decreto Legislativo 176.” <https://www2.camara.leg.br/legin/fed/decleg/2025/decretolegislativo-176-26-junho-2025-797660-norma-pl.html>

[^3]: STF. “ADC 96 e ações conexas.” <https://portal.stf.jus.br/processos/detalhe.asp?incidente=7303647>

[^4]: STF. (2025). “Decisão que restabeleceu aumento do IOF não alcança período de suspensão.” <https://noticias.stf.jus.br/postsnoticias/decisao-que-restabeleceu-aumento-do-iof-nao-alcanca-periodo-de-suspensao-esclarece-stf/>

---

_Este contrato não substitui interpretação jurídica nem counsel._
