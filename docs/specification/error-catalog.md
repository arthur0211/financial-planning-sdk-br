# Catálogo de estados, warnings e reason codes

_Contrato draft de governança; SDK/CLI local separado, sem autoridade de aprovação · 9 de agosto de 2026_

---

## 📋 Objetivo

Erros não podem ser texto livre, converter desconhecido em zero nem vazar payload. SDK, CLI e relatórios futuros compartilham o mesmo catálogo versionado. Mensagens ajudam o humano; `code`, `status` e metadados são a interface estável.

## 📝 Envelope

```text
Diagnostic
  code
  category
  severity: info | warning | error | fatal
  computational_status
  message_template_id
  json_pointer
  retryable
  remediation_id
  authority_refs[]
  model_refs[]
  safe_context
```

`safe_context` contém IDs, unidades e limites, nunca valor pessoal bruto. Localização traduz apenas a mensagem; código, severidade e significado não mudam.

## 🔐 Semântica normativa dos metadados

`schemas/reason-codes.schema.json` contém 62 IDs no `enum` fechado e exatamente 62 entradas em `x-reason-code-catalog`. Cada ID aparece uma única vez em cada estrutura e uma única vez como bullet neste documento. O schema Draft 2020-12 restringe a instância ao vocabulário; o validador semântico candidato verifica também a estrutura e os valores da extensão de catálogo. Esse verde é diagnóstico local e não aprova artefato, cálculo ou uso.

Cada entrada possui exatamente estes cinco campos:

| Campo | Restrição draft normativa | Semântica |
| --- | --- | --- |
| `category` | um de `contract`, `unit`, `valuation`, `policy`, `data`, `model`, `solver`, `privacy`, `deployment` | domínio responsável pela classe do evento; deve coincidir com o enum de `Diagnostic.category` |
| `default_severity` | um de `info`, `warning`, `error`, `fatal` | severidade conservadora usada quando o código é emitido; deve coincidir com o enum de `Diagnostic.severity` |
| `default_status` | um de `computed_with_warnings`, `indeterminate`, `rejected` | estado computacional padrão associado ao código; `computed` e qualquer estado de aprovação são proibidos como default |
| `owner` | identificador ASCII lowercase não vazio, com segmentos separados por hífen | owner funcional do contrato; não é atestação de revisão nem autoridade externa |
| `remediation_id` | identificador ASCII lowercase não vazio, com segmentos separados por hífen | referência estável à ação de remediação que o diagnostic deve repetir exatamente |

`remediation_id` é referencial, não texto livre. Um mesmo ID pode atender mais de um reason code somente quando a multiplicidade estiver declarada em `x-shared-remediation-ids` e a lista apontar de volta para entradas que usam exatamente aquele ID. Na versão atual, `replace-data-artifact` é compartilhado apenas por `DATA_CHECKSUM_MISMATCH` e `DATA_SIGNATURE_INVALID`; todas as demais remediações têm multiplicidade um. Compartilhar uma ação não funde causas, severidades ou evidência.

## ⚙️ Estados computacionais

| Estado | Condição | Pode haver métricas? |
| --- | --- | --- |
| `computed` | cálculo e gates requeridos concluíram; todos os eixos estão definitivos/permitidos e nenhum código bloqueia por severity/default | sim |
| `computed_with_warnings` | existe limitação não fatal real e nenhum blocker incompatível permanece | sim, inseparáveis dos warnings |
| `indeterminate` | falta dado, autoridade, status ou identificação | não há resposta material definitiva |
| `rejected` | contrato, escopo, segurança ou numérico inviável | não |

Estados de modelo, política, dado e deployment permanecem campos separados.

O estado do envelope é derivado da matriz completa: `rejected` prevalece sobre `indeterminate`, que prevalece sobre `computed_with_warnings`, que prevalece sobre `computed`. Tanto `governance_reason_codes` quanto diagnostics consultam `default_severity` e `default_status` do catálogo fechado; um código bloqueante não pode coexistir com saída computada.

## 🔍 Namespaces mínimos

### Contrato e unidade

- `CONTRACT_SCHEMA_UNSUPPORTED`
- `CONTRACT_REQUIRED_FIELD_MISSING`
- `CONTRACT_DUPLICATE_KEY`
- `CONTRACT_INPUT_LIMIT_EXCEEDED`
- `UNIT_CURRENCY_MISMATCH`
- `UNIT_PRICE_BASIS_MISMATCH`
- `UNIT_VALUATION_DATE_MISMATCH`
- `RATE_DOMAIN_INVALID`
- `DATE_INTERVAL_INVALID`
- `NUMERIC_ROUNDING_APPLIED`

### Identidade e valuation

- `VALUATION_CONTEXT_MISSING`
- `VALUATION_MEASURE_INCOMPATIBLE`
- `ECONOMIC_CLAIM_DUPLICATE`
- `ECONOMIC_CLAIM_CYCLE`
- `LEDGER_RECONCILIATION_FAILED`
- `RETURN_INCOME_DOUBLE_COUNT`
- `SURVIVAL_TREATMENT_DOUBLE_WEIGHTED`
- `HOUSEHOLD_STATE_UNDEFINED`
- `NON_ANTICIPATIVITY_VIOLATION`

### Política e autoridade

- `LEGAL_AUTHORITY_MISSING`
- `LEGAL_STATUS_UNKNOWN`
- `LEGAL_STATUS_CONTESTED`
- `POLICY_REVIEW_EXPIRED`
- `RULE_UNSUPPORTED_CASE`
- `AUTHORITY_CONFLICT`
- `POLICY_SIGNATURE_INVALID`
- `POLICY_KNOWLEDGE_GAP`
- `RETROACTIVITY_UNMODELED`

### Dados e licença

- `DATA_SNAPSHOT_MISSING`
- `DATA_SCHEMA_MISMATCH`
- `DATA_REVISION_UNRESOLVED`
- `DATA_QUALITY_BELOW_GATE`
- `DATA_LICENSE_UNKNOWN`
- `DATA_LICENSE_RESTRICTED`
- `DATA_CHECKSUM_MISMATCH`
- `DATA_SIGNATURE_INVALID`

### Modelo, cenário e solver

- `MODEL_OUT_OF_SCOPE`
- `MODEL_REVIEW_EXPIRED`
- `MODEL_APPROVAL_INTEGRITY_FAILED`
- `MODEL_PARAMETER_UNIDENTIFIED`
- `RNG_SPEC_MISSING`
- `SCENARIO_WEIGHT_INVALID`
- `SIMULATION_NOT_CONVERGED`
- `SOLVER_INFEASIBLE`
- `SOLVER_UNBOUNDED`
- `SOLVER_TOLERANCE_EXCEEDED`
- `SOLVER_GLOBAL_STATUS_UNKNOWN`
- `MIP_GAP_EXCEEDED`

### Privacidade e deployment

- `PII_IN_PUBLIC_ARTIFACT`
- `SECRET_IN_INPUT_OR_LOG`
- `REGULATED_USE_UNDECLARED`
- `REGULATED_USE_CLASS_MISMATCH`
- `GOVERNANCE_DEPLOYMENT_CLASS_PARITY`
- `GOVERNANCE_ARTIFACT_APPROVAL_REVIEW`
- `GOVERNANCE_APPROVAL_BLOCKED`
- `RUN_MANIFEST_PRIVACY_INVALID`
- `EXECUTION_STATUS_INCOHERENT`
- `DIAGNOSTIC_CATALOG_MISMATCH`
- `DEPLOYMENT_CAPABILITY_FORBIDDEN`
- `SUITABILITY_RECORD_MISSING`
- `HUMAN_REVIEW_REQUIRED`
- `EXECUTION_DISABLED`

## 📊 Mapeamento conservador

| Evento | Estado padrão |
| --- | --- |
| warning de arredondamento dentro do contrato | `computed_with_warnings` |
| fonte requerida ausente | `indeterminate` |
| status jurídico contestado sem cenário aprovado | `indeterminate` |
| policy expirada sem substituta | `indeterminate` |
| schema inválido ou unidade incompatível | `rejected` |
| assinatura/checksum inválido | `rejected` |
| solver não factível | `rejected` para a alternativa; nunca “plano inviável” universal |
| modelo fora da população | `indeterminate` ou `rejected`, conforme exista cálculo parcial explicitamente válido |
| capability regulatória proibida | `rejected` |

Nenhum fallback altera esse mapeamento sem `fallback_id`, razão, impacto e consentimento explícito do caso de uso.

## 🔧 Exit codes CLI propostos

| Código | Significado |
| --- | --- |
| `0` | comando concluído; verificar estado no JSON |
| `2` | contrato/uso da CLI inválido |
| `3` | resultado `indeterminate` |
| `4` | política, autoridade, dado ou licença bloqueou |
| `5` | falha numérica/solver/budget |
| `6` | segurança, assinatura ou capability proibida |
| `70` | erro interno não classificado |

O stdout contém apenas resultado JSON quando solicitado; diagnósticos operacionais vão para stderr. Pipe desabilita ANSI. Um resultado com warnings ainda pode sair `0`, mas warnings permanecem estruturados no JSON.

## 🧪 Critérios de aceite

- paridade de código/status entre SDK e CLI;
- snapshot/golden apenas do envelope, não de texto localizado;
- todo código possui teste, owner, remediação e documentação;
- código desconhecido é rejeitado pelo schema da versão correspondente;
- logs não repetem o valor em `json_pointer`;
- nenhuma mensagem afirma adequação, recomendação ou certeza jurídica;
- catálogo possui política de depreciação e aliases temporários explícitos.

---

_O catálogo está materializado como contrato draft em `schemas/reason-codes.schema.json`; sua validação local não autoriza release nem estabelece autoridade externa._
