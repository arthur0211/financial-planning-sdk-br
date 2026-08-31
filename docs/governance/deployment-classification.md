# Classificação regulatória de implantação

_Controle de engenharia; não constitui parecer ou autorização · 8 de agosto de 2026_

---

## 📋 Objetivo

A mesma biblioteca pode ser usada em pesquisa local ou em serviço materialmente regulado. O nome da função não decide o enquadramento. Este controle impede que capacidades prescritivas sejam ativadas sem contexto, operador e revisão.

> ⚠️ **Limite:** a classificação é um gate técnico conservador. O uso concreto ainda precisa de análise jurídica atual.

## 📊 Classes

| Classe | Uso | Saída permitida | Gate |
| --- | --- | --- | --- |
| `A_RESEARCH_CORE` | pesquisa, educação, cálculo local | métricas, atribuição de modelo, sensibilidade e Pareto sobre alternativas fornecidas | sem ranking prescritivo, ativo específico ou CTA |
| `B_PROFESSIONAL_ASSIST` | apoio a profissional | comparação personalizada sujeita a revisão humana | operador, reviewer e perímetro aprovados |
| `C_REGULATED_ADVICE` | recomendação individualizada | somente em estrutura autorizada e governada | autorização, suitability, conflitos, registros e counsel |
| `D_EXECUTION` | ordem, contratação ou intermediação | nenhuma no projeto-base | hard-disabled e integração separada |

A ordem de severidade é fechada: `A_RESEARCH_CORE < B_PROFESSIONAL_ASSIST < C_REGULATED_ADVICE < D_EXECUTION`. A classe efetiva é a mais alta entre a classe declarada e a classe mínima derivada das capacidades. Ela nunca pode ser rebaixada por nome de produto, disclaimer ou configuração downstream.

## 📝 Contexto obrigatório

```text
RegulatoryUseContext
  declared_deployment_class:
    A_RESEARCH_CORE | B_PROFESSIONAL_ASSIST |
    C_REGULATED_ADVICE | D_EXECUTION
  operator_legal_entity
  operator_jurisdiction
  authorization_type
  authorization_registry_id
  client_specific
  instrument_scope:
    cashflow_only | generic_asset_class | security |
    insurance | pension_product
  alternatives_origin:
    user_supplied | professional_supplied | system_generated
  ranking_enabled
  recommendation_language_enabled
  execution_enabled
  compensation_model
  conflict_policy_id
  suitability_record_id
  human_reviewer_id
  counsel_opinion_id
  retention_policy_id
```

Todos os campos existem no payload; campos condicionais não aplicáveis usam o marker explícito `not_applicable`. Enums não aceitam valores livres e flags são booleanos, nunca `null`. Contexto ausente, valor desconhecido ou combinação contraditória é rejeitado; em particular, `A_RESEARCH_CORE` nunca é usado como default.

## 🔍 Classe mínima derivada

As regras são avaliadas de cima para baixo, e vence a classe mais severa aplicável:

| Capacidade observada | Classe mínima |
| --- | --- |
| `execution_enabled=true`, CTA transacional, transmissão de ordem, contratação ou intermediação | `D_EXECUTION` |
| recomendação individualizada, ranking/destaque para cliente, linguagem de recomendação, universo gerado pelo sistema ou produto/instrumento específico em fluxo prescritivo | `C_REGULATED_ADVICE` |
| comparação personalizada preparada para uso profissional, ainda sem recomendação/execução e com revisão humana obrigatória | `B_PROFESSIONAL_ASSIST` |
| cálculo local não prescritivo sobre alternativas fornecidas, sem ranking, destaque, recomendação, produto gerado ou CTA | `A_RESEARCH_CORE` |

Ambiguidade não deriva classe A: retorna `REGULATED_USE_UNDECLARED` ou `REGULATED_USE_CLASS_MISMATCH`. Declarar uma classe mais severa é permitido; declarar classe inferior à derivada é erro fatal. Classe A é deliberadamente conservadora: não gera universo, não escolhe alternativa, não ordena empate, não converte Pareto em “melhor” e não produz linguagem de adequação.

## 🧾 GovernanceEnvelope obrigatório

Entrada e saída carregam um envelope inseparável do resultado:

```text
GovernanceEnvelope
  artifact_status: draft | approved
  disclaimer_id
  disclaimer_version
  disclaimer_hash
  model_risk_policy_id
  declared_deployment_class
  derived_minimum_deployment_class
  effective_deployment_class
  intended_use[]
  prohibited_uses[]
  warnings[]
  regulatory_use_context: RegulatoryUseContext
```

`artifact_status` é enum fechado. `draft` nunca autoriza uso ou release; `approved` exige checksum verificável, reviewer independente identificado, datas de aprovação/expiração válidas e todos os gates condicionais da classe. O reporting não pode remover, ocultar ou contradizer o envelope.

## 🔐 Regras fail-closed

- contexto ausente → `REGULATED_USE_UNDECLARED`;
- classe declarada inferior à mínima derivada → `REGULATED_USE_CLASS_MISMATCH`;
- `GovernanceEnvelope` ausente ou `artifact_status=draft` → resultado não elegível para release/uso downstream;
- classe A não gera universo investível nem campo `best`/`recommended`;
- classe A retorna vetores, trade-offs e fronteira de Pareto sem destaque dominante;
- classe B exige aprovação humana antes de exportar ao cliente;
- classe C exige autorização, suitability, conflitos, registro e versão inspecionável do algoritmo;
- CTA, integração de ordem ou alteração automática de carteira eleva a D;
- D permanece indisponível no projeto-base;
- saída não pode rebaixar a classe declarada pela aplicação;
- disclaimer não substitui nenhum desses gates.

## ⚙️ Algoritmos em implantação regulada

Quando aplicável, preservar:

- fonte/commit e artefato efetivamente executado;
- schema, modelo, parâmetros e policy packs;
- configurações, restrições e dependências;
- alternativas consideradas e origem;
- dados e momento de conhecimento;
- suitability e revisão humana;
- conflitos e remuneração;
- resultado entregue e warnings;
- prazo de retenção e controle de acesso.

A Resolução CVM 19 alcança sistemas automatizados no âmbito por ela disciplinado; a Resolução CVM 30 trata recomendações dirigidas a cliente específico.[^1][^2]

## 🧪 Testes de conformidade do produto

Para classe A, testes devem falhar se:

- schema contiver `recommended`, `best_product`, `buy`, `sell` ou CTA;
- o motor gerar ativos/produtos não fornecidos;
- um relatório esconder alternativa Pareto-incomparável;
- texto afirmar adequação ao perfil;
- exportação remover escopo e warnings;
- comando abrir rede ou executar ordem.

Esses testes não certificam não incidência regulatória; apenas demonstram coerência com o escopo pretendido.

## 🔗 Referências

[^1]: CVM. “Resolução CVM 19 — texto consolidado.” <https://conteudo.cvm.gov.br/export/sites/cvm/legislacao/resolucoes/anexos/001/resol019consolid.pdf>

[^2]: CVM. “Resolução CVM 30 — texto consolidado.” <https://conteudo.cvm.gov.br/export/sites/cvm/legislacao/resolucoes/anexos/001/resol030consolid.pdf>

---

_Última atualização: 8 de agosto de 2026_
