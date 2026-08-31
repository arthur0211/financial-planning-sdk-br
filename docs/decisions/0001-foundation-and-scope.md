# ADR 0001 — Fundação, superfície e escopo inicial

- **Status:** aceito para a fase de fundação; licença definida pelo ADR 0012; nome do pacote pendente
- **Data:** 8 de agosto de 2026
- **Decisores:** mantenedor do projeto; revisão adversarial matemática, regulatória e de software

## 📋 Contexto

O objetivo é construir um SDK/CLI open source de planejamento financeiro para o Brasil com rigor científico, atuarial e de software. Começar por Monte Carlo, recomendação ou integrações criaria uma superfície maior do que a validade disponível. O repositório ainda é documentação, sem engine validada.

## ✅ Decisão

1. Adotar uma única distribuição Python, monólito modular, antes de considerar múltiplos pacotes ou serviços.
2. Definir JSON Schema Draft 2020-12 como contrato normativo; usar somente JSON no MVP.
3. Fazer SDK e CLI chamarem a mesma camada de casos de uso.
4. Manter kernel determinístico, puro, offline e sem persistência/telemetria.
5. Separar ingestão de rede em `fetch → raw snapshot → normalize/verify → immutable artifact → compute`.
6. Começar por contratos 0.0 e depois núcleo determinístico 0.1; adiar stochastic, solver, policy packs materiais e integrações.
7. Limitar o projeto-base a cálculo/pesquisa classe A, sem ranking prescritivo, recomendação ou execução.
8. Na fase original, tratar Apache-2.0 como recomendação até decisão do mantenedor. Este item foi satisfeito e substituído pelo ADR 0012.
9. Manter `NERI` fora da API até existir uma definição verificável do mantenedor ou fonte.

## 🔍 Razões

- um núcleo pequeno permite vetores fechados, mutação, análise dimensional e auditoria independente;
- JSON reduz superfície de parser e oferece contrato entre linguagens;
- separação entre rede e cálculo preserva reprodução, privacidade e teste;
- monólito modular reduz custo de compatibilidade durante exploração;
- classificação de deployment reconhece que nomes de funções e disclaimers não definem o enquadramento real;
- licença de código não libera dados de terceiros.

## ⚖️ Alternativas rejeitadas agora

| Alternativa | Motivo |
| --- | --- |
| API web/SaaS primeiro | privacidade, disponibilidade e regulação antes do kernel |
| microsserviços | overhead e falhas distribuídas sem necessidade demonstrada |
| plugin discovery | supply chain e execução dinâmica prematuras |
| YAML no MVP | tags/aliases, dois formatos e maior superfície de segurança |
| “planner completo” numa release | policy packs e modelos sem owners/revisores próprios |
| recomendar produtos | ultrapassa o escopo educacional/research do projeto-base |
| copiar arquitetura de um único OSS | componentes não resolvem o problema familiar/BR completo |

## 📦 Consequências

Positivas:

- especificação e teste precedem estabilização acidental de uma fórmula;
- interfaces permanecem pequenas e reproduzíveis;
- modelos e regras podem evoluir por fingerprints independentes;
- downstream precisa declarar classe e responsabilidade.

Custos:

- primeira release executável será deliberadamente limitada;
- policy packs e dados requerem stewards e revisão contínua;
- documentação e corpus 0.0 exigem investimento antes de features visíveis;
- a decisão posterior de licença e governança não remove os gates independentes de nome estável, validação, authority e release.

## 🧪 Critério de reversão

Reavaliar monólito ou JSON-only apenas se um caso real demonstrar isolamento operacional, cadência/licença incompatível ou interoperabilidade que não possa ser atendida por módulos e adapters. A mudança exige novo ADR, benchmark e threat-model delta.

## 🔗 Referências internas

- [Estudo fundacional](../research/financial-planning-sdk-br-sota.md)
- [Parecer adversarial](../reviews/adversarial-review-2026-08-08.md)
- [Arquitetura](../architecture.md)
- [Classificação de implantação](../governance/deployment-classification.md)
