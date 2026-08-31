# Governança de risco de modelo

_Contrato fundacional para modelos financeiros e atuariais · 8 de agosto de 2026_

---

## 📋 Estado atual

Não existe modelo executável neste repositório. As fórmulas e arquiteturas são propostas em revisão. O parecer adversarial classificou a fundação como `MAJOR REVISION` e proibiu claim SOTA antes da resolução dos gates.[^1]

O objetivo desta política é impedir que implementação, convergência ou popularidade sejam confundidas com validade.

## 🎯 Definição de risco de modelo

Risco de modelo é a possibilidade de decisões, métricas ou comunicações inadequadas resultarem de:

- problema econômico mal formulado;
- hipótese ou dado inadequado;
- erro matemático ou numérico;
- implementação divergente da especificação;
- uso fora da população, data ou finalidade validadas;
- regra jurídica desatualizada ou contestada;
- explicação ou interface que exceda o que o modelo sustenta.

## 📝 Model card obrigatório

Cada modelo material deve registrar:

```text
model_id
specification_version
artifact_status: draft | approved
test_only
owner
independent_reviewer
intended_purpose
prohibited_uses
supported_population_and_cases
equations_and_units
valuation_context
information_set
data_and_parameter_versions
policy_dependencies
assumptions
known_limitations
validation_evidence
benchmark_protocol
uncertainty_decomposition
failure_modes
fallback
approved_at
review_expires_at
approval_attestation
```

`artifact_status` é enum fechado, mas não é autoatestação. Modelo `draft`, ou sem owner, reviewer independente, trust policy/registry Ed25519, chave do owner fora de banda, runtime pinado, release attestation independente, evidência verificável ou prazo vigente no `evaluation_time`, é `research-only` e não entra em resultado `computed`. Owner e reviewer são resolvidos pelo registry externo com NFKC, casefold, skeleton conservador e aliases declarados; duas grafias da mesma pessoa não criam independência. `approved` descreve uma decisão registrada dentro de escopo e prazo; não significa adequação universal nem conformidade regulatória. `test_only: true` identifica exclusivamente probes sintéticos isolados da superfície pública.

Cada evidência positiva inclui timestamp, resumo do conteúdo, path local regular e fingerprint SHA-256 não nula recalculada. O benchmark de modelo aprovado está `completed`, preserva o artefato pré-registrado e contém ao menos um comparador independente com a mesma verificabilidade; nomes, URLs ou checksums sem conteúdo não bastam.

## 🔍 Cinco dimensões de validade

| Dimensão | Pergunta | Gate |
| --- | --- | --- |
| **Conceitual** | o problema representa a decisão? | revisão de domínio e ADR |
| **Matemática** | equações, medidas e unidades fecham? | derivação e casos analíticos |
| **Numérica** | algoritmo resolve a especificação? | convergência, resíduos e comparadores |
| **Empírica** | parâmetros descrevem o contexto? | calibração, holdout e stress |
| **Uso** | saída é interpretável e apropriada ao deployment? | validação operacional, jurídica e humana |

Nenhuma dimensão substitui outra.

## ⚙️ Estados de resultado

Estados computacionais propostos:

- `computed` — execução concluída dentro das tolerâncias, com artefato externamente atestado, modelo aprovado para o uso declarado, policy definitiva, dado aprovado, licença permitida, uso elegível e nenhum reason code bloqueante;
- `computed_with_warnings` — execução concluída com ao menos uma limitação não fatal real e nenhum blocker de severidade/default incompatível;
- `indeterminate` — informação, regra ou status necessário é desconhecido;
- `rejected` — contradição, escopo não suportado ou falha numérica.

Separadamente, o resultado carrega:

- `model_use_status`;
- `policy_status`;
- `data_quality_status`;
- `regulatory_use_status`;
- `reproducibility_class`.

O status é derivado pela matriz completa de eixos e metadados fechados do catálogo; não pode ser escolhido para esconder um blocker. `computed` nunca significa “plano válido”, “adequado” ou “recomendado”.

## 📊 Incerteza

Relatórios devem separar:

- incerteza aleatória de trajetória;
- erro amostral Monte Carlo;
- incerteza de parâmetro;
- incerteza de especificação/modelo;
- incerteza jurídica/política;
- qualidade e revisão de dado;
- incerteza comportamental e de preferência.

Um intervalo Monte Carlo estreito não reduz incerteza de modelo. Um solver convergente não valida parâmetros.

## 🧪 Programa mínimo de challenge

- casos fechados e dimensional analysis;
- invariantes e testes metamórficos;
- mutação de fórmulas críticas;
- comparadores diferenciais pinados;
- enumeração em problemas pequenos;
- rolling-origin e holdout temporal congelado;
- stress econômico, atuarial, jurídico e operacional;
- perturbation tests de parâmetros e inputs;
- backtest point-in-time sem revisão futura;
- reprodução independente;
- tentativa explícita de encontrar cenários onde o baseline vence.

Bibliotecas como HARK, QuantLib e `R-fixedincome` são **comparadores independentes**, não oráculos. Oráculos são soluções analíticas, enumeração exaustiva em caso reduzido ou exemplos oficiais dentro de seu escopo.

## 🔄 Ciclo de vida

1. `proposed` — hipótese e especificação incompleta;
2. `experimental` — implementação sem claim estável;
3. `research` — casos analíticos e benchmark reproduzível;
4. `beta` — revisão independente e contexto brasileiro;
5. `stable` — compatibilidade, validação externa e histórico;
6. `deprecated` — substituído, mas reproduzível;
7. `retired` — bloqueado para novas execuções.

Mudança em equação, calibração, policy pack ou dataset não é mascarada por versão de API.

## 🚫 Usos proibidos no projeto-base

- recomendação individualizada ou execução;
- garantia de benefício, imposto ou cobertura;
- inferência individual de saúde/mortalidade a partir de tábua populacional;
- atribuição chamada de causal sem desenho causal identificável;
- política estocástica que use informação futura;
- policy pack vencido, contestado ou sem reviewer;
- cálculo com dados licenciados fora do escopo;
- narrativa que omita warnings ou transforme `indeterminate` em zero.

## 📈 Gate para claim SOTA

“Estado da arte” só pode aparecer como conclusão de benchmark se:

- todos os bloqueadores científicos e regulatórios estiverem fechados;
- comparadores, versões e casos estiverem pré-registrados;
- houver holdout temporal congelado;
- métricas, tolerâncias e regra de ranking forem definidas antes do resultado;
- derrotas e falhas forem publicadas;
- ganhos forem estatística e economicamente materiais;
- resultados forem estáveis a perturbações e stresses;
- reprodução e challenge independentes tiverem êxito;
- houver revisão atuarial, científica, jurídica, privacy e de licença proporcional ao escopo;
- o claim identificar exatamente qual capacidade, versão, população e data superou qual baseline.

Até lá, usar “orientado à fronteira” e “ainda não validado”.

## 🔐 Relação com disclaimers

[DISCLAIMER.md](DISCLAIMER.md) comunica limites ao usuário. Este documento controla o processo interno. Nenhum disclaimer corrige um modelo defeituoso ou uso fora do escopo.

## 🔗 Referências

[^1]: Financial Planning SDK Brasil. (2026). “Revisão adversarial e pré-mortem da fundação.” [Documento interno](docs/reviews/adversarial-review-2026-08-08.md)

ASOP 56 pode ser usada como referência internacional de governança de modelagem, sem ser apresentada como norma brasileira.[^2]

[^2]: Actuarial Standards Board. “ASOP No. 56 — Modeling.” <https://www.actuarialstandardsboard.org/asops/modeling-3/>

---

_Última atualização: 8 de agosto de 2026_
