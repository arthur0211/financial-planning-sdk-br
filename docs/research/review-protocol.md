# Protocolo de pesquisa e revisão de escopo

_Financial Planning SDK Brasil · revisão executada em 8 de agosto de 2026_

---

## 📋 Classificação do trabalho

Este levantamento é uma **revisão de escopo rápida, estruturada e orientada à engenharia**, não uma revisão sistemática PRISMA nem uma meta-análise. Houve um único revisor, busca bibliográfica assistida por bases públicas, encadeamento de citações por títulos e DOI, inspeção de repositórios e consulta direta a fontes oficiais brasileiras.

O método foi escolhido para responder simultaneamente a quatro classes de pergunta — científica, atuarial, regulatória e de software — sem confundir a autoridade de uma fonte em uma classe com autoridade em outra. Um paper pode sustentar um modelo; uma lei sustenta uma obrigação; um repositório demonstra uma implementação; nenhum deles, isoladamente, prova eficácia de um produto completo.

> 📌 **Regra epistemológica:** toda conclusão do estudo deve ser classificável como evidência externa, inferência de engenharia, hipótese de produto ou decisão ainda pendente.

## 🎯 Perguntas de pesquisa

O protocolo investigou:

1. Quais problemas matemáticos compõem planejamento financeiro ao longo da vida?
2. Quais resultados devem ser calculados além de uma probabilidade binária de sucesso?
3. Como traduzir modelos internacionais para renda, inflação, mortalidade, tributação e previdência brasileiras?
4. Quais fontes brasileiras podem alimentar o sistema e quais licenças limitam uso ou redistribuição?
5. Quais projetos open source podem servir como dependência, adaptador, benchmark ou apenas inspiração?
6. Que arquitetura permite evolução sem misturar regra normativa, dado observado, hipótese e recomendação?
7. Que evidência seria necessária antes de chamar o projeto de estado da arte?

## 🔍 Fontes e estratégia de busca

### Bases consultadas

- **OpenAlex** — descoberta bibliográfica ampla e verificação de trabalhos relacionados por metadados abertos[^1]
- **Crossref** — confirmação de títulos, periódicos, anos e DOI[^2]
- **CFA Institute Research and Policy Center** — monografias de aconselhamento financeiro ao longo da vida[^3]
- **Society of Actuaries** — avaliação de estratégias de renda na aposentadoria[^4]
- **GitHub e GitHub API** — documentação, licença detectada, atividade e escopo de implementações[^5]
- **Fontes oficiais brasileiras** — Planalto, CVM, BCB, Tesouro Nacional, Receita Federal, IBGE, INSS, SUSEP, PREVIC e Open Finance Brasil

Google/web search foi usado apenas como mecanismo de descoberta. Sempre que possível, a evidência foi promovida para a página oficial, texto legal, DOI, documentação do projeto ou repositório original.

### Consultas bibliográficas amplas

As buscas abaixo foram executadas no OpenAlex em 8 de agosto de 2026. Os totais são apenas o número retornado pelo mecanismo antes de triagem e são altamente sensíveis ao índice e à formulação da consulta.

| Consulta | Resultados brutos | Uso no estudo |
| --- | ---: | --- |
| `life cycle financial planning consumption portfolio human capital` | 31.555 | Descoberta ampla; ruído elevado |
| `retirement income dynamic spending longevity annuity` | 1.130 | Desacumulação e longevidade |
| `goals based wealth management stochastic optimization financial planning` | 9.092 | Metas e otimização; ruído elevado |
| `Brazil retirement planning pension mortality inflation` | 962 | Contexto brasileiro; ruído elevado |

Esses totais **não são contagens de estudos elegíveis**. A seleção foi feita por título, resumo quando disponível, fonte, DOI e contribuição direta às perguntas. Trabalhos canônicos foram recuperados também por pesquisa de título exato e encadeamento de referências.

### Consultas direcionadas

Foram usadas combinações e títulos exatos relacionados a:

- `lifetime portfolio selection`, `optimal consumption`, `human capital` e `labor income`;
- `retirement income`, `dynamic spending`, `annuitization` e `longevity risk`;
- `goals based investing`, `mental accounts`, `shortfall` e `utility`;
- `multi-period portfolio optimization`, `model predictive control`, `robust optimization` e `distributionally robust`;
- `mortality forecasting`, `Lee-Carter`, `cohort mortality` e `joint life`;
- `Brazil financial planning`, `planejamento financeiro`, `necessidade de renda`, `capital necessário` e a sigla `NERI`;
- nomes dos repositórios e dos provedores oficiais brasileiros.

## ⚙️ Processo de seleção

```mermaid
flowchart LR
    accTitle: Seleção e síntese das evidências
    accDescr: Processo de pesquisa que separa descoberta ampla, verificação em fonte primária, classificação de autoridade e tradução para requisitos testáveis do projeto

    discover[🔍 Descobrir fontes] --> verify[✅ Verificar origem]
    verify --> classify[🏷️ Classificar autoridade]
    classify --> extract[📥 Extrair contribuição]
    extract --> challenge[🧪 Procurar limitações]
    challenge --> translate[⚙️ Traduzir em requisito]
    translate --> ledger[(📝 Registrar no ledger)]
```

### Critérios de inclusão

- modelo matemático diretamente relevante a decisões financeiras familiares ao longo da vida;
- métrica, protocolo de validação ou crítica metodológica aplicável ao motor;
- fonte oficial brasileira necessária a regras, dados, consentimento ou licenciamento;
- software open source com implementação reutilizável, arquitetura transferível ou valor como comparador diferencial;
- fonte com autoria, origem e versão verificáveis;
- material em português ou inglês.

### Critérios de exclusão

- conteúdo promocional usado como prova de eficácia;
- estratégia de investimento sem método, suposições ou limitações observáveis;
- repositório sem licença usado como fonte de código;
- duplicata, agregador ou texto secundário quando a fonte primária estava disponível;
- estudo sem ligação operacional com as perguntas de pesquisa;
- alegação sobre lei, tributação ou integração baseada apenas em memória ou artigo de terceiros.

### Extração mínima

Para cada item material foram registrados: identificador, tipo de fonte, autoridade, ano, título, localizador, finalidade, transferibilidade ao Brasil, limitação e data de verificação. O resultado está em [evidence-ledger.csv](evidence-ledger.csv).

## 📊 Hierarquia de evidência

O ledger usa uma classificação contextual, não um ranking universal:

| Código | Classe | Pode sustentar | Não sustenta sozinho |
| --- | --- | --- | --- |
| `LAW` | Lei ou norma oficial consolidada | obrigação e escopo regulatório na vigência | qualidade matemática ou produto futuro |
| `GOV` | dado, metodologia ou manual oficial | definição, disponibilidade e proveniência | ausência de erro ou adequação universal |
| `PEER` | artigo revisado por pares | método e resultado no domínio estudado | validade automática no Brasil |
| `MONO` | monografia técnica institucional | síntese e arquitetura conceitual | consenso científico completo |
| `ACT` | estudo atuarial profissional | métricas e práticas de avaliação | recomendação universal |
| `OSS` | código e documentação open source | comportamento implementado e padrões | correção científica só por existir |
| `STD` | padrão ou especificação técnica | contrato de interoperabilidade | conformidade real da futura implementação |

Cada uso também recebe um papel de engenharia:

- **Autoridade** — fonte que define regra, esquema ou dado oficial
- **Base científica** — modelo a implementar ou comparar
- **Benchmark** — implementação independente para teste diferencial
- **Adaptador** — dependência opcional de integração
- **Inspiração** — padrão arquitetural sem reutilização direta
- **Alerta** — evidência de limitação, licença ou risco

## 📚 Tratamento de “NERI”

Foram pesquisadas a sigla exata e combinações com `planejamento financeiro`, `aposentadoria`, `necessidade de renda` e `capital necessário`. A sigla não foi localizada como conceito técnico consolidado nas fontes examinadas. No material oficial de educação financeira consultado, aparecem os conceitos descritivos de **renda necessária**, **necessidade de renda complementar** e **capital necessário**, mas não a sigla.[^6]

Consequentemente:

- o estudo não inventa uma expansão para `NERI`;
- o domínio proposto usa `needs` e `retirement_income_gap`;
- `NERI` pode virar alias ou nome editorial apenas após definição verificável do usuário e registro no glossário;
- nenhum cálculo depende dessa nomenclatura.

## 🔄 Reprodutibilidade

Uma atualização da revisão deve:

1. registrar data, executor e versões das APIs usadas;
2. repetir as quatro consultas amplas e guardar apenas as novas contagens como diagnóstico;
3. verificar DOI pelo endpoint de obras da Crossref;
4. consultar licença e estado dos repositórios pelo GitHub API, depois confirmar arquivos de licença ambíguos no próprio repositório;
5. consultar textos consolidados e páginas oficiais para fatos brasileiros sujeitos a mudança;
6. atualizar o ledger sem apagar o registro anterior;
7. marcar fontes retiradas, substituídas ou superadas;
8. revisar qualquer requisito de software afetado.

O acesso ao OpenAlex foi de baixo volume e sem endereço de e-mail institucional para o _polite pool_. A repetição profissional deve fornecer um contato do mantenedor e respeitar as políticas de uso da API.[^1]

## ⚠️ Limitações

- Revisão conduzida por um único revisor, sem dupla triagem independente
- Ausência de busca integral em bases fechadas como Scopus ou Web of Science
- Não houve avaliação quantitativa de risco de viés por paper nem meta-análise
- Parte dos artigos só foi avaliada por metadados, resumo e contribuição estabelecida; acesso integral deve ser confirmado antes de implementar fórmulas específicas
- A atividade de um repositório não comprova maturidade, segurança ou correção
- Leis, normas, tabelas tributárias, calendários e contratos de dados mudam; a verificação vale para 8 de agosto de 2026
- A tradução de modelos internacionais para o Brasil é uma inferência de engenharia que ainda exige validação empírica, atuarial, jurídica e profissional local

> ⚠️ **Interpretação correta:** o corpus é suficiente para definir uma arquitetura e um programa de validação. Não é evidência de que um motor ainda não implementado produz aconselhamento adequado ou melhora resultados financeiros.

## 🔗 Referências

[^1]: OpenAlex. “API Overview.” <https://docs.openalex.org/how-to-use-the-api/api-overview>

[^2]: Crossref. “REST API.” <https://www.crossref.org/documentation/retrieve-metadata/rest-api/>

[^3]: CFA Institute Research and Policy Center. (2024). “Lifetime Financial Advice: A Personalized Optimal Multilevel Approach.” <https://doi.org/10.56227/24.1.3>

[^4]: Society of Actuaries Research Institute. (2023). “A Primer on Retirement Income Strategy Design and Evaluation.” <https://www.soa.org/resources/research-reports/2023/ret-income-strat-de/>

[^5]: GitHub. “REST API endpoints for repositories.” <https://docs.github.com/en/rest/repos/repos>

[^6]: CVM e Planejar. (2025). “TOP Planejamento Financeiro Pessoal”, 2ª ed. <https://www.gov.br/investidor/pt-br/educacional/publicacoes-educacionais/livros-cvm/livro-top-planejamento-financeiro-pessoal>

---

_Última atualização: 8 de agosto de 2026_
