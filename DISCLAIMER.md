# Disclaimer e limites de uso

_Financial Planning SDK Brasil · blueprint sem implementação pública · 9 de agosto de 2026_

---

## 📋 Finalidade

Este projeto fornece pesquisa, especificações e, futuramente, infraestrutura open source para cálculos e cenários financeiros sob premissas explícitas. O projeto-base tem finalidade **educacional, científica e de engenharia**.

Nesta data, o repositório contém documentação, schemas, fixtures sintéticas e tooling executável de contratos, governança e conformance. Não existe SDK, CLI ou motor financeiro; o tooling não calcula um plano, não recomenda produto e não constitui release.

O repositório ainda não possui `LICENSE`. Disponibilidade do código-fonte ou intenção open source não concede, por si só, permissão de uso, modificação ou distribuição. Quando o mantenedor escolher uma licença, o texto dela governará o software; este documento não a substitui.

## 🤝 Ausência de relação profissional

O acesso, estudo, fork, contribuição ou execução futura não cria, **por si só e no contexto do projeto-base**, relação cliente-consultor, fiduciária, atuarial, contábil, jurídica, de distribuição ou de consumo de serviço financeiro com mantenedores e contribuidores. Uma implantação downstream, contratação ou atuação separada pode criar relações e deveres próprios. Os mantenedores do projeto-base não conhecem os fatos do usuário, não monitoram mudanças pessoais/normativas e não assumem dever de atualizar um resultado downstream.

## ⚠️ Sem garantias e confiança limitada

Na máxima extensão permitida pela lei aplicável, documentação, exemplos, schemas e futuro software serão fornecidos “no estado em que se encontram”, sem garantia de correção, completude, atualidade, comerciabilidade, adequação a finalidade específica, não violação ou disponibilidade. Nada garante que uma hipótese, dado, política, solver ou resultado reflita o caso real.

Quem usa ou incorpora o projeto deve validar independentemente entradas, modelos, normas, licenças e saídas antes de qualquer decisão. Nenhuma cláusula pretende excluir direito ou responsabilidade que a lei não permita excluir. Limitação de garantia não autoriza negligência de segurança, privacidade, regulação ou model risk pelo projeto.

## 🚫 Serviços que o projeto-base não presta

O projeto-base não presta:

- consultoria, análise, administração ou recomendação de valores mobiliários;
- suitability ou certificação de adequação de produto a um cliente;
- assessoria jurídica, tributária, contábil ou atuarial;
- certificação de direito ou valor de benefício previdenciário;
- intermediação, distribuição, cotação ou contratação de seguro/previdência;
- iniciação, execução ou transmissão de ordens;
- garantia de retorno, renda, benefício, cobertura ou resultado fiscal.

Resultados futuros serão condicionais às entradas, políticas, dados e modelos identificados. Convergência numérica não significa correção econômica, adequação pessoal nem autorização regulatória.

## ⚠️ Uso e implantação mudam o enquadramento

Os nomes de módulos, a licença open source, a finalidade educacional e este aviso **não alteram o enquadramento jurídico produzido pelo comportamento real**.

Uma implantação que gere alternativas, personalize, ordene, destaque ou recomende classes de ativos, valores mobiliários ou produtos pode estar sujeita à regulação e a obrigações de registro, suitability, conflitos, guarda e supervisão. Sistemas automatizados não ficam isentos apenas por usarem algoritmo.[^1][^2]

Quem incorporar este projeto em serviço profissional, SaaS, aplicativo B2C ou processo regulado deve:

1. classificar o deployment conforme [deployment-classification.md](docs/governance/deployment-classification.md);
2. obter análise jurídica atual e específica;
3. identificar a entidade operadora e suas autorizações;
4. implementar controles de suitability, privacidade, conflitos e registros quando aplicáveis;
5. manter revisão humana e governança de modelo proporcionais ao risco.

## 📊 Tributos e previdência

Tabelas, normas, decisões judiciais e regras previdenciárias mudam. Um cálculo futuro deve declarar data-base, fatos suportados, fontes, status jurídico e limitações. `indeterminate` ou cenário contestado não pode ser convertido em resposta definitiva.

O simulador oficial do INSS é apenas uma referência e não garante o direito ao benefício.[^3] Materiais e tabelas da Receita Federal ajudam a interpretar casos, mas não substituem análise da legislação e dos fatos individuais.[^4]

## 🔐 Dados pessoais

O projeto-base não deve receber dados pessoais reais em issues, pull requests, exemplos ou relatórios públicos. Não envie CPF, CNIS, data de nascimento completa, informações de saúde, renda, patrimônio, contas, posições ou documentos.

Local-first e ausência de telemetria reduzem superfície, mas não tornam uma aplicação automaticamente conforme à LGPD. Cada implantação é responsável por papéis, finalidades, bases legais, retenção, direitos, segurança, decisões automatizadas e incidentes.[^5]

## 🔗 Dados e software de terceiros

A licença futura do código não concederá direitos sobre dados BCB, Tesouro, CVM, IBGE, B3, ANBIMA, Open Finance, Open Insurance ou qualquer outra fonte. A disponibilidade de uma URL não implica autorização para scraping, armazenamento, redistribuição ou derivação comercial.

Consulte [DATA_LICENSES.md](DATA_LICENSES.md) antes de usar qualquer adaptador ou snapshot.

## 👤 Responsabilidade do implementador

O implementador downstream deve avaliar adequação técnica e jurídica, executar validação independente, preservar avisos e impedir que saídas excedam o escopo aprovado. Não deve apresentar o projeto como homologado por CFA Institute, CVM, BCB, SUSEP, PREVIC, Receita Federal, INSS, IBGE, Planejar ou qualquer outra instituição.

Resultados futuros devem carregar um `GovernanceEnvelope` inseparável, com versão e hash do disclaimer, política de model risk, classe declarada, classe mínima derivada das capacidades, classe efetiva, `intended_use`, `prohibited_uses`, `artifact_status`, contexto regulatório completo e warnings. Interface não pode esconder esses campos em tooltip opcional nem exportar métrica desacompanhada de escopo. Contexto ausente não recebe classe A por default; classe declarada abaixo da derivada é rejeitada. Alterar ou remover avisos não transfere validação ou aprovação do projeto-base ao produto downstream.

Nenhum disclaimer substitui comportamento seguro, evidência, licença, consentimento ou autorização.

## 🔗 Referências

[^1]: CVM. “Resolução CVM 19 — texto consolidado.” <https://conteudo.cvm.gov.br/export/sites/cvm/legislacao/resolucoes/anexos/001/resol019consolid.pdf>

[^2]: CVM. “Resolução CVM 30 — texto consolidado.” <https://conteudo.cvm.gov.br/export/sites/cvm/legislacao/resolucoes/anexos/001/resol030consolid.pdf>

[^3]: INSS. (2026). “Regras de aposentadoria mudam em 2026; entenda.” <https://www.gov.br/inss/pt-br/noticias/noticias/regras-de-transicao-mudam-os-requisitos-para-aposentadoria-em-2026>

[^4]: Receita Federal. (2026). “Tributação de 2026.” <https://www.gov.br/receitafederal/pt-br/assuntos/meu-imposto-de-renda/tabelas/2026>

[^5]: Brasil. “Lei 13.709 — Lei Geral de Proteção de Dados Pessoais.” <https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709compilado.htm>

---

_Este texto é uma especificação de governança do projeto, não um parecer jurídico._
