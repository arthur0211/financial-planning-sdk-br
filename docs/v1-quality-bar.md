# V1 Reference Acceptance Bar

Status: `draft_active`
Autoridade: `technical_evaluation_only`
Alvo: primeira versão local da biblioteca; não é gate regulatório, jurídico ou de publicação.

## A barra em uma frase

> A v1 vence quando um usuário sem contexto consegue instalar o pacote em ambientes limpos suportados e executar um corpus público e congelado de planejamento determinístico por SDK e CLI, obtendo resultados canônicos iguais a derivações independentes, diagnósticos úteis e reprodutíveis, mutações materiais integralmente detectadas e limites offline/sem autoridade verificáveis, sem perder para os comparadores nas dimensões obrigatórias abaixo.

Esse corpus executável é o equivalente, para uma biblioteca financeira, às imagens reais usadas como referência visual no experimento Claude of Duty: ele torna a comparação repetível e expõe a maior diferença restante em vez de aceitar uma impressão de qualidade.

## Escopo técnico fechado de `0.1`

A barra mede um núcleo determinístico local:

- dinheiro e decimais com convenção explícita;
- datas civis, tempo e convenções de taxa declaradas;
- fatores de acumulação e desconto fornecidos ou derivados sob convenção fechada;
- fluxos, PV, FV, anuidades/contribuições e necessidade de funding determinística;
- replay de ledger com conservação, ordenação e explicação por evento;
- uma API Python e uma CLI sobre os mesmos contratos JSON.

Não entram por inferência: regra tributária ou previdenciária brasileira, produto financeiro, índice de mercado, mortalidade, otimização, cenário estocástico, suitability, recomendação, execução, rede ou dados pessoais. Uma exclusão explícita não é uma falha da v1; uma alegação implícita de suporte é.

## Reference Acceptance Pack

O pack deve ser versionado, distribuído com o projeto e possuir manifesto fechado. Cada caso material precisa registrar:

- identificador, versão, categoria e finalidade;
- input JSON canônico e output esperado canônico;
- unidades, datas, moeda, timing e convenções;
- pelo menos duas rotas de validação materialmente distintas, ou uma identidade exata mais uma representação numérica independente quando duas derivações algorítmicas não fizerem sentido;
- tolerância explícita; para dinheiro na fronteira pública, comparação em centavos, e para valores internos, tolerância decimal declarada;
- propriedades/invariantes e mutações plausíveis que o caso deve matar;
- proveniência e limites da evidência;
- partição explícita entre suportado, rejeitado e fora de escopo.

O pack não pode chamar a própria implementação de oráculo, converter digest local em autenticação, nem chamar checagem técnica de validação profissional.

## Matriz obrigatória

| Dimensão | Evidência inspecionável | Condição de vitória da v1 |
| --- | --- | --- |
| correção matemática | goldens fechados, segunda derivação/identidade, propriedades e casos de fronteira | todos os casos suportados concordam; nenhuma divergência não explicada |
| cobertura do escopo | manifesto que liga cada requisito `0.1` a casos positivos, negativos e limites | 100% dos requisitos declarados ligados; nenhuma capacidade apenas documental |
| SDK/CLI | mesmo input executado pelas duas superfícies e comparado em bytes canônicos | paridade de resultado, reason codes e exit codes em todo o pack |
| determinismo | repetições com locale, timezone, hash seed e ordem de execução variados | mesmos bytes para o mesmo contrato; estado global não observável |
| diagnósticos | corpus negativo fechado, JSON Pointer, reason code e remediação | erro estável, específico e acionável; nunca traceback como contrato público |
| resistência a mutação | mutantes de fórmula, arredondamento, timing, unidade, ledger e validação | 100% dos mutantes declarados materialmente viáveis mortos por assertions sem crash/timeout |
| API pública | inventário de símbolos, typing estrito e política de compatibilidade | API pequena, documentada, tipada e sem import acidental como contrato |
| instalação e pacote | wheel e sdist construídos de checkout limpo, instalados em ambientes descartáveis | import, SDK, CLI, schemas e pack funcionam a partir dos artefatos, sem usar a árvore fonte |
| plataforma | matriz Python 3.11–3.13 em Windows e Linux | todas as células suportadas verdes ou exceção explícita antes da v1 |
| offline e segurança | testes que bloqueiam rede, escrita implícita, path traversal, PII/secret e inputs sem orçamento | compute/validate não usam rede/telemetria/persistência implícita e falham fechado |
| documentação | quickstart executado, referência de API, conceitos, erros, exemplos e limites | usuário fresco conclui os casos do pack sem conhecimento interno |
| desempenho delimitado | benchmark reprodutível com tamanhos pequenos/médios/grandes e budgets | orçamento publicado satisfeito, sem usar performance para relaxar correção |
| A/B anonimizado | transcritos equivalentes de nossa API/CLI e comparadores permitidos, rótulos aleatórios | nenhuma derrota em requisito obrigatório e escore agregado não inferior |

Cada linha obrigatória é binária: uma média alta não compensa um blocker. “100%” acima se refere ao inventário fechado e versionado da v1; não significa correção universal, cobertura de todo planejamento financeiro ou estado da arte científico.

## Comparadores

Os comparadores fornecem barras parciais, não uma arquitetura a copiar:

- [QuantLib](https://github.com/lballabio/QuantLib): amplitude de engenharia quantitativa, documentação, exemplos, test suite e fuzz suite; somente operações realmente sobrepostas entram em comparação numérica, com versão e convenções fixadas;
- [rateslib](https://github.com/attack68/rateslib): referência pública de ergonomia e documentação, não comparador executável; sua licença source-available impõe restrições materiais, portanto nenhum código, execução de benchmark ou validator será usado sem permissão compatível;
- [lifelib](https://lifelib.io/): modelos atuariais práticos acompanhados por documentação e testes;
- [OpenFisca](https://openfisca.org/doc/key-concepts/tax_and_benefit_system.html): separação entre engine genérico e pacotes de legislação por jurisdição;
- [Python Packaging User Guide](https://packaging.python.org/en/latest/flow/): fluxo normativo de source tree, wheel, sdist e instalação;
- implementação atual do próprio projeto: baseline congelado que toda sprint precisa superar sem regressão.

Quando uma biblioteca não expuser a mesma operação, a comparação será por tarefa equivalente e contrato público observado, não por contagem de features. Código, dados ou textos externos não serão copiados, executados para benchmark ou redistribuídos sem licença/permissão compatível e decisão registrada.

## Protocolo cego A/B

1. O lead fixa uma tarefa, input e rubrica antes de obter as respostas.
2. Um harness remove nomes, ordena aleatoriamente os candidatos e preserva resultados/erros sem edição favorável.
3. O crítico avalia correção primeiro; uma resposta numericamente errada perde independentemente de ergonomia.
4. Depois pontua legibilidade da chamada, explicação, estabilidade, ação do erro e limites explícitos.
5. O relatório revela os rótulos somente após o julgamento e registra o maior gap.

Uma avaliação por agent é challenge interno. Ela não substitui revisão humana, teste em plataforma real ou validação científica externa.

## Regra do loop

Cada sprint escolhe a menor fatia que reduz o maior gap mensurável. Builder e crítico recebem contextos frescos e separados. O crítico inspeciona código, artefato instalado, outputs e testes reais; um verde autorrelatado pelo builder não conta. Se a fatia perder o A/B ou falhar qualquer requisito obrigatório, o finding volta para nova rodada. O loop encerra somente quando todas as linhas obrigatórias estão verdes, as exclusões estão honestas e nenhum finding crítico/alto material permanece — ou quando o owner interromper.

## Estado inicial

O vertical atual de PV e ledger, seu package smoke e sua conformance local são baseline útil, mas ainda não satisfazem esta barra: o escopo `0.1` não está integralmente implementado, a matriz Windows/Linux não está demonstrada e não existe licença ou autoridade de release. Esse estado é `implementation_in_progress`, não “v1 completa”.
