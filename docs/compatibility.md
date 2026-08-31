# Política de compatibilidade dos contratos F0

_Contrato documental para schemas e reason codes · 30 de agosto de 2026_

---

## 📋 Estado e escopo

Esta política governa os artefatos JSON Schema Draft 2020-12 em `schemas/`. A versão atual é `0.0.0`, permanece `draft`, não constitui release de SDK e não autoriza cálculo financeiro. O único caso aceito por `input.schema.json` é `contract_conformance_probe`; seus valores e resultados são sintéticos.

O contrato normativo é composto pelos arquivos declarados em `schemas/conformance-manifest.json`, pelos exemplos positivos e negativos ali enumerados e pelas verificações determinísticas de `scripts/validate_contracts.py`. Prosa explicativa não substitui schema, código de diagnóstico ou gate humano.

## 🔢 Identidade e versão

- Cada schema possui `$id` imutável no namespace `urn:financial-planning-sdk-br:schema:<nome>:<versão>`.
- `contract_version` identifica o conjunto coerente de contratos, não a versão de modelo, policy pack, dado ou software.
- Um consumidor rejeita versão ou `$id` desconhecido com `CONTRACT_SCHEMA_UNSUPPORTED`; não escolhe automaticamente a versão “mais próxima”.
- Antes de uma release `0.0.x`, qualquer mudança pode ser incompatível, mas ainda exige incremento de versão, fixtures e changelog. Não existe promessa de estabilidade pública em `0.0.0`.
- Depois da primeira release de contratos, versões publicadas permanecem reproduzíveis; correções não reescrevem silenciosamente um `$id` já publicado.

## 🔄 Classes de mudança

| Classe | Exemplos | Regra de versão |
| --- | --- | --- |
| Incompatível | remover/renomear campo, tornar opcional um gate obrigatório, alterar unidade ou significado, mudar status padrão de reason code, aceitar capability antes bloqueada | nova versão incompatível do contrato |
| Aditiva controlada | novo `case_type`, novo campo opcional sem default permissivo, novo reason code documentado, nova enumeração que consumidores antigos devem rejeitar | nova versão de contrato; nunca mutação silenciosa |
| Corretiva | descrição, exemplo ou mensagem localizada sem mudança de forma, status ou significado | patch documental, preservando `$id` somente se a instância aceita for idêntica |

Mudar equação, calibração, policy pack, dataset ou deployment não é mascarado por versão de API. Cada eixo conserva sua própria identidade no `RunManifest`.

## 🔐 Compatibilidade fail-closed

- Objetos normativos usam `additionalProperties: false`.
- Campos materiais não recebem default permissivo. `not_applicable` e `unknown` são valores explícitos e distintos; `unknown` nunca equivale a autorização.
- Chave JSON duplicada, inclusive alias Unicode após NFKC/casefold, falha antes da validação de schema.
- Timestamps materiais usam parser RFC 3339 próprio, com data civil real, `T` e timezone obrigatório; datas impossíveis, `-00:00` e a forma tolerante com espaço não são aceitos mesmo sem extras opcionais de formato.
- Todo documento JSON passa pelo mesmo parser limitado: bytes e profundidade são controlados antes do parse; inteiros/decimais têm orçamento de dígitos; `NaN`, infinidade, expoente e zero negativo são rejeitados.
- Reason code desconhecido falha; texto localizado não cria código novo.
- A execução direta de `validate_contracts.py` é diagnóstico/draft-only e recusa `approved`, `computed` e `computed_with_warnings` em qualquer contexto. A coerência futura desses estados continua especificada pelo schema/matriz, mas só poderá ser exercitada por uma boundary externa autenticada ainda inexistente; o Python candidato nunca promove status.
- O resultado conserva `GovernanceEnvelope`, diagnostics e `RunManifest`; exportadores não podem destacar uma métrica desacompanhada desses campos.
- Nenhum `$ref` normativo pode exigir rede. O pack só admite URNs locais canônicas registradas, detecta ciclos mesmo em `$defs` não usados e rejeita IDs resolvidos por alias.
- Raiz, diretório de schemas, exemplos e arquivos inventariados devem ser regulares, sem symlink, junction ou reparse point.

## ⚖️ Classificação de implantação

`RegulatoryUseContext` registra três valores distintos:

1. `declared_deployment_class`: classe informada pelo chamador;
2. `derived_minimum_deployment_class`: piso inferido das capacidades habilitadas;
3. `effective_deployment_class`: maior risco entre a classe declarada e o piso derivado.

A classe derivada é recalculada exatamente das capabilities, e não apenas comparada a um piso permissivo. Execução habilitada deriva `D_EXECUTION`; prescrição, universo gerado pelo sistema ou instrumento específico em fluxo personalizado/rankeado deriva `C_REGULATED_ADVICE`; personalização, ranking não prescritivo, instrumento específico isolado ou remuneração diferente de `none` deriva `B_PROFESSIONAL_ASSIST`; somente a ausência dessas capabilities deriva `A_RESEARCH_CORE`. A classe efetiva é o máximo entre declarada e derivada.

O `GovernanceEnvelope` repete as três classes e o validador exige paridade exata com `RegulatoryUseContext`. `artifact_status` continua enumerando `draft`/`approved`, mas o validator Python direto aceita operacionalmente apenas o caminho draft e não possui argumentos CLI, parser ou verificador de trust. Os protótipos policy/registry/result v4 foram superados e nenhum gate os consome. Uma futura aprovação de contrato exige launcher e relatório externos próprios, fechados e autenticados fora do checkout. Os eixos bloqueadores continuam fail-closed; nenhum estado representa certificação jurídica ou adequação.

O schema ainda descreve os campos necessários a um futuro `ModelCard.artifact_status=approved`: owner/reviewer distintos, janela temporal, evidência local hash-eada e benchmark. Hoje, qualquer instância assim recebe diagnóstico de autoridade ausente. O protótipo de registry tratava tipo de principal como mera assertion do owner; foi removido e nunca provou identidade humana. Probes vivem somente em `tests/contracts/fixtures/`, carregam `test_only: true` e jamais podem receber aprovação/computação operacional.

## 🔏 RunManifest e privacidade

O `RunManifest` contém fingerprints não nulos somente de artefatos aplicáveis; eixos não usados são omitidos. Um manifesto público usa `manifest_privacy_class=public_non_personal`, `linkability_scope=none` e `input_reference.strategy=none`. Um operador que precise de reconciliação privada pode usar ID local aleatório ou HMAC SHA-256 não nulo com key ID, escopo `single_case` ou `single_operator`, acesso e retenção próprios. Hash bruto em hexadecimal/base64 não pode ser disfarçado de ID local. `input_sha256` simples não faz parte do contrato: hash não chaveado de payload pessoal é correlacionável e não constitui anonimização.

## ❌ Reason codes e depreciação

O enum e `x-reason-code-catalog` em `reason-codes.schema.json` devem ter o mesmo conjunto. Cada código registra categoria, severidade padrão, estado computacional padrão, owner e remediação. O validador também exige paridade com `docs/specification/error-catalog.md`.

Um código não muda de significado. Para substituí-lo:

1. adicionar um novo código em nova versão do contrato;
2. documentar o código anterior como deprecated e o sucessor explícito;
3. manter alias apenas em camada de migração opt-in e com prazo;
4. serializar sempre o código canônico da versão selecionada;
5. rejeitar alias expirado ou desconhecido.

A versão `0.0.0` não declara aliases.

## 🧪 Conformance pack

Executar na raiz:

```powershell
python .\scripts\validate_contracts.py
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_docs.ps1
```

Não existe comando contextual para uma fixture `approved`. Os antigos parâmetros de trust foram removidos; passá-los produz erro de CLI e o shim programático de compatibilidade recusa material externo sem ler seus paths. `validate_docs.ps1` aceita somente `-Mode`; parâmetros antigos de bootstrap também são recusados pelo binding do PowerShell.

O primeiro comando exige Python 3.11 ou posterior e `jsonschema` 4.18 ou posterior. Ele não abre rede nem escreve arquivos por design, mas seu startup/import continua pertencendo ao processo candidato; `PYTHONPATH`/`sitecustomize` maliciosos podem invalidar o valor diagnóstico, nunca criar autoridade. Ele valida o meta-schema Draft 2020-12, resolução local de referências, paridade do catálogo de reason codes, inventário do manifesto, formatos e casos positivos/negativos. Também acumula, sem traceback, erros de manifesto corrompido, `$ref` ausente/cíclico, aliases de IDs/paths, campos abertos, chaves prescritivas Unicode e cobertura direta incompleta. A versão exata do validador aparece na saída para auditoria.

Em todo o corpus, e com orçamento público mais estrito para input/diagnostics, os controles rejeitam documentos acima do budget, profundidade JSON acima de 32, número acima de 64 dígitos e padrões conservadores de PII/segredo em chaves, valores, IDs e base64 decodificável limitado. Esses scanners usam normalização Unicode/confusable e são defesa em profundidade; não substituem DLP, classificação ou revisão de privacidade de uma implantação.

Adicionar ou alterar um schema exige, no mesmo change set:

- atualizar o manifesto;
- incluir ao menos um caso válido e um inválido para o comportamento novo;
- preservar exemplos sem PII, segredo ou dado externo;
- classificar a mudança segundo esta política;
- obter os reviewers independentes requeridos para matemática, política, privacidade, licença ou deployment.

## ⚠️ Limites atuais

- Há package Python local `0.1.0.dev0` e workflows candidatos para Python 3.11, 3.13 e 3.14, mas não há lockfile transitivo nem execução remota observada neste checkout. `requires-python >=3.11`, CI declarativa e pins diretos continuam verificações de desenvolvimento, não ambiente hermético ou promessa de release.
- O pack executa os validadores semânticos sobre seu corpus e a suíte adversarial. Existe um runtime/CLI local estreito para `deterministic_cashflow_ledger`, mas não há runtime de produto, serviço, release nem garantia de cobertura universal dos scanners heurísticos.
- Existem 21 vetores matemáticos `draft` e um motor local estreito ligado a sete desses vetores; não existem policy pack aprovado, model card aprovado ou validação humana externa.
- `artifact_status: approved` e estados computados são recusados pelo Python direto; nenhum contexto externo é consumido por esse processo.
- Não existe consumer de trust. `Structure` foi exercitado no Windows PowerShell 5.1 e 7.x, e a matriz instalada histórica permanece parcial/fail-closed; nenhum workflow ou teste local cria compatibilidade de authority em plataforma alguma.
- O source original está sob Apache-2.0 conforme o ADR 0012; dados e recursos de terceiros continuam fora dessa concessão.

Até esses gaps serem fechados, a compatibilidade demonstrada é somente a do pack contratual F0 local.

## 👤 Gates humanos bloqueantes

Passar o conformance pack não altera `artifact_status` de `draft` para `approved`. Não existe hoje uma boundary que autorize essa promoção: os protótipos v4 foram descomissionados depois de falsos verdes de closure, quórum e replay, e `F0` sempre falha. A ausência de relatório externo específico de contratos, reviewer humano verificável, freshness apropriada e demais vínculos continua bloqueando “F0 pronto”, “contrato aprovado” ou “release pronta”, mesmo que todos os checks locais estejam verdes.

A decisão Apache-2.0 e o roster de mantenedor estão registrados, mas não promovem artefato. Enquanto reviewer independente e authority externa permanecerem abertos, o resultado correto é **corpus contratual mecanicamente diagnosticável, ainda não aprovado para F0 ou release**.

---

_Este documento é política de engenharia, não parecer jurídico, atuarial, tributário ou de investimentos._
