# Privacidade e proteção de dados

_Política arquitetural do projeto-base · 9 de agosto de 2026_

---

## 📋 Escopo atual

O repositório contém documentação, schemas, fixtures sintéticas e tooling executável de contratos, governança e conformance, mas não contém SDK, CLI ou motor financeiro e **não possui fluxo destinado a coletar, transmitir ou armazenar dados de usuários**. O tooling trabalha sobre artefatos locais e fixtures de teste; isso não o autoriza a receber PII real. Esta política define o comportamento obrigatório de uma implementação futura do núcleo; não é aviso de privacidade de uma aplicação downstream.

Princípio padrão:

> O núcleo calcula localmente sobre artefatos fornecidos pelo chamador, não abre rede, não envia telemetria e não persiste payload pessoal por conta própria.

Uma aplicação que incorpore o núcleo deve publicar seu próprio aviso, mapear papéis e demonstrar conformidade conforme os fatos da implantação.

## 🚫 Dados proibidos no repositório público

Não envie a issues, pull requests, commits, fixtures, screenshots ou relatórios:

- CPF, RG, CNIS ou identificadores equivalentes;
- data de nascimento completa vinculada a pessoa real;
- renda, patrimônio, contas, posições ou transações reais;
- dados de saúde, incapacidade, biometria ou seguros vinculados;
- composição familiar identificável;
- credenciais, tokens, certificados ou consentimentos;
- exportações de Open Finance, Open Insurance, Meu INSS ou Área do Investidor.

Exemplos e testes devem ser integralmente sintéticos. Redação parcial não é anonimização quando a pessoa continua identificável.

## 👤 Papéis por implantação

Antes de tratar dados pessoais, o operador deve registrar:

```text
deployment_id
controller
joint_controllers
processors
subprocessors
data_subject_categories
purposes
legal_basis_by_purpose
sensitive_data_basis
retention_policy
international_transfers
automated_decision_profile
rights_request_channel
incident_response_owner
dpo_or_privacy_owner
```

O mantenedor do código não é automaticamente controlador dos dados processados localmente por terceiros. Pode, porém, assumir papel próprio se operar serviço, receber telemetria, processar crash report ou aceitar payload real em suporte.

## 🔍 Classificação mínima

| Classe | Exemplos | Controle padrão |
| --- | --- | --- |
| **Pública não pessoal** | taxa agregada, metadado oficial | licença e integridade |
| **Pessoal financeiro** | renda, saldo, carteira, meta | minimização, base/finalidade, acesso e retenção |
| **Pessoal regulatório** | CNIS, suitability, histórico contributivo | segregação, trilha e prazo legal |
| **Sensível** | saúde, incapacidade ou inferência equivalente | base específica, RIPD e acesso reforçado |
| **Credencial/segredo** | token, certificado, chave | vault externo; nunca em input ou manifesto |

Dados financeiros são pessoais quando vinculados a uma pessoa, mas não são automaticamente “sensíveis” na definição legal. Dados de saúde/incapacidade e atributos que os revelem podem ser sensíveis.[^1]

## ⚙️ Contrato do núcleo

Uma implementação conforme deve:

- funcionar com rede desabilitada;
- não importar cliente HTTP no núcleo matemático;
- não emitir telemetria por padrão;
- não gravar payload, stack dump ou temporário sem ação explícita;
- separar payload pessoal de `RunManifest`;
- usar identificadores pseudônimos aleatórios, não hashes de CPF/nascimento;
- rejeitar hash bruto disfarçado de ID local e HMAC nulo/sentinel;
- oferecer redaction estruturada em logs e erros;
- limitar bytes, profundidade e dígitos antes/durante parsing, inclusive em envelopes e diagnósticos;
- aceitar consentimento/credencial apenas em conectores externos especializados;
- permitir ao chamador definir armazenamento e criptografia.

CI futuro deve conter teste que bloqueie acesso à rede nos comandos `validate` e `compute`.

## 📝 Manifestos reproduzíveis sem PII

O manifesto privado do operador pode guardar, quando houver finalidade, base, acesso e retenção definidos:

- ID local aleatório ou HMAC SHA-256 não nulo com `key_id`, tratados como dado potencialmente pessoal e pseudônimo, nunca como anonimização;
- versões de software, schema, modelo, parâmetros, políticas e dados;
- seed, runtime, solver e warnings;
- referências pseudônimas.

Não pode guardar:

- campos pessoais brutos;
- fragmentos de input em mensagens de erro;
- hashes isolados de CPF, nascimento, CEP ou salário;
- token, consent ID, certificado ou URL assinada;
- path que revele nome do usuário quando não necessário.

Hash bruto de payload pessoal pode permitir correlação, confirmação por dicionário ou reidentificação quando combinado com outros dados. Portanto não entra nem como `input_sha256` nem disfarçado de `local_id` em output público, log, fixture, issue ou manifesto redistribuído. Quando a reconciliação privada for necessária, o contrato limita a estratégia a ID aleatório do operador ou HMAC chaveado e limita a linkabilidade a `single_case`/`single_operator`.

O scanner recursivo de defesa em profundidade examina chaves e valores de inputs, envelopes, diagnósticos e IDs após normalização Unicode. Ele detecta formatos/dígitos de CPF, segredos sem depender de caixa e conteúdo textual em base64 dentro de budget. Esse controle conservador não prova anonimização e não autoriza inserir dados reais em testes.

## 🔄 Retenção, exclusão e direitos

Uma implantação precisa definir retenção por finalidade. Exclusão controlada pelo titular é um requisito importante, mas pode coexistir com conservação exigida por obrigação legal/regulatória. A Resolução CVM 30, por exemplo, prevê guarda de documentos de suitability em seu âmbito; o projeto-base não decide qual regra se aplica a um operador específico.[^2]

O fluxo deve suportar:

- acesso e confirmação;
- correção;
- portabilidade quando aplicável;
- anonimização/bloqueio/eliminação quando cabíveis;
- registro da justificativa de retenção;
- oposição e revogação conforme base/finalidade;
- contestação e revisão de decisão automatizada.

O art. 20 da LGPD torna especialmente importante explicar critérios e permitir revisão de decisões exclusivamente automatizadas que afetem interesses.[^1]

## 🔐 Open Finance e Open Insurance

Consentimento setorial, autenticação e confirmação têm lifecycle próprio. Conector não deve reutilizar dado após revogação ou expiração. Credenciais e tokens ficam em vault da aplicação/participante, nunca no núcleo.

Somente uma entidade apta no ecossistema pode operar as integrações aplicáveis; cliente gerado a partir de documentação pública não concede participação nem direito aos dados.[^3][^4]

Consentimento setorial e base legal LGPD são controles relacionados, mas não intercambiáveis.

## ⚠️ Avaliação de impacto e incidentes

RIPD e revisão de DPO/privacy owner devem ser gates para deployments que processem saúde, incapacidade, dependentes, perfil patrimonial detalhado, menores ou recomendação automatizada.

Cada aplicação deve possuir:

- inventário e diagrama de fluxo;
- threat model;
- resposta e comunicação de incidente;
- testes de isolamento e autorização;
- gestão de subprocessadores;
- recuperação e eliminação segura;
- evidência de treinamento e revisão.

## 🔗 Referências

[^1]: Brasil. “Lei 13.709 — Lei Geral de Proteção de Dados Pessoais.” <https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709compilado.htm>

[^2]: CVM. “Resolução CVM 30 — texto consolidado.” <https://conteudo.cvm.gov.br/export/sites/cvm/legislacao/resolucoes/anexos/001/resol030consolid.pdf>

[^3]: Banco Central do Brasil. “Resolução Conjunta 1 — Open Finance, versão consolidada.” <https://normativos.bcb.gov.br/Lists/Normativos/Attachments/51028/Res_Conj_0001_v8_P.pdf>

[^4]: SUSEP. “Open Insurance — documentos de referência.” <https://www.gov.br/susep/pt-br/assuntos/open-insurance/documentos_de_referencia>

---

_Este documento define o baseline do projeto; cada deployment exige aviso e avaliação próprios._
