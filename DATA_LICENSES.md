# Governança de licenças e dados

_Baseline de dados do projeto-base · 8 de agosto de 2026_

---

## 📋 Regra central

**Licença do código, licença do adaptador e direitos sobre o dado são objetos separados.**

O projeto-base não redistribuirá datasets, snapshots, credenciais ou derivados enquanto o recurso não possuir manifesto revisado. Uma URL pública não implica autorização para automação, armazenamento, redistribuição, uso comercial ou criação de produto.

## 🚫 Default seguro

Quando a licença ou contrato não estiver verificado:

- o recurso recebe `redistribution: prohibited_or_unknown`;
- nenhum dado real entra em Git, wheel, sdist, documentação ou fixture;
- testes usam dados sintéticos;
- adaptador, se existir, apenas ajuda o usuário autorizado a criar artefato local;
- cálculo recebe o artefato pronto e não abre rede;
- CI não raspa nem baixa a fonte.

`adapter-only` reduz redistribuição pelo projeto, mas não resolve direitos do usuário nem termos de acesso.

## 📝 Data License Manifest

Cada recurso precisa de:

```text
dataset_id
resource_id
licensor
source_url
license_id
license_text_url
license_version
contract_id
retrieved_at
observed_at
effective_at
source_artifact_path
source_checksum
privacy_class
automated_access
storage_allowed
redistribution
commercial_use
derivative_database
produced_work_notice
share_alike
machine_readable_offer
attribution_status
attribution_text
contract_expiry
reviewed_by
reviewed_on
review_expires_at
artifact_status
```

Enums são fechados:

- `artifact_status`: `draft | approved`;
- `privacy_class`: `public_aggregate | public_market | public_regulated_entity | contractual_market | personal_financial | personal_financial_or_sensitive | personal_regulatory`;
- `automated_access`, `storage_allowed`, `redistribution`, `commercial_use` e `derivative_database`: `allowed | restricted | contract_required | prohibited | unknown | not_applicable`;
- `produced_work_notice`, `share_alike` e `machine_readable_offer`: `required | not_required | conditional | contract_required | unknown | not_applicable`;
- `attribution_status`: `provided | required | contract_required | unknown | not_applicable`.

`unknown`, `unassigned`, `not_applicable` e `open` são markers explícitos, não aprovações. Ausência nunca equivale a `allowed`. Recurso `draft`, sem artefato local/checksum verificado/reviewer/prazo, com marker não resolvido em direito material ou ausente do manifesto é bloqueado para ingestão e distribuição. Em `approved`, `source_artifact_path` precisa apontar para arquivo local regular e o SHA-256 deve ser recalculado sobre seus bytes; URL, diretório, arquivo renomeado ou digest nulo não bastam.

## 📊 Matriz inicial

| Fonte/recurso | Regime observado | Risco | Política inicial |
| --- | --- | --- | --- |
| **BCB Focus** | ODbL específica do dataset[^1] | base derivada/share-alike | pacote de dados separado após análise |
| **Tesouro Direto taxas** | ODbL do dataset[^2] | notice e derivados | não embutir no wheel |
| **CVM informe diário** | ODbL do dataset[^3] | revisões e base derivada | preservar vintages e manifesto |
| **IBGE mortalidade/projeções** | licença do recurso ainda não registrada | acesso/redistribuição incertos | adapter-only; não raspar HTML |
| **B3 market data** | política/contrato por uso e produto[^4] | armazenamento, derivação e redistribuição | nenhum snapshot real sem contrato |
| **B3 posição do cliente** | dado pessoal sob canal autorizado | privacidade e direito de acesso | separar de market data |
| **ANBIMA REUNE** | uso de referência e restrições de distribuição[^5] | uso comercial/índices | sem redistribuição |
| **ANBIMA Feed** | termos e autorização específicos[^6] | uso interno, derivados e cessação | conector somente para autorizado |
| **ANBIMA calendário** | termo do recurso ainda precisa ser fechado | redistribuição incerta | snapshot não distribuído |
| **CNIS/Meu INSS** | dado do titular; não é open data | LGPD, sigilo e credenciais | importação fornecida pelo usuário |
| **Open Finance** | compartilhamento regulado | consentimento e participação | pacote externo por participante |
| **Open Insurance** | compartilhamento regulado | consentimento, participação e saúde | pacote externo segregado |

Não se generaliza a licença de Focus para SGS, PTAX ou todo o BCB. Cada `resource_id` tem seu próprio manifesto.

A matriz e o CSV devem ter cobertura correspondente. B3 posição do cliente, calendário ANBIMA e CNIS/Meu INSS permanecem registrados como recursos `draft` e fail-closed, ainda que nenhum dado seja armazenado. Recurso citado ou solicitado que não tenha linha própria retorna `DATA_LICENSE_MANIFEST_MISSING`; não herda termos de outra linha nem entra em release.

## ⚙️ ODbL

A ODbL pode exigir:

- manutenção de avisos;
- share-alike quando uma base derivada é usada publicamente;
- acesso em formato legível por máquina à base derivada ou às alterações, conforme o caso;
- aviso na obra produzida;
- análise separada de direitos sobre conteúdos individuais.[^7]

Determinar se um artefato é `Derivative Database`, `Collective Database` ou `Produced Work` é decisão jurídico-técnica por caso. “Atribuir a fonte” não encerra a análise.

## 🔐 Market data contratual

B3 diferencia consumo, distribuição, uso próprio e desenvolvimento de produtos em suas políticas. Dados ou derivados fora da licença podem exigir autorização e remuneração.[^4]

ANBIMA possui termos por produto. REUNE e Feed não devem ser tratados como dados públicos livres só porque uma página pode ser acessada.[^5][^6]

Credenciais pertencem ao usuário/entidade autorizada e não entram em config de exemplo, logs ou CI.

## 👤 Dados pessoais

Licença de base e base legal LGPD são controles ortogonais:

- uma base aberta pode conter obrigações de privacidade;
- consentimento para compartilhar dados pessoais não concede licença de market data;
- direito do titular a acessar seus dados não autoriza redistribuição pelo projeto;
- agregação não garante anonimização.

Consulte [PRIVACY.md](PRIVACY.md).

## 📦 Release e Data BOM

Todo release futuro precisa comprovar:

- nenhum arquivo de dado real não aprovado no artefato;
- inventário de fixtures e sua origem sintética;
- manifestos de recursos distribuídos;
- textos de atribuição e notices;
- obrigações de share-alike satisfeitas;
- contratos não expirados;
- checksum e assinatura quando aplicáveis;
- separação entre código, configuração e dados.

Um gate automatizado deve listar todos os arquivos acima de tamanho definido e extensões de dados, e exigir allowlist humana.

## 🔗 Referências

[^1]: Banco Central do Brasil. “Expectativas de Mercado.” <https://dadosabertos.bcb.gov.br/dataset/expectativas-mercado>

[^2]: Tesouro Nacional. “Taxas dos Títulos Ofertados pelo Tesouro Direto.” <https://www.tesourotransparente.gov.br/ckan/dataset/taxas-dos-titulos-ofertados-pelo-tesouro-direto>

[^3]: CVM. “Fundos de Investimento: Informe Diário.” <https://dados.cvm.gov.br/dataset/fi-doc-inf_diario>

[^4]: B3. (2026). “Política de Consumo de Market Data.” <https://www.b3.com.br/data/files/A0/D0/A2/FD/F441B9105B12E5A9AC094EA8/Politica%20de%20Consumo%20Market%20Data%20B3.pdf>

[^5]: ANBIMA. “REUNE.” <https://www.anbima.com.br/informacoes/reune/reune_result.asp>

[^6]: ANBIMA. “Termos de uso ANBIMA Feed — segmento do investidor.” <https://www.anbima.com.br/pt_br/informar/termos-de-uso-anbima-feed-segmento-do-investidor.htm>

[^7]: Open Data Commons. “Open Database License 1.0.” <https://opendatacommons.org/licenses/odbl/1-0/>

---

_Este inventário é preliminar e não concede direitos de uso._
