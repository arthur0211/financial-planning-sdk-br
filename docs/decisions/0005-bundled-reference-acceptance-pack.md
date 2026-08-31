# ADR 0005 — Reference Acceptance Pack local e empacotado

**Estado:** aceito somente para desenvolvimento local `draft`
**Data:** 2026-08-09

> **Nota de substituição parcial:** a decisão original de expor o status cacheado sem reparsar foi superada pelo [ADR 0007](0007-opaque-value-objects-and-closed-schema-profile.md). O histórico abaixo permanece registrado; o runtime corrente revalida canonicalidade, binding e schema em todo acesso de confiança.

## Contexto

O SDK/CLI já compartilhava o caso de uso determinístico e possuía um harness de conformance no checkout, mas um usuário de uma instalação nova não tinha um artefato empacotado para verificar a reprodução dessa superfície. O corpus em `tests/` também não deve ser apresentado como referência matemática independente, authority ou gate de release.

## Decisão

Empacotar `reference-acceptance-pack.v1.json` com roster fechado de três casos sintéticos:

1. soma de valor presente e empate de arredondamento `half_even`;
2. transferência interna, retorno de preço, distribuição e identidade do ledger;
3. rejeição de distribuição separada sob `total_return`.

Cada caso fixa request, operação, `derivation_id`, output esperado completo e SHA-256 dos bytes esperados sob `FPBR-C14N-1`. O runtime fixa separadamente os digests canônicos de request e do roster de assertions, além do manifesto canônico que reúne roster, rota, derivação e os três digests por caso. Request incompleto ou alterado recebe `REFERENCE_PACK_REQUEST_INVALID`; roster de assertions alterado recebe `REFERENCE_PACK_EXPECTED_OUTPUT_INVALID`, ambos antes de executar qualquer caso. O digest da representação canônica do pack continua como uma camada adicional. A canonicalização evita que somente a convenção LF/CRLF de um checkout novo invalide o pack. Essas duplicações são controles locais contra drift acidental; hashes locais não autenticam autoria, independência ou aprovação.

`run_reference_acceptance_pack()` e `finplanbr reference run` chamam exatamente o mesmo runner e emitem o mesmo relatório canônico. Cada assertion contém `rule_id`, JSON Pointer, valor esperado, valor observado e estado. O caso só passa quando o output canônico completo e todas as assertions coincidem. Pack alterado, expected output re-hasheado, `derivation_id` trocado ou request que mude a matemática falha fechado.

O parser comum mede a profundidade lexicalmente, de forma iterativa, antes do decoder e mantém uma captura residual de `RecursionError`. Ele também rejeita lone surrogates escapados em chaves ou valores antes da canonicalização. Assim, JSON sintaticamente válido acima do budget de 32 níveis ou texto que não forme UTF-8 canônico vira `JsonContractError`/`DCL_JSON_INPUT` nas superfícies de arquivo e diagnóstico fechado no pack, sem depender de `UnicodeEncodeError`, `ValueError` de conversão de inteiro ou traceback público da versão do Python. Índices de JSON Pointer recebem um limite lexical antes de `int()`.

O report público foi elevado de `finplanbr.reference-acceptance-report.v1` para `finplanbr.reference-acceptance-report.v2`. A v1 era draft local, não publicada, e fica `superseded_unreleased`: o runtime não a emite silenciosamente. A v2 substitui strings agregadas por objetos fechados com `code`, `location`, `scope` e `remediation_id`. A leitura do recurso acumula short reads até provar EOF ou obter `MAX_INPUT_BYTES+1`; excesso recebe `REFERENCE_PACK_INPUT_LIMIT` antes de hash. Falha de aquisição ou excesso usa `pack_sha256=null` e `pack_sha256_basis=not_available`; JSON adquirido mas não parseável usa o digest raw, e documento parseado usa o digest de `FPBR-C14N-1`. A validação estrutural ocorre antes da comparação do digest canônico para preservar a classe acionável; nenhuma rota de caso é executada enquanto pack, roster, rotas, derivações, requests, assertions e expected outputs não forem aceitos.

O schema v2 `2.0.0-draft.2` fecha as relações observáveis entre status global, diagnóstico, contadores e número/status dos casos; cada diagnostic liga `code`, família de `location`, `scope` e remediação, preservando índices não nominais que o parser estrutural pode realmente emitir. O incremento a partir de `draft.1` torna o tightening observável sem mudar `report_format`. Para cada um dos três casos, fecha identidade, digest esperado, relação `status`↔`diagnostic`↔`exact_output_match`, roster de assertions e valores esperados; assertion `passed` fixa o valor observado correspondente, enquanto assertion `failed` exige `observed=null`. O relatório só nasce da fábrica interna com `bytes` imutáveis, canônicos e com `status` igual ao campo serializado; depois expõe esse status sem reparsar e limita a linha completa a 64 KiB. A CLI prepara a linha inteira antes de stdout, faz uma única chamada de escrita e trata short write como erro; falha interna anterior à escrita produz somente mensagem estática redigida em stderr. Isso não promete atomicidade do pipe ou resistência a outro processo que controle o mesmo descritor.

Todo relatório declara:

- `artifact_status=draft`;
- `provenance=repository_local_untrusted`;
- `reference_independence=not_claimed`;
- `authority=none`;
- `deployment_eligibility=not_authorized`;
- `release_authorized=false`.

## Consequências

Uma instalação do wheel pode reproduzir a mesma observação sintética por SDK e CLI sem ler `tests/`, acessar rede ou persistir estado. O smoke descartável executa separadamente `build --wheel` e `build --sdist`, instala o wheel construído diretamente da source e compara seus bytes com a superfície source e com um segundo wheel construído e instalado a partir do sdist. Essa paridade de report não implica igualdade dos bytes dos wheels, build reproduzível ou equivalência ampla de artefato. O pack melhora onboarding, diagnóstico de instalação e paridade das interfaces.

O roster nominal, requests, matemática, expected outputs e pack `1.0.0-draft.1` permanecem byte a byte inalterados: são três casos e o passe continua 3/3. A mudança v2 pertence somente ao envelope de relatório e ao tratamento de aquisição/JSON inválido.

O pack não é holdout, implementação independente, validação profissional, regra brasileira, comparator externo, evidência de supply chain ou autorização para publicar. Mudar caso, output, derivação, roster ou formato é mudança pública versionada e exige testes, atualização documental e nova revisão; não se “corrige” um vermelho recalculando os expected bytes sem justificar a alteração matemática.
