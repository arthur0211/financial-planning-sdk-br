---
status: superseded
executable: false
accepted_by_gate: false
authority: none
---

# HISTÓRICO SUPERADO — NÃO EXECUTÁVEL

Este documento preserva o corpus de trust tentado entre R2 e R11 e removido do [changelog operacional](../changelog-codex.md). As frases históricas abaixo mantêm o tempo verbal em que foram registradas, mas não descrevem o sistema atual, não constituem protocolo aceito e não podem ser usadas como instrução, evidência de authority, aprovação ou autorização de release.

R12 descomissionou os consumers, a PKI e os resultados candidatos. Os metadados no topo deste arquivo governam todo o conteúdo, inclusive trechos que mencionam verificações verdes, assinaturas, attestations, quórum, aprovação ou equivalência.

## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R2–R3 — composição e hardening adversarial dos gates

- validator ganhou modos cumulativos `Structure`, `F0`, `Release00` e `Release01`, invariantes positivos, enums, datas, markers, FKs, contenção de links locais na raiz e composição dos validators de contratos/vetores nos gates aplicáveis.
- required paths passaram a verificar arquivo/diretório, link e conteúdo mínimo, em vez de mera existência;
- `F0` deixou de aprovar licença ou humanidade por palavras: exige trust policy owner-controlled fora do repositório, com digests do `LICENSE`, registro/attestação externos e bundle fechado dos validators;
- reviewer só conta por identidade ativa `natural_person` declarada na autoridade externa, distinta do owner; agents não são inferidos nem aceitos por blacklist/heurística;
- os três CSVs de governança ganharam `source_artifact_path`; `approved` agora recalcula o SHA-256 do arquivo local regular e rejeita digest zero, mismatch e reviewer/data não resolvidos;
- `LegalEvent` ganhou `clarifies`; o esclarecimento do STF aponta para o evento restaurador e não pode alterar, substituir, suspender ou restaurar;
- `Release00` conta apenas entradas fechadas do manifesto matemático e denuncia todo JSON não registrado;
- Markdown vazio agora entra no resumo de findings sem provocar crash; marker é normalizado por Unicode NFKC, case, whitespace e pontuação;
- `Release01` fecha recursivamente `dist`, parseia nomes/tags, valida `RECORD`, packages/import, TOML dentro do sdist, coerência wheel–sdist–projeto, budgets/traversal/executáveis, clean build offline e instalação/import em venv;
- `scripts/test_governance_gates.py` cobre os bypasses R2 em cópias temporárias, inclusive trust/no-op/licença/reviewer e archives adversariais; nenhuma fixture sintética é uma aprovação real.

## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R4 — trust e release sem autoautenticação

- a política de trust passou a envelope JSON fechado assinado com Ed25519 pelo owner; chave pública/fingerprint são fornecidos fora de banda e policy/registry vinculam commit, árvore-fonte, domínio, prazos e revogações;
- reviewer registry preserva aliases, mas os resolve/deduplica por NFKC, casefold e skeleton de confusáveis; owner e reviewer independente têm chaves/fingerprints distintos;
- runtime Python é absoluto e digest-pinado; lookup por `PATH` foi removido dos validators compostos, e o validator Release01 roda de snapshot read-only com hashes antes/depois e saída estruturada;
- `Release01` não faz mais build, instalação, import ou smoke local: exige attestação externa assinada contendo árvore/artefatos, builder/runtime, rede bloqueada, fronteira de filesystem, comandos e resultados;
- `dist` é snapshottado por bytes antes de inspeção, exige parents não-reparse, arquivo regular com `nlink=1`, inventário fechado e manifesto final estável;
- wheel rejeita tipo Unix não regular e valida `RECORD`; sdist rejeita specials; budgets precedem leitura material, e parity compara bytes entre source/wheel/sdist, inclusive namespace packages declarados;
- o gate `Release00` passou a validar o contrato atualizado de `spec_case_mapping` e os novos campos de derivação do manifesto.

## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R6 — trust/governança no Windows

- substituída a descoberta implícita de `sys.executable` no fixture por seleção explícita de runtime externo regular, `nlink=1`, sem reparse, executável por PowerShell e com identidade kernel coincidente; a venv redirector foi mantida rejeitada, sem exceção no verifier;
- movida a geração do dependency lock sintético para o próprio runtime selecionado, com ambiente Python herdado sanitizado, e tornada obrigatória a passagem explícita desse runtime aos fixtures;
- reutilizado o runtime por classe nas suítes de trust, contratos e gates, sem aceitar o alias Store, relaxar hardlink/reparse ou alterar o `ExternalTrustBootstrap` real;
- validado o inventário completo da árvore contido no resultado assinado e criado snapshot fechado do runner matemático, manifesto das rotas, dependências de execução e corpus JSON para `Release00`;
- corrigido o snapshot unitário que deslocava `validate_math_vectors.py` para `%TEMP%` sem `tests/conformance`, causando import impossível;
- exigido relatório JSON fechado do self-check com SUT `not_evaluated`, contagens, cache de validação 70/3, fronteira estática/local não autenticada do oracle e isolamento honesto; um math validator no-op assinado não satisfaz o gate;
- registrado o resultado histórico sintético 53/53 de `Release00`, posteriormente invalidado em R7 pelo ataque suspend/swap/restore e não reutilizado como evidência atual;
- mantidos os limites: inspeção de release é somente estática, filesystem/rede não são sandboxados, chaves/licença/governança sintéticas não autorizam uso real e nenhum package, `dist` ou release foi criado.

## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R7 — autoridade externa de `Release00`

- invalidado o falso verde anterior: um atacante Windows same-UID conseguia suspender o filho Python, trocar/restaurar o entry point matemático já hash-eado e obter rc 0;
- removida de `F0`/`Release00` toda execução local de `validate_contracts.py` e `validate_math_vectors.py`; markers sintéticos confirmam ausência de ambos e o watcher suspend/swap/restore observa zero filho matemático;
- introduzidos policy v4, atestação matemática externa v1 e resultado de bootstrap v2 assinado; o bootstrap externo autentica árvore, runtime/dependency lock, argv, sandbox efêmero/read-only/sem rede e relatório fechado, sem executar candidato;
- estreitada a decisão F0 para `trust_material_validated` com `contract_validation=not_attested`; a decisão matemática é `math_self_check_attested`, sempre com `release_authorized=false`;
- corrigido split-read de resultado/chave: digest, parse, fingerprint e Ed25519 usam um único snapshot de bytes via stdin, e o verifier devolve o digest autenticado;
- carregado o inventário assinado da árvore em cache binário; Markdown, CSV, manifest e vetores são consumidos desses bytes, com drift persistente reprovado ao final;
- adicionados probes determinísticos que trocam resultado/chave e arquivos decisórios entre aquisição e consumo, além de negativos de assinatura, domínio, source tree, runtime, report, sandbox, expiry, revogação e no-op;
- renomeadas as claims matemáticas para `oracle_boundary.status=static_checks_passed` e `declared_validation_types`; common-mode, carga dinâmica e nondeterminismo além de 3 probes/70 respostas permanecem explícitos;
- runner composto R7 verde em 62/62 no Windows (27 governance, 16 release artifacts e 19 trust), contratos 26/26 e matemática 46/46 com um skip POSIX esperado; crítica independente e todas as decisões humanas continuam abertas.

## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R8 — autenticação, lifecycle, quórum e build

- removida a circularidade de autenticação do resultado: PowerShell agora verifica Ed25519 estrito no boundary C#/.NET sobre o snapshot canônico, sem executar o runtime fornecido ou importar `cryptography`; o consumidor Python usa apenas biblioteca padrão;
- adicionados vetores RFC 8032 e negativos de assinatura zero, bit tamper, `S+L`, encoding `y>=p`, sign bit inválido, identidade/baixa ordem, fake user-site/PYTHONPATH e runtime malicioso que imprime `signature_verified`;
- migrado o resultado para v3, separando `current_release_evaluation` de `historical_validation`; corrente usa relógio observado e skew de 300 segundos, histórico nunca satisfaz gate e `issued_at` é o instante observado;
- tornado explícito que expiry é o mínimo de policy, registry, owner, result/math/build signers e todas as atestações presentes; revogações da policy e do registry cobrem todo fingerprint participante e são rechecadas pelos consumidores;
- mantido `signed-person-registry.v3`, agora exigindo `principal_type=natural_person`; math requer `math-conformance`, build requer `build-release`, e math/build/result usam pessoas e chaves distintas com quórum fail-closed 1/2/3;
- migrada a atestação de build para v3: pacote `build` ligado ao dependency lock, runtime exato, fonte read-only/efêmera/sem rede, writes disjuntos, argv+cwd exatos, hashes/resultados de build/test/smoke e `content_equivalent=true` obrigatório para aceite;
- composto de governance verde em 73/73 no Windows e contratos adversariais verdes em 28/28; fixtures/chaves/licença/atestações continuam estritamente sintéticas em temporários;
- preservados os limites: F0 mantém contratos `not_attested`, Release00 mantém `release_authorized=false`, crítica independente está pendente e não foram criados LICENSE, SDK/CLI/motor, package, `dist`, atestação real ou release.

## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R10 — authority mínima, temporalidade e build não autoritativo

- removida de `validate_contracts.py` a capacidade de consumir trust: parser de resultado, Ed25519 e runtime-lock antigos foram apagados; CLI/trust context são recusados sem leitura e aprovações/estados computados nunca passam no processo candidato;
- endurecido o `ExternalTrustBootstrap` externo com entrypoint absoluto e flags obrigatórios `-I -S -B`; Ed25519 sign/verify é somente stdlib e o bootstrap não ativa user-site nem roots de dependências antes de autenticar;
- exercitado o verificador C#/.NET sobre o mesmo corpus RFC 8032 no Windows PowerShell 5.1 e PowerShell 7.x, com `Add-Type -PassThru`, referência host-aware e rejeição de zero signature, `S+L`, pontos não canônicos/baixa ordem, fake `cryptography` e runtime malicioso;
- migrados registry/result para v4: `point_in_time_evaluation`, UTC canônico em segundos, um relógio consumidor, skew 300 s e expiração estrita de todas as fontes; igualdade, -1 s, offsets e microssegundos falham;
- limitada revogação ao instante observado (`post_issuance_freshness=not_attested`, rollback offline ausente); targets desconhecidos falham no bootstrap, mas mudança posterior não é chamada de freshness atual;
- substituída “pessoa natural verificada” por `principal_type_assertion`, assurance declarada e `human_identity_verified=false`; fixtures são explicitamente `synthetic_test_only` e nenhum gate humano real foi satisfeito;
- migrada a atestação de build para v4 como `signed_build_claim`: artifacts permanecem digests opacos, equivalência é `not_evaluated`, release não é autorizada e `Release01` sempre falha sem relatório externo fechado de inspeção;
- apagada do PowerShell a função obsoleta capaz de materializar/executar validators candidatos; ataques de split-read, swap/restore e markers confirmam ausência de filhos matemático, contratual e de artifact inspector;
- validações pré-documentação: governance composto 83/83, contratos 29/29, release artifacts 16/16 e matemática 46/46 com um skip POSIX esperado no Windows; crítica independente R10 ainda pendente;
- preservados os bloqueios: sem `LICENSE`, reviewers humanos verificados, freshness/CRL online, SDK/CLI/motor, `src`, package, `dist`, attestation real ou release.

## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R11 — fechamento rejeitado pela rodada seguinte

O changelog não continha uma seção autônoma de R11. O registro de R12 identifica os findings que invalidaram aquela tentativa: closure `._pth`/stdlib não autenticada, guards mutáveis, signer final capaz de fabricar math/build/quórum, material `test_only` abrindo gates e replay/untracked no binding do checkout.

As rodadas R5 e R7 dedicadas ao harness matemático e à fronteira corpus/oracle/SUT não foram movidas para cá, pois não pertencem ao corpus de trust descomissionado.
