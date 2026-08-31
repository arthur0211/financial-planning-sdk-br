# Fronteira de confiança e release

_Contrato operacional fail-closed · 9 de agosto de 2026_

## Estado atual

Não existe autoridade de release implementada ou integrada. O checkout candidato produz apenas diagnósticos locais; ele não autentica licença, identidade, reviewer, fonte, runtime, dependências, sandbox, build, artefato ou release.

`validate_docs.ps1` implementa `Structure` e falha incondicionalmente em `F0`, `Release00` e `Release01`. O contrato canônico exige processo novo `powershell|pwsh -NoProfile ... -File <gate> -Mode <modo>`; switches, valores, ordem, modo e as duas grafias relativas documentadas são comparados lexicalmente por `Ordinal` no argv .NET antes de comandos nominais ou leitura. As únicas opções intermediárias são nenhuma, `-NonInteractive`, `-ExecutionPolicy Bypass` ou ambas nessa ordem. O path absoluto precisa identificar o path efetivo do script e, no Windows, usa comparação `OrdinalIgnoreCase` por identidade do filesystem; essa semântica não aceita variação de casing em path relativo, switch ou modo.

Toda invocação não canônica chama `[Environment]::Exit(2)`: `-Command`, argumento extra, casing/abreviação, módulo, pipeline, `&` e dot-source não são interfaces de uso. Em particular, `&` e dot-source encerram o host que os invocou antes de sua próxima instrução. Os modos progressivos canônicos escrevem blockers diretamente e chamam `[Environment]::Exit(1)` antes da boundary de trust do host, de autoload, import, helper ou leitura. Os antigos argumentos de resultado, chave, fingerprint, runtime e evaluation time continuam removidos; nenhum modo abre paths externos, verifica assinatura ou inicia validator candidato.

Apenas `Structure` prossegue para uma boundary suportada somente no Windows. Windows PowerShell Desktop precisa corresponder ao executável/`PSHOME` fixo sob `System32`; PowerShell Core precisa ser `pwsh.exe` sob as subárvores aceitas de `Program Files`, com executável, argumento de host, `PSHOME` e manifests builtin coerentes e com ancestrais sem reparse. Cópia do host em `%TEMP%`, host desconhecido ou `Structure` em Linux/macOS retorna RC2 antes do import e sem decisão de consistência. Essa boundary depende da proteção do sistema operacional e não autentica administrador nem PowerShell engine comprometidos. O checkout pode estar fora desses paths de instalação, mas sua raiz, ancestrais e toda a árvore precisam estar livres de symlink/junction/reparse; uma entrada reparse não é atravessada. Depois desse preflight, `Structure` desabilita module autoload, esvazia `PSModulePath`, importa os manifests builtin Management/Utility por path absoluto sob `$PSHOME` e usa comandos qualificados.

`validate_release_trust.py` está descomissionado. O arquivo é um stub diagnóstico sem imports, parser de argumentos, leitura de inputs, escrita de resultado, subprocesso, Git, runtime, chave ou assinatura. Ele ignora argv, imprime um único objeto ASCII com `status=external_authority_not_implemented`, `authority_decision_attempted=false`, `external_material_read=false` e `release_authorized=false`, e retorna código 2.

| Superfície | Comportamento atual |
| --- | --- |
| `Structure` | valida coerência documental/CSV local somente na boundary Windows suportada e em árvore sem reparse; não é autoridade |
| `F0` | sempre falha RC1 antes da boundary de host; registra que licença, mantenedor e governança locais não autenticam reviewer independente nem authority externa |
| `Release00` | sempre falha RC1 no mesmo ponto; math self-check local é comando separado e não satisfaz o gate |
| `Release01` | sempre falha RC1 no mesmo ponto; não há autoridade externa nem relatório fechado de inspeção |
| parâmetros antigos | inexistentes; PowerShell os recusa antes de executar o script |
| PKI/fixtures sintéticas | removidas; nenhum teste cria chave ou atestação utilizável |

## Protótipo v4 superado

Os identificadores machine-readable dos protótipos de trust, registry, atestação matemática/build e resultado de bootstrap de R2–R11 foram retirados da documentação operacional. Eles estão **superados e não são aceitos por nenhum gate**. O scan de documentação operacional normaliza cada linha com Unicode FormKC e remove caracteres `Cf` antes de procurar IDs e headings legados. O corpus vive somente no [histórico invalidado e não executável](../history/trust-r2-r11-superseded.md), cujo front matter declara exatamente `status=superseded`, `executable=false`, `accepted_by_gate=false` e `authority=none`; seu H1 é exato e o roster fechado de H2 contém, em ordem `Ordinal`, exatamente R2–R3, R4, R6, R7, R8, R10 e R11, todos explicitamente históricos, superados e não executáveis. Referências operacionais apontam ao documento inteiro, sem fragmento, e não reproduzem um protocolo disponível.

A revisão adversarial demonstrou que o protótipo ainda permitia falsos verdes:

- o runtime pinava um executável, mas não autenticava independentemente sua closure de startup; `._pth`, biblioteca padrão e arquivos carregados a montante podiam ser alterados para forjar a decisão;
- flags/guards de startup permaneciam estado mutável dentro da mesma boundary;
- a assinatura externa do resultado era uma autoridade única capaz de forjar as claims internas de matemática, build e quórum;
- material `test_only` conseguia satisfazer `F0`/`Release00`, confundindo exercício sintético com autoridade;
- binding a “commit atual” não fechava inventário, estado untracked e replay do checkout observado;
- rodadas anteriores já haviam encontrado import injection, runtime circular, split-read, swap/restore same-UID e equivalência de artefato opaca.

Não há correção local honesta para esse conjunto enquanto o verificador, seus guards ou sua closure nascerem do próprio candidato. Por isso o código morto de Ed25519/C#/.NET, parsing de resultado, atestações aninhadas e bootstrap sintético foi removido em vez de ficar inalcançável.

## Requisitos para uma autoridade futura

Uma futura boundary só poderá ser integrada depois de implementação e revisão independentes fora do checkout candidato. No mínimo, ela precisa:

1. possuir raiz de confiança, executável e closure autenticados fora de banda, incluindo startup config, `._pth`, biblioteca padrão, módulos nativos, dependências e loader;
2. receber uma fonte imutável vinculada a revisão/commit autorizado e a inventário fechado que cubra arquivos tracked, untracked e ausência de drift/replay;
3. executar em ambiente efêmero, fonte read-only e rede bloqueada, com argv, cwd, outputs e limites fechados;
4. emitir relatórios fechados de contratos, matemática e inspeção de wheel/sdist, cada um ligado aos bytes realmente avaliados;
5. exigir relatórios de domínio assinados de forma aninhada **e** threshold/quórum independente, impedindo que o signer externo final fabrique math, build ou identidade;
6. provar domínio apropriado — inclusive `math-conformance` — e evidência de identidade/assurance quando um gate exigir pessoa humana;
7. fechar relógio, expiração estrita, revogação/freshness e proteção contra rollback com semântica auditável;
8. assinar a decisão final sem depender de código, runtime, path ou payload indicado apenas pelo candidato.

Mesmo um protocolo futuro não autoriza publicação automaticamente. A licença, o mantenedor e a governança do source foram decididos no ADR 0012; reviewer humano independente, CI/supply chain e autorização de package/release permanecem decisões separadas.

## Diagnósticos locais preservados

O conformance pack matemático continua separado:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_math_vectors.ps1 -SelfCheck -OutputFormat json
```

Esse self-check avalia corpus e rotas locais `test_only`; mantém SUT `not_evaluated`. `oracle_boundary.status=static_checks_passed` e `declared_validation_types` descrevem checagens estáticas, não um oracle autenticado. Common-mode, carga dinâmica, ausência de isolamento hermético e nondeterminismo além das 70 respostas/três repetições permanecem riscos.

`validate_contracts.py` preserva snapshot imutável dos bytes dos schemas e recheck final, mas continua draft-only e não consome trust. O manifesto fecha 33 casos — 11 `valid`/`expected_valid=true` e 22 `invalid`/`expected_valid=false` — e o inventário total sob `schemas/examples` admite somente os dois diretórios diretos e as fixtures regulares, canônicas, manifestadas e `nlink=1`; qualquer outra classe de entrada, alias Unicode/case, nesting ou drift falha. No Windows, streams Win32 integram o snapshot e o recheck de raiz, diretórios e fixtures e qualquer stream nomeado/não padrão falha; em não Windows, `None` significa ADS `not_applicable`, não enumeração vazia. Os 62 reason codes exigem IDs e metadados semânticos normativos, remediações referencialmente fechadas e multiplicidade exatamente 1:1 em bullets Markdown canônicas; candidatos variantes por marcador, indentação, casing, compatibilidade Unicode, `Cf` ou confusável conhecido são recusados, enquanto prosa inline não conta.

Agent review e ciclos builder–critic são challenge interno declarado. Eles não provam independência, validade científica, identidade humana ou aprovação de domínio e não satisfazem nenhum gate de reviewer externo.

`validate_release_artifacts.py` continua um inspector estático candidato; aceita apenas `--root` e emite `candidate-release-static-diagnostic.v3`. Wheel e sdist são capturados uma vez em `ArtifactBlob`, tuple imutável `(nome, bytes, SHA-256)` com digest revalidado em cada fronteira, de modo que o hash reportado, a inspeção e a paridade estreita usam a mesma instância; a releitura final do path original apenas detecta drift observável.

O subconjunto suportado é intencionalmente menor que os formatos gerais. Wheel exige ZIP32 raw gap-free, bijeção local/central, somente `stored`/`deflated` e, opcionalmente, UTF-8. Cada fatia `stored` precisa ter tamanhos comprimido/decodificado iguais; cada stream raw `deflated` precisa alcançar EOF sem `unused_data`, `unconsumed_tail`, cauda ou concatenação. Ambos exigem tamanho decodificado e CRC32 declarados, e metadata e bytes decodificados raw precisam reconciliar com `zipfile` antes de validar `RECORD`. Falham prefixo/orphan/gap/trailing record, comment, descriptor, extra field, ZIP64, multi-disk, encryption, flag/método não modelado e qualquer desacordo de visão. Sdist exige exatamente um membro gzip e TAR POSIX USTAR estrito; falham concatenação/trailer não zero, membro depois do primeiro EOF, PAX, GNU long/sparse, base-256, links/devices/tipos especiais e desacordo com `tarfile`. ZIP, TAR e `RECORD` compartilham paths Win32 estritos e trie `casefold` + NFC, inclusive contra control/reserved chars, trailing dot/space, alternate data stream, device DOS, colisão normalizada, ancestral-file, file/directory, duplicata e diretório explícito vazio/não modelado.

A única observação de paridade é `python_source_payload_parity=observed_on_revalidated_non_atomic_local_snapshots`; `source_artifact_parity` e `build_equivalence` ficam `not_evaluated`, authority ausente e release não autorizado. O `.dist-info` canônico aceita somente `METADATA/WHEEL/RECORD`, `.data` precisa do root canônico e o sdist mínimo rejeita membros fora de `PKG-INFO`, `pyproject.toml` e `src/`. Metadata/build files não são cobertos pela claim estreita, e rechecks finais de `dist`, `pyproject.toml`, `src` e `tests` não eliminam swap/restore same-UID porque os snapshots não são atômicos. Seus resultados não satisfazem `Release01`.

Há SDK/CLI/package apenas para desenvolvimento local, Apache-2.0, `MAINTAINERS.md` e `GOVERNANCE.md`. Não há reviewer independente, `dist` autorizado, chave, atestação, authority ou release real neste repositório.
