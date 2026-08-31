# ADR 0012 — Apache-2.0 e governança da publicação do source

**Estado:** aceito pelo proprietário para publicação do código-fonte; package/release continuam bloqueados
**Data:** 2026-08-30
**Decisor:** Arthur Amorim (`@arthur0211`), proprietário do repositório

## Contexto

O checkout concluiu a remediação técnica de prontidão para GitHub, mas permaneceu em `HOLD` porque não existiam decisão de licença, roster de mantenedores, governança pública, commit ou remoto. Em 30 de agosto de 2026, o proprietário autorizou integralmente os defaults recomendados: Apache-2.0, staging privado inicial, publicação posterior somente após checks remotos e `@arthur0211` como mantenedor.

A decisão humana sobre o source não implementa a autoridade externa exigida por `F0`, `Release00` ou `Release01`. Também não constitui revisão jurídica independente, validação matemática, conformidade regulatória ou autorização para PyPI/GitHub Release.

## Decisão

1. Licenciar o código-fonte e a documentação original do repositório sob Apache License 2.0.
2. Declarar `Apache-2.0` no metadata Python e incluir o texto de `LICENSE` nos artefatos candidatos de forma fechada e verificável.
3. Publicar `MAINTAINERS.md` e `GOVERNANCE.md` com um mantenedor real e sem inventar reviewer independente.
4. Criar primeiro um remoto privado, executar os checks no commit candidato e configurar permissões mínimas e proteção de `main` antes da conversão para público.
5. Manter dados, snapshots, marcas e recursos de terceiros fora da concessão automática; cada recurso continua sob seu próprio manifesto e termos.
6. Manter package, tag, release, deployment, recomendação e promoção de artefato fora de escopo.

Esta decisão substitui somente a pendência de licença registrada no item 8 e nas consequências do ADR 0001. O restante do escopo e todas as boundaries técnicas permanecem vigentes.

## Revisão e independência

A aprovação é decisão do proprietário sobre material que ele autoriza publicar. Nenhum parecer jurídico independente foi obtido e nenhum agente é contado como reviewer humano. Mudanças futuras de licença ou outras mudanças materiais continuam sujeitas à política de revisão independente registrada em `GOVERNANCE.md`.

## Consequências

- o repositório pode ser reconhecido como open source depois que o remoto público contiver o texto íntegro da licença;
- contribuições intencionalmente submetidas passam a seguir a cláusula 5 da Apache-2.0, salvo declaração explícita em contrário;
- `pyproject.toml`, `METADATA`, wheel, sdist, inventários e hashes canônicos mudam legitimamente e precisam ser rebaselineados;
- o perfil de metadata recebe nova revisão que liga SPDX, autores/mantenedores e arquivo de licença;
- `F0`, `Release00` e `Release01` continuam RC1 por ausência de autoridade externa, mesmo com os documentos humanos presentes;
- visibilidade pública continua reversível para privada se o canal de segurança ou os checks remotos não puderem ser habilitados.

O rebaseline local da política `finplanbr-setuptools-84.0.0-metadata.v5`, depois de validar o output real do setuptools 84 e o binding byte a byte do `LICENSE`, produziu os seguintes goldens candidatos:

| Artefato canônico | SHA-256 |
| --- | --- |
| wheel direto e reconstruído | `e0beb5a21f3b78fbb1aada8327301bbf3340566f8f979d70c1bb869072ec5194` |
| sdist | `643af37b9d91ead26753e00bffd63425ef310e90d1847942fd732a9b0d457435` |

Esse rebaseline inclui a estabilização explícita da construção do parser no Python 3.14, sem cor dependente do terminal. Os hashes continuam locais, self-issued e sem crédito de matriz cross-OS, autenticação externa ou release.

## Alternativas rejeitadas

- publicar sem licença, porque disponibilização pública não concede permissão de uso ou redistribuição;
- usar MIT, porque Apache-2.0 explicita licença de patentes e terminação em litígio;
- criar reviewer fictício ou tratar automação como aprovação humana;
- acoplar a licença do código a datasets, feeds ou snapshots com regimes próprios;
- interpretar a publicação do source como autorização de package ou release.
