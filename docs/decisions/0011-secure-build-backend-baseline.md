# ADR 0011 — baseline seguro do backend de build

**Estado:** aceito para desenvolvimento local e CI candidata; release continua bloqueada
**Data:** 2026-08-30

## Contexto

O projeto fixava `setuptools==80.10.2` como backend de build e incorporava essa versão ao perfil canônico de metadata. Em julho de 2026, o advisory revisado [GHSA-h35f-9h28-mq5c / CVE-2026-59890](https://github.com/advisories/GHSA-h35f-9h28-mq5c) classificou versões anteriores a `83.0.0` como afetadas por bypass de exclusão de `MANIFEST.in` em colisões de normalização Unicode NFC/NFD em APFS/HFS+. O impacto relevante é a inclusão não intencional de arquivos em sdists publicados.

O checkout não usa `MANIFEST.in`, não autoriza publicação e já valida roster e bytes do sdist. Esses controles reduzem a exposição atual, mas não justificam conservar um backend com vulnerabilidade conhecida em uma futura cadeia pública.

## Decisão

1. Fixar `setuptools==84.0.0` no `build-system`, nos ambientes de desenvolvimento, no Dockerfile de portabilidade e nos workflows candidatos.
2. Exigir o mesmo pin no agregador da matriz instalada; uma célula que reporte outra versão permanece inválida.
3. Promover a política fechada de metadata para `finplanbr-setuptools-84.0.0-metadata.v4` e validar o campo `Generator` do wheel contra a nova versão.
4. Rebaselinear os arquivos canônicos somente depois de construir wheel direto e sdist em diretório descartável fora do checkout, reconstruir o segundo wheel e provar igualdade integral entre os wheels canônicos.
5. Preservar todos os hashes anteriores como evidência histórica ligada ao source e backend de sua época; nunca reinterpretá-los como artifacts atuais ou releases.

O source corrente produziu localmente:

| Artefato canônico | SHA-256 candidato |
| --- | --- |
| wheel direto e reconstruído | `9bb574f672d62e15215575a46e4c45865fbf221b40811ef9e7b627efb0bef9cb` |
| sdist | `7a0f6d77b9e60a30b9d6d92b777f7f99da9776134241643aa292224a97ba0c27` |

Esses valores foram observados em Windows com CPython 3.13, em execução local descartável. Eles não provam convergência cross-OS, origem autenticada, inexistência de vulnerabilidades futuras ou autoridade de release. A matriz completa precisa ser reexecutada sobre um único source freeze antes de qualquer claim de portabilidade corrente.

## Consequências

- o pin conhecido como vulnerável deixa de ser uma dependência ativa do projeto;
- mudanças no README ou em `pyproject.toml` continuam alterando legitimamente os hashes canônicos;
- fixtures, política de metadata e documentação precisam mudar juntas quando o backend mudar novamente;
- Dependabot pode propor upgrades, mas nenhuma atualização automática promove artifact, tag ou release;
- `F0`, `Release00` e `Release01` continuam falhando por desenho.

## Alternativas rejeitadas

- usar apenas `setuptools>=83`, porque a matriz e o perfil de metadata exigem bytes e proveniência de toolchain fechados;
- manter `80.10.2` alegando ausência de `MANIFEST.in`, porque isso preservaria risco conhecido na cadeia de build;
- aceitar qualquer versão instalada e normalizar o campo `Generator`, porque apagaria drift do produtor antes da admissão;
- publicar os novos artifacts ou hashes, pois a mudança técnica não resolve licença, reviewer, autoridade externa ou autenticação da evidência.
