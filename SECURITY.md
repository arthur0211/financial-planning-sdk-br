# Política de segurança

## Versões suportadas

Não há versão estável ou release publicado. A branch principal contém um pré-release técnico e recebe correções em regime de melhor esforço.

| Versão | Suporte |
| --- | --- |
| `main` / `0.1.0.dev0` | avaliação técnica, sem SLA |
| tags ou pacotes externos | não existem releases autorizados |

## Como relatar uma vulnerabilidade

Não abra uma issue pública com exploit, segredo, PII ou caminho de reprodução sensível.

1. Use [Report a vulnerability](https://github.com/arthur0211/financial-planning-sdk-br/security/advisories/new) na aba **Security** do repositório.
2. Se o botão não estiver disponível, não publique detalhes: abra somente uma issue sem conteúdo sensível indicando indisponibilidade do canal.
3. Inclua versão ou commit, impacto, pré-condições, reprodução mínima e sugestões de contenção.

Não envie dados reais de clientes, contas, documentos, credenciais ou tokens.

O canal privado de vulnerabilidades está habilitado e verificado neste repositório público. Secret scanning e push protection também estão ativos como defesa em profundidade; eles não substituem a comunicação privada nem autorizam publicar detalhes sensíveis em issue, discussão ou pull request.

## Escopo de interesse

- execução de código ou import não intencional;
- bypass de schema, reason code ou governance envelope;
- path traversal, symlink, reparse point, hardlink ou alternate data stream;
- exposição de input, PII, stderr candidato ou paths privados;
- escape de limites de subprocesso e cleanup de descendentes;
- corrupção silenciosa de aritmética, canonicalização ou artefatos;
- promoção indevida de `draft`, `not_observed` ou `authority=none`.

Erros financeiros ou científicos sem vetor de segurança também são importantes. Abra uma issue de bug e identifique claramente a hipótese, a convenção e a evidência disponível.

## Processo de resposta

O mantenedor fará triagem, confirmará o escopo e decidirá a correção antes de qualquer divulgação. Não há prazo contratual de resposta. Uma correção local ou teste verde não implica publicação de release.

## Limites

O threat model corrente está em [docs/security/threat-model.md](docs/security/threat-model.md). Administrador, kernel, runtime ou checkout arbitrariamente comprometidos permanecem fora de várias claims locais. O projeto não deve ser usado como controle de segurança, cálculo profissional ou sistema regulado.
