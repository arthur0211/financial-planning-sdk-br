# Changelog

Este arquivo registra mudanças voltadas a usuários e contribuidores. A cronologia detalhada de auditoria local está em [docs/changelog-codex.md](docs/changelog-codex.md).

## Unreleased

### Adicionado

- SDK e CLI locais para o vertical `deterministic_cashflow_ledger`.
- Reference Acceptance Pack com três casos sintéticos.
- contratos JSON, reason codes, vetores, propriedades e testes de mutação.
- harness de portabilidade instalada para Python 3.11 a 3.14.
- documentação pública de arquitetura, operação, contribuição e segurança.
- templates de issue e pull request, código de conduta e política de suporte.
- CI técnico com Actions pinadas e matriz instalada mantida como diagnóstico manual fail-closed.
- metadata do projeto com URLs canônicas e atualização semanal de dependências por pull request.
- README equivalente em PT-BR e inglês, além de checklist fail-closed para staging e publicação.
- backend de build atualizado para `setuptools==84.0.0`, com política de metadata v5, licença source-bound e goldens candidatos rebaselineados.
- CI candidata com Python 3.11/3.13/3.14, cobertura de branches, CodeQL, dependency review e testes estáticos de least privilege.
- licença Apache-2.0, roster de mantenedor e governança de publicação do source registrados no ADR 0012.

### Corrigido

- pins SHA-256 das rotas matemáticas reconciliados com os bytes publicados, sem alteração das fórmulas ou dos outputs esperados;
- fixture de launcher passa a pinçar o executável Python regular resolvido, e o teste de cancelamento preserva a injeção primária sem interferir no `wait` de cleanup no POSIX.
- parser do CLI mantém ajuda e construção sem cor dependente do terminal no Python 3.14, inclusive sob streams substituídos em testes;
- fixtures multi-OS removem symlink e junction pelo mecanismo correto, limitam ADS a NTFS e emitem tipos Unix explícitos nos membros ZIP sintéticos;
- CodeQL recebe somente a permissão adicional `actions: read` exigida para consultar a própria execução;
- goldens candidatos rebaselineados para wheel `e0beb5a2…` e sdist `643af37b…`, ainda sem authority ou autorização de release.

### Limites conhecidos

- nenhuma revisão jurídica independente da licença ou dos direitos sobre recursos de terceiros;
- nenhuma regra brasileira vigente ou recomendação;
- nenhuma autenticação externa de evidência;
- células Windows instaladas ainda `not_observed` sem runner elevado;
- nenhum package registry, tag estável ou release autorizado.
