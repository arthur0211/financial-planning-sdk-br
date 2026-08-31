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

### Limites conhecidos

- nenhuma revisão jurídica independente da licença ou dos direitos sobre recursos de terceiros;
- nenhuma regra brasileira vigente ou recomendação;
- nenhuma autenticação externa de evidência;
- células Windows instaladas ainda `not_observed` sem runner elevado;
- nenhum package registry, tag estável ou release autorizado.
