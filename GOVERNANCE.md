# Governança do projeto

_Versão inicial · 30 de agosto de 2026_

## Missão e limites

O Financial Planning SDK Brasil mantém um SDK/CLI local e determinístico, atualmente limitado a `deterministic_cashflow_ledger`. O repositório público serve para inspeção, colaboração e pesquisa de engenharia. Ele não fornece recomendação financeira, suitability, execução, cálculo profissional validado, regra brasileira certificada, serviço ou release autorizado.

## Papéis

- **Proprietário/mantenedor:** identidade listada em `MAINTAINERS.md`; administra o repositório e decide sobre o código-fonte.
- **Contribuidor:** pessoa que propõe mudanças sob os termos de `LICENSE` e `CONTRIBUTING.md`.
- **Reviewer independente:** pessoa competente no domínio afetado, sem autoria material da mudança e sem conflito não declarado.
- **Autoridade de release:** boundary externa futura; não existe nem pode ser simulada pelo checkout candidato.

Um agente, workflow, teste, fixture ou documento local nunca conta como pessoa ou autoridade externa.

## Decisões e revisão

| Mudança | Autoridade mínima |
| --- | --- |
| documentação editorial e manutenção mecânica | mantenedor |
| API pública, comportamento CLI ou schema | mantenedor, testes e ADR quando alterar contrato |
| matemática, política, privacidade, licença, dependência crítica ou deployment | mantenedor e reviewer humano independente do domínio |
| tag, package, release ou promoção de `draft` | autoridade externa ainda não implementada, além das revisões humanas aplicáveis |

Na ausência de reviewer independente, a mudança material permanece candidata e não recebe selo de independência. Correção emergencial de segurança pode ser aplicada pelo mantenedor para contenção, mas precisa registrar escopo, evidência, limitações e revisão pendente.

## Fluxo de contribuição

1. Abra issue ou proposta para mudança material.
2. Registre ADR quando o contrato público, matemática, licença, dependência, privacidade, política ou trust boundary mudar.
3. Faça pull request pequeno, com testes e documentação no mesmo change set.
4. Execute os checks aplicáveis e declare skips, limitações e evidência adversa.
5. Resolva comentários antes de merge. Review do próprio autor não é independência.

O commit inicial é uma publicação de source autorizada pelo proprietário e conserva explicitamente todas as claims técnicas como locais, draft e não profissionais. Ele não substitui revisão independente dos domínios materiais.

## Branch principal e proteções

`main` é a branch pública de desenvolvimento. Force-push e deleção devem ficar bloqueados. Pull request, resolução de conversas e checks remotos são exigidos para mudanças posteriores quando suportados pelo plano do GitHub. A exigência de aprovação independente só deve ser habilitada quando existir reviewer real; não criar aprovação fictícia ou usar o mesmo owner como independência.

## Segurança e conduta

Use o canal privado indicado em `SECURITY.md` e `MAINTAINERS.md` para vulnerabilidade, PII, segredo ou conduta sensível. O mantenedor pode conter abuso, remover conteúdo e restringir participação. Divulgação coordenada e correção não criam SLA, release ou garantia.

## Licença e dados

O código-fonte e a documentação original são oferecidos sob Apache-2.0, conforme `LICENSE`. Isso não altera licenças, contratos ou direitos de datasets, snapshots, marcas e recursos de terceiros descritos em `DATA_LICENSES.md` e nos manifestos de governança.

## Transparência

Decisões materiais, conflitos de interesse, exceções emergenciais e limites de validação devem permanecer rastreáveis. Resultado verde local, GitHub Actions, merge ou visibilidade pública não prova correção profissional, authority ou autorização de package/release.

## Alteração desta política

Mudanças nesta governança exigem pull request, justificativa e aprovação explícita do proprietário. Se alterarem licença, revisão independente, segurança, deployment ou release, aplicam-se também os gates materiais acima.
