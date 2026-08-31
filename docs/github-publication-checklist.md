# Checklist de publicação no GitHub

_Estado em 30 de agosto de 2026: licença e publicação do source autorizadas; staging privado ativo em `arthur0211/financial-planning-sdk-br`; checks remotos em remediação multi-OS; conversão pública pendente; release/package em `NO-GO`._

Este checklist separa quatro decisões que não são equivalentes: preparar o checkout, criar um remoto privado, tornar o source público e publicar um package/release. Um resultado verde em qualquer etapa não autoriza a etapa seguinte.

## 1. Preparação técnica local

- [x] manter a venv fora do checkout inspecionado por `Structure`;
- [x] substituir o backend vulnerável por `setuptools==84.0.0` e registrar o [ADR 0011](decisions/0011-secure-build-backend-baseline.md);
- [x] fixar GitHub Actions por SHA completo, remover persistência de credencial do checkout e declarar permissões/timeouts;
- [x] preparar testes em Python 3.11, 3.13 e 3.14, cobertura de branches com piso de 80%, CodeQL e dependency review;
- [x] oferecer README equivalente em PT-BR e inglês;
- [x] concluir a revalidação local pós-remediação e registrar resultados reais, inclusive skips e limites;
- [x] executar Gitleaks dedicado sobre a árvore candidata antes do primeiro commit;
- [x] registrar a autorização explícita do proprietário sobre PII, proveniência, titularidade e publicação da árvore candidata, sem alegar revisão jurídica independente;
- [x] confirmar pelo proprietário que os arquivos candidatos podem ser redistribuídos sob os termos declarados e que recursos externos continuam separados pelos manifestos aplicáveis.

Resultado local reconciliado em 30 de agosto de 2026: `Structure` passou sobre 840 arquivos e 88 diretórios; contratos passaram em 44/44; SDK em 112/112; a conformidade executou 69 testes, com 68 aprovados e um skip POSIX esperado; o runner de conformidade fechou 71 propriedades e 23/23 mutantes; governança passou em 87/87; cobertura de branches ficou em 81% sobre 100 testes não temporais; Ruff, mypy e actionlint passaram. Gitleaks 8.30.1 foi obtido do release oficial, conferido por SHA-256 e terminou sem findings depois de aplicar a única exceção exata do fixture negativo sintético. O smoke instalado passou em CPython 3.14 com `setuptools==84.0.0`.

A portabilidade foi validada de forma dividida, não como célula oficial: todo o recorte host-bound executado no Python regular ficou verde, salvo dois lives AppContainer corretamente ignorados; a classe canônica de artefatos passou no ambiente CPython 3.14. O runtime Astral 3.14 recusou o host PowerShell com `host_path_unexpected`, enquanto o Python regular não tinha o backend 84 para build. A matriz Windows/Linux × Python 3.11–3.14 do freeze atual continua pendente e nenhum desses resultados concede autoridade.

Regexes internas e Gitleaks são defesa em profundidade; não substituem revisão humana de PII/proveniência nem secret scanning e push protection do GitHub.

## 2. Decisões humanas bloqueantes

- [x] o mantenedor escolheu Apache-2.0 e a decisão está registrada no ADR 0012;
- [x] o mantenedor confirmou identidade pública, responsabilidades e contato em `MAINTAINERS.md` e `GOVERNANCE.md`;
- [ ] existe ao menos um reviewer humano independente para mudanças materiais;
- [x] existe regra honesta para manter mudanças materiais bloqueadas enquanto reviewer independente não estiver disponível;
- [ ] o Private Vulnerability Reporting está ativo; no GitHub ele só pode ser habilitado depois que o repositório se tornar público, portanto a conversão precisa habilitá-lo e verificá-lo imediatamente ou reverter para privado;
- [x] o owner autorizou explicitamente a criação do remoto privado, o primeiro push e a conversão posterior para público após checks verdes.

A ausência de reviewer independente mantém mudanças materiais, package e release bloqueados; ela não deve ser disfarçada com aprovação fictícia. A visibilidade pública só avança com o canal de segurança tratado na própria transição.

## 3. Primeiro commit e staging privado

Depois da autorização explícita:

1. confirmar que `git status --short` contém somente o inventário revisado;
2. executar novamente os gates documentados a partir de um checkout limpo;
3. criar um commit inicial auditável, idealmente assinado, sem artifacts, caches, venv, PII ou segredos;
4. criar `arthur0211/financial-planning-sdk-br` inicialmente como privado, sem GitHub Release, Packages ou deployment;
5. fazer o primeiro push somente do commit aprovado e conferir no GitHub o inventário renderizado.

Staging privado é preparação colaborativa. Ele não altera `authority=none`, `artifact_status=draft` ou `release_authorized=false`.

Estado observado: os commits iniciais foram enviados para o remoto privado, sem tag, Release, Package, environment, secret ou variável. Dependabot, labels, políticas de merge e token read-only do workflow foram configurados. As primeiras execuções remotas falharam fechado e expuseram diferenças reais de symlink/junction, ADS, path 8.3, metadata ZIP e Python 3.14.7. O discovery de portabilidade também misturava fixtures Windows e a admissão Linux oficial `uid/gid=65532` com um runner Ubuntu genérico; a CI agora separa essas boundaries e ainda precisa voltar verde no mesmo commit antes da conversão pública.

## 4. Configuração obrigatória no GitHub

- [ ] imediatamente após tornar o repositório público, habilitar e verificar Private Vulnerability Reporting; reverter para privado se a operação falhar;
- [ ] habilitar secret scanning e push protection quando disponíveis após a conversão pública;
- [x] habilitar Dependabot alerts e security updates no staging privado;
- [ ] confirmar execução do CodeQL e dependency review sem permissões extras;
- [x] criar os labels usados pelos templates e Dependabot, incluindo `proposal` e `dependencies`;
- [ ] configurar ruleset de `main`: pull request obrigatório, checks obrigatórios, resolução de conversas, bloqueio de force-push e deleção;
- [ ] exigir review real quando houver reviewer independente; não configurar uma ficção de independência baseada no mesmo owner;
- [x] manter ausentes environments, secrets e variables de publicação enquanto release continuar fora do escopo;
- [ ] revisar a aba Community Standards e corrigir qualquer arquivo ainda não reconhecido pelo GitHub.

Checks candidatos para o ruleset devem ser escolhidos somente depois de sua primeira execução real, usando os nomes exibidos pelo GitHub. Não adivinhar nomes de checks antes dessa execução.

## 5. Conversão para público

Somente considerar a mudança de visibilidade quando:

- licença, mantenedor e governança estiverem decididos e presentes, e a ativação imediata do canal privado tiver plano de rollback;
- o inventário, a proveniência e a autorização do proprietário estiverem registrados sem findings bloqueantes;
- CI e security workflows tiverem executado no mesmo commit candidato;
- nenhum finding aberto de severidade bloqueante permanecer sem decisão registrada;
- README, disclaimer e metadata descreverem corretamente o status pre-alpha/draft.

A publicação do source não autoriza tag estável, GitHub Release, GitHub Packages, PyPI, deployment ou uso profissional.

## 6. Release e package permanecem separados

`F0`, `Release00` e `Release01` continuam falhando por desenho. Uma futura rota para PyPI exige nova autoridade, TestPyPI, build e publish separados, GitHub Environment com aprovação humana e Trusted Publishing/OIDC sem token persistente. Nenhuma dessas superfícies deve ser habilitada nesta fase.
