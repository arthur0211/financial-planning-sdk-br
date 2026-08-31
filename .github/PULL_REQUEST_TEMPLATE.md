# Pull request

## Problema e escopo

Descreva o problema, quem é afetado e o que ficou fora deste pull request.

## Mudança

Explique o comportamento anterior, o novo comportamento e as decisões relevantes.

## Evidência

Liste comandos, RCs e contagens. Não use apenas “testes passaram”.

```text
comando:
resultado:
```

## Riscos e limites

Indique impacto em matemática, API, schemas, reason codes, privacidade, dados, licença, subprocessos e deployment.

## Checklist

- [ ] O escopo permanece local, determinístico e sem recomendação.
- [ ] SDK e CLI continuam usando o mesmo caso de uso.
- [ ] Schemas, fixtures, manifesto e reason codes foram atualizados quando necessário.
- [ ] Testes positivos, negativos e de mutação cobrem a mudança.
- [ ] Documentação e ADR foram atualizados quando aplicável.
- [ ] Nenhuma PII, credencial ou dado sem licença foi incluído.
- [ ] O texto não promove build local a authority, release ou validação profissional.
- [ ] Os gates ainda abertos estão registrados.
