# ADR 0004 — fronteira de conformance local do SDK

**Status:** aceito para o draft local 0.1; não autoriza release
**Data:** 2026-08-09

## Contexto

O corpus matemático contém 21 vetores e o harness formal de SUT exige todos eles, duas rotas de validação e manifests de mutação externamente pinados. O primeiro SDK implementa apenas `deterministic_cashflow_ledger`. Forçar esse pacote a responder pelos demais tópicos criaria suporte fictício; enfraquecer o gate de 21 vetores confundiria um recorte local com conformance integral.

## Decisão

Criar um diagnóstico separado e estritamente local:

- um manifesto particiona o corpus inteiro em sete vetores suportados e 14 fora do escopo;
- cada vetor suportado conserva ID, tópico, status e fingerprint do corpus fonte;
- o SDK público é carregado por um worker fixo em subprocesso com `-I -S -B`;
- 58 propriedades em sete famílias usam `Fraction`, centavos inteiros e contextos hostis para testar PV/arredondamento, transferências, convenções de retorno, recusa de contexto operacional, isolamento Decimal, limite de dígitos, o bound de 4.096 termos e a boundary Mapping-only;
- 19 mutações fechadas alteram o código-fonte real, inclusive precisão 97/128, expoentes/rounding, herança do contexto ambiente após limpeza de flags, quantização monetária, reconciliação e restauração do bypass tipado; survivor, crash, timeout ou mutante inviável tornam o diagnóstico vermelho;
- `--skip-mutations` produz estado `partial`, nunca o status de conformance local completa;
- todo relatório mantém `official_21_vector_sut_conformance=not_evaluated`, `release_authorized=false` e digest local não autenticado.

O comando canônico é:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_sdk_conformance.ps1 -OutputFormat Json
```

## Consequências

O projeto ganha evidência executável de que o pacote público, e não apenas um adapter matemático de referência, satisfaz o recorte que declara implementar. Drift do manifesto, fingerprint, fonte, worker ou adapter fecha o diagnóstico. A execução continua sem sandbox de filesystem/rede, sem pin externo e sem autoridade sobre fórmula no mundo real, Brasil, licença, deployment ou release.

## Alternativas rejeitadas

- retornar `not_applicable` pelos 14 vetores não implementados;
- chamar o bridge parcial de conformance do SUT de 21 vetores;
- importar o SDK no processo do runner e perder a separação de startup/import;
- contar crash ou timeout de mutante como kill satisfatório;
- publicar workflow ou pacote para obter evidência antes da decisão de licença e release.
