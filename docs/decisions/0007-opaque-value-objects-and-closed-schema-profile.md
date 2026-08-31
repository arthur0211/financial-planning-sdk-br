# ADR 0007 — value objects opacos e perfil fechado de schema

**Estado:** aceito somente para o vertical local `draft` 0.1
**Data:** 2026-08-10

## Contexto

Os quatro value objects públicos — `ValidationIssue`, `ValidationReport`, `DeterministicResult` e `ReferenceAcceptanceReport` — eram subclasses de `tuple`. Seus construtores normais validavam parte do contrato, mas `tuple.__new__` podia criar instâncias com aridade e conteúdo arbitrários. Acesso posicional e serialização podiam então observar ou emitir esse estado sem passar pelas fábricas. Construção base com `object.__new__`, cópia, pickle e subclasses também precisavam ter comportamento fail-closed explícito, não apenas depender de `__new__` nominal ou de annotations.

Havia ainda duas divergências no wire. As fábricas internas de resultado determinístico e report de referência aceitavam objetos canônicos mínimos que não satisfaziam seus schemas públicos completos. Em sentido inverso, o pattern de pointer/mensagem do `ValidationReport` era interpretado pelo motor `re` do Python com a extensão de `$` que aceita posição anterior a um LF final, enquanto `ValidationIssue` exigia consumo integral ASCII. O [teste oficial de regex ECMAScript do JSON Schema](https://github.com/json-schema-org/JSON-Schema-Test-Suite/blob/main/tests/draft2020-12/optional/ecmascript-regex.json) fixa que `^abc$` não aceita `"abc\n"`; a lista de line terminators de ECMAScript contém somente LF, CR, U+2028 e U+2029, não U+0085 ([ECMA-262](https://tc39.es/ecma262/multipage/ecmascript-language-lexical-grammar.html#sec-line-terminators)).

A crítica do snapshot R3 mostrou que `__init_subclass__` não é uma barreira absoluta: um mixin à esquerda que não chama `super()` ou uma metaclass que reordena o MRO pode suprimir o hook da classe pública. Nesse estado, métodos herdados ainda faziam dispatch virtual para `_document`, `_validated_document`, `_validated_pair` ou `_validated_sequence` sobrescritos antes de provar o tipo/registro. O mesmo ataque ao perfil de schema encontrou `$id`/`$schema` aninhados, ciclos de `$ref` direto e indireto e tokens como `a%2Fb`, que não podem ser tratados como nomes literais porque `$ref` é uma URI-reference e JSON Pointer em fragmento usa percent-encoding ([JSON Schema Core 2020-12, seção 8.2.3.1](https://json-schema.org/draft/2020-12/json-schema-core.html#name-direct-references-with-ref); [RFC 6901, seção 6](https://www.rfc-editor.org/rfc/rfc6901.html#section-6)).

## Decisão

### Value objects

- os quatro tipos deixam de herdar de `tuple` e passam a fachadas opacas, sem `__dict__`, sobre estado imutável ligado à identidade e ao tipo público exato em registro privado por weak reference;
- somente a fábrica validada do tipo público exato registra estado. `object.__new__` pode produzir no máximo um shell sem estado, e toda operação observável herdada da biblioteca sobre esse shell falha fechado;
- não existe slot de payload gravável e `tuple.__new__` deixa de ser aplicável porque os tipos não são tuples. Em CPython, `object.__setattr__(value, "__class__", outro_tipo_publico)` pode trocar classes de layout compatível; o binding entre identidade e tipo exato torna o objeto inerte enquanto a classe diverge, e restaurar a classe recupera somente o estado original já registrado. Subclass comum é recusada pelo hook; subclass hostil que suprima o hook pode existir como classe Python, mas permanece não registrada e inerte para factories, métodos e descriptors herdados do SDK;
- operações compatíveis de sequência, igualdade, ordenação, hash, cópia, propriedades e métodos `to_dict`/`to_json_bytes` chamam primeiro uma guarda não virtual de identidade/tipo exato. Só depois dessa prova podem chamar helpers, sempre qualificados pela classe pública;
- cada acesso de confiança confere tipo e aridade exatos, bytes `FPBR-C14N-1`, bindings de formato/versão/status/authority e o schema público completo. O `ValidationIssue` valida o fragmento `$defs/issue` do schema público completo;
- `copy.copy` e `copy.deepcopy` retornam a própria instância somente depois dessa revalidação. Pickle é recusado explicitamente; não existe reconstrução que contorne a fábrica;
- o contrato preserva comparação e acesso sequencial material usados pelo draft local, mas não preserva `isinstance(value, tuple)`. Como o pacote não foi publicado, não é criada rota de compatibilidade insegura.

O registro de identidade não pretende isolar monkeypatching ou código Python arbitrário no mesmo processo. A propriedade exigida é mais estreita: nenhuma rota normal de construção base, mutação de instância, factory, cópia, pickle, método ou descriptor herdado do SDK trata tipo não exato, estado não registrado ou estado inválido como value object confiável, e nenhum helper virtual é chamado antes dessa recusa. Método público definido ou substituído pelo próprio atacante no mesmo processo está fora da claim.

### Perfil fechado de JSON Schema

O runtime incorpora um validator somente de biblioteca padrão, sem nova dependência. Ele não é uma implementação geral de JSON Schema Draft 2020-12. Seu perfil reconhece exatamente o vocabulário, os quatro IDs, os quatro digests, os refs locais diretos, o formato `date`, a extensão local `x-significant-digit-budget` e os 17 patterns presentes nos schemas empacotados. `$schema`, `$id` e `$defs` são aceitos somente na raiz. Nome de definição e token de `#/$defs/<nome>` compartilham a gramática ASCII `[A-Za-z_][A-Za-z0-9_.-]*`; `%`, `#`, barra, til, whitespace, controle e backslash não são aproximados nem decodificados. O grafo de todos os refs diretos precisa resolver e ser acíclico antes de qualquer matching. Qualquer keyword, formato, `$ref`, pattern, dialeto, topologia ou digest fora desse inventário falha fechado antes de validar instâncias; `RecursionError` residual é normalizado para `ClosedSchemaError` ou `SchemaInstanceError` conforme a fase.

Essa recusa de keyword desconhecida é política deliberada do perfil fechado do projeto, não semântica geral do Draft. A especificação permite extensões e define o comportamento de keywords desconhecidas ([JSON Schema Core, seção 6.5](https://json-schema.org/draft/2020-12/json-schema-core.html#name-extending-json-schema)). Da mesma forma, `format` é annotation no metaschema padrão; este perfil local configura o único formato suportado, `date`, como assertion e rejeita qualquer outro ([JSON Schema Validation, seção 7.2](https://json-schema.org/draft/2020-12/json-schema-validation.html#name-implementation-requirements)). Siblings de `$ref` continuam aplicáveis, conforme o modelo do Draft 2020-12.

Os patterns continuam com semântica de busca. O único prefix pattern, `^/`, permanece capaz de casar o prefixo de uma string maior. Nos 16 patterns que expressam consumo integral, `$(?![\s\S])` acrescenta uma guarda de fim absoluto que neutraliza somente a extensão de LF final do Python. Testes diferenciais executam todos os 17 patterns contra `jsonschema` e cobrem sufixos LF, CR, U+0085, U+2028 e U+2029. Também percorrem wires válidos e mutados dos quatro schemas. `jsonschema` é dependência apenas de desenvolvimento/teste, não de runtime.

Os IDs e versões dos schemas não mudam. A alteração observável dos bytes restaura o consumo integral que os patterns já declaravam sob a semântica ECMAScript; não amplia domínio, formato ou status. Para impedir troca silenciosa de contrato, o runtime fixa:

| Schema | SHA-256 dos bytes empacotados |
| --- | --- |
| `deterministic-request.schema.json` | `46776bfb416d3b18898aca55da4e44bf9ce229209c6180d1f6018ff20ed86ba9` |
| `deterministic-result.schema.json` | `7264cd620bf32999eb53c17f9779c4fe9c73fd3955818a29577a374edf4dce43` |
| `reference-acceptance-report.schema.json` | `9019eaa881279123e6b805beb7af907b04d487c7b270693743b7799696a0ed82` |
| `validation-report.schema.json` | `7bdbbeabdce9636d9428bf028d6d584724c0c2e5524aa5fe15dde2e841ddfb44` |

## Consequências

Fábricas de resultado/report recusam payload canônico que não satisfaça todo o schema; schema e construtor concordam sobre terminadores; shells, subclasses forjadas e instâncias sob troca compatível de `__class__` não expõem wire nem campos por operações herdadas. Cada accessor relê e valida o schema empacotado, favorecendo fail-closed sobre custo mínimo de acesso. Alterar um dos quatro schemas exige revisar digest, vocabulário, gramática/topologia de refs, inventário de patterns, testes diferenciais e esta decisão.

O Reference Acceptance Pack v1 permanece byte a byte congelado, com SHA-256 raw `b3e5c8078a7258d8df521bb5c8843ef371feeaf681fb6710a6cd57a45918c18c`. Nenhum ID, versão, expected output, regra financeira, authority ou eligibility do pack foi promovido.

Os testes locais e o smoke em source, wheel direto e wheel reconstruído do sdist demonstram apenas o comportamento do snapshot candidato. Nas três superfícies, o smoke compara os quatro accessors de schema, desafia 16 recusas de resource/vocabulário/ref/topologia e exercita os quatro value objects contra left-MRO, custom-metaclass MRO e troca compatível de `__class__`. Isso não autentica o schema, não torna o validator uma implementação Draft geral, não isola código same-UID e não estabelece revisão independente, F0, licença, publicação ou release.

## Alternativas rejeitadas

- manter subclasses de `tuple` e validar apenas propriedades/serializadores: indexação base ainda observaria o payload forjado;
- confiar em `frozen`, `slots`, annotations ou `__new__` nominal para integridade runtime;
- aceitar pickle e tentar validar somente em `__setstate__`, deixando outras rotas de reconstrução dependentes do protocolo;
- validar apenas constantes/status nas fábricas, sem reconciliar o schema público inteiro;
- usar diretamente `re.fullmatch`, que mudaria a semântica de busca de `pattern` e do prefixo `^/`;
- traduzir silenciosamente qualquer regex, keyword, formato ou referência para uma aproximação Python;
- adicionar `jsonschema` como dependência runtime ou alegar cobertura geral de Draft 2020-12;
- alterar o pack v1, promover versão/authority ou recalcular expected outputs para acomodar o tightening de infraestrutura.
