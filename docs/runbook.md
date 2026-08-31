# Runbook do Financial Planning SDK Brasil

_Operação local para mantenedores não técnicos · 11 de agosto de 2026_

---

## 📋 O que existe hoje

O repositório contém pesquisa, contratos, tooling de conformance e um primeiro SDK/CLI local para PV e ledger determinístico. Não há motor de produção, banco, serviço, regra brasileira ou release. Rodar as validações abaixo verifica contratos delimitados; **não valida as fórmulas no mundo real** e não autoriza uso profissional. A regra de vitória técnica e os gaps correntes ficam na [barra v1](v1-quality-bar.md) e no [scorecard vivo](v1-scorecard.md).

## ▶️ Preparar e executar o SDK local

Na raiz do repositório:

```powershell
$FinPlanBrVenv = Join-Path $env:LOCALAPPDATA 'finplanbr\venvs\dev'
$FinPlanBrBootstrap = (py -3.12 -c "import sys; print(sys.executable)").Trim()
& $FinPlanBrBootstrap -m venv $FinPlanBrVenv
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install setuptools==84.0.0
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install --no-deps --no-build-isolation --editable .
& "$FinPlanBrVenv\Scripts\finplanbr.exe" validate .\examples\deterministic-cashflow-ledger.json
& "$FinPlanBrVenv\Scripts\finplanbr.exe" compute deterministic .\examples\deterministic-cashflow-ledger.json
& "$FinPlanBrVenv\Scripts\finplanbr.exe" reference run
```

O ambiente precisa permanecer fora do checkout: `Structure` percorre deliberadamente toda a árvore e não trata `.venv`, `build` ou `dist` como conteúdo confiável do projeto. O setup instala somente a toolchain de build e o checkout editável; o pacote não tem dependência de runtime. A instalação de `setuptools` pode acessar o índice configurado, mas `validate` e `compute deterministic` não usam rede. Para desenvolvimento sem instalação:

```powershell
$FinPlanBrToolState = Join-Path $env:LOCALAPPDATA 'finplanbr\tool-state'
$env:COVERAGE_FILE = Join-Path $FinPlanBrToolState 'coverage'
$env:MYPY_CACHE_DIR = Join-Path $FinPlanBrToolState 'mypy'
$env:RUFF_CACHE_DIR = Join-Path $FinPlanBrToolState 'ruff'
```

Essas variáveis mantêm coverage e caches de análise fora do checkout. As ferramentas criam os diretórios necessários quando executadas.

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m financial_planning_sdk_br validate .\examples\deterministic-cashflow-ledger.json
python -m financial_planning_sdk_br compute deterministic .\examples\deterministic-cashflow-ledger.json
python -m financial_planning_sdk_br reference run
```

Testes e qualidade:

Os comandos Ruff/Mypy exigem o extra local de desenvolvimento. Se a venv foi criada apenas com a instalação mínima acima, instale-o antes (isso pode consultar o índice configurado):

```powershell
& "$FinPlanBrVenv\Scripts\python.exe" -m pip install --editable '.[dev]'
$env:PATH = "$FinPlanBrVenv\Scripts;$env:PATH"
```

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m unittest discover -s .\tests\sdk -p 'test_*.py' -v
python -m unittest tests.sdk.test_schema_validation tests.sdk.test_value_object_hardening -v
python -m ruff check .\src .\tests\sdk
python -m mypy --strict .\src\financial_planning_sdk_br
python -m compileall -q .\src\financial_planning_sdk_br .\tests\sdk
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_sdk_conformance.ps1 -OutputFormat Json
python .\scripts\smoke_local_package.py
python -m unittest discover -s .\tests\portability -p 'test_*.py' -v
python -I -B .\scripts\freeze_source_snapshot.py --summary
```

O smoke script copia apenas `pyproject.toml`, `LICENSE`, README e `src` para um diretório temporário, executa `build --wheel` e `build --sdist` separadamente sem isolamento de build e fecha o inventário do payload, incluindo os quatro schemas públicos. Os roots de import de `build` e `pip` são resolvidos antes do subprocesso `-I -S`, pois no CPython 3.11–3.13 `-S` oculta o prefixo da venv; o child aceita somente essa lista absoluta fechada e continua ignorando `PYTHONPATH`/startup hooks. Depois instala o wheel direto da source, constrói explicitamente um segundo wheel a partir do sdist com `pip wheel --no-build-isolation`, fecha também esse inventário e o instala em outro target temporário. Em source e nas duas instalações, roda o Reference Acceptance Pack duas vezes pela CLI e uma vez pelo SDK, exigindo bytes idênticos, 3/3 casos e as fronteiras não autorizativas. Compara os quatro accessors de schema, 16 recusas de resource/vocabulário/ref/topologia e o report de 4.096 eventos inválidos nas rotas `validate` e `compute`: RC2, sem traceback, total exato, 128 issues retidas e bytes idênticos. Probes instalados exercitam os quatro value objects contra factories mínimas schema-invalid, trailing LF, shell, `tuple.__new__`, atributo de payload forjado, left-MRO, custom-metaclass MRO, troca compatível de `__class__`, cópia e pickle; qualquer método/descriptor herdado que exponha estado ou despache helper antes da guarda reprova. Os hashes dos dois wheels podem divergir por metadata/build; o que o smoke observa são payloads runtime, não reproducible-build claim, assinatura, equivalência ampla de artefato ou autorização de release.

O freeze de handoff tem ordem exata, não locale-dependent: `git ls-files --cached --others --exclude-standard -z` fornece o inventário; cada path relativo canônico é ordenado por seus bytes UTF-8 em ordem crescente; cada entrada registra `path`, tamanho e SHA-256 dos bytes. O manifesto `finplanbr.source-freeze.v1` é serializado em `FPBR-C14N-1`, sem newline, e seu SHA-256 vira o identificador do snapshot. Arquivos ignorados ficam fora do inventário. O CLI exige que o interpreter já tenha iniciado com `-I`, pois `sitecustomize`/`usercustomize` pode executar antes da primeira linha do script e nenhum auto-reexec interno desfaz esse risco; sem isolated mode, retorna RC2 antes de inventariar. A leitura rechecada detecta drift durante cada arquivo, mas o conjunto não é snapshot atômico nem autenticação, approval ou authority. Execute o comando somente depois da última escrita; qualquer alteração posterior invalida o hash e exige novo freeze.

### Executar a matriz instalada/offline

Crie uma pasta de evidência fora do checkout e não faça writes no repositório entre as células:

```powershell
$evidenceRoot = Join-Path $env:TEMP ("finplanbr-portability-evidence-" + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($evidenceRoot) | Out-Null
foreach ($version in @('3.11', '3.12', '3.13', '3.14')) {
    python .\scripts\run_linux_portability_cell.py `
        --python $version `
        --output (Join-Path $evidenceRoot "linux-py$version.json")
    if ($LASTEXITCODE -ne 0) { throw "Linux $version não observado" }
}
```

Esse comando requer Docker Engine ativo. Cada launcher cria somente containers/imagem `finplanbr-portability-<nonce>*`, rotulados com o mesmo nonce, sem portas publicadas, e faz cleanup por identidade/label exato. Não reutilize nem altere containers existentes. As quatro imagens Python oficiais são referências `python@sha256:...` fechadas em `scripts/portability_runtime_pins.py`; atualizar um digest exige novo freeze e nova matriz. A aquisição da imagem/toolchain ocorre antes; build, canonicalização fechada do sdist e dos dois wheels, reconstrução, instalação e probes do candidato rodam depois com `--network none` e filesystem read-only, em `/work` descartável. O audit hook é apenas observador secundário.

O build chama wheel e sdist separadamente. O output bruto do sdist é aceito somente se tiver roster/ordem exatos e exatamente um PAX `mtime` canônico antes de cada entrada. Todos os campos USTAR são byte-validados: name integral/prefix vazio, slash e type exatos, números octais zero-padded com NUL, checksum de seis dígitos + NUL + espaço, magic/version, links/owners/devices/reserved vazios, padding zero e EOF no record de 10.240 bytes. O `mtime` inteiro do header precisa corresponder ao arredondamento do float PAX. A célula Windows admite apenas o tuple de backend diretórios 0777/arquivos 0666/uid-gid 0; a Linux oficial, diretórios 0755/arquivos 0644/uid-gid 65532. Perfis mistos ou cruzados, base-256, byte após NUL e owner nominal falham antes que o writer possa apagá-los; a visão raw ainda é reconciliada com `tarfile`. Os oito membros gerados (`PKG-INFO`, `setup.cfg` e `egg-info`) normalizam uma única vez na entrada e são substituídos por uma representação LF; package, packs, LICENSE, README e pyproject permanecem byte-exact. O writer próprio do USTAR fixa ordem, name integral/prefix vazio, campos octais com zero/NUL, checksum com seis dígitos + NUL + espaço, ownership, modes, timestamps, padding por membro, dois EOF e padding ao record de 10.240 bytes. O envelope `finplanbr-sdist-gzip-ustar-stored-canonical.v1` usa header RFC 1952 fixo `1f8b08000000000000ff`, blocos DEFLATE `STORED` próprios de até 65.535 bytes e trailer CRC32/ISIZE; não chama writer de `tarfile` nem compressor de zlib/zlib-ng para os bytes canônicos. O inspector mantém os parsers raw/biblioteca, reserializa os payloads e exige igualdade integral do TAR e do gzip. É exatamente esse sdist canônico, com SHA capturado antes e depois, que alimenta `pip wheel`.

Os wheels brutos direto e reconstruído passam por parser ZIP32 raw, reconciliação com `zipfile`, roster e `RECORD` semanticamente válidos. O canonicalizador recebe a cópia do source freeze verificado; aceita a convenção de newline do backend somente quando ela normaliza para a política fechada, liga `dist-info/licenses/LICENSE` ao source, substitui `METADATA` pelos headers normativos mais o README congelado e fixa `WHEEL`, `entry_points.txt` e `top_level.txt` em LF. Depois reserializa, sem compressor de backend, no perfil `finplanbr-wheel-zip32-stored-canonical.v2`: 24 membros em ordem exata, nomes ASCII/flags zero, timestamp `1980-01-01 00:00:00`, `STORED`, versões 20, creator Unix, regular file 0644 e nenhum extra/comment/data descriptor/ZIP64. `RECORD` é regenerado em LF depois dessas substituições, na ordem do roster e com self-row final. O inspector reconstrói o arquivo esperado e exige igualdade integral. Assim, newline de metadata gerada, timestamp, ordem do ZIP/`RECORD`, flag UTF-8 alternativa, versões/attrs permissíveis e método/blocos DEFLATE não podem variar silenciosamente. O SHA-256 raw de direct-wheel e sdist-wheel precisa ser idêntico na célula e vira `wheel_archive_sha256`; o agregador exige o mesmo valor entre as oito células.

Além disso, o inspector exige 18 arquivos de package, 24 membros no wheel e 29 arquivos + quatro diretórios no sdist, e liga source, os dois wheels e o sdist por digests lógicos. LICENSE/README/pyproject do sdist e `dist-info/licenses/LICENSE` do wheel precisam corresponder aos bytes congelados; o `METADATA` canônico tem exatamente SPDX, authorship, extras/dependências e corpo README source-bound, todos na representação LF definida pela política. O binding `finplanbr.portability-package-binding.v2` inclui `wheel_archive_sha256` e `sdist_archive_sha256`; na célula, o segundo precisa coincidir com o artifact reportado e com o input usado para reconstruir o wheel. A metadata corrente segue `finplanbr-setuptools-84.0.0-metadata.v5`, conforme o [ADR 0012](decisions/0012-apache-source-publication-governance.md). A normalização é exclusiva dos membros gerados na entrada bruta; na inspeção final, os oito gerados precisam coincidir byte a byte com LF e `SOURCES.txt` não admite LF terminal. Package, schemas, LICENSE, README e pyproject permanecem byte-exact. `unexpected_payload.py`, `secret.schema.json`, metadata/dependência adicional, source mismatch, CRLF residual, LF terminal em `SOURCES.txt`, base-256, tail pós-NUL, owner/group, perfil de backend misto/cruzado, PAX ausente/empilhado/desligado, ordem/EOF/octal/checksum/name-prefix TAR alternativos, header/codificação/fronteira gzip alternativa, timestamps/ordem/compressão ZIP alternativos, `RECORD` reordenado, ZIP comment/extra, PAX desconhecido, symlink/special member e qualquer byte após gzip são controles negativos testados, não conteúdo tolerado.

Para uma célula Windows, primeiro adquira as ferramentas pinadas enquanto a rede ainda está permitida. Em seguida abra PowerShell elevado e execute:

```powershell
$toolVenv = Join-Path $env:TEMP 'finplanbr-portability-tools-py311'
python -m venv --copies $toolVenv
$toolPython = Join-Path $toolVenv 'Scripts\python.exe'
& $toolPython -m pip install --disable-pip-version-check build==1.4.0 setuptools==84.0.0
pwsh -NoProfile -File .\scripts\run_windows_portability_cell.ps1 `
    -PythonMinor '3.11' `
    -PythonExecutable $toolPython `
    -OutputPath (Join-Path $evidenceRoot 'windows-py3.11.json')
```

Use um tool-venv dedicado porque o runner confere a toolchain com `-P -s`. Em instalações Microsoft Store, um `build` disponível apenas no user-site pode executar `python -m build` e ainda falhar corretamente nessa conferência; não remova `-s` nem conte esse ambiente parcialmente observado. A aquisição do tool-venv ocorre antes da boundary. O launcher continua responsável pelas regras firewall/ACL temporárias durante a célula; um build/install local sem esses controles é apenas diagnóstico e não preenche a matriz.

O workflow de portabilidade instalada é manual (`workflow_dispatch`) porque o agregador permanece fail-closed sem autenticação externa e pode terminar RC1 mesmo com células tecnicamente coerentes. CI de pull request usa workflows técnicos separados e não promove a matriz manual a gate de release.

Repita com o interpreter correspondente para 3.12–3.14. O runner cria regras outbound Block temporárias somente para os paths absolutos do Python/console da célula e ACL Deny somente numa cópia descartável sob `%TEMP%`. Ele captura o estado prévio e só emite `passed` depois de restaurar os SDDL e provar que suas regras sumiram. Em sessão não elevada, retorna RC1 `not_observed`; não transforme isso em skip e não use audit hook como substituto.

Com os oito arquivos, e somente eles, agregue:

```powershell
$matrixPath = Join-Path $env:TEMP ("finplanbr-portability-matrix-" + [Guid]::NewGuid().ToString('N') + '.json')
python .\scripts\aggregate_portability_matrix.py $evidenceRoot --output $matrixPath
```

O agregador atual nunca retorna RC0: os JSON de célula são self-issued e não existe receipt externo autenticável. Oito reports coerentes, inclusive com um único `wheel_archive_sha256` e um único `sdist_archive_sha256`, produzem `all_cells_consistent=true`, mas também `EVIDENCE_ORIGIN_UNAUTHENTICATED`, `evidence_authentication=not_implemented`, `status=failed` e RC1. O hash raw do sdist precisa coincidir entre artifact e `packaging` na célula; oito reports que se autoconsistem mas carregam oito sdists distintos agora quebram `PACKAGING_MATRIX`. Diretório parcial, campo `packaging` ausente, hashes raw divergentes dentro/entre células, célula ausente, freeze divergente ou Windows `not_observed` acrescentam falhas de consistência. A escrita no path de evidência é explícita e fica fora da claim de “nenhuma escrita implícita nas rotas testadas”. O [workflow declarado](../.github/workflows/installed-portability.yml) fixa actions por SHA, mas `ubuntu-latest`/`windows-latest`, YAML e artifact sem receipt não autenticam execução. Não contorne o RC1 com chave/assinatura criada no checkout. Veja o [ADR 0008](decisions/0008-installed-offline-portability-matrix.md).

### Executar o diagnóstico AppContainer separado

Em Windows, somente depois de freeze integral estável, preregistro dos controles e autorização explícita para um único ensaio, execute sem indicar hosts:

```powershell
python .\scripts\run_windows_appcontainer_spike.py --timeout-seconds 300
```

Não faça retry automático nem “tente de novo” depois de RC1. Preserve o JSON, feche endpoint/profile/TEMP, confira resíduos e rehash do freeze antes de decidir qualquer nova revisão. Oito lives históricos desta sprint consumiram autorizações distintas e não devem ser repetidos; nenhum nono live está autorizado.

`--pwsh` e `--windows-powershell` não existem mais e recebem RC2 `invalid_usage`; não substitua o host por cópia em `%TEMP%`. A boundary Python descobre Windows PowerShell 5.1 somente por `GetSystemDirectoryW`. PowerShell 7 é aceito no path MSI exato sob `FOLDERID_ProgramFiles` ou como MSIX realmente registrado para `Microsoft.PowerShell_8wekyb3d8bbwe`; nome de pasta parecido em `WindowsApps` não basta, pois full name, family, package path, publisher, arquitetura e versão são obtidos e reconciliados pelas APIs AppModel do Windows.

Antes de criar a pasta temporária ou compilar, a boundary abre cada componente da cadeia sem seguir reparse, confere path final/`FILE_ID_INFO` 128-bit/owner, prova que o token corrente não abre os acessos de mutação relevantes para substituir ou alterar a cadeia e valida SHA-256, versão e assinatura Microsoft por WinVerifyTrust. Para o `powershell.exe` inbox, a assinatura pode ser ligada ao catálogo Windows pelo hash do mesmo handle. A raiz do volume também é verificada e bloqueada contra delete/alteração; a permissão Windows comum de criar um sibling novo na raiz não é apresentada como “root read-only”, pois não substitui o filho protegido já existente. Os handles permanecem abertos com share-read durante a única execução e são revalidados antes/depois. A política WinVerifyTrust é offline/cache-only, desabilita revogação e, portanto, não prova freshness nem detecta necessariamente revogação posterior ao cache local.

Na fundação histórica R11, o wrapper v5 não persistia bootstrap, driver, source compilado, DLL nem EXE. A boundary corrente conserva o mesmo consumo in-memory e eleva os contratos a wrapper v23, request v16, input binding v15 e input in-memory v9; bootstrap input e driver output permanecem v2, helper v17, raw v9, expected/summary v11, profile prelaunch/receipt v4 e helper failure receipt v6. `Program.cs` continua sendo o único source consumido por handle share-read-only do checkout. Outer/inner continuam `fpbr-json-ascii-fixed-order-lf.v1`, reconstruídos antes de `ScriptBlock.Create`, Roslyn e helper, com zero `CommandAst`, autoload desabilitado, `FullLanguage`, lockdown `None` e `PSModulePath` vazio.

O driver valida a forma fechada por `System.Text.Json`, mas somente a igualdade raw com a reconstrução autoriza consumo. Ele compila diretamente com Roslyn disponível no `$PSHOME` aceito. Cada referência TPA sob `$PSHOME` entra em ordem canônica e fica aberta share-read-only entre hash, `ModuleMetadata(..., leaveOpen=true)`, emit e rehash; o roster e seu digest seguem no envelope. O SHA-256 do PE é calculado sobre o mesmo `byte[]` entregue a `Assembly.Load`, e `Program.Entry` é resolvido por reflection na assembly retornada. O driver output v2 reporta `observed_bootstrap_input_sha256` e `observed_in_memory_input_sha256`, ambos sobre bytes raw com LF; o Python exige igualdade com os hashes do produtor antes de aceitar o envelope e então liga bootstrap, driver, request, source, referências, PE, retorno e helper stdout. `TokenProbe.cs`, `.csproj`, scripts `.ps1`, DLL e EXE ficam fora do input, build, request e claim.

O helper corrente executa CPython 3.13 real em `-I -B` sob AppContainer, usando runtime/source efêmeros externos ao profile. `BoundAppContainerIdentity` é o único owner do SID importado. `ValidatedTokenFacts`, `ValidatedProfileIdentity`, `LaunchAuthorizationProof`, `BoundClassicTokenObservation` e `ValidatedClassicTokenObservation` são proof objects selados e ligados a issuer/owner; seus construtores `internal` decorrem da acessibilidade C# de tipos aninhados, enquanto emissão e callsites ficam confinados ao contexto. A prova de token liga role, process handle, PID e label/ordem de arm antes da serialização. A prova de profile liga leituras frescas initial/network-before/network-after/final com checkpoint e ordinal. A prova de launch não expõe `Pointer` ou `Apply`: seu `CreateSuspendedProcess` one-shot mantém o lifetime lock enquanto aplica apenas `SECURITY_CAPABILITIES` (`0x00020009`) e chama `CreateProcessW`; nunca aplique `ALL_APPLICATION_PACKAGES_POLICY` (`0x0002000f`) ou `OPT_OUT`. Root e rede usam essa operação; `STARTUPINFOEX` também carrega `HANDLE_LIST` e `JOB_LIST`. Para o root, facts e efeito AAP precisam sair do mesmo primary token e ser consumidos pelo mesmo issuer/owner/processo antes de emitir os flags públicos. O ensaio exige job membership pré-resume, breakaway negado, child/grandchild, kill-on-close e canary/decoy handle. O contexto só libera o SID por `LocalFree` depois de arms, processos, handles e attribute lists. O par AAP/no-AAP fica presente durante preflight, root e full network; depois do full, revalide ACL, identidade, streams e bytes, remova a árvore e confirme ausência antes do controle final. Filesystem executa controles para read e todas as mutações declaradas. A rede usa listener WSL2 guest-NAT efêmero e sequência preflight-zero → control0 → A-B-B-A → control5; nenhuma mudança de firewall, exemption, portproxy, Docker object ou policy é permitida.

Para cada um dos cinco tokens de rede, use o mesmo `NetworkTokenObservationContext` emitido pelo mesmo `NetworkArmPlan` do começo ao fim. A ordem tipada é `launch_policy → read_base → aap_membership → aap_rosters → lpac → identity → aap_effect → validate_lpac → validate_roster → bind`, seguida de `RequireComplete`; duplicate, skip, reverse, cross-plan, contexto novo/nulo, bind antecipado ou uso pós-completion devem falhar como invariante. O processo realmente criado, a policy regular, o primary token usado por facts + efeito AAP, `ValidateFacts`, bind e proof precisam receber a mesma instância. `TokenIsLessPrivilegedAppContainer=true` é invariante; `false` suportado apenas corrobora; erro 87 vira `null/unsupported` neutro, nunca `false` ou passe. Root usa a prova classic atômica. Child/grandchild usam o reader sem contexto de rede e sustentam apenas lineage por PID/parent, SID, integridade, capabilities e roster AAP, não observação comportamental direta.

O profile é wrapper-owned. Só `CreateAppContainerProfile=S_OK` autoriza cleanup; collision falha sem delete. `AppContainerProfileLease` reconcilia, no mesmo processo que chamou Create, o SID retornado com `DeriveAppContainerSidFromAppContainerName`; somente depois emite um `OwnedProfileBinding` exact-type, selado e frozen. O wrapper não rederiva nem usa dict mutável para reancorar a autoridade: chama `current_wire()`, que revalida os campos/snapshot e devolve bytes canônicos + digest fresco como um par atômico ligado ao input binding v15. O helper não chama Create, Delete, Derive ou `FreeSid`: importa a string exata com `ConvertStringSidToSidW`, exige `IsValidSid`, revision 1, identifier authority 15, base RID 2 e contagem de subauthorities exatamente 8 ou 12, e reconcilia texto `Ordinal` e bytes por `EqualSid`. O path retornado por `GetAppContainerFolderPath` precisa ser um descendente canônico não vazio de `LocalAppData\Packages`, com um ou mais componentes Win32 válidos, existente e reparse-free. `component_count` e `terminal_ac` são diagnósticos; não exija depth específico nem terminal `AC`. O diretório fica aberto sem share-delete e sua identidade é lida novamente no início, antes/depois de cada arm de rede e ao fim da boundary; os proofs exigem checkpoint, referência e ordinal coerentes. Prelaunch/receipt v4 nunca expõem path, componentes ou SID de conta. Cleanup exige delete/ausência/recreate mesmo SID+shape/delete/ausência; qualquer termo falso produz RC1, e o reason primário permanece separado de eventual `cleanup_override_reason`.

As referências primárias delimitam apenas a API: a Microsoft documenta [`DeriveAppContainerSidFromAppContainerName`](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deriveappcontainersidfromappcontainername), [`ConvertStringSidToSidW`](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsidtosidw), [`IsValidSid`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsid) e as [constantes de SID AppContainer do SDK](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-container-sid-constants). O artigo de Raymond Chen de 2022-05-02 sobre [`S-1-15-2-...`](https://devblogs.microsoft.com/oldnewthing/20220502-00/?p=106550) é contexto diagnóstico, não contrato normativo. Essas fontes não autorizam inferir equivalência entre caller contexts nem um mecanismo universal para o shape de 12 subauthorities. O ensaio aceita 8/12 como política fechada ligada às constantes publicadas e à evidência local; caller-context independence não é claim e controller Python comprometido permanece fora da boundary.

Trate RC0 como observação local somente quando `status=observed_pass` e todas as dimensões recomputadas estiverem verdadeiras. RC1 nunca é passe parcial; preserve `primary_reason`, `reason` e `cleanup_override_reason`, sem anexar paths privados, SID de conta, exceções ou hash de bytes rejeitados. Mesmo RC0 continua `portability_cell=not_counted`, `diagnostic_only=true`, `evidence_authentication=not_implemented`, `authority=none` e `release_authorized=false`. Packaging e matriz 3.11–3.14 continuam fora deste diagnóstico.

Em RC1 produzido pelo helper v17, `helper_failure_receipt` v6 só pode conter `format`, `status`, `stage`, `substage` e `failure_class`. Os stages fechados continuam `entry`, `profile_binding`, `profile_storage`, `runtime_copy_acl`, `fingerprint_initial`, `listeners_controls`, `job_attributes`, `root_launch`, `root_report`, `lineage`, `network_differential` e `fingerprint_final_cleanup`. Em `profile_binding`, os únicos substages continuam `profile_binding_entry`, `profile_prelaunch_parse`, `profile_sid_import`, `profile_sid_validate`, `profile_sid_roundtrip`, `profile_folder_query`, `profile_folder_canonical`, `profile_localappdata_canonical`, `profile_ancestry` e `profile_boundary_compare`.

No v6, `network_differential` possui exatamente 98 substages únicos nesta ordem compacta e determinística:

| Bloco | Expansão ordenada |
| --- | --- |
| `TOKEN(P)` | `P_token_launch_policy` → `P_token_read_base` → `P_token_aap_membership` → `P_token_aap_rosters` → `P_token_lpac` → `P_token_identity` → `P_token_aap_effect` → `P_token_validate_lpac` → `P_token_validate_roster` → `P_token_bind` |
| `ARM(P)` | `P` → `P_launch` → `TOKEN(P)` → `P_process` → `P_report` → `P_exit` → `P_result` |
| preâmbulo | `network_differential_entry` → `network_endpoint_bind` → `network_preflight_prepare` → `network_preflight_profile_before` → `network_preflight_capability_import` → `network_preflight_request_setup` |
| preflight token | `network_preflight_zero` → `network_preflight_zero_launch` → `TOKEN(network_preflight_zero)` → `network_preflight_zero_process` → `network_preflight_zero_report` → `network_preflight_zero_exit` → `network_preflight_zero_result` → `network_preflight_zero_expectation` → `network_preflight_profile_after` |
| transição full | `network_control_before` → `network_full_snapshot` → `network_full_firewall_snapshot` → `network_full_listener_snapshot` → `network_full_prepare` → `network_full_profile_before` → `network_full_capability_import` → `network_full_request_setup` |
| A-B-B-A | `ARM(network_arm_zero_1)` → `ARM(network_arm_internet_client_1)` → `ARM(network_arm_internet_client_2)` → `ARM(network_arm_zero_2)` |
| cauda | `network_full_profile_after` → `network_control_after` |

Concatene os blocos da tabela de cima para baixo; dentro de A-B-B-A, expanda os quatro `ARM` da esquerda para a direita; em cada `ARM` ou preflight, expanda `TOKEN` no ponto indicado. Com cada `TOKEN` contado como um placeholder, o skeleton tem `6 + 9 + 8 + 4×7 + 2 = 53` itens. Substituir os cinco placeholders por dez fases adiciona `5×9`, totalizando exatamente `53 + 45 = 98`.

Stage e substage significam apenas a categoria entrada/ativa quando a falha foi classificada; não provam conclusão, alcance da operação seguinte, detalhe observado ou crédito parcial. `failure_class` vem de allowlist por tipo; `NotObservedException` vira somente `not_observed`. Mensagem, Win32/HRESULT, path, SID, digest, tamanho e valor observado não entram. O wrapper só admite o receipt após framing canônico, privacy e igualdade dos RCs outer/driver/helper; unknown, extra, tipo inválido, pair stage/substage incorreto ou combinação forjada removem o receipt. O report final e `artifacts` precisam manter rosters exatos. No modo A, sem helper+recompute completos, `driver_binding`, `helper_report`, `boundary_summary` e os quatro hashes derivados ficam presentes com JSON `null`; remover a chave não satisfaz esse contrato. No modo B, `observations_complete` e recompute podem terminar em `observed_pass` ou `not_observed`: os três witnesses e todos os hashes do roster ficam não nulos e são revalidados contra snapshots canônicos privados, transcripts e contexto de path efêmero. Em todo caminho runtime, o snapshot privado pre-scrub liga os sete hashes retidos também no modo A; cleanup pode zerar somente os quatro hashes derivados e exige esse snapshot. Um modo A sintético sem pre-snapshot não prova esse binding anterior. Cleanup posterior faz scrub dos três witnesses e quatro hashes derivados, muda `reason/status`, mas preserva o outcome recomputado em `primary_reason` e registra separadamente `cleanup_override_reason`.

No produtor v6 fechado, erro 87 da consulta LPAC é apenas `null/unsupported`; não emite `NotObserved`, e query `true` falha como invariante. Os caminhos `NotObserved` na sequência tipada são indisponibilidade da API `CheckTokenMembershipEx` sob `aap_membership`, ausência conjunta de AAP em TokenGroups + RestrictedSids e efeito AAP regular não observado; os dois últimos ocorrem enquanto `validate_roster` é a categoria ativa e o receipt não os separa. Estado de membership inconsistente permanece `internal_invariant_failure`. Essa granularidade é prospectiva e não explica retroativamente qualquer receipt anterior.

Antes de qualquer revalidação, snapshot ou canonicalização final, o report público inteiro passa por um walker iterativo de tipos JSON exatos. São admitidos somente `dict`, `list`, `str`, `int`, `bool` e `None` builtin, com chaves `str` builtin, profundidade até 128 e até 100.000 nós. Float inclusive finito/NaN/infinito, bytes, tuple/set, subclasses equivalentes, chave derivada, ciclo e excesso estrutural devem terminar em RC1 fechado, nunca traceback ou promoção. Um alias acíclico compartilhado é permitido e serializado como valores JSON repetidos. Não use esse gate genérico para substituir os limites semânticos de cada campo.

Os cinco primeiros lives permanecem históricos como registrados no ADR 0010. O sexto, autorizado uma única vez no freeze integral `a5559191aee153b542895ff4251cf5097649cdbc4b5efd023bd7058cdd79aeef` (`finplanbr.source-freeze.v1`, 212 entradas, 30.784 bytes canônicos), retornou RC1 `not_observed` e admitiu somente o receipt v3 `network_differential/stage_entry/not_observed`. Raw, summary, bindings, dimensões, A-B-B-A e crédito permaneceram ausentes. A evidência capturada registra cleanup de endpoint/profile/TEMP, pós-inventário limpo e freeze estável. Como o stage v3 era reutilizado em duas regiões de código e `stage_entry` não as distinguia, não atribua o resultado a uma região, operação ou causa do throw.

O sétimo live foi autorizado uma única vez no freeze integral `6378174a1da09a711511ee7e4f2335150c695060820de2de142e308d77a89639` (`finplanbr.source-freeze.v1`, 212 entradas, 30.784 bytes canônicos). Retornou RC1 `not_observed`, com `reason=primary_reason=helper_not_observed`, e admitiu exatamente `{"failure_class":"not_observed","format":"finplanbr.windows-appcontainer-helper-failure-receipt.v4","stage":"network_differential","status":"not_observed","substage":"network_preflight_zero_token"}`. `helper_report`, `boundary_summary` e `driver_binding` ficaram `null`; raw, dimensões, A-B-B-A, conclusão e crédito permaneceram ausentes. A evidência capturada registra cleanup de endpoint/profile/TEMP, pós-inventário sem marker, listener/watchdog/launcher, processos/mapeamentos do moniker ou resíduos, e duas leituras pós-run com o mesmo freeze. Não infira que o token foi lido, validado ou ligado: o marcador v4 significa somente que a categoria agregada estava ativa.

O diagnóstico anterior não criou profile e foi estritamente read-only. Em 32 monikers, as derivações por Python empacotado, pwsh7 empacotado e Windows PowerShell não empacotado foram pairwise distintas; os dois contexts empacotados observaram 12 subauthorities e o não empacotado observou 8. Isso falsifica a premissa operacional de rederive ordinal cross-context e é compatível com escopo pelo caller, mas não estabelece lei causal nem prova o mecanismo interno do Windows. O helper v17 importa o SID criado/reconciliado pelo controller em vez de derivá-lo novamente. O receipt v6 é prospectivo: nunca substitua substages dos receipts v3/v4/v5 históricos por uma das dez fases correntes.

O oitavo live foi executado uma única vez, sem retry, no freeze integral `a3a34d782152974b9b9f81b211c36402d1ef110f4a2ce55b6dfc0c9cdb72e52c` (`finplanbr.source-freeze.v1`, 212 entradas, 30.785 bytes canônicos). Retornou RC1 `not_observed`, `reason=primary_reason=helper_not_observed`, e admitiu exatamente `{"failure_class":"not_observed","format":"finplanbr.windows-appcontainer-helper-failure-receipt.v5","stage":"network_differential","status":"not_observed","substage":"network_preflight_zero_token_validate_lpac"}`. Raw, summary, bindings, dimensões, A-B-B-A, conclusão e crédito permaneceram ausentes; cleanup/pós-inventário/freeze ficaram estáveis. Diagnóstico read-only reproduziu Win32 87/`STATUS_INVALID_INFO_CLASS`, mas como a consulta precedia a validação de AppContainer, isso não prova a causa do sistema operacional. Não execute nem autorize nono live por este documento.

Para regressões determinísticas, use a injeção somente interna exercitada pelos testes, nunca acrescente flags CLI de host:

```powershell
python -m unittest discover -s .\tests\portability -p 'test_windows_appcontainer_spike.py' -v
python -m unittest discover -s .\tests\portability -p 'test_windows_appcontainer_profile.py' -v
python -m unittest discover -s .\tests\portability -p 'test_windows_appcontainer_boundary_report.py' -v
python -m unittest discover -s .\tests\portability -p 'test_windows_host_trust.py' -v
python -m unittest discover -s .\tests\portability -p 'test_windows_appcontainer_helper_authority.py' -v
```

Os testes opt-in live permanecem pulados. Não defina `FINPLANBR_RUN_WINDOWS_APPCONTAINER_DIAGNOSTIC=1`: não há autorização para nono live. Uma autorização futura distinta teria de fixar novo freeze READY, endpoint, controles, cleanup e número máximo de runs.

O recorte fake cobre framing, CLM, host/source locks, transactional privacy admission, profile collision/crash/timeout, handle identity/race, reasons/subpredicados de profile, os 98 substages prospectivos de rede, receipt/recompute mutations, filesystem A/B, ordem de rede, endpoint lease e authority IL negativa. A crítica independente fresca sobre os pins pré-documentação `Program.cs=0fb585d4b80b642db8776e814afc7f94c7b5e699fdea6015fd843c72b0400443`, wrapper `0f31bc363feecfdb585c3e8d1a653b66b9fc13d10e247ec20c03304f39e79cdc`, boundary report `22f68ed9c43068ca7171c2a82a586328bf0aae8c6ec3ceae0b9d27cc8b1e4746`, authority `0101d5032863fda4e40e6e364d4156fdb2dbadd448a4a80e50ab2ad64b707be9`, spike `9fe74e93738135479674558450c66445642890c5a966c5c9e45b0421beee4b4d` e boundary test `4764f3d0f7d89d11031be3fc87ce31535b681f157a48a7cf209cc3adb0837fdf` retornou P0=0/P1=0/P2=0. Dois testes compilados/reflection passaram; 17 categorias independentes mudaram source, compilaram e morreram por diagnóstico nomeado, zero survivor, incluindo split-source, policy/top flags, proof issuer/process/consume/ctor e lifecycle pós-full por componente. Esses verdes são source/compile/reflection/IL/fakes ZERO-LIVE, não live v6, PASS, conclusão, authority, portabilidade ou release. Comprometimento arbitrário do Python candidato fica fora da claim; nenhum nono live é autorizado.

O output é JSON canônico em stdout. `--output` grava por arquivo temporário + `os.replace` e recusa sobrescrever; `--force` torna essa substituição explícita. Destino existente precisa ser arquivo regular com `nlink=1`, e alternate data stream é recusado no Windows. Isso é atomicidade local da troca de path, não defesa contra atacante same-UID. Não use input real identificável em exemplos, issues ou logs. O contrato e as limitações estão em [deterministic-cashflow-ledger.md](specification/deterministic-cashflow-ledger.md).

Na API Python, preserve o documento como `JsonObject` e passe-o diretamente a `validate_deterministic_request()` ou `compute_deterministic()`. A raiz precisa ser `dict` exata e todos os descendentes precisam ser somente `dict`, `list`, `str`, `int`, `bool` e `None` exatos. Não passe subclass, custom `Mapping`/container, código arbitrário, objeto manual ou `dataclasses.replace()`: são recusados antes de walker/encoder chamar protocolo do objeto e não há alegação de sandbox. O SDK canonicaliza sob 1 MiB/76.814 nós/profundidade 32 e faz strict reparse; só esse snapshot entra no parser. `JsonScalar`, `JsonValue` e `JsonObject` preservam typing público sem `Any`.

Os retornos `ValidationIssue`, `ValidationReport`, `DeterministicResult` e `ReferenceAcceptanceReport` são opacos, selados e imutáveis; não conte com `isinstance(value, tuple)` nem use pickle. Acesso posicional/comparação permanece disponível para a compatibilidade material do draft, mas cada operação herdada prova identidade e tipo público exato antes de chamar helpers qualificados; depois revalida estado canônico, bindings e schema. Subclass comum é recusada. Um mixin/metaclass hostil pode criar uma classe ao suprimir o hook, e CPython pode permitir troca de `__class__` entre layouts compatíveis, mas ambos ficam inertes para factories, propriedades, sequência, cópia e métodos/descriptors herdados; restaurar a classe recupera somente o wire original. Método público definido/substituído pelo próprio caller no mesmo processo fica fora dessa claim.

Os accessors de schema usam um perfil stdlib fechado, restrito aos quatro recursos empacotados e seus SHA-256; ele não é um validator geral de JSON Schema Draft 2020-12. `$schema`, `$id` e `$defs` são exclusivos da raiz. Nome de definição e token de `#/$defs/<nome>` precisam casar `[A-Za-z_][A-Za-z0-9_.-]*`; todos os refs precisam resolver e formar grafo acíclico antes do matching. Keyword, formato, ref, topology ou pattern fora do inventário é drift e falha com `ClosedSchemaError`; recursão residual na instância vira `SchemaInstanceError`, nunca `RecursionError`. O perfil trata `date` como assertion local, aplica siblings de `$ref` e preserva search semantics de `pattern`. Os 16 patterns de consumo integral usam uma guarda de fim absoluto; `^/` continua prefixo. Os testes diferenciais com a dependência de desenvolvimento `jsonschema` cobrem todos os 17 patterns e terminadores LF, CR, U+0085, U+2028 e U+2029. Consulte o [ADR 0007](decisions/0007-opaque-value-objects-and-closed-schema-profile.md) antes de alterar schema, digest ou vocabulário.

O kernel ignora o contexto Decimal ambiente. Precision, rounding, `Emin`, `Emax`, clamp, traps e flags do chamador devem permanecer idênticos antes/depois. Para investigar regressão dessa boundary sem gerar artefato:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m unittest tests.sdk.test_decimal_context_and_api -v
```

Interprete as falhas numéricas separadamente:

| Código | Significado local | Ação |
| --- | --- | --- |
| `DCL_INVALID_MONEY` / `DCL_INVALID_DECIMAL` | texto de entrada fora do domínio fechado, inclusive 39º algarismo | corrigir o `JsonObject`/JSON sem arredondamento implícito |
| `DCL_NUMERIC_OVERFLOW` | resultado monetário exato excede 38 algarismos | reduzir/reformular o caso; não aumentar o limite silenciosamente |
| `DCL_NUMERIC_INVARIANT_FAILED` | signal, inexatidão ou estado não finito apareceu fora da quantização nomeada | preservar request/report e tratar como defeito do kernel ou bound, não como input aprovado |
| `DCL_LEDGER_RECONCILIATION_FAILED` | identidade inteira em centavos não fechou | preservar sequência e investigar replay; não forçar `reconciled=true` |

Antes de interpretar qualquer JSON do AppContainer, confirme também o outer envelope: `format`, `authority`, `evidence_authentication`, `diagnostic_only`, `portability_cell` e `release_authorized` têm valores/tipos exatos; host/input/expected/endpoint/profile/moniker precisam reconciliar com snapshots privados. Modo B só é válido com `temporary_directory_cleanup=verified`, `temporary_code_artifacts=absent_at_final_inventory` e `temporary_code_artifact_observation=final_inventory_only_transient_activity_not_observed`. Cleanup `failed` sem override, override TEMP sem cleanup `failed`, detecção sem primary correspondente, tipo derivado, NaN, ciclo, chave extra/ausente ou drift tornam o report inválido. Os fallbacks de validator/privacy permanecem Mode A scrubbed e RC1.

Nos artifacts, compare sempre o roster integral ao snapshot privado pós-cleanup. O snapshot pre-scrub liga os sete hashes retidos em todo caminho runtime Mode A que o fornece, é obrigatório sob cleanup e, no modo B, liga os 11 hashes aos transcripts; o pós-cleanup é obrigatório em qualquer modo, inclusive all-null. Em downgrade, apenas `driver_stdout_sha256`, `helper_stdout_sha256`, `in_memory_assembly_sha256` e `in_memory_compiler_reference_set_sha256` podem passar a `null`; os outros sete valores não podem ser apagados nem substituídos. Um modo A sintético sem pre-snapshot não recebe claim de binding privado anterior.

### Interpretar `reference run`

O comando não recebe arquivo, rede ou credencial. Ele acumula short reads até provar EOF ou obter 1 MiB + 1 byte do pack sintético empacotado e retorna `0` quando os três outputs completos e suas assertions reproduzem os expected bytes fixos; pack inválido ou qualquer caso divergente retorna `1`. Requests, assertions e o manifesto que os reúne possuem digests canônicos fixos antes da execução. `finplanbr reference run --help` repete os exit codes, os campos de triagem e os IDs de remediação sem exigir leitura do código. Confira no JSON:

- `report_format=finplanbr.reference-acceptance-report.v2`;
- `status=local_technical_acceptance_passed`;
- `case_count=3`, `passed_count=3` e `failed_count=0`;
- `provenance=repository_local_untrusted` e `reference_independence=not_claimed`;
- `pack_sha256_basis=fpbr_c14n_1` no pack parseado;
- `authority=none`, `deployment_eligibility=not_authorized` e `release_authorized=false`;
- em cada caso, `exact_output_match=true`, digests iguais e assertions com `rule_id`, pointer, esperado e observado.

Um passe isola drift de instalação e paridade SDK/CLI para três casos candidatos e repete os rosters de 4.096 cashflows e 4.096 eventos inválidos por SDK/CLI em source, wheel direto e wheel reconstruído do sdist. Ele não substitui o runner de sete vetores/71 propriedades/um gate do pack/23 mutações, não é conformance do corpus integral, não é cálculo profissional validado e não fecha F0 ou release.

As versões observáveis são diferentes por função e não devem ser comparadas como se fossem uma única versão:

| Superfície | Versão atual | Como observar |
| --- | --- | --- |
| distribuição/CLI | `0.1.0.dev0` | `finplanbr --version` ou metadata instalado |
| engine determinístico | `0.1.0.dev0` | `engine_version` no report/result |
| contrato determinístico | `0.1.0-draft.1` | `contract_version` |
| pack sintético corrente | `2.0.0-draft.1` | `pack_version` |
| pack v1 histórico congelado | `1.0.0-draft.1`; raw SHA-256 `b3e5c8078a7258d8df521bb5c8843ef371feeaf681fb6710a6cd57a45918c18c` | recurso empacotado, não selecionado pelo runner corrente |
| report do pack | `finplanbr.reference-acceptance-report.v2`; schema `2.0.0-draft.3` | `report_format` e `$id` do schema empacotado |
| ValidationReport de input | `finplanbr.validation-report.v2`; schema `2.0.0-draft.2` | `report_format` e `validation_report_schema()` |

`finplanbr.reference-acceptance-report.v1` foi um draft local não publicado e está `superseded_unreleased`; esta versão do runtime não o emite silenciosamente. O pack v1 não foi alterado nem sobrescrito: permanece fixture histórica empacotada. O runner corrente seleciona somente o pack v2, cujo caso `validate` adota incondicionalmente `ValidationReport` v2; os dois requests/outputs `compute` são canonicamente idênticos aos do v1. O v2 tem SHA-256 raw `b469fafe7c089e02487d9afe57319b47a96f88b9426b4c75e1c29cf00f831955` e digest `FPBR-C14N-1` `2ffed5c0a763cec1f2b8aae44f457af59b5827407fa353c47ecf01d9029e71cd`.

Quando `status=local_technical_acceptance_invalid_pack`, `diagnostics` contém exatamente um objeto fechado com `code`, `location`, `scope` e `remediation_id`, sem texto da exceção nem conteúdo rejeitado. `pack_sha256_basis` explica o digest: `not_available` com `pack_sha256=null` quando o recurso não foi adquirido ou excedeu o limite antes do hash, `raw_input` para JSON adquirido dentro do limite mas não parseável e `fpbr_c14n_1` depois do parse.

| Classe | Codes | Próxima ação |
| --- | --- | --- |
| recurso ausente ou ilegível | `REFERENCE_PACK_RESOURCE_MISSING`, `REFERENCE_PACK_RESOURCE_UNREADABLE` | `reinstall_distribution`: reinstalar o mesmo artefato por fonte conhecida e repetir |
| recurso vazio ou acima do byte budget | `REFERENCE_PACK_INPUT_LIMIT` | `reinstall_distribution`: não hashear/editar o fragmento; reinstalar e repetir |
| JSON inválido ou acima do depth budget | `REFERENCE_PACK_JSON_INVALID`, `REFERENCE_PACK_DEPTH_BUDGET` | `reinstall_distribution`: não editar o pack instalado; reinstalar e repetir |
| digest canônico divergente | `REFERENCE_PACK_DIGEST_MISMATCH` | `reinstall_distribution`: substituir a instalação possivelmente corrompida |
| versão incompatível | `REFERENCE_PACK_VERSION_MISMATCH` | `verify_installed_versions`: conferir a matriz acima e evitar mistura de package/schema/pack |
| constante ou forma fechada divergente | `REFERENCE_PACK_CONSTANT_MISMATCH`, `REFERENCE_PACK_STRUCTURE_INVALID` | `inspect_bundled_pack_drift`: preservar o report e inspecionar drift do artefato fonte |
| roster, rota, derivação, request ou expected output divergente | `REFERENCE_PACK_ROSTER_MISMATCH`, `REFERENCE_PACK_ROUTE_MISMATCH`, `REFERENCE_PACK_DERIVATION_MISMATCH`, `REFERENCE_PACK_REQUEST_INVALID`, `REFERENCE_PACK_EXPECTED_OUTPUT_INVALID` | `inspect_bundled_pack_drift`: não recalcular expected para produzir verde; revisar a mudança e o ADR |
| pack íntegro, caso divergente | `REFERENCE_CASE_FAILED` | `inspect_case_output_mismatch`: usar `cases[].diagnostic`, digests e assertions para localizar a divergência |

Os comandos `validate` e `compute deterministic`, tanto na CLI quanto no SDK, aceitam no máximo 1 MiB, 76.814 nós e profundidade 32, teto estrutural do request publicado. O resultado aceita até 5.180.619 bytes/108.065 nós, teto estrutural separado do schema de saída; o roster material de 4.096 cashflows mede 711.078 bytes/28.695 nós na entrada e 1.372.838 bytes/36.897 nós na saída. O preflight de profundidade é iterativo e ignora colchetes dentro de strings; chaves/valores com lone surrogate escapado são recusados antes da canonicalização. JSON válido mais profundo retorna RC2 com `DCL_JSON_INPUT` em stderr, sem traceback. `reference run` conserva o default 1 MiB/20.000 nós e segue short reads até EOF ou 1 MiB + 1 byte: excesso retorna RC1 com `REFERENCE_PACK_INPUT_LIMIT`, sem calcular hash do fragmento.

`ValidationReport` v2 conta todas as violações, materializa no máximo as primeiras 128 em ordem de descoberta e ordena somente esse prefixo. No wire, `truncation.status=complete` não contém contador; `truncated` contém apenas `omitted_issue_count`. Os accessors derivam `issue_count=len(issues)+omitted_issue_count` e `issues_truncated`. Pointer/mensagem aceitam somente ASCII imprimível e até 128 caracteres; o schema `2.0.0-draft.2` agora impõe o mesmo consumo integral, inclusive contra LF final. O report usa budget próprio de 128 KiB/1.024 nós e todo accessor reconcilia novamente schema/canonicalidade; valide consumidores contra `validation_report_schema()`. A CLI prepara os bytes inteiros antes da primeira escrita e usa uma tentativa. Falha de serialização anterior à escrita recebe fallback v2 estático/redigido; short write retorna RC1 sem retry ou fallback concatenado. Isso não garante atomicidade do descritor.

O reference report v2, incluindo newline da CLI, fica limitado a 64 KiB; assertion divergente expõe somente `observed=null`. A fábrica vincula bytes canônicos imutáveis ao status serializado depois de validar o schema inteiro. A CLI prepara esse report antes de stdout, consulta o status por accessor que reparsa e revalida canonicalidade/binding/schema, e faz uma única escrita; short write retorna RC1, mas isso não é garantia de atomicidade do pipe/console diante de falha de I/O ou atacante same-UID.

O wheel padrão do smoke contém o metadata necessário ao entry point `finplanbr`; já o inspector candidato aceita deliberadamente um perfil de archive mais estreito. Portanto `smoke_local_package.py` e `validate_release_artifacts.py` são evidências diferentes: o primeiro prova instalação/execução local descartável; o segundo continua diagnóstico negativo e não deve ser “feito passar” relaxando seu contrato ou removendo a CLI.

## ⚙️ Validação rápida

Abra PowerShell na raiz `E:\Downloads\financial-planning-sdk-br` e execute:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_docs.ps1 -Mode Structure
```

Saída esperada:

```text
Local consistency check passed in Structure mode: ... Markdown files and 5 CSV contracts. This is not release authority.
```

O script verifica:

- um H1 e code fences balanceados em cada Markdown;
- referências de footnotes e links locais, rejeitando caminho que saia da raiz do repositório;
- ausência dos placeholders originais;
- termos de contrato já substituídos;
- presença de marcadores contratuais positivos, não só uma blacklist;
- headers, linhas, IDs duplicados, enums fechados, datas/precisão e markers nos cinco contratos CSV;
- FKs entre eventos e autoridades, além das relações tipadas entre eventos/autoridades;
- `court_clarification` exclusivamente como relação `clarifies`, sem criar suspensão/restauração;
- em registros `approved`, artefato-fonte local regular, SHA-256 recalculado, reviewer independente presente no registro externo aprovado e datas válidas;
- invariantes de `artifact_status`, política contestada `scenario_only`, data do DLeg 176 e recursos obrigatórios no manifesto.

Ele não testa links externos, validade jurídica, exatidão matemática, licença efetiva nem atualidade de fonte.

Valide também schemas/casos e o corpus matemático:

```powershell
python .\scripts\validate_contracts.py
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_math_vectors.ps1 -SelfCheck -OutputFormat json
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_sdk_conformance.ps1 -OutputFormat Json
```

O primeiro comando Python é somente diagnóstico/draft-only. Ele não aceita trust, não pode aprovar uma fixture e recusa `approved`, `computed` e `computed_with_warnings`; execute-o em ambiente controlado para obter diagnóstico útil, pois import/startup do processo candidato não é uma boundary de autoridade. Não existe consumidor de trust. O runner matemático reporta `filesystem_isolation=not_enforced` e `network_isolation=not_enforced`: um módulo hostil ainda pode escrever fora do cwd ou usar rede, portanto use ambiente descartável para SUT não confiável.

O conformance pack de contratos contém exatamente 33 casos manifestados: 11 em `schemas/examples/valid` com `expected_valid=true` e 22 em `schemas/examples/invalid` com `expected_valid=false`. Diretório, expectativa e o inventário inteiro de entradas formam um único invariant: somente os dois diretórios diretos esperados e fixtures regulares `nlink=1`, ASCII lowercase `*.json`, canônicas e manifestadas são aceitos. Arquivo órfão, nesting, diretório vazio/extra, extensão ou casing alternativo, confusável Unicode, hardlink e qualquer entrada top-level adicional falham; uma releitura final detecta drift posterior ao snapshot. No Windows, `FindFirstStreamW`/`FindNextStreamW` enumera a raiz, diretórios e fixtures no snapshot e no recheck: arquivos precisam expor exatamente o stream padrão `::$DATA` com o tamanho declarado e qualquer stream nomeado/não padrão falha. Fora do Windows, o valor `None` registra que ADS Win32 é `not_applicable`; não representa enumeração vazia nem prova de ausência de mecanismo análogo. Os 62 reason codes têm IDs e metadados semânticos fechados (`category`, `default_severity`, `default_status`, `owner`, `remediation_id`), multiplicidade compartilhada de remediação declarada e exatamente uma bullet canônica correspondente em `docs/specification/error-catalog.md`. Bullets variantes por `*`/`+`, indentação, casing, FormKC, `Cf` ou confusável conhecido são candidatos não canônicos e falham; uso inline em prosa permanece não normativo. Essa cobertura continua `draft` e não converte um caso válido em estado aprovado ou computado.

As revisões adversariais por agents documentadas no corpus são challenge interno e ajudam a encontrar contraprovas. Elas não satisfazem reviewer humano independente, counsel, aprovação de modelo/política ou authority de release.

O terceiro comando é uma fronteira adicional, descrita no [ADR 0004](decisions/0004-local-sdk-conformance-boundary.md). `tests/vectors/sdk/v1/manifest.json` fixa por digest local não autenticado a partição completa do corpus: sete vetores executados pelo SDK e 14 declarados fora do vertical. O worker usa o mesmo protocolo dos vetores, carrega o package público em processo `-I -S -B`, repete o lote, roda 71 casos de propriedade e executa um gate semântico do pack corrente. Em seguida, 23 cópias temporárias da fonte recebem mutações fechadas; somente divergência sem crash, timeout ou mutante inviável conta como kill. Três mutantes compostos têm roster/cardinalidade e kill cases obrigatórios, incluindo saldo corrente sequencial + pack, half-down negativo e reconciliação coordenada. O mutante `typed_request_bypass_restored` usa uma request interna schema-válida, mas viola exclusivamente a boundary do objeto tipado; ele precisa morrer por `property::api::parsed_object_rejected`. O harness não captura `ValueError` nem converte crash em kill/viabilidade. O comando padrão exige 23/23 kills e cobertura de todos os casos obrigatórios. `-SkipMutations` é útil para depuração, mas reporta `local_sdk_conformance_partial`.

Esse diagnóstico não é o SUT gate integral. Ele declara filesystem/rede/process-tree não isolados, runtime e digests não autenticados e `official_21_vector_sut_conformance=not_evaluated`. Use somente código local confiável; execução de código hostil ainda requer sandbox externo. Nenhum resultado autoriza release ou confirma regra/fórmula no mundo real.

No Windows, não use o redirector/App Execution Alias da Microsoft Store para validar contenção por Job Object. Neste host, esse launcher permitiu que o processo real criado pelo alias ficasse fora do job e fez o probe de descendente falhar corretamente; o mesmo conjunto 46/46 passou com uma instalação regular do Python 3.12. Prefira um executável regular ou o Python provisionado pelo CI e nunca enfraqueça o teste para acomodar o redirector.

`-SelfCheck` verifica corpus e rotas locais `test_only`; seu status é `self_check_passed` com SUT `not_evaluated`. Para uma conformance técnica de SUT futura, forneça juntos os dois pares de pins: `-SutMutantsManifest` + `-SutMutantsManifestSha256` e `-OracleBundleManifest` + `-OracleBundleManifestSha256`, além de `-SutCommand` ou `-SutModule`. Exemplo de forma, não um comando executável hoje:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_math_vectors.ps1 -SutModule '<module:callable>' -SutMutantsManifest 'C:\external\sut-mutants.json' -SutMutantsManifestSha256 '<sha256>' -OracleBundleManifest 'C:\external\oracle-bundle.json' -OracleBundleManifestSha256 '<sha256>' -OutputFormat json
```

O formato aceita apenas launcher `python_script` controlado pelo runner, com caminho absoluto e SHA-256 do Python. Artefatos base/operador/mutante precisam ser arquivos regulares, sem hardlink ou ancestral junction/reparse. O base declarado é executado antes dos mutantes; qualquer base inválido, survivor, crash, timeout, não viabilidade, mudança de identidade/hash ou alteração do snapshot reprova o gate estrito. Um SHA-256 fornecido pelo caller fixa bytes, mas não autentica autoria, independência, aprovação ou release.

## 🚦 Modos de gate

Somente `Structure` está implementado como check executável que pode passar. Os demais nomes são reservas fail-closed:

| Modo | O que faz hoje | Estado obrigatório |
| --- | --- | --- |
| `Structure` | valida documentos, CSVs, relações, markers e evidência local declarada | pode passar; continua não autoritativo |
| `F0` | retorna diretamente os três blockers humanos e o blocker externo, antes de trust de host/helpers/leituras | sempre falha em RC1 |
| `Release00` | acrescenta blocker de autoridade matemática externa na mesma saída antecipada | sempre falha em RC1; não executa math/contratos |
| `Release01` | acrescenta blocker de inspeção/autoridade de artefatos na mesma saída antecipada | sempre falha em RC1; não executa build/inspector |

Execute:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_docs.ps1 -Mode Structure
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_docs.ps1 -Mode F0
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_docs.ps1 -Mode Release00
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_docs.ps1 -Mode Release01
```

Os três últimos comandos precisam retornar não zero. `F0` reconhece que `LICENSE`, `MAINTAINERS.md` e `GOVERNANCE.md` são decisões locais do owner, mas explica que elas não autenticam reviewer independente nem autoridade externa; `Release00` e `Release01` acumulam blockers próprios. Alterar documentos candidatos não remove o blocker externo.

Os parâmetros antigos `-BootstrapResultPath`, `-BootstrapResultSha256`, `-BootstrapResultPublicKeyPath`, `-BootstrapResultPublicKeyFingerprint`, `-PythonRuntimePath` e `-EvaluationTime` foram removidos. PowerShell os recusa no binding antes do corpo do script; não há fallback v4, leitura de resultado/chave, Ed25519, `Add-Type`, runtime externo ou parser de attestation no gate candidato.

O contrato executável exige um processo novo `powershell` ou `pwsh`. A gramática é lexical e fechada: switches, valores, ordem, modo e path relativo são comparados por `Ordinal`, sem abreviação nem variação de caixa. Antes do path do gate, somente estas quatro sequências são aceitas:

- `-NoProfile -File`;
- `-NoProfile -NonInteractive -File`;
- `-NoProfile -ExecutionPolicy Bypass -File`;
- `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File`.

Depois vêm o path canônico do próprio gate, `-Mode` e exatamente um de `Structure`, `F0`, `Release00` ou `Release01`. Os únicos paths relativos aceitos são `./scripts/validate_docs.ps1` e `.\scripts\validate_docs.ps1`, nessas caixas e grafias exatas. Um path absoluto sem segmento `..` precisa identificar o path efetivo do script; no Windows essa identidade de filesystem é intencionalmente `OrdinalIgnoreCase`, portanto uma variante apenas de casing do path absoluto continua a mesma entrada. Essa exceção não se estende ao path relativo, aos switches nem ao modo. Qualquer outra forma (`-Command`, common parameter, argumento extra, switch abreviado, path alternativo, módulo, pipeline, `&` ou dot-source) escreve uma única recusa e chama `[Environment]::Exit(2)`. Essa chamada encerra o host PowerShell atual: **não use `&` nem dot-source**, pois o wrapper morre antes da instrução seguinte. Invoque sempre um processo novo.

Os modos progressivos canônicos escrevem 4/5/6 blockers e chamam `[Environment]::Exit(1)` antes da boundary de trust do host, de autoload, import, helper ou leitura do checkout. Somente `Structure`, depois de passar a guarda lexical, exige Windows e estabelece uma boundary suportada e estreita: Windows PowerShell Desktop precisa corresponder ao executável e `PSHOME` esperados sob `System32\WindowsPowerShell`; PowerShell Core precisa ser `pwsh.exe` sob a subárvore aceita de `Program Files\PowerShell` ou `Program Files\WindowsApps`, com coerência entre executável, argumento de host e `PSHOME`. Executável, home e manifests builtin Management/Utility precisam existir em cadeias sem reparse. Cópia do host em `%TEMP%`, host desconhecido e `Structure` em Linux/macOS retornam RC2 antes do import e sem decisão de consistência; isso não é um falso passe multiplataforma. Administrador ou PowerShell engine comprometidos estão explicitamente fora da claim.

Depois dessa verificação, `Structure` exige que a raiz, todos os ancestrais e cada entrada da árvore do repositório sejam locais e sem symlink/junction/reparse; uma entrada reparse não é atravessada. Só então desabilita module autoload, esvazia `PSModulePath` no processo, importa `Microsoft.PowerShell.Management` e `Microsoft.PowerShell.Utility` pelos manifests absolutos sob `$PSHOME` e usa comandos nominais qualificados. Nos scans de legado, normaliza o texto linha a linha com Unicode FormKC, remove caracteres de formato da categoria `Cf` e então procura IDs/headings; o arquivo histórico precisa conservar exatamente sete H2, na ordem `Ordinal` R2–R3, R4, R6, R7, R8, R10 e R11. Esse hardening delimita o diagnóstico local; não cria authority.

O antigo bootstrap candidato foi reduzido a um stub:

```powershell
python -I -S -B .\scripts\validate_release_trust.py
```

A saída é sempre `external_authority_not_implemented` e o código é 2. O stub ignora argumentos e não lê material externo nem cria resultado. Ele não é template para copiar, signer, verifier ou authority.

O inspector de artefatos também é apenas diagnóstico candidato. Ele aceita somente `--root`; o antigo `--external-attestation-sha256` foi removido e é rejeitado pelo argparse. Cada wheel/sdist original é lido uma vez para um `ArtifactBlob`, tuple imutável em nível C com `(nome, bytes, SHA-256)`. A integridade bytes–digest é recalculada antes/depois de inspeção, paridade e emissão JSON; o SHA-256 reportado, os parsers e a paridade estreita recebem a mesma instância. Uma releitura separada do `dist` original ao final serve apenas para detectar drift observável e não troca os bytes que sustentaram o diagnóstico.

O formato `candidate-release-static-diagnostic.v3` usa `python_source_payload_parity=observed_on_revalidated_non_atomic_local_snapshots`, mantém a paridade ampla `source_artifact_parity=not_evaluated`, `build_equivalence=not_evaluated`, authority ausente e release não autorizado. Ele compara somente o inventário e os bytes de payload Python entre o snapshot de `src`, wheel e `sdist/src`; relê `pyproject.toml`, `src`, `tests` e o manifesto de `dist` ao final, mas declara explicitamente que os snapshots locais não são atômicos contra swap/restore same-UID. Metadata, arquivos de build e demais efeitos da construção não entram nessa claim estreita. `package_tests` deriva do snapshot fechado de `tests`, rechecado antes do resultado.

A policy `closed_minimal_python_payload` aceita no `.dist-info` canônico somente `METADATA`, `WHEEL` e `RECORD`, valida o root `.data` canônico e rejeita membros de sdist fora de `PKG-INFO`, `pyproject.toml` e `src/`; `entry_points.txt`, `setup.py`, diretórios explícitos vazios/não modelados e qualquer membro extra falham. A mesma política de path Win32 estrita vale para ZIP, TAR e `RECORD`: NFC obrigatório, sem caracteres de controle ou `<>:\"|?*`, segmento terminado em ponto/espaço, alternate data stream ou basename DOS reservado; o trie `casefold` + NFC rejeita colisão normalizada, arquivo ancestral, colisão arquivo/diretório e duplicata explícita.

O wheel aceito é deliberadamente um ZIP32 gap-free e com bijeção exata entre local headers e central directory, usando apenas `stored`/`deflated` e, opcionalmente, a flag UTF-8. O decoder raw consome a fatia local delimitada por `compressed_size`: em `stored`, tamanho comprimido e tamanho declarado precisam ser iguais; em `deflated`, o stream precisa alcançar EOF sem `unused_data`, `unconsumed_tail`, cauda ou stream concatenado. Nos dois casos, os bytes decodificados precisam ter o tamanho declarado e CRC32 correto. Antes de `RECORD`, a ordem, metadata e bytes decodificados dessa visão raw precisam coincidir com a visão de `zipfile`. Prefixo autoextraível, gap/orphan, record trailing, comment, data descriptor, extra field, ZIP64, multi-disk, encryption, outra flag/método ou desacordo entre as visões raw/`zipfile` são features não suportadas e falham. O sdist aceito tem exatamente um membro gzip, tolera apenas padding final zero, e seu stream é POSIX USTAR estrito com dois blocos EOF: gzip concatenado/trailer não zero, membro após EOF, PAX, GNU long-name/long-link/sparse, número base-256, link, device, tipo especial, bytes reservados/padding ou desacordo raw/`tarfile` falham. Esse subconjunto estrito reduz ambiguidade de parser; não satisfaz `Release01` nem afirma aceitar todo wheel/sdist válido no ecossistema Python.

Math self-check permanece um diagnóstico separado:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate_math_vectors.ps1 -SelfCheck -OutputFormat json
```

Ele avalia corpus/rotas locais `test_only`, mantém SUT `not_evaluated` e não satisfaz `Release00`. Para um SUT técnico não confiável, use sandbox externo: o runner local declara filesystem/network `not_enforced` e POSIX process-tree best-effort.

Depois de alterar gates ou tooling, rode:

```powershell
python .\scripts\test_governance_gates.py
python -m unittest tests.contracts.test_contract_adversarial -v
python -m unittest tests.conformance.test_math_conformance -v
```

A suíte de governance trabalha em cópias temporárias sem criar PKI. Ela prova RC1 direto de F0/00/01 mesmo com documentos humanos falsos; RC2 lexical para casing, abreviações, paths relativos e argumentos extras, junto da aceitação intencional de casing alternativo apenas no path absoluto Windows; término do host quando `&` ou dot-source tentam contornar a gramática; autoload/`PSModulePath` hostis sem redirecionar os módulos builtin; rejeição de cada argumento legado; ausência de filhos contract/math/artifact/trust; normalização FormKC/`Cf`, roster histórico fechado; e paridade do caminho canônico de Structure no Windows PowerShell 5.1 e PowerShell 7.x. Os probes de contracts exercitam ADS Win32 antes/depois do snapshot e variantes confusáveis do catálogo sem atribuir essa cobertura a plataformas não Windows. Os probes de artifact também exercitam identidade do `ArtifactBlob`, consumo total/CRC/tamanho de `stored` e `deflated`, reconciliação de bytes raw/`zipfile`, swap/restore do path original, trie normalizado em wheel/sdist/`RECORD`, `.dist-info`/`.data`, membros não modelados e rechecks finais de `dist`, `pyproject.toml`, `src` e `tests`.

O protótipo v4 está superado porque não autenticava independentemente a closure de runtime (`._pth`/stdlib/startup), seus guards eram mutáveis, o signer externo final podia fabricar claims aninhadas/quórum, material `test_only` conseguia abrir gates e o binding de commit/inventário permitia replay/untracked. Uma futura autoridade precisa viver fora do checkout com closure e fonte autenticadas fora de banda, inventário fechado, relatórios de domínio assinados de forma aninhada **e** threshold/quórum independente, além de sandbox verificável. Veja a [fronteira de confiança atual](governance/release-trust.md); o corpus R2–R11 permanece somente no [histórico invalidado e não executável](./history/trust-r2-r11-superseded.md).

Não crie arquivo vazio para satisfazer gate. Apache-2.0, o mantenedor e a governança local estão registrados no ADR 0012, mas reviewer independente, supply chain autenticada e autorização de package/release continuam decisões separadas. Há package local editável, mas não há `dist` autorizado, atestação real ou release.

## 🔍 Leitura recomendada

Para decidir se o projeto está pronto para código, leia nesta ordem:

1. [README](../README.md): status e gate atual;
2. [parecer adversarial](reviews/adversarial-review-2026-08-08.md): bloqueadores e pré-mortem;
3. [ADR 0001](decisions/0001-foundation-and-scope.md): escopo e superfície;
4. [ADR 0002](decisions/0002-valuation-claims-and-survival.md): correções matemáticas fundacionais;
5. [contrato matemático](specification/mathematical-engine.md): semântica proposta;
6. [ADR 0011](decisions/0011-secure-build-backend-baseline.md): backend de build e novos goldens candidatos;
7. [checklist de publicação](github-publication-checklist.md), [deployment](governance/deployment-classification.md), [privacidade](../PRIVACY.md), [licenças](../DATA_LICENSES.md) e [disclaimer](../DISCLAIMER.md).

### Preparar uma contribuição no GitHub

Antes de commit ou push, execute os checks proporcionais ao escopo e confirme que nenhum arquivo ignorado, segredo, PII, artefato de build ou evidência temporária entrou no stage. Use `git status --short` e revise o inventário completo do primeiro commit.

O GitHub hospeda código e discussão; ele não é registry nem gate de release. Não crie tag, GitHub Release, package ou deployment a partir de um build local. A branch principal deve receber somente mudanças revisadas, e workflows verdes continuam evidência técnica self-issued, sem alterar `authority=none` ou `release_authorized=false`.

Os workflows públicos cobrem runtime SDK em Python 3.11–3.14, análise estática e cobertura de branches em 3.13, diagnósticos neutros no Ubuntu, backend/diagnósticos e smoke instalado no Windows, governança Windows, corpus matemático, CodeQL Python e dependency review. A CI comum não executa o live AppContainer nem chama o runner manual da matriz: o opt-in permanece ausente. No job Windows, rode primeiro as classes independentes do host; a classe de PowerShell real só é admitida se a aquisição dos hosts protegidos passar. `host_chain_mutable_by_current_token` no preflight do runner hospedado é registrado como boundary não suportada, não como teste executado ou PASS; qualquer outro resultado inesperado falha. Cada action usa SHA integral, `checkout` não persiste credencial e cada job declara timeout. Checks obrigatórios de ruleset devem usar apenas os nomes reais observados no GitHub.

O piso de cobertura é 80% do pacote público com branches habilitados. Os testes de `test_sdk_conformance` executam deadlines e cleanup do supervisor e rodam integralmente no job de runtime, sem instrumentação; coverage não faz parte da boundary temporal desses testes e por isso eles ficam fora da medição. Um passe no piso também não cobre subprocessos filhos, C#, PowerShell, paths opt-in live ou ameaças fora do modelo. Redução do piso exige justificativa explícita; aumento deve ser gradual e acompanhado de testes semanticamente relevantes.

## 📝 Atualizar uma fonte

1. Abrir a fonte primária oficial, paper/DOI ou repositório original.
2. Registrar data de verificação e limitação no ledger adequado:
   - acadêmico: `docs/research/evidence-ledger.csv`;
   - software/comparadores: `docs/research/software-comparator-manifest.csv`;
   - norma/autoridade: `docs/governance/regulatory-authority-ledger.csv`;
   - evento jurídico: `docs/governance/legal-event-ledger.csv`;
   - dado/licença: `docs/governance/data-license-manifest.csv`.
3. Para norma, registrar artigo/pinpoint, edição, efeito, conhecimento, evento e status; uma página explicativa não substitui a autoridade.
4. Para dado, registrar o recurso exato; não generalizar licença de um dataset para toda a instituição.
5. Atualizar a limitação no texto que usa a fonte.
6. Rodar o validator.
7. Exigir reviewer independente se a mudança afetar cálculo, política, privacidade, licença ou deployment.

Não transformar `TBD`, status contestado ou fonte inacessível em suposição permissiva.

## 🔐 Incidente documental ou de dados

Se PII, credencial ou dado não licenciado aparecer no repositório:

1. interromper publicação/compartilhamento;
2. não copiar o conteúdo para issue, chat ou relatório;
3. identificar o arquivo e o owner por caminho, sem reproduzir o segredo/dado;
4. remover somente com autorização e preservar evidência mínima segura;
5. rotacionar credencial se aplicável;
6. avaliar histórico Git, caches, artefatos e mirrors quando existirem;
7. registrar causa, alcance e controle preventivo no changelog/threat model.

Este workspace possui histórico Git na branch `main` e remoto público em `arthur0211/financial-planning-sdk-br`. Não há tag, GitHub Release, Package ou deployment. Visibilidade do source, proteção de branch e publicação de package continuam decisões separadas; caches e cópias externas permanecem fora do histórico.

## ⚠️ Falhas comuns

| Sintoma | Causa provável | Ação |
| --- | --- | --- |
| link local ausente | arquivo movido ou ADR não criado | corrigir destino; não ocultar do validator |
| CSV não importa | vírgula/aspas ou header divergente | abrir a linha e preservar uma linha por registro |
| enum/data/FK inválido | vocabulário livre, precisão incompatível ou referência ausente | usar o enum fechado e registrar `unknown` sem inferir dado |
| termo superseded | contrato antigo reapareceu | reconciliar com ADR 0002 e parecer adversarial |
| fonte externa 403 | bloqueio de automação, não prova de 404 | verificar manualmente e buscar recurso oficial estável |
| registro `draft`, `unknown` ou `unassigned` | revisão/artefato ainda não aprovado | manter fail-closed; não liberar policy/data pack |
| matemática contestada | reviewer divergiu | criar issue/RFC, derivação e vetor reduzido; não estabilizar API |
| probe Windows de process tree falha só com Python Store | App Execution Alias/redirector cria o processo real fora do Job Object | executar a suíte com Python regular; não contar o escape como PASS |

## 🔄 Recuperação

Conteúdo untracked não pode ser recuperado por `git restore`; preserve uma cópia ou checkpoint antes de alteração ampla. Trabalhe em branch e checkpoints incrementais. Não use comandos destrutivos para “limpar” divergências. Se a validação falhar, reverta apenas a edição responsável ou corrija o contrato de forma explícita.

## 🛣️ Próximo endurecimento do código

Antes de qualquer release: executar CI Windows/Linux; promover o bridge de sete vetores para um SUT que implemente o roster completo e use pins externos; substituir a sensibilidade local de 23 mutações por uma campanha independente e versionada; definir um perfil de artefato compatível com o entry point e com o arquivo Apache-2.0 sem diluir os checks; construir de modo reproduzível em executor descartável; e obter crítica matemática/software humana independente. JSON Schemas públicos, diagnóstico local e smoke instalado já existem, mas não satisfazem esses gates. O inspector candidato continua diagnóstico e não substitui supply-chain authority.

---

_Última atualização: 30 de agosto de 2026_
