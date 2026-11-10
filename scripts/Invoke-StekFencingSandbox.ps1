# STEK-SEC-FENCING-001 | isolated SANDBOX ONLY | reversible, no production access
# PowerShell 7+ recommended. All repository data in this workflow are synthetic.
[CmdletBinding()]
param(
  [ValidateSet('ProvisionRepo','EnforceAndTest','RollbackOnly','Status')]
  [string]$Stage = 'Status',
  [int]$AppId = 0,
  [long]$InstallationId = 0,
  [string]$PemPath = '',
  [switch]$ConfirmSandboxRuleMutation
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $false }
$Owner = '9qrv90-a11y'
$RepoName = 'stek-odessa-crm-sandbox'
$Repo = "$Owner/$RepoName"
$Root = 'C:\Git\stek-odessa-crm-sandbox'
$Evidence = 'C:\Git\STEK_SEC_FENCING_001_EVIDENCE'
$Report = Join-Path $Evidence 'fencing-report.json'
$PayloadFile = Join-Path $Evidence 'ruleset-payload.json'
$RuleName = 'STEK-Server-Fencing-Branches-Test'
$AppSlug = 'stek-execution-router-sandbox'
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$ApiBase = "https://api.github.com/repos/$Repo"
function Invoke-Cli([string]$Executable, [string[]]$Arguments) {
  $lines = & $Executable @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) { throw "$Executable failed (exit $LASTEXITCODE): $($lines | Out-String)" }
  return ($lines | Out-String)
}
function Write-Utf8([string]$Path,[string]$Content) {
  [IO.File]::WriteAllText($Path,$Content,$Utf8)
}
function Assert-Sandbox {
  $obj = Invoke-Cli 'gh' @('api',"repos/$Repo")
  $meta = $obj | ConvertFrom-Json
  if ($meta.full_name -cne $Repo -or $meta.visibility -ne 'public' -or $meta.owner.login -cne $Owner) {
    throw 'HOLD: target must be the exact public synthetic sandbox repository.'
  }
  return $meta
}
function Get-Rule([long]$Id) {
  return (Invoke-Cli 'gh' @('api',"repos/$Repo/rulesets/$Id") | ConvertFrom-Json)
}
function Save-Report($Data) {
  New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
  Write-Utf8 $Report ($Data | ConvertTo-Json -Depth 14)
}
function ConvertTo-B64Url([byte[]]$Bytes) {
  return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function New-AppJwt([int]$Id,[string]$KeyPath) {
  if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7+ is required for RSA.ImportFromPem.' }
  $pem = [IO.File]::ReadAllText($KeyPath)
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $h = ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"RS256","typ":"JWT"}'))
  $p = ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes((@{iat=$now-60;exp=$now+480;iss=$Id}|ConvertTo-Json -Compress)))
  $message = "$h.$p"
  $rsa = [Security.Cryptography.RSA]::Create()
  try {
    $rsa.ImportFromPem($pem.ToCharArray())
    $signature = $rsa.SignData([Text.Encoding]::ASCII.GetBytes($message),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return "$message.$(ConvertTo-B64Url $signature)"
  } finally { $rsa.Dispose(); $pem = $null }
}
function Invoke-AppApi([string]$Token,[string]$Method,[string]$Endpoint,$Object=$null) {
  $url = if ($Endpoint.StartsWith('https://')) { $Endpoint } else { "https://api.github.com$Endpoint" }
  $headers = @{Authorization="Bearer $Token";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28';'User-Agent'='STEK-Fencing-Sandbox'}
  $req = @{Uri=$url;Method=$Method;Headers=$headers;ErrorAction='Stop'}
  if ($null -ne $Object) {
    $req.ContentType = 'application/json'
    $req.Body = ConvertTo-Json -InputObject $Object -Depth 14 -Compress
  }
  return Invoke-RestMethod @req
}
function Set-SandboxRuleDisabled([long]$RuleId) {
  if ($RuleId -le 0) { throw 'Rollback ID is missing' }
  $current = Get-Rule $RuleId
  if ($current.name -cne $RuleName -or $current.target -ne 'branch') { throw 'HOLD: ruleset name/target mismatch; no rollback performed.' }
  if (-not (Test-Path $PayloadFile)) { throw 'HOLD: original ruleset payload not found. Manual recovery needed; no generic API mutation.' }
  $p = Get-Content $PayloadFile -Raw | ConvertFrom-Json
  if ($p.name -cne $RuleName -or $p.target -ne 'branch') { throw 'HOLD: payload mismatch' }
  $p.enforcement = 'disabled'
  $rollbackJson = Join-Path $Evidence 'ruleset-disable.json'
  Write-Utf8 $rollbackJson ($p | ConvertTo-Json -Depth 14)
  $null = Invoke-Cli 'gh' @('api','--method','PUT',"repos/$Repo/rulesets/$RuleId",'--input',$rollbackJson)
  $readback = Get-Rule $RuleId
  if ($readback.enforcement -ne 'disabled') { throw 'ROLLBACK_INCOMPLETE: readback does not show disabled' }
  return $true
}
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
$meta = Assert-Sandbox
if ($Stage -eq 'Status') {
  $s = [ordered]@{
    repo=$Repo; visibility=$meta.visibility; local_root_exists=(Test-Path $Root);
    app_pem_supplied=([bool]$PemPath -and (Test-Path $PemPath));
    report_exists=(Test-Path $Report);
    rulesets=@((Invoke-Cli 'gh' @('api',"repos/$Repo/rulesets") | ConvertFrom-Json) | ForEach-Object { @{id=$_.id;name=$_.name;enforcement=$_.enforcement} });
    scope='SANDBOX_ONLY'; production_touched=$false
  }
  $s | ConvertTo-Json -Depth 6
  return
}
if ($Stage -eq 'ProvisionRepo') {
  if (Test-Path $Root) { throw "HOLD: local directory exists; will not replace: $Root" }
  if ($meta.size -gt 0) { throw 'HOLD: nonempty remote repository; refusing to overwrite.' }
  New-Item -ItemType Directory -Path $Root -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $Root '.github\workflows') -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $Root 'scripts') -Force | Out-Null
  Write-Utf8 (Join-Path $Root 'README.md') ('# STEK Server-Side Fencing Sandbox' + "`n`n" + 'Synthetic repository for STEK-SEC-FENCING-001. No production access or real business data.' + "`n")
  $lease = [ordered]@{
    schema_version='stek-writer-leases-v1'; generation=1; repository=$Repo
    active_lease=[ordered]@{
      lease_id='STEK-SEC-FENCING-001-SANDBOX-LEASE-V1'; task_id='STEK-SEC-FENCING-001'
      status='ACTIVE'; writer_principal_type='GITHUB_APP_INSTALLATION'
      allowed_actors=@("$AppSlug[bot]")
      allowed_refs=@('refs/heads/codex/test-task-1','refs/heads/setup/test-env-1')
      issued_by=$Owner; issued_at=([DateTimeOffset]::Now.ToString('o'))
      expires_at=([DateTimeOffset]::Now.AddDays(7).ToString('o'))
    }
  }
  Write-Utf8 (Join-Path $Root 'writer-leases.json') ($lease | ConvertTo-Json -Depth 9)
  $wf=@(
    'name: STEK Sandbox Lease Audit (post-push only)'
    'on:'
    '  push:'
    '    branches:'
    "      - 'codex/**'"
    "      - 'setup/**'"
    'permissions:'
    '  contents: read'
    'jobs:'
    '  audit:'
    '    runs-on: ubuntu-latest'
    '    steps:'
    '      - uses: actions/checkout@v4'
    '      - name: Check actor, ref and lease expiry'
    '        env:'
    '          EVENT_ACTOR: ${{ github.actor }}'
    '          EVENT_REF: ${{ github.ref }}'
    '        run: |'
    "          python3 - <<'PYCODE'"
    '          import json,os,sys,datetime'
    "          with open('writer-leases.json',encoding='utf-8') as f: d=json.load(f)"
    "          l=d.get('active_lease') or {}"
    "          actor=os.environ.get('EVENT_ACTOR','')"
    "          ref=os.environ.get('EVENT_REF','')"
    "          expiry=l.get('expires_at','')"
    "          try: expiration=datetime.datetime.fromisoformat(expiry.replace('Z','+00:00'))"
    "          except (ValueError,TypeError): expiration=datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)"
    "          valid=(l.get('status')=='ACTIVE' and actor in l.get('allowed_actors',[]) and ref in l.get('allowed_refs',[]) and expiration>datetime.datetime.now(datetime.timezone.utc))"
    "          print('LEASE_AUDIT='+('PASS' if valid else 'BLOCKED'))"
    '          sys.exit(0 if valid else 1)'
    '          PYCODE'
  ) -join "`n"
  Write-Utf8 (Join-Path $Root '.github\workflows\lease-enforcement.yml') $wf
  Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $Root 'scripts\Invoke-StekFencingSandbox.ps1') -ErrorAction Stop
  $null=Invoke-Cli 'git' @('-C',$Root,'init','-b','main')
  $null=Invoke-Cli 'git' @('-C',$Root,'remote','add','origin',"https://github.com/$Repo.git")
  $null=Invoke-Cli 'git' @('-C',$Root,'add','README.md','writer-leases.json','.github/workflows/lease-enforcement.yml','scripts/Invoke-StekFencingSandbox.ps1')
  $null=Invoke-Cli 'git' @('-C',$Root,'-c','user.name=STEK Sandbox Setup','-c','user.email=stek-sandbox@users.noreply.github.com','commit','-m','chore(sandbox): isolated synthetic fencing baseline')
  $null=Invoke-Cli 'git' @('-C',$Root,'push','-u','origin','main')
  foreach ($branch in @('codex/test-task-1','setup/test-env-1')) {
    $null=Invoke-Cli 'git' @('-C',$Root,'branch',$branch,'main')
    $null=Invoke-Cli 'git' @('-C',$Root,'push','-u','origin',$branch)
  }
  $r=[ordered]@{status='PROVISIONED';repository=$Repo;root=$Root;main_sha=(Invoke-Cli 'git' @('-C',$Root,'rev-parse','main')).Trim();branches=@('main','codex/test-task-1','setup/test-env-1');production_touched=$false}
  Save-Report $r; $r|ConvertTo-Json -Depth 6
  return
}
if ($Stage -eq 'RollbackOnly') {
  if (-not $ConfirmSandboxRuleMutation) { throw 'Explicit -ConfirmSandboxRuleMutation switch required' }
  if (-not (Test-Path $Report)) { throw 'HOLD: missing original audit report (ruleset ID)' }
  $record=Get-Content $Report -Raw | ConvertFrom-Json
  $id=[long]$record.ruleset_id
  $result=Set-SandboxRuleDisabled $id
  $record.rollback_confirmed=$result; $record.rollback_at=[DateTimeOffset]::UtcNow.ToString('o')
  Save-Report $record
  Write-Output "ROLLBACK VERIFIED: rule $id disabled on SANDBOX"
  return
}
if ($Stage -eq 'EnforceAndTest') {
  if (-not $ConfirmSandboxRuleMutation) { throw 'Explicit -ConfirmSandboxRuleMutation switch required' }
  if ($AppId -lt 1 -or -not $PemPath -or -not (Test-Path -LiteralPath $PemPath)) { throw 'AppId and existing PemPath required' }
  if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7+ required' }
  if (-not (Test-Path (Join-Path $Root '.git'))) { throw 'Run ProvisionRepo first' }
  if ($PemPath.StartsWith($Root,[StringComparison]::OrdinalIgnoreCase)) { throw 'PEM must remain outside Git worktree' }
  if (Test-Path $Report) {
    $prior=Get-Content $Report -Raw | ConvertFrom-Json
    if ($prior.PSObject.Properties.Name -contains 'ruleset_id' -and $prior.ruleset_id) { throw 'Existing ruleset ID in report; reconcile/rollback before retry' }
  }
  $jwt=New-AppJwt $AppId $PemPath
  $app=Invoke-AppApi $jwt 'GET' '/app'
  if ([int]$app.id -ne $AppId -or $app.slug -cne $AppSlug) { throw 'App ID or slug mismatch' }
  $insts=@(Invoke-AppApi $jwt 'GET' '/app/installations')
  if ($InstallationId -gt 0) { $insts=@($insts | Where-Object {$_.id -eq $InstallationId}) }
  else { $insts=@($insts | Where-Object {$_.account.login -eq $Owner}) }
  if ($insts.Count -ne 1) { throw 'HOLD: select exactly one owner installation of the Sandbox App' }
  $InstallationId=[long]$insts[0].id
  $tokenObj=Invoke-AppApi $jwt 'POST' "/app/installations/$InstallationId/access_tokens" @{repositories=@($RepoName)}
  $token=$tokenObj.token
  $repolist=Invoke-AppApi $token 'GET' '/installation/repositories?per_page=100'
  if ($repolist.total_count -ne 1 -or $repolist.repositories[0].full_name -cne $Repo) { throw 'HOLD: installation token is not sandbox-only' }
  $existingRules=@(Invoke-Cli 'gh' @('api',"repos/$Repo/rulesets") | ConvertFrom-Json)
  if (@($existingRules|Where-Object{$_.name -eq $RuleName}).Count -gt 0) { throw 'Existing named ruleset; no overwrite or duplicate' }
  $rs=[ordered]@{
    name=$RuleName;target='branch';enforcement='active'
    bypass_actors=@([ordered]@{actor_id=$AppId;actor_type='Integration';bypass_mode='always'})
    conditions=[ordered]@{ref_name=[ordered]@{include=@('refs/heads/codex/**','refs/heads/setup/**');exclude=@()}}
    rules=@(@{type='deletion'},@{type='non_fast_forward'},@{type='creation'},@{type='update'},@{type='required_linear_history'})
  }
  Write-Utf8 $PayloadFile ($rs|ConvertTo-Json -Depth 14)
  $audit=[ordered]@{schema='STEK_SANDBOX_FENCING_AUDIT_V2';repository=$Repo;app_id=$AppId;installation_id=$InstallationId;started_at=[DateTimeOffset]::UtcNow.ToString('o');status='STARTED';ruleset_id=$null;results=[ordered]@{};production_touched=$false;scope='SANDBOX_ONLY'}
  Save-Report $audit
  $ruleId=0
  try {
    $created=Invoke-Cli 'gh' @('api','--method','POST',"repos/$Repo/rulesets",'--input',$PayloadFile) | ConvertFrom-Json
    $ruleId=[long]$created.id
    $audit.ruleset_id=$ruleId
    Save-Report $audit
    $live=Get-Rule $ruleId
    if ($live.enforcement -ne 'active' -or $live.name -cne $RuleName) { throw 'RULESET_LIVE_READBACK_FAILED' }
    # Negative test with existing owner Git credential on a harmless synthetic branch.
    $negBranch='stek-negative-'+([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $null=Invoke-Cli 'git' @('-C',$Root,'branch',$negBranch,'main')
    $null=Invoke-Cli 'git' @('-C',$Root,'switch',$negBranch)
    Write-Utf8 (Join-Path $Root 'negative-owner-attempt.txt') ([DateTimeOffset]::UtcNow.ToString('o'))
    $null=Invoke-Cli 'git' @('-C',$Root,'add','negative-owner-attempt.txt')
    $null=Invoke-Cli 'git' @('-C',$Root,'-c','user.name=STEK Sandbox Negative Test','-c','user.email=stek-sandbox@users.noreply.github.com','commit','-m','test(sandbox): intentionally rejected owner branch update')
    $output1=(& git -C $Root push origin 'HEAD:refs/heads/codex/test-task-1' 2>&1 | Out-String); $exit1=$LASTEXITCODE
    $output2=(& git -C $Root push --force origin 'HEAD:refs/heads/codex/test-task-1' 2>&1 | Out-String); $exit2=$LASTEXITCODE
    $ruleRejection=($output1 -match '(?i)GH013|repository rule|ruleset|rule violations')
    $deny=($exit1 -ne 0 -and $exit2 -ne 0 -and $ruleRejection)
    $audit.results.negative_owner=[ordered]@{pass=$deny;normal_exit=$exit1;force_exit=$exit2;server_rule_error=$ruleRejection}
    Save-Report $audit
    if (-not $deny) { throw 'Negative owner test inconclusive or failed: denial must be server-side GH013/ruleset' }
    # Positive mutation: GitHub App IAT, no token in URL, shell, arguments or files.
    $ref="/repos/$Repo/git/ref/heads/codex/test-task-1"
    $start=(Invoke-AppApi $token 'GET' $ref).object.sha
    $tree=(Invoke-AppApi $token 'GET' "/repos/$Repo/git/commits/$start").tree.sha
    $blob=(Invoke-AppApi $token 'POST' "/repos/$Repo/git/blobs" @{content="sandbox-app-proof $([DateTimeOffset]::UtcNow.ToString('o'))";encoding='utf-8'}).sha
    $newTree=(Invoke-AppApi $token 'POST' "/repos/$Repo/git/trees" @{base_tree=$tree;tree=@(@{path='app-proof.txt';mode='100644';type='blob';sha=$blob})}).sha
    $newCommit=(Invoke-AppApi $token 'POST' "/repos/$Repo/git/commits" @{message='test(sandbox): app update under ruleset';tree=$newTree;parents=@($start)}).sha
    if ((Invoke-AppApi $token 'GET' $ref).object.sha -ne $start) { throw 'REF_DRIFT before non-force App update' }
    $null=Invoke-AppApi $token 'PATCH' "/repos/$Repo/git/refs/heads/codex/test-task-1" @{sha=$newCommit;force=$false}
    $finish=(Invoke-AppApi $token 'GET' $ref).object.sha
    $passApp=$finish -eq $newCommit
    $audit.results.positive_app=[ordered]@{pass=$passApp;previous_sha=$start;new_sha=$newCommit;actual_sha=$finish;force=$false}
    Save-Report $audit
    if (-not $passApp) { throw 'App update readback does not match' }
    # GitHub Actions is a post-push AUDIT; it never supplies server pre-receive authorization.
    $ciStatus='NOT_FOUND'; $ciRunId=$null; $ciResult=$null
    for ($i=0; $i -lt 24; $i++) {
      Start-Sleep -Seconds 5
      $runs=Invoke-Cli 'gh' @('api',"repos/$Repo/actions/runs?head_sha=$newCommit") | ConvertFrom-Json
      $job=@($runs.workflow_runs | Where-Object {$_.name -eq 'STEK Sandbox Lease Audit (post-push only)'}) | Select-Object -First 1
      if ($job) {
        $ciStatus=$job.status; $ciRunId=$job.id; $ciResult=$job.conclusion
        if ($ciStatus -eq 'completed') { break }
      }
    }
    $audit.results.post_push_audit=[ordered]@{pass=($ciStatus -eq 'completed' -and $ciResult -eq 'success');status=$ciStatus;conclusion=$ciResult;run_id=$ciRunId;head=$newCommit}
    if (-not $audit.results.post_push_audit.pass) { throw "GitHub Actions post-push audit not PASS: $ciStatus / $ciResult" }
    $audit.status='SANDBOX_RULESET_NEGATIVE_AND_APP_POSITIVE_PASS'
    $audit.finished_at=[DateTimeOffset]::UtcNow.ToString('o')
    Save-Report $audit
    $audit|ConvertTo-Json -Depth 10
  } catch {
    $errorText=$_.Exception.Message
    $audit.status='FAILED_ROLLBACK_PENDING'
    $audit.error_summary=$errorText
    Save-Report $audit
    if ($ruleId -gt 0) {
      try {
        $null=Set-SandboxRuleDisabled $ruleId
        $audit.status='FAILED_ROLLBACK_VERIFIED'
        $audit.rollback_verified=$true
      } catch {
        $audit.status='FAILED_ROLLBACK_UNVERIFIED'
        $audit.rollback_error=$_.Exception.Message
      }
      Save-Report $audit
    }
    throw "$($audit.status): $errorText"
  } finally {
    $token=$null; $jwt=$null
  }
}
