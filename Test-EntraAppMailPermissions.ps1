#Requires -Version 7.4
<#
.SYNOPSIS
    Ferramenta interativa de diagnóstico de um App Registration do Microsoft Entra ID e das
    permissões de correio (Mail.*) do Microsoft Graph.

.DESCRIPTION
    Pede interativamente o Tenant ID, o Client ID (Application ID) e o Client Secret, autentica-se
    com o fluxo OAuth 2.0 client credentials e apresenta, para cada permissão, quatro estados:
      - Atribuída no App Registration   (requiredResourceAccess; requer Application.Read.All)
      - Admin consent concedido          (appRoleAssignments: Application.Read.All;
                                          oauth2PermissionGrants: Directory.Read.All)
      - Efetivamente utilizável no token (claim "roles" do JWT; é a fonte de verdade)
      - Necessária mas ausente           (comparação com as permissões de correio)

    Menu: ligação e permissões, leitura de e-mails, envio de e-mails, leitura e envio e uma
    matriz de permissões Mail com sondagens não destrutivas. O comportamento é adaptativo:
    um teste só faz pedidos ao Microsoft Graph se a permissão necessária estiver no token.
    Antes de qualquer leitura ou envio é pedida confirmação explícita (predefinição: Não).

    Segurança:
      - As credenciais nunca são guardadas em ficheiros, logs, transcrições, variáveis globais
        ou variáveis de ambiente.
      - O segredo é lido com Read-Host -AsSecureString e só é convertido para texto dentro de
        Get-GraphToken; a referência em texto é descartada logo a seguir.
      - O token fica apenas em memória, no âmbito do script, como SecureString, e nunca é
        apresentado. Tudo é limpo à saída (try/finally).
      - Os registos de erro do PowerShell ($Error) que referenciem pedidos HTTP (e que poderiam
        conter o cabeçalho Authorization ou o corpo do pedido de token) são removidos.

.PARAMETER ShowDebug
    Mostra informação de diagnóstico adicional (método, URL relativo, código HTTP, duração,
    tentativas). Nunca mostra o segredo, o token, nem o corpo do pedido de token.

.EXAMPLE
    pwsh -NoProfile -File ./Test-EntraAppMailPermissions.ps1

    Execução normal (Windows, macOS ou Linux).

.EXAMPLE
    ./Test-EntraAppMailPermissions.ps1 -ShowDebug

    Execução com informação de diagnóstico adicional.

.NOTES
    Versão     : 1.1.0
    Requisitos : PowerShell 7.4+; acesso HTTPS (443) a login.microsoftonline.com e
                 graph.microsoft.com (cloud global da Microsoft).
    Dependências: nenhuma (apenas Invoke-RestMethod; sem módulos Microsoft.Graph/MSAL).
    Códigos de saída:
      0 = sem testes FAIL
      1 = pelo menos um teste FAIL
      2 = autenticação não concluída / cancelada
      3 = erro inesperado
    Não execute com dot-sourcing nem com Start-Transcript ativo.
#>
[CmdletBinding()]
param(
    [switch]$ShowDebug
)

if ($MyInvocation.InvocationName -eq '.') {
    throw 'Não execute este script com dot-sourcing (". ./Test-EntraAppMailPermissions.ps1"): o estado em memória ficaria na sua sessão. Use ./Test-EntraAppMailPermissions.ps1 ou pwsh -File.'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

#region Estado e constantes (apenas âmbito do script, apenas em memória)

$script:GraphBaseUrl              = 'https://graph.microsoft.com/v1.0'
$script:LoginBaseUrl              = 'https://login.microsoftonline.com'
$script:GraphScope                = 'https://graph.microsoft.com/.default'
$script:GraphResourceAppId        = '00000003-0000-0000-c000-000000000000'
$script:TokenRefreshMarginMinutes = 5
$script:ShowDebugEnabled          = $ShowDebug.IsPresent

$script:TenantId        = $null
$script:ClientId        = $null
$script:ClientSecret    = $null   # SecureString
$script:AccessToken     = $null   # SecureString
$script:TokenExpiresOn  = [DateTimeOffset]::MinValue
$script:TokenClaims     = $null
$script:TokenRoles      = @()
$script:RolesKnown      = $false  # $false se o JWT não puder ser descodificado (roles desconhecidas)
$script:SessionBlocked  = $false  # $true se a renovação do token falhou: bloqueia testes até nova autenticação
$script:LastTokenResult = $null   # apenas resultados de falha (nunca contém token)
$script:Inventory       = $null
$script:LastMailbox     = $null
$script:Results         = [System.Collections.Generic.List[object]]::new()

$script:ReadPermissions = @('Mail.ReadBasic', 'Mail.ReadBasic.All', 'Mail.Read', 'Mail.ReadWrite')
$script:SendPermission  = 'Mail.Send'

# Roles de aplicação que permitem ler applications/servicePrincipals/appRoleAssignments (app-only)
$script:ApplicationReadRoles = @('Application.Read.All', 'Application.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
# Roles de aplicação que permitem ler oauth2PermissionGrants (app-only)
$script:GrantReadRoles = @('Directory.Read.All', 'Directory.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All')
$script:MaxRetryAfterSeconds = 120

$script:MailPermissionCatalog = @(
    [pscustomobject]@{
        Name           = 'Mail.ReadBasic'
        Capability     = 'Leitura (metadados)'
        Recommendation = 'Preferível quando só precisa de metadados (assunto, remetente, datas): sem corpo nem anexos (privilégio mínimo).'
    }
    [pscustomobject]@{
        Name           = 'Mail.ReadBasic.All'
        Capability     = 'Leitura (metadados)'
        Recommendation = 'Variante app-only de leitura básica; equivalente a Mail.ReadBasic. Conceda apenas uma das duas.'
    }
    [pscustomobject]@{
        Name           = 'Mail.Read'
        Capability     = 'Leitura (completa)'
        Recommendation = 'Conceda apenas se precisar do corpo/anexos; caso contrário prefira Mail.ReadBasic. Restrinja as caixas com RBAC for Applications.'
    }
    [pscustomobject]@{
        Name           = 'Mail.ReadWrite'
        Capability     = 'Leitura e escrita'
        Recommendation = 'Evite se a aplicação não precisa de criar/alterar/apagar mensagens. Não é necessária para enviar (use Mail.Send).'
    }
    [pscustomobject]@{
        Name           = 'Mail.Send'
        Capability     = 'Envio'
        Recommendation = 'Necessária para /sendMail. Permite enviar como qualquer utilizador: restrinja os remetentes com RBAC for Applications / Application Access Policy.'
    }
    [pscustomobject]@{
        Name           = 'User.Read.All'
        Capability     = 'Resolução da caixa (opcional)'
        Recommendation = 'Opcional; só serve para resolver/validar a caixa. Dispensável se usar o UPN diretamente (User.ReadBasic.All é menos privilegiada).'
    }
)

# IDs bem conhecidos das app roles do Microsoft Graph. Só são usados se não for possível ler
# o service principal do Graph (a fonte primária é sempre o próprio tenant).
$script:WellKnownGraphRoleIds = @{
    '6be147d2-ea4f-4b5a-a3fa-3eab6f3c140a' = 'Mail.ReadBasic'
    '693c5e45-0940-467d-9b8a-1022fb9d42ef' = 'Mail.ReadBasic.All'
    '810c84a8-4a9e-49e6-bf7d-12d183f40d01' = 'Mail.Read'
    'e2a3a72e-5f79-4c64-b1b1-878b674786c9' = 'Mail.ReadWrite'
    'b633e1c5-b582-4048-a93e-9f11b44c7e96' = 'Mail.Send'
    'df021288-bdef-4463-88db-98f22de89214' = 'User.Read.All'
    '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30' = 'Application.Read.All'
}

#endregion

#region Utilitários de saída e texto

function Protect-SensitiveText {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [int]$MaxLength = 800,
        [switch]$SingleLine
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $clean = $Text
    # JWT, pares chave=valor sensíveis e cabeçalhos Bearer
    $clean = [regex]::Replace($clean, 'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*', '[token removido]')
    $clean = [regex]::Replace($clean, '(?i)"?\b(client_secret|access_token|refresh_token|id_token|password|client_assertion)\b"?\s*[=:]\s*"?[^&\s",]+', '$1=[removido]')
    $clean = [regex]::Replace($clean, '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [removido]')
    if ($SingleLine) { $clean = [regex]::Replace($clean, '\s*[\r\n]+\s*', ' ') }
    # Remove caracteres de controlo C0/C1 (incluindo ANSI ESC) e de controlo bidirecional/largura zero
    # Os intervalos U+200B-U+200F, U+202A-U+202E e U+2066-U+2069 são construídos com [char] para não
    # haver caracteres invisíveis no código-fonte.
    $unicodeControls = '{0}-{1}{2}-{3}{4}-{5}' -f [char]0x200B, [char]0x200F, [char]0x202A, [char]0x202E, [char]0x2066, [char]0x2069
    $clean = [regex]::Replace($clean, ('[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F' + $unicodeControls + ']'), '')
    $clean = $clean.Trim()
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength) + '...' }
    return $clean
}

function Format-DisplayText {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Value,
        [int]$MaxLength = 80,
        [string]$Placeholder = '-'
    )
    if ($null -eq $Value) { return $Placeholder }
    $text = Protect-SensitiveText -Text ([string]$Value) -MaxLength $MaxLength -SingleLine
    if ([string]::IsNullOrWhiteSpace($text)) { return $Placeholder }
    return $text
}

function Write-DebugInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    if ($script:ShowDebugEnabled) {
        Write-Host ('  [DEBUG] {0}' -f (Protect-SensitiveText -Text $Message -SingleLine)) -ForegroundColor DarkGray
    }
}

function Write-Message {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ConsoleColor]$Color = 'Gray'
    )
    Write-Host ('  {0}' -f $Message) -ForegroundColor $Color
}

function Write-Section {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Title)
    Write-Host ''
    Write-Host ('=== {0} ===' -f $Title) -ForegroundColor Cyan
}

function Write-Banner {
    Write-Host ''
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host '  Diagnóstico de App Registration (Entra ID) e permissões Mail Graph' -ForegroundColor Cyan
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Message 'As credenciais são mantidas apenas em memória durante esta execução e nunca são gravadas.'
    Write-Message 'Não execute esta ferramenta com Start-Transcript ativo.' -Color DarkYellow
    Write-Host ''
}

function Get-StatusColor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Status)
    switch ($Status) {
        'PASS'    { return [ConsoleColor]::Green }
        'FAIL'    { return [ConsoleColor]::Red }
        'WARNING' { return [ConsoleColor]::Yellow }
        'SKIPPED' { return [ConsoleColor]::Cyan }
        default   { return [ConsoleColor]::Gray }
    }
}

function Format-RoleList {
    [CmdletBinding()]
    param([string[]]$Roles)
    $list = @($Roles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($list.Count -eq 0) { return '(nenhuma)' }
    return ($list -join ', ')
}

function Format-UnixTime {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '-' }
    try {
        return [DateTimeOffset]::FromUnixTimeSeconds([long]$Value).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz')
    }
    catch { return '-' }
}

function Format-GraphDate {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '-' }
    if ($Value -is [datetime])       { return $Value.ToLocalTime().ToString('yyyy-MM-dd HH:mm') }
    if ($Value -is [DateTimeOffset]) { return $Value.ToLocalTime().ToString('yyyy-MM-dd HH:mm') }
    $parsed = [DateTimeOffset]::MinValue
    $ok = [DateTimeOffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)
    if ($ok) { return $parsed.ToLocalTime().ToString('yyyy-MM-dd HH:mm') }
    return (Format-DisplayText -Value $Value -MaxLength 40)
}

#endregion

#region Utilitários de dados e validação

function Get-SafeProperty {
    # Acesso seguro a propriedades aninhadas (compatível com Set-StrictMode -Version Latest).
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Path
    )
    $current = $InputObject
    foreach ($segment in $Path) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if ($current.Contains($segment)) { $current = $current[$segment] } else { return $null }
        }
        else {
            $property = $current.PSObject.Properties[$segment]
            if ($null -eq $property) { return $null }
            $current = $property.Value
        }
    }
    return $current
}

function Test-GuidFormat {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    return (-not [string]::IsNullOrWhiteSpace($Value) -and
        $Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Test-TenantIdFormat {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if (Test-GuidFormat -Value $Value) { return $true }
    return ($Value -match '^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
}

function Test-EmailFormat {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 320) { return $false }
    if ($Value -match '(^\.|\.\.|\.@)') { return $false }
    return ($Value -match '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
}

function ConvertTo-UrlSegment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)
    return [uri]::EscapeDataString($Value)
}

function Get-UserResourcePath {
    # /users/{upn}; se o UPN começar por '$', o Graph interpreta-o como segmento de sistema
    # ($count, $ref...), por isso usa-se a sintaxe de chave /users('{upn}') com plicas duplicadas.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Mailbox)
    if ($Mailbox.StartsWith('$')) {
        return ("/users('{0}')" -f (ConvertTo-UrlSegment -Value $Mailbox.Replace("'", "''")))
    }
    return ('/users/{0}' -f (ConvertTo-UrlSegment -Value $Mailbox))
}

function ConvertFrom-Jwt {
    # Descodifica apenas o payload (base64url). Não valida a assinatura: serve só para diagnóstico.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { throw 'O token recebido não tem o formato JWT esperado.' }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        0 { }
        2 { $payload += '==' }
        3 { $payload += '=' }
        default { throw 'O payload do token não é base64url válido.' }
    }
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    return ($json | ConvertFrom-Json)
}

#endregion

#region Entrada interativa

function Read-RequiredInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [scriptblock]$Validator,
        [string]$ValidationMessage = 'Valor inválido.',
        [string]$DefaultValue,
        [ValidateRange(1, 10)][int]$MaxAttempts = 3
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $label = if ($DefaultValue) { '{0} [{1}]' -f $Prompt, $DefaultValue } else { $Prompt }
        $raw = Read-Host -Prompt $label
        if ($null -eq $raw) {
            # EOF (stdin redirecionado/fechado): aborta em vez de repetir indefinidamente
            throw [System.OperationCanceledException]::new('Fim da entrada (EOF): operação abortada.')
        }
        $value = ([string]$raw).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
            if ($DefaultValue) { $value = $DefaultValue }
            else {
                Write-Message 'Este valor é obrigatório.' -Color Yellow
                continue
            }
        }
        if ($null -eq $Validator -or (& $Validator $value)) { return $value }
        Write-Message $ValidationMessage -Color Yellow
    }
    throw [System.OperationCanceledException]::new(('Número máximo de tentativas atingido ({0}).' -f $Prompt))
}

function Read-ClientSecret {
    [CmdletBinding()]
    param()
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $secure = Read-Host -Prompt 'Client Secret (o VALOR do segredo; não será apresentado)' -AsSecureString
        if ($null -eq $secure) {
            throw [System.OperationCanceledException]::new('Fim da entrada (EOF): operação abortada.')
        }
        if ($secure.Length -gt 0) {
            $secure.MakeReadOnly()
            return $secure
        }
        $secure.Dispose()
        Write-Message 'O Client Secret é obrigatório.' -Color Yellow
    }
    throw [System.OperationCanceledException]::new('Número máximo de tentativas atingido (Client Secret).')
}

function Read-Mailbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$DefaultValue
    )
    return Read-RequiredInput -Prompt $Prompt -DefaultValue $DefaultValue `
        -Validator { param($v) Test-EmailFormat -Value $v } `
        -ValidationMessage 'Formato de e-mail/UPN inválido (ex.: utilizador@contoso.com).'
}

function Confirm-Action {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    $raw = Read-Host -Prompt ('{0} (S/N) [N]' -f $Message)
    if ($null -eq $raw) { return $false }   # EOF = Não
    return (([string]$raw).Trim() -match '^(?i)(s|sim)$')
}

#endregion

#region Resultados

function New-TestResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'SKIPPED', 'WARNING')][string]$Status,
        [string]$RequiredPermission = '-',
        [string]$DetectedPermission = '-',
        [string]$Endpoint = '-',
        [string]$ErrorMessage = '-',
        [string]$Recommendation = '-',
        [string]$Detail = '',
        [ValidateSet('None', 'MissingPermission', 'UserCancelled', 'NotTestedByDesign', 'NoValidToken')][string]$SkipReason = 'None'
    )
    [pscustomobject]@{
        PSTypeName         = 'EntraAppMailDiag.TestResult'
        TestName           = $Name
        Status             = $Status
        RequiredPermission = $RequiredPermission
        DetectedPermission = $DetectedPermission
        Endpoint           = $Endpoint
        ErrorMessage       = $ErrorMessage
        Recommendation     = $Recommendation
        Detail             = $Detail
        SkipReason         = $SkipReason
        Superseded         = $false   # $true = falha de autenticação ultrapassada por uma autenticação posterior bem-sucedida
        Timestamp          = [DateTimeOffset]::Now
    }
}

function Set-AuthFailureSuperseded {
    # Uma autenticação bem-sucedida torna obsoletas as falhas de autenticação anteriores:
    # deixam de contar como FAIL no resumo e no código de saída.
    [CmdletBinding()]
    param()
    foreach ($result in $script:Results) {
        if ($result.Status -eq 'FAIL' -and $result.TestName -eq 'Autenticação (client credentials)') {
            $result.Superseded = $true
        }
    }
}

function Test-SessionUsable {
    # Devolve $true se há um token válido com roles conhecidas. Caso contrário regista um
    # SKIPPED (sem pedidos ao Graph) e devolve $false.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TestName,
        [string]$RequiredPermission = '-'
    )
    if ($script:SessionBlocked -or $null -eq $script:AccessToken) {
        Write-Message 'Teste ignorado: não há um token válido (a última renovação falhou). Use a opção 1 para autenticar novamente.' -Color Cyan
        Add-TestResult (New-TestResult -Name $TestName -Status SKIPPED -SkipReason NoValidToken `
            -RequiredPermission $RequiredPermission -DetectedPermission '(sem token)' -Endpoint 'Nenhum (pedido não efetuado)' `
            -ErrorMessage 'Sem token válido: a renovação do token falhou e o token anterior foi descartado.' `
            -Recommendation 'Use a opção 1 para obter um novo token; corrija a causa indicada (ex.: segredo expirado).')
        return $false
    }
    if (-not $script:RolesKnown) {
        Write-Message 'Teste ignorado: não foi possível descodificar o token, pelo que as roles são desconhecidas.' -Color Cyan
        Add-TestResult (New-TestResult -Name $TestName -Status SKIPPED -SkipReason NoValidToken `
            -RequiredPermission $RequiredPermission -DetectedPermission 'roles não determináveis' -Endpoint 'Nenhum (pedido não efetuado)' `
            -ErrorMessage 'O token foi obtido mas o payload JWT não pôde ser descodificado; o comportamento adaptativo exige as roles.' `
            -Recommendation 'Use a opção 1 para obter um novo token. Se persistir, verifique se um proxy altera a resposta de autenticação.')
        return $false
    }
    return $true
}

function Write-TestResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Result)
    $color = Get-StatusColor -Status $Result.Status
    Write-Host '  ------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host ('  {0,-21}: {1}' -f 'Nome do teste', $Result.TestName) -ForegroundColor White
    Write-Host ('  {0,-21}: ' -f 'Estado') -NoNewline
    Write-Host $Result.Status -ForegroundColor $color
    $fields = [ordered]@{
        'Permissão necessária' = $Result.RequiredPermission
        'Permissão detetada'   = $Result.DetectedPermission
        'Endpoint utilizado'   = $Result.Endpoint
        'Mensagem de erro'     = $Result.ErrorMessage
        'Recomendação'         = $Result.Recommendation
    }
    if (-not [string]::IsNullOrWhiteSpace($Result.Detail)) { $fields['Detalhe'] = $Result.Detail }
    foreach ($key in $fields.Keys) {
        $value = if ([string]::IsNullOrWhiteSpace([string]$fields[$key])) { '-' } else { [string]$fields[$key] }
        Write-Host ('  {0,-21}: {1}' -f $key, $value)
    }
}

function Add-TestResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Result)
    $script:Results.Add($Result)
    Write-TestResult -Result $Result
}

#endregion

#region Segurança da sessão

function Clear-SensitiveErrorRecord {
    # Os ErrorRecord de pedidos HTTP mantêm referências ao HttpRequestMessage (cabeçalho
    # Authorization / corpo do pedido de token). Remove-os de $Error para não ficarem na sessão.
    [CmdletBinding()]
    param()
    $errors = $global:Error
    for ($i = $errors.Count - 1; $i -ge 0; $i--) {
        $record = $errors[$i]
        $remove = $false
        if ($record -is [System.Management.Automation.ErrorRecord]) {
            if ($record.TargetObject -is [System.Net.Http.HttpRequestMessage]) { $remove = $true }
            elseif ($record.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') { $remove = $true }
            elseif ($record.Exception -is [System.Net.Http.HttpRequestException]) { $remove = $true }
        }
        elseif ($record -is [System.Net.Http.HttpRequestException]) { $remove = $true }
        if ($remove) { $errors.RemoveAt($i) }
    }
}

function Clear-SessionSecret {
    [CmdletBinding()]
    param()
    if ($null -ne $script:ClientSecret) { $script:ClientSecret.Dispose() }
    if ($null -ne $script:AccessToken)  { $script:AccessToken.Dispose() }
    $script:ClientSecret    = $null
    $script:AccessToken     = $null
    $script:TokenClaims     = $null
    $script:TokenRoles      = @()
    $script:RolesKnown      = $false
    $script:TokenExpiresOn  = [DateTimeOffset]::MinValue
    $script:LastTokenResult = $null
    $script:TenantId        = $null
    $script:ClientId        = $null
    Clear-SensitiveErrorRecord
}

#endregion

#region Erros de rede e de autenticação

function Get-NetworkErrorInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Exception]$Exception)

    $category = 'Rede'
    $recommendation = 'Verifique a ligação à Internet, o proxy e a firewall (HTTPS/443 para login.microsoftonline.com e graph.microsoft.com).'
    $detailSource = $Exception
    $current = $Exception
    $found = $false

    while ($null -ne $current -and -not $found) {
        if ($current -is [System.Net.Sockets.SocketException]) {
            $socketCode = $current.SocketErrorCode.ToString()
            if ($socketCode -in @('HostNotFound', 'NoData', 'TryAgain')) {
                $category = 'DNS'
                $recommendation = 'Não foi possível resolver o nome do servidor. Verifique o DNS, a VPN e se o proxy permite resolver login.microsoftonline.com e graph.microsoft.com.'
            }
            elseif ($socketCode -eq 'TimedOut') {
                $category = 'Timeout'
                $recommendation = 'A ligação expirou. Verifique a firewall/proxy e tente novamente.'
            }
            elseif ($socketCode -eq 'ConnectionRefused') {
                $category = 'Ligação recusada'
                $recommendation = 'A ligação foi recusada. Verifique a firewall/proxy local.'
            }
            else {
                $category = ('Socket ({0})' -f $socketCode)
            }
            $detailSource = $current
            $found = $true
        }
        elseif ($current -is [System.Security.Authentication.AuthenticationException]) {
            $category = 'TLS'
            $recommendation = 'Falha no handshake TLS/certificado. Verifique se um proxy de inspeção SSL interceta o tráfego (certificado raiz não confiável), a data/hora do sistema e o suporte de TLS 1.2+.'
            $detailSource = $current
            $found = $true
        }
        elseif ($current -is [System.TimeoutException] -or $current -is [System.OperationCanceledException]) {
            $category = 'Timeout'
            $recommendation = 'O pedido excedeu o tempo limite. Verifique a rede/proxy e tente novamente mais tarde.'
            $detailSource = $current
            $found = $true
        }
        elseif ($current.Message -match '(?i)proxy|\b407\b') {
            $category = 'Proxy'
            $recommendation = 'Erro de proxy. O PowerShell 7 usa o proxy do sistema (Windows) ou HTTPS_PROXY/HTTP_PROXY (macOS/Linux). Se o proxy exigir autenticação, configure-o antes de executar.'
            $detailSource = $current
            $found = $true
        }
        elseif ($current.Message -match '(?i)No such host|Name or service not known|nodename nor servname') {
            $category = 'DNS'
            $recommendation = 'Não foi possível resolver o nome do servidor. Verifique o DNS e a ligação à rede.'
            $detailSource = $current
            $found = $true
        }
        $current = $current.InnerException
    }

    [pscustomobject]@{
        Category       = $category
        Detail         = Protect-SensitiveText -Text $detailSource.Message -SingleLine -MaxLength 300
        Recommendation = $recommendation
    }
}

function Get-AadErrorGuidance {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$ErrorCode)

    $tenantRecommendation = 'Confirme o Tenant ID (GUID em Entra ID > Visão geral) ou o domínio (ex.: contoso.onmicrosoft.com). Esta ferramenta usa a cloud global; tenants US Gov/China não são suportados.'
    $map = @{
        'AADSTS90002'   = @('Tenant inválido ou não encontrado.', $tenantRecommendation)
        'AADSTS900023'  = @('Identificador de tenant com formato inválido.', $tenantRecommendation)
        'AADSTS90013'   = @('Dados de entrada inválidos (frequentemente o tenant ou parâmetros mal formados).', $tenantRecommendation)
        'AADSTS700016'  = @('Client ID (Application ID) não encontrado no tenant indicado.', 'Confirme o "Application (client) ID" do App Registration (não o Object ID). Se a app for multi-tenant e estiver registada noutro tenant, tem de existir um service principal (consentimento) neste tenant.')
        'AADSTS7000215' = @('Client Secret inválido.', 'Use o VALOR do segredo (só é mostrado no momento da criação), não o "Secret ID". Se perdeu o valor, crie um novo segredo em Certificates & secrets.')
        'AADSTS7000222' = @('Client Secret expirado.', 'Crie um novo segredo em Certificates & secrets, atualize os consumidores e remova o segredo expirado.')
        'AADSTS53003'   = @('Acesso bloqueado por uma política de Acesso Condicional.', 'Consulte Sign-in logs > Service principal sign-ins e as políticas de Acesso Condicional para identidades de workload (ex.: localização/IP).')
        'AADSTS50076'   = @('Uma política exige MFA.', 'O fluxo client credentials não suporta MFA interativa. Reveja as políticas de Acesso Condicional/segurança aplicáveis a esta aplicação.')
        'AADSTS50079'   = @('Uma política exige registo de MFA.', 'O fluxo client credentials não suporta MFA interativa. Reveja as políticas de Acesso Condicional/segurança aplicáveis a esta aplicação.')
        'AADSTS700027'  = @('Falha na validação da asserção do cliente (certificado).', 'Relevante se usar certificado: confirme que o certificado carregado corresponde à chave privada e não expirou.')
        'AADSTS65001'   = @('Consentimento não concedido.', 'Em API permissions, use "Grant admin consent" para as permissões necessárias.')
        'AADSTS50034'   = @('A conta indicada não existe no tenant.', 'Não é esperado em client credentials; confirme o tenant e o tipo de fluxo.')
        'AADSTS500011'  = @('O recurso (Microsoft Graph) não foi encontrado no tenant.', 'Confirme o scope https://graph.microsoft.com/.default e o tenant.')
        'AADSTS70011'   = @('Scope inválido.', 'Para client credentials o scope tem de ser https://graph.microsoft.com/.default.')
        'AADSTS7000112' = @('A aplicação (service principal) está desativada.', 'Em Enterprise applications > Properties, ative "Enabled for users to sign-in".')
        'AADSTS7000218' = @('O pedido não contém client_secret nem client_assertion.', 'Confirme que introduziu o segredo.')
        'AADSTS700025'  = @('A aplicação está configurada como cliente público.', 'Em Authentication, desative "Allow public client flows" para usar segredos.')
        'AADSTS50194'   = @('A aplicação não está configurada como multi-tenant.', 'Use o tenant onde a aplicação está registada ou configure-a como multi-tenant.')
        'AADSTS7000229' = @('O service principal da aplicação não existe neste tenant (app multi-tenant não provisionada / sem admin consent).', 'Um administrador do tenant de destino tem de conceder admin consent (ex.: https://login.microsoftonline.com/{tenant}/adminconsent?client_id={clientId}) para criar o service principal.')
        'AADSTS90014'   = @('Falta um campo obrigatório no pedido de token.', 'Confirme que o Client ID e o Client Secret foram introduzidos; se persistir, verifique se um proxy altera o corpo do pedido.')
    }

    if (-not [string]::IsNullOrWhiteSpace($ErrorCode) -and $map.ContainsKey($ErrorCode)) {
        return [pscustomobject]@{ Cause = $map[$ErrorCode][0]; Recommendation = $map[$ErrorCode][1] }
    }
    return [pscustomobject]@{
        Cause          = 'Erro de autenticação não mapeado.'
        Recommendation = 'Pesquise o código AADSTS em https://login.microsoftonline.com/error e consulte os Sign-in logs do service principal com o Trace ID/Correlation ID.'
    }
}

#endregion

#region Token

function Get-GraphToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][securestring]$ClientSecret
    )

    $tokenUrl = '{0}/{1}/oauth2/v2.0/token' -f $script:LoginBaseUrl, (ConvertTo-UrlSegment -Value $TenantId)
    $result = [pscustomobject]@{
        Success           = $false
        Token             = $null
        ExpiresOn         = [DateTimeOffset]::MinValue
        Claims            = $null
        HttpStatus        = $null
        ErrorCode         = $null
        ErrorMessage      = $null
        Cause             = $null
        Recommendation    = $null
        TraceId           = $null
        CorrelationId     = $null
        IsNetworkError    = $false
        SecretLooksLikeId = $false
        ClaimsDecoded     = $false
        DecodeWarning     = $null
        Endpoint          = 'POST ' + $tokenUrl
    }

    $plainSecret = $null
    $body = $null
    $response = $null
    $accessToken = $null
    $statusCode = 0

    try {
        # Único ponto onde o segredo existe em texto simples.
        $plainSecret = [System.Net.NetworkCredential]::new('', $ClientSecret).Password
        $result.SecretLooksLikeId = Test-GuidFormat -Value $plainSecret
        $body = @{
            client_id     = $ClientId
            client_secret = $plainSecret
            scope         = $script:GraphScope
            grant_type    = 'client_credentials'
        }
        $plainSecret = $null

        Write-DebugInfo ('POST {0} (grant_type=client_credentials)' -f $tokenUrl)
        try {
            # -SkipHttpErrorCheck: erros HTTP não geram ErrorRecord que referencie o corpo do pedido.
            $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body `
                -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck `
                -StatusCodeVariable 'statusCode' -TimeoutSec 30
        }
        catch {
            $network = Get-NetworkErrorInfo -Exception $_.Exception
            $result.IsNetworkError = $true
            $result.ErrorCode      = 'NETWORK'
            $result.ErrorMessage   = 'Erro de rede ({0}): {1}' -f $network.Category, $network.Detail
            $result.Cause          = 'Não foi possível contactar o endpoint de autenticação.'
            $result.Recommendation = $network.Recommendation
            return $result
        }
        finally {
            if ($null -ne $body) { $body.Clear() }
            $body = $null
        }

        $result.HttpStatus = [int]$statusCode
        Write-DebugInfo ('Endpoint de token -> HTTP {0}' -f $statusCode)
        $accessToken = Get-SafeProperty $response 'access_token'

        if ($statusCode -eq 200 -and -not [string]::IsNullOrEmpty($accessToken)) {
            $claims = $null
            try {
                $claims = ConvertFrom-Jwt -Token $accessToken
                $result.ClaimsDecoded = $true
            }
            catch {
                # O token continua utilizável; só as claims (roles/expiração) ficam desconhecidas.
                $result.DecodeWarning = 'Não foi possível descodificar o payload do token: roles não determináveis.'
            }
            $exp = Get-SafeProperty $claims 'exp'
            if ($null -ne $exp) {
                $result.ExpiresOn = [DateTimeOffset]::FromUnixTimeSeconds([long]$exp)
            }
            else {
                $expiresIn = [int](Get-SafeProperty $response 'expires_in')
                $result.ExpiresOn = [DateTimeOffset]::UtcNow.AddSeconds([math]::Max(60, $expiresIn))
            }
            $secureToken = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            $secureToken.MakeReadOnly()
            $result.Token   = $secureToken
            $result.Claims  = $claims
            $result.Success = $true
            return $result
        }

        if ($statusCode -eq 407) {
            $result.ErrorCode      = 'HTTP407'
            $result.ErrorMessage   = 'HTTP 407 - o proxy exige autenticação.'
            $result.Cause          = 'Proxy com autenticação.'
            $result.Recommendation = 'Configure as credenciais do proxy no sistema ou use uma rede sem proxy autenticado.'
            return $result
        }

        $aadCode = $null
        $codes = @(Get-SafeProperty $response 'error_codes')
        if ($codes.Count -gt 0 -and $null -ne $codes[0]) { $aadCode = 'AADSTS{0}' -f $codes[0] }
        $description = [string](Get-SafeProperty $response 'error_description')
        if (-not $aadCode -and $description -match 'AADSTS(\d+)') { $aadCode = 'AADSTS' + $Matches[1] }
        $firstLine = ($description -split "`r?`n")[0]
        $oauthError = [string](Get-SafeProperty $response 'error')

        $result.ErrorCode     = $aadCode
        $result.TraceId       = Get-SafeProperty $response 'trace_id'
        $result.CorrelationId = Get-SafeProperty $response 'correlation_id'
        if ([string]::IsNullOrWhiteSpace($firstLine)) {
            $result.ErrorMessage = 'HTTP {0} - resposta inesperada do endpoint de token (possível proxy/página intermédia).' -f $statusCode
        }
        else {
            $result.ErrorMessage = 'HTTP {0} | {1} | {2}' -f $statusCode, $oauthError, (Protect-SensitiveText -Text $firstLine -SingleLine -MaxLength 400)
        }
        $guidance = Get-AadErrorGuidance -ErrorCode $aadCode
        $result.Cause          = $guidance.Cause
        $result.Recommendation = $guidance.Recommendation
        return $result
    }
    catch {
        $result.ErrorCode      = 'LOCAL'
        $result.ErrorMessage   = 'Erro ao processar a resposta de autenticação: {0}' -f (Protect-SensitiveText -Text $_.Exception.Message -SingleLine)
        $result.Cause          = 'Resposta de token inválida ou inesperada.'
        $result.Recommendation = 'Execute novamente; se persistir, use -ShowDebug.'
        return $result
    }
    finally {
        $plainSecret = $null
        $accessToken = $null
        $response = $null
        if ($null -ne $body) { $body.Clear() }
        $body = $null
        Clear-SensitiveErrorRecord
    }
}

function Set-SessionToken {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$TokenResult)
    if ($null -ne $script:AccessToken) { $script:AccessToken.Dispose() }
    $script:AccessToken    = $TokenResult.Token
    $script:TokenExpiresOn = $TokenResult.ExpiresOn
    $script:TokenClaims    = $TokenResult.Claims
    $script:RolesKnown     = [bool]$TokenResult.ClaimsDecoded
    $script:SessionBlocked = $false
    $script:TokenRoles     = @(@(Get-SafeProperty $TokenResult.Claims 'roles') |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if (-not $script:RolesKnown -and $TokenResult.DecodeWarning) {
        Write-Message ('AVISO: {0} Os testes que dependem das roles serão ignorados (SKIPPED).' -f $TokenResult.DecodeWarning) -Color Yellow
    }
}

function Clear-SessionToken {
    # Descarta o token e as roles atuais (ex.: após falha de renovação) e bloqueia os testes.
    [CmdletBinding()]
    param()
    if ($null -ne $script:AccessToken) { $script:AccessToken.Dispose() }
    $script:AccessToken    = $null
    $script:TokenClaims    = $null
    $script:TokenRoles     = @()
    $script:RolesKnown     = $false
    $script:TokenExpiresOn = [DateTimeOffset]::MinValue
    $script:SessionBlocked = $true
}

function Update-GraphToken {
    # Renova o token se faltar menos do que a margem definida (ou se -Force).
    [CmdletBinding()]
    param([switch]$Force)

    if (-not $Force -and $null -ne $script:AccessToken -and
        $script:TokenExpiresOn -gt [DateTimeOffset]::UtcNow.AddMinutes($script:TokenRefreshMarginMinutes)) {
        return $true
    }
    if ($null -eq $script:ClientSecret -or -not $script:TenantId -or -not $script:ClientId) { return $false }

    if (-not $Force) { Write-Message 'O token está perto de expirar; a obter um novo token...' -Color DarkGray }
    $tokenResult = Get-GraphToken -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $script:ClientSecret
    if (-not $tokenResult.Success) {
        $script:LastTokenResult = $tokenResult
        Write-Message ('Falha ao obter/renovar o token: {0}' -f $tokenResult.ErrorMessage) -Color Red
        if ($null -ne $script:AccessToken) {
            Write-Message 'O token anterior e as respetivas roles foram descartados; os testes ficam bloqueados até uma autenticação bem-sucedida (opção 1).' -Color Yellow
        }
        Clear-SessionToken
        return $false
    }

    $previousRoles = @($script:TokenRoles)
    Set-SessionToken -TokenResult $tokenResult
    $tokenResult = $null
    $script:LastTokenResult = $null

    $added = @($script:TokenRoles | Where-Object { $previousRoles -notcontains $_ })
    $removed = @($previousRoles | Where-Object { $script:TokenRoles -notcontains $_ })
    if ($previousRoles.Count -gt 0 -and ($added.Count -gt 0 -or $removed.Count -gt 0)) {
        Write-Message ('As permissões do token mudaram. Adicionadas: {0}. Removidas: {1}.' -f (Format-RoleList $added), (Format-RoleList $removed)) -Color Yellow
    }
    return $true
}

function Test-TokenRole {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    return ($script:TokenRoles -contains $Name)
}

function Get-MatchingTokenRole {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Names)
    return @($Names | Where-Object { $script:TokenRoles -contains $_ })
}

function Get-TokenClaimWarning {
    [CmdletBinding()]
    param()
    $warnings = [System.Collections.Generic.List[string]]::new()
    if (-not $script:RolesKnown) {
        $warnings.Add('Não foi possível descodificar o token: aud/tid/appid e roles não determináveis.')
        return $warnings.ToArray()
    }
    $claims = $script:TokenClaims
    $aud = [string](Get-SafeProperty $claims 'aud')
    $appId = [string](Get-SafeProperty $claims 'appid')
    if (-not $appId) { $appId = [string](Get-SafeProperty $claims 'azp') }
    $tid = [string](Get-SafeProperty $claims 'tid')
    $idtyp = [string](Get-SafeProperty $claims 'idtyp')

    if ($aud -notmatch '^(https://graph\.microsoft\.com/?|00000003-0000-0000-c000-000000000000)$') {
        $warnings.Add(('aud inesperado ({0}); esperado https://graph.microsoft.com.' -f $aud))
    }
    if ($appId -and $appId -ne $script:ClientId) {
        $warnings.Add(('appid do token ({0}) difere do Client ID indicado.' -f $appId))
    }
    if ((Test-GuidFormat -Value $script:TenantId) -and $tid -and $tid -ne $script:TenantId) {
        $warnings.Add(('tid do token ({0}) difere do Tenant ID indicado.' -f $tid))
    }
    if ($idtyp -and $idtyp -ne 'app') {
        $warnings.Add(('idtyp = {0}; esperado "app" para client credentials.' -f $idtyp))
    }
    if ($null -ne (Get-SafeProperty $claims 'scp')) {
        $warnings.Add('O token contém a claim scp (delegada), o que não é esperado em client credentials.')
    }
    if (@($script:TokenRoles).Count -eq 0) {
        $warnings.Add('O token não contém roles: nenhuma permissão de Aplicação com admin consent está efetiva.')
    }
    return $warnings.ToArray()
}

function Show-TokenInfo {
    [CmdletBinding()]
    param()
    $claims = $script:TokenClaims
    $appId = Get-SafeProperty $claims 'appid'
    if (-not $appId) { $appId = Get-SafeProperty $claims 'azp' }
    $remaining = [math]::Floor(($script:TokenExpiresOn - [DateTimeOffset]::UtcNow).TotalMinutes)

    Write-Section 'Token de acesso (o token em si nunca é apresentado)'
    $rows = [ordered]@{
        'Aplicação (app_displayname)' = Get-SafeProperty $claims 'app_displayname'
        'appid'                       = $appId
        'aud'                         = Get-SafeProperty $claims 'aud'
        'tid'                         = Get-SafeProperty $claims 'tid'
        'idtyp'                       = Get-SafeProperty $claims 'idtyp'
        'Emitido em (iat)'            = Format-UnixTime (Get-SafeProperty $claims 'iat')
        'Expira em (exp)'             = '{0} (faltam {1} min)' -f (Format-UnixTime (Get-SafeProperty $claims 'exp')), $remaining
        'roles'                       = if ($script:RolesKnown) { Format-RoleList $script:TokenRoles } else { 'não determináveis (token não descodificado)' }
    }
    foreach ($key in $rows.Keys) {
        Write-Host ('  {0,-28}: {1}' -f $key, (Format-DisplayText -Value $rows[$key] -MaxLength 400))
    }
}

function Get-TokenEndpointDisplay {
    return ('POST {0}/{1}/oauth2/v2.0/token' -f $script:LoginBaseUrl, $script:TenantId)
}

function New-AuthFailureResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$TokenResult)
    $details = [System.Collections.Generic.List[string]]::new()
    if ($TokenResult.ErrorMessage)  { $details.Add([string]$TokenResult.ErrorMessage) }
    if ($TokenResult.TraceId)       { $details.Add(('Trace ID: {0}' -f $TokenResult.TraceId)) }
    if ($TokenResult.CorrelationId) { $details.Add(('Correlation ID: {0}' -f $TokenResult.CorrelationId)) }
    $recommendation = ('Causa provável: {0} {1}' -f $TokenResult.Cause, $TokenResult.Recommendation).Trim()
    if ($TokenResult.SecretLooksLikeId) {
        $recommendation += ' ATENÇÃO: o valor introduzido tem formato GUID; é muito provável que tenha usado o "Secret ID" em vez do "Value".'
    }
    return New-TestResult -Name 'Autenticação (client credentials)' -Status FAIL `
        -RequiredPermission 'Credenciais válidas (Tenant ID, Client ID, Client Secret)' `
        -DetectedPermission '(sem token)' -Endpoint $TokenResult.Endpoint `
        -ErrorMessage ($details -join ' | ') -Recommendation $recommendation
}

#endregion

#region Microsoft Graph

function ConvertFrom-GraphError {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $info = [pscustomobject]@{ Code = $null; Message = $null; RequestId = $null; Date = $null }
    $raw = $null
    if ($null -ne $ErrorRecord.ErrorDetails) { $raw = $ErrorRecord.ErrorDetails.Message }
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        try {
            $json = $raw | ConvertFrom-Json -ErrorAction Stop
            $graphError = Get-SafeProperty $json 'error'
            $info.Code = [string](Get-SafeProperty $graphError 'code')
            $info.Message = [string](Get-SafeProperty $graphError 'message')
            $inner = Get-SafeProperty $graphError 'innerError'
            $info.RequestId = Get-SafeProperty $inner 'request-id'
            $date = Get-SafeProperty $inner 'date'
            if ($date -is [datetime]) { $info.Date = $date.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            elseif ($null -ne $date) { $info.Date = [string]$date }
        }
        catch {
            $info.Message = $raw
        }
    }
    if (-not $info.RequestId) {
        try {
            $response = Get-SafeProperty $ErrorRecord.Exception 'Response'
            if ($null -ne $response) {
                $info.RequestId = $response.Headers.GetValues('request-id') | Select-Object -First 1
            }
        }
        catch { }
    }
    $info.Message = Protect-SensitiveText -Text $info.Message -SingleLine -MaxLength 500
    return $info
}

function Get-RetryDelaySeconds {
    # Devolve o atraso pedido pelo Retry-After (sem limite superior; quem chama decide se aborta)
    # ou um backoff exponencial (máx. 30 s) se o cabeçalho não existir.
    [CmdletBinding()]
    param([AllowNull()][object]$Response, [int]$Attempt)
    $seconds = [math]::Min(30, [math]::Pow(2, $Attempt))
    try {
        $retryAfter = $Response.Headers.RetryAfter
        if ($null -ne $retryAfter) {
            if ($null -ne $retryAfter.Delta) {
                $seconds = [math]::Ceiling($retryAfter.Delta.TotalSeconds)
            }
            elseif ($null -ne $retryAfter.Date) {
                $seconds = [math]::Ceiling(($retryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds)
            }
        }
    }
    catch { }
    return [int][math]::Max(1, $seconds)
}

function Invoke-GraphRequest {
    <#
        Função central para pedidos ao Microsoft Graph. Nunca lança exceções por erros HTTP ou de
        rede: devolve sempre um objeto com Success, StatusCode, Data, ErrorCode, ErrorMessage,
        RequestId, ErrorDate, Endpoint, IsNetworkError, NetworkInfo e OutcomeUnknown.
        OutcomeUnknown = $true num POST com erro de rede/timeout ou HTTP 504: o pedido pode ter
        sido processado e NUNCA é repetido automaticamente.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body,
        [ValidateRange(0, 5)][int]$MaxRetries = 3
    )

    if ($Uri -match '^https://') {
        # Só URLs do Graph (ex.: @odata.nextLink): o token nunca é enviado para outro anfitrião.
        if (-not $Uri.StartsWith($script:GraphBaseUrl + '/', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'URL fora do Microsoft Graph recusado (proteção do token).'
        }
        $fullUri = $Uri
    }
    else {
        $fullUri = $script:GraphBaseUrl + $Uri
    }
    $displayUri = $fullUri.Substring($script:GraphBaseUrl.Length)

    $result = [pscustomobject]@{
        Success        = $false
        StatusCode     = $null
        Data           = $null
        ErrorCode      = $null
        ErrorMessage   = $null
        RequestId      = $null
        ErrorDate      = $null
        Endpoint       = '{0} {1}' -f $Method, $displayUri
        IsNetworkError = $false
        NetworkInfo    = $null
        OutcomeUnknown = $false
    }

    $bodyBytes = $null
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 10 -Compress
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    }
    # POST só é repetido em 429 (pedido não processado), para evitar envios duplicados.
    $retryableStatus = if ($Method -eq 'GET') { @(429, 503, 504) } else { @(429) }

    $attempt = 0
    $refreshedAfter401 = $false
    while ($true) {
        $attempt++
        if (-not (Update-GraphToken)) {
            $result.ErrorCode = 'TokenUnavailable'
            $result.ErrorMessage = 'Não foi possível obter/renovar o token de acesso.'
            return $result
        }

        $statusCode = 0
        $params = @{
            Method             = $Method
            Uri                = $fullUri
            Authentication     = 'Bearer'
            Token              = $script:AccessToken
            StatusCodeVariable = 'statusCode'
            TimeoutSec         = 60
            ErrorAction        = 'Stop'
        }
        if ($null -ne $bodyBytes) {
            $params['Body'] = $bodyBytes
            $params['ContentType'] = 'application/json; charset=utf-8'
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $data = Invoke-RestMethod @params
            $stopwatch.Stop()
            Write-DebugInfo ('{0} {1} -> HTTP {2} ({3} ms)' -f $Method, $displayUri, $statusCode, $stopwatch.ElapsedMilliseconds)
            $result.Success = $true
            $result.StatusCode = [int]$statusCode
            $result.Data = $data
            return $result
        }
        catch {
            $stopwatch.Stop()
            $errorRecord = $_
            $response = Get-SafeProperty $errorRecord.Exception 'Response'

            if ($null -eq $response) {
                $network = Get-NetworkErrorInfo -Exception $errorRecord.Exception
                Write-DebugInfo ('{0} {1} -> erro de rede {2} ({3} ms)' -f $Method, $displayUri, $network.Category, $stopwatch.ElapsedMilliseconds)
                $result.IsNetworkError = $true
                $result.NetworkInfo = $network
                $result.ErrorCode = 'NETWORK'
                $result.ErrorMessage = 'Erro de rede ({0}): {1}' -f $network.Category, $network.Detail
                # Num POST o pedido pode ter chegado ao serviço: resultado desconhecido, sem repetição.
                $result.OutcomeUnknown = ($Method -eq 'POST')
                return $result
            }

            $status = [int]$response.StatusCode
            $graphError = ConvertFrom-GraphError -ErrorRecord $errorRecord
            $result.StatusCode = $status
            $result.ErrorCode = $graphError.Code
            $result.ErrorMessage = $graphError.Message
            $result.RequestId = $graphError.RequestId
            $result.ErrorDate = $graphError.Date
            Write-DebugInfo ('{0} {1} -> HTTP {2} {3} ({4} ms)' -f $Method, $displayUri, $status, $graphError.Code, $stopwatch.ElapsedMilliseconds)

            if ($status -eq 401 -and -not $refreshedAfter401) {
                $refreshedAfter401 = $true
                Write-Message 'Token rejeitado (HTTP 401). A obter um novo token e a repetir uma vez...' -Color DarkYellow
                if (Update-GraphToken -Force) { continue }
                return $result
            }
            if ($Method -eq 'POST' -and $status -eq 504) {
                # Gateway timeout num POST: o serviço pode ter processado o pedido.
                $result.OutcomeUnknown = $true
                return $result
            }
            if (($retryableStatus -contains $status) -and ($attempt -le $MaxRetries)) {
                $delay = Get-RetryDelaySeconds -Response $response -Attempt $attempt
                if ($delay -gt $script:MaxRetryAfterSeconds) {
                    Write-Message ('Microsoft Graph pediu para aguardar {0} s (limite: {1} s). O pedido foi abortado; tente mais tarde.' -f $delay, $script:MaxRetryAfterSeconds) -Color Yellow
                    $result.ErrorMessage = ('{0} | Retry-After de {1} s excede o limite de {2} s: pedido abortado.' -f $result.ErrorMessage, $delay, $script:MaxRetryAfterSeconds).Trim(' ', '|')
                    return $result
                }
                Write-Message ('Microsoft Graph pediu para aguardar (HTTP {0}). Nova tentativa {1}/{2} dentro de {3} s...' -f $status, $attempt, $MaxRetries, $delay) -Color DarkYellow
                Start-Sleep -Seconds $delay
                continue
            }
            return $result
        }
        finally {
            Clear-SensitiveErrorRecord
        }
    }
}

function Get-GraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateRange(1, 100)][int]$MaxPages = 20
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0
    while ($next -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-GraphRequest -Method GET -Uri $next
        if (-not $response.Success) {
            return [pscustomobject]@{ Success = $false; Items = $items.ToArray(); Response = $response; Truncated = $false }
        }
        foreach ($item in @(Get-SafeProperty $response.Data 'value')) {
            if ($null -ne $item) { $items.Add($item) }
        }
        $next = [string](Get-SafeProperty $response.Data '@odata.nextLink')
    }
    # Truncated = ainda havia páginas quando o limite foi atingido (resultado incompleto).
    $truncated = -not [string]::IsNullOrEmpty($next)
    return [pscustomobject]@{ Success = $true; Items = $items.ToArray(); Response = $null; Truncated = $truncated }
}

function Format-GraphErrorMessage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Response)
    if ($Response.IsNetworkError) { return [string]$Response.ErrorMessage }
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($Response.StatusCode)   { $parts.Add(('HTTP {0}' -f $Response.StatusCode)) }
    if ($Response.ErrorCode)    { $parts.Add(('Código: {0}' -f $Response.ErrorCode)) }
    if ($Response.ErrorMessage) { $parts.Add(('Mensagem: {0}' -f $Response.ErrorMessage)) }
    if ($Response.RequestId)    { $parts.Add(('request-id: {0}' -f $Response.RequestId)) }
    if ($Response.ErrorDate)    { $parts.Add(('data: {0}' -f $Response.ErrorDate)) }
    if ($parts.Count -eq 0) { return 'Erro desconhecido.' }
    return ($parts -join ' | ')
}

function Get-GraphFailureGuidance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Response,
        [Parameter(Mandatory)][ValidateSet('Read', 'Send', 'ResolveUser', 'Inventory')][string]$Operation,
        [string]$Mailbox = '<caixa>'
    )
    $message = Format-GraphErrorMessage -Response $Response
    $code = [string]$Response.ErrorCode
    $status = $Response.StatusCode
    $graphMessage = [string]$Response.ErrorMessage

    $policyHint = ('Mesmo com a permissão no token, o Exchange Online devolve ErrorAccessDenied se uma Application Access Policy ' +
        '(New-ApplicationAccessPolicy) ou uma atribuição RBAC for Applications com âmbito (management scope) não incluir ' +
        'a caixa {0}. Verifique com Test-ApplicationAccessPolicy -Identity {0} -AppId <ClientId> ou ' +
        'Test-ServicePrincipalAuthorization -Identity <ClientId> -Resource {0}.') -f $Mailbox
    $mailboxCodes = @('ResourceNotFound', 'ErrorInvalidUser', 'MailboxNotEnabledForRESTAPI', 'ErrorNonExistentMailbox',
        'Request_ResourceNotFound', 'ErrorMailboxNotFound')

    if ($Response.IsNetworkError) {
        $recommendation = $Response.NetworkInfo.Recommendation
    }
    elseif ($code -eq 'TokenUnavailable') {
        $recommendation = 'Não há token válido. Use a opção 1 para voltar a autenticar e confirme se o segredo não expirou.'
    }
    elseif ($code -eq 'MailboxNotEnabledForRESTAPI') {
        $recommendation = ('A caixa {0} não está disponível via REST: pode estar alojada on-premises (híbrido), estar inativa/eliminada, não ter licença Exchange Online ou ainda estar a ser provisionada.' -f $Mailbox)
    }
    elseif ($status -eq 404 -or $mailboxCodes -contains $code) {
        $recommendation = ('Caixa/utilizador não encontrado: confirme o UPN/endereço {0}, se tem licença Exchange Online, se não está on-premises e se não foi criada há pouco tempo (aguarde o provisionamento).' -f $Mailbox)
    }
    elseif ($status -eq 401) {
        $recommendation = 'Token rejeitado mesmo após renovação. Confirme que o token é para https://graph.microsoft.com, que o service principal está ativo e que não há políticas a bloquear a aplicação.'
    }
    elseif ($status -eq 403) {
        if ($Operation -in @('Read', 'Send') -and $graphMessage -match '(?i)AccessPolicy|RAOP') {
            # A sugestão de Application Access Policy / RBAC for Applications só se aplica a caixas de correio.
            $recommendation = 'Bloqueado por uma Application Access Policy / RBAC for Applications configurada no Exchange Online. ' + $policyHint
        }
        else {
            switch ($Operation) {
                'Read' {
                    $recommendation = 'Se a permissão faltar: adicione uma de Mail.ReadBasic, Mail.ReadBasic.All, Mail.Read ou Mail.ReadWrite (Aplicação), conceda admin consent e obtenha um novo token. ' + $policyHint
                }
                'Send' {
                    $recommendation = 'Se a permissão faltar: adicione Mail.Send (Aplicação), conceda admin consent e obtenha um novo token. ' + $policyHint
                }
                'ResolveUser' {
                    $recommendation = 'Falta User.Read.All (ou User.ReadBasic.All) como permissão de Aplicação com admin consent. Esta verificação é opcional.'
                }
                'Inventory' {
                    $recommendation = 'Não verificável sem Application.Read.All (Aplicação). Conceda-a temporariamente ou use uma app de diagnóstico com admin consent.'
                }
            }
        }
    }
    elseif ($code -eq 'ErrorInvalidRecipients' -or $graphMessage -match '(?i)recipient') {
        $recommendation = 'Destinatário inválido ou rejeitado. Confirme o endereço do destinatário.'
    }
    elseif ($code -in @('ErrorMessageSubmissionBlocked', 'ErrorSubmissionQuotaExceeded', 'ErrorQuotaExceeded')) {
        $recommendation = 'O envio foi bloqueado ou excedeu a quota (ex.: remetente restrito por spam de saída). Verifique o remetente no portal do Exchange/Defender.'
    }
    elseif ($code -eq 'ErrorSendAsDenied') {
        $recommendation = 'Envio "como" outro utilizador recusado. Envie a partir da própria caixa indicada em /users/{remetente}/sendMail.'
    }
    elseif ($status -in @(429, 503, 504)) {
        $recommendation = 'Limitação (throttling) ou serviço indisponível após várias tentativas. Tente mais tarde.'
    }
    elseif ($status -eq 400) {
        $recommendation = 'Pedido inválido. Verifique os valores introduzidos (caixa, destinatário, assunto).'
    }
    else {
        $recommendation = 'Consulte o código de erro na documentação do Microsoft Graph e indique o request-id ao suporte Microsoft.'
    }
    return [pscustomobject]@{ ErrorMessage = $message; Recommendation = $recommendation }
}

#endregion

#region Inventário de permissões

function Get-AppPermissionInventory {
    [CmdletBinding()]
    param()

    $inventory = [pscustomobject]@{
        AppDisplayName          = $null
        ServicePrincipalId      = $null
        GraphServicePrincipalId = $null
        NameResolution          = 'GraphServicePrincipal'
        AssignedState           = 'NotVerifiable'
        AssignedMessage         = $null
        AssignedEndpoint        = $null
        AssignedApplication     = @()
        AssignedDelegated       = @()
        AssignedUnresolved      = @()
        ConsentState            = 'NotVerifiable'
        ConsentMessage          = $null
        ConsentEndpoint         = $null
        ConsentedApplication    = @()
        DelegatedConsentState   = 'NotVerifiable'
        DelegatedConsentMessage = $null
        DelegatedConsentEndpoint = $null
        ConsentedDelegated      = @()
        UserConsentedDelegated  = @()
        Warnings                = [System.Collections.Generic.List[string]]::new()
    }

    $roleMap = @{}
    $scopeMap = @{}
    $notRequested = 'Nenhum (pedido não efetuado)'
    $canReadApps = $script:RolesKnown -and (@(Get-MatchingTokenRole -Names $script:ApplicationReadRoles).Count -gt 0)
    $canReadGrants = $script:RolesKnown -and (@(Get-MatchingTokenRole -Names $script:GrantReadRoles).Count -gt 0)
    $grantMissingMessage = 'Não verificável: Directory.Read.All (ou Directory.ReadWrite.All/DelegatedPermissionGrant.ReadWrite.All) ausente do token (pedido não efetuado).'

    # 0) Adaptativo: sem uma role de leitura de diretório no token não se faz nenhum pedido.
    if (-not $canReadApps) {
        $missing = 'Não verificável: Application.Read.All (ou Application.ReadWrite.All/Directory.Read.All/Directory.ReadWrite.All) ausente do token (pedido não efetuado).'
        foreach ($key in $script:WellKnownGraphRoleIds.Keys) { $roleMap[$key] = $script:WellKnownGraphRoleIds[$key] }
        $inventory.NameResolution           = 'WellKnownIds'
        $inventory.AssignedState            = 'NotVerifiable'
        $inventory.AssignedMessage          = $missing
        $inventory.AssignedEndpoint         = $notRequested
        $inventory.ConsentState             = 'NotVerifiable'
        $inventory.ConsentMessage           = $missing
        $inventory.ConsentEndpoint          = $notRequested
        $inventory.DelegatedConsentMessage  = if ($canReadGrants) { 'Não verificável: o service principal não pode ser resolvido sem Application.Read.All (pedido não efetuado).' } else { $grantMissingMessage }
        $inventory.DelegatedConsentEndpoint = $notRequested
        return $inventory
    }

    # 1) Service principal do Microsoft Graph: mapeia IDs de appRoles/scopes para nomes.
    $graphSpUri = '/servicePrincipals(appId=''{0}'')?$select=id,appRoles,oauth2PermissionScopes' -f $script:GraphResourceAppId
    $graphSp = Invoke-GraphRequest -Method GET -Uri $graphSpUri
    if ($graphSp.Success) {
        $inventory.GraphServicePrincipalId = [string](Get-SafeProperty $graphSp.Data 'id')
        foreach ($role in @(Get-SafeProperty $graphSp.Data 'appRoles')) {
            if ($null -ne $role) { $roleMap[[string]$role.id] = [string]$role.value }
        }
        foreach ($scope in @(Get-SafeProperty $graphSp.Data 'oauth2PermissionScopes')) {
            if ($null -ne $scope) { $scopeMap[[string]$scope.id] = [string]$scope.value }
        }
    }
    else {
        foreach ($key in $script:WellKnownGraphRoleIds.Keys) { $roleMap[$key] = $script:WellKnownGraphRoleIds[$key] }
        $inventory.NameResolution = 'WellKnownIds'
    }

    # 2) Permissões atribuídas no App Registration (requiredResourceAccess).
    $appUri = '/applications(appId=''{0}'')?$select=id,appId,displayName,requiredResourceAccess' -f $script:ClientId
    $inventory.AssignedEndpoint = 'GET ' + $appUri
    $app = Invoke-GraphRequest -Method GET -Uri $appUri
    if ($app.Success) {
        $assignedApp = [System.Collections.Generic.List[string]]::new()
        $assignedDelegated = [System.Collections.Generic.List[string]]::new()
        $unresolved = [System.Collections.Generic.List[string]]::new()
        $inventory.AppDisplayName = [string](Get-SafeProperty $app.Data 'displayName')
        foreach ($resource in @(Get-SafeProperty $app.Data 'requiredResourceAccess')) {
            if ($null -eq $resource) { continue }
            if ([string](Get-SafeProperty $resource 'resourceAppId') -ne $script:GraphResourceAppId) { continue }
            foreach ($access in @(Get-SafeProperty $resource 'resourceAccess')) {
                if ($null -eq $access) { continue }
                $id = [string](Get-SafeProperty $access 'id')
                $type = [string](Get-SafeProperty $access 'type')
                if ($type -eq 'Role') {
                    if ($roleMap.ContainsKey($id)) { $assignedApp.Add($roleMap[$id]) } else { $unresolved.Add(('Role:{0}' -f $id)) }
                }
                elseif ($type -eq 'Scope') {
                    if ($scopeMap.ContainsKey($id)) { $assignedDelegated.Add($scopeMap[$id]) } else { $unresolved.Add(('Scope:{0}' -f $id)) }
                }
            }
        }
        $inventory.AssignedState = 'Verified'
        $inventory.AssignedApplication = @($assignedApp | Sort-Object -Unique)
        $inventory.AssignedDelegated = @($assignedDelegated | Sort-Object -Unique)
        $inventory.AssignedUnresolved = @($unresolved | Sort-Object -Unique)
    }
    elseif ($app.StatusCode -eq 403) {
        $inventory.AssignedState = 'NotVerifiable'
        $inventory.AssignedMessage = 'Não verificável sem Application.Read.All (HTTP 403).'
    }
    elseif ($app.StatusCode -eq 404) {
        $inventory.AssignedState = 'Error'
        $inventory.AssignedMessage = 'Objeto application não encontrado neste tenant (habitual em apps multi-tenant registadas noutro tenant).'
    }
    else {
        $inventory.AssignedState = 'Error'
        $inventory.AssignedMessage = Format-GraphErrorMessage -Response $app
    }

    # 3) Service principal da aplicação e admin consent.
    $spUri = '/servicePrincipals(appId=''{0}'')?$select=id,appId,displayName' -f $script:ClientId
    $assignmentsUri = '/servicePrincipals(appId=''{0}'')/appRoleAssignments' -f $script:ClientId
    $inventory.ConsentEndpoint = 'GET ' + $assignmentsUri
    $sp = Invoke-GraphRequest -Method GET -Uri $spUri
    if ($sp.Success) {
        $inventory.ServicePrincipalId = [string](Get-SafeProperty $sp.Data 'id')
        if (-not $inventory.AppDisplayName) { $inventory.AppDisplayName = [string](Get-SafeProperty $sp.Data 'displayName') }

        $assignments = Get-GraphCollection -Uri $assignmentsUri
        if ($assignments.Success) {
            $consentedApp = [System.Collections.Generic.List[string]]::new()
            foreach ($assignment in $assignments.Items) {
                $resourceId = [string](Get-SafeProperty $assignment 'resourceId')
                $isGraph = if ($inventory.GraphServicePrincipalId) {
                    $resourceId -eq $inventory.GraphServicePrincipalId
                } else {
                    [string](Get-SafeProperty $assignment 'resourceDisplayName') -eq 'Microsoft Graph'
                }
                if (-not $isGraph) { continue }
                $roleId = [string](Get-SafeProperty $assignment 'appRoleId')
                if ($roleMap.ContainsKey($roleId)) { $consentedApp.Add($roleMap[$roleId]) }
                else { $consentedApp.Add(('(id desconhecido: {0})' -f $roleId)) }
            }
            $inventory.ConsentState = 'Verified'
            $inventory.ConsentedApplication = @($consentedApp | Sort-Object -Unique)
            if ($assignments.Truncated) {
                $inventory.Warnings.Add('appRoleAssignments: limite de páginas atingido; a lista de consentimentos pode estar incompleta.')
            }
        }
        elseif ($assignments.Response.StatusCode -eq 403) {
            $inventory.ConsentMessage = 'Não verificável sem Application.Read.All (HTTP 403).'
        }
        else {
            $inventory.ConsentState = 'Error'
            $inventory.ConsentMessage = Format-GraphErrorMessage -Response $assignments.Response
        }

        # oauth2PermissionGrants em app-only exige Directory.Read.All (ou DelegatedPermissionGrant.ReadWrite.All);
        # Application.Read.All não chega.
        $grantFilter = ConvertTo-UrlSegment -Value ("clientId eq '{0}'" -f $inventory.ServicePrincipalId)
        $grantsUri = '/oauth2PermissionGrants?$filter=' + $grantFilter
        $grants = $null
        if ($canReadGrants) {
            $inventory.DelegatedConsentEndpoint = 'GET ' + $grantsUri
            $grants = Get-GraphCollection -Uri $grantsUri
        }
        else {
            $inventory.DelegatedConsentMessage = $grantMissingMessage
            $inventory.DelegatedConsentEndpoint = $notRequested
        }
        if ($null -ne $grants -and -not $grants.Success) {
            if ($grants.Response.StatusCode -eq 403) {
                $inventory.DelegatedConsentState = 'NotVerifiable'
                $inventory.DelegatedConsentMessage = 'Não verificável: HTTP 403 ao ler oauth2PermissionGrants (requer Directory.Read.All com admin consent).'
            }
            else {
                $inventory.DelegatedConsentState = 'Error'
                $inventory.DelegatedConsentMessage = Format-GraphErrorMessage -Response $grants.Response
            }
        }
        elseif ($null -ne $grants) {
            if ($grants.Truncated) {
                $inventory.Warnings.Add('oauth2PermissionGrants: limite de páginas atingido; a lista pode estar incompleta.')
            }
            $adminScopes = [System.Collections.Generic.List[string]]::new()
            $userScopes = [System.Collections.Generic.List[string]]::new()
            foreach ($grant in $grants.Items) {
                $resourceId = [string](Get-SafeProperty $grant 'resourceId')
                if ($inventory.GraphServicePrincipalId -and $resourceId -ne $inventory.GraphServicePrincipalId) { continue }
                $scopes = @(([string](Get-SafeProperty $grant 'scope')).Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries))
                if ([string](Get-SafeProperty $grant 'consentType') -eq 'AllPrincipals') {
                    foreach ($s in $scopes) { $adminScopes.Add($s) }
                }
                else {
                    foreach ($s in $scopes) { $userScopes.Add($s) }
                }
            }
            $inventory.DelegatedConsentState = 'Verified'
            $inventory.ConsentedDelegated = @($adminScopes | Sort-Object -Unique)
            $inventory.UserConsentedDelegated = @($userScopes | Sort-Object -Unique)
        }
    }
    elseif ($sp.StatusCode -eq 403) {
        $inventory.ConsentMessage = 'Não verificável sem Application.Read.All (HTTP 403).'
    }
    elseif ($sp.StatusCode -eq 404) {
        $inventory.ConsentState = 'Error'
        $inventory.ConsentMessage = 'Service principal não encontrado neste tenant (a aplicação nunca foi consentida/provisionada aqui).'
    }
    else {
        $inventory.ConsentState = 'Error'
        $inventory.ConsentMessage = Format-GraphErrorMessage -Response $sp
    }
    if (-not $sp.Success) {
        $inventory.DelegatedConsentMessage = 'Não verificável: o service principal da aplicação não foi resolvido (pedido não efetuado).'
        $inventory.DelegatedConsentEndpoint = $notRequested
    }

    return $inventory
}

function Get-StateLabel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$State, [bool]$Present)
    if ($State -ne 'Verified') { return 'N/V' }
    if ($Present) { return 'Sim' }
    return 'Não'
}

function Get-PermissionGap {
    [CmdletBinding()]
    param([AllowNull()][pscustomobject]$Inventory)
    $assignedNotConsented = @()
    $consentedNotInToken = @()
    if ($null -ne $Inventory) {
        if ($Inventory.AssignedState -eq 'Verified' -and $Inventory.ConsentState -eq 'Verified') {
            $assignedNotConsented = @($Inventory.AssignedApplication | Where-Object { @($Inventory.ConsentedApplication) -notcontains $_ })
        }
        if ($Inventory.ConsentState -eq 'Verified') {
            $consentedNotInToken = @($Inventory.ConsentedApplication | Where-Object { $_ -notmatch '^\(' -and $script:TokenRoles -notcontains $_ })
        }
    }
    return [pscustomobject]@{
        AssignedNotConsented = $assignedNotConsented
        ConsentedNotInToken  = $consentedNotInToken
        ReadCovered          = (@(Get-MatchingTokenRole -Names $script:ReadPermissions).Count -gt 0)
        SendCovered          = (Test-TokenRole -Name $script:SendPermission)
    }
}

function Get-MissingPermissionLabel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [bool]$ReadCovered)
    if ($script:ReadPermissions -contains $Name) {
        if ($ReadCovered) { return 'Ausente (leitura já coberta por outra permissão)' }
        return 'Necessária mas ausente (leitura: basta uma das 4)'
    }
    if ($Name -eq $script:SendPermission) { return 'Necessária mas ausente (envio)' }
    if ($Name -eq 'User.Read.All') { return 'Ausente (opcional: resolução da caixa)' }
    return 'Ausente'
}

function Show-PermissionTable {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Inventory)

    $gap = Get-PermissionGap -Inventory $Inventory
    $catalogNames = @($script:MailPermissionCatalog | ForEach-Object { $_.Name })
    $otherNames = @(@($Inventory.AssignedApplication) + @($Inventory.ConsentedApplication) + @($script:TokenRoles) |
        Where-Object { $_ -and $catalogNames -notcontains $_ } | Sort-Object -Unique)

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @($catalogNames + $otherNames)) {
        $assigned = Get-StateLabel -State $Inventory.AssignedState -Present (@($Inventory.AssignedApplication) -contains $name)
        $consented = Get-StateLabel -State $Inventory.ConsentState -Present (@($Inventory.ConsentedApplication) -contains $name)
        $inToken = Test-TokenRole -Name $name
        $state = if ($inToken) {
            'Utilizável (presente no token)'
        } elseif ($consented -eq 'Sim') {
            'Consentida mas ausente do token (aguardar propagação / novo token)'
        } elseif ($assigned -eq 'Sim') {
            'Atribuída sem admin consent'
        } elseif ($catalogNames -contains $name) {
            Get-MissingPermissionLabel -Name $name -ReadCovered $gap.ReadCovered
        } else {
            '-'
        }
        $inTokenLabel = 'Não'
        if ($inToken) { $inTokenLabel = 'Sim' }
        elseif (-not $script:RolesKnown) { $inTokenLabel = 'N/D'; $state = 'Roles não determináveis (token não descodificado)' }
        $rows.Add([pscustomobject]@{
            'Permissão'            = $name
            'Tipo'                 = 'Aplicação'
            'Atribuída (App Reg.)' = $assigned
            'Admin consent'        = $consented
            'No token'             = $inTokenLabel
            'Estado'               = $state
        })
    }

    $delegatedNames = @(@($Inventory.AssignedDelegated) + @($Inventory.ConsentedDelegated) + @($Inventory.UserConsentedDelegated) |
        Where-Object { $_ } | Sort-Object -Unique)
    foreach ($name in $delegatedNames) {
        $consentLabel = 'Não'
        if ($Inventory.DelegatedConsentState -ne 'Verified') { $consentLabel = 'N/V' }
        elseif (@($Inventory.ConsentedDelegated) -contains $name) { $consentLabel = 'Sim (admin)' }
        elseif (@($Inventory.UserConsentedDelegated) -contains $name) { $consentLabel = 'Sim (utilizador)' }
        $assignedLabel = Get-StateLabel -State $Inventory.AssignedState -Present (@($Inventory.AssignedDelegated) -contains $name)
        $rows.Add([pscustomobject]@{
            'Permissão'            = $name
            'Tipo'                 = 'Delegada'
            'Atribuída (App Reg.)' = $assignedLabel
            'Admin consent'        = $consentLabel
            'No token'             = 'n/a'
            'Estado'               = 'Informativa: não utilizável com client credentials'
        })
    }

    Write-Section ('Permissões do Microsoft Graph - {0}' -f (Format-DisplayText -Value $Inventory.AppDisplayName -Placeholder '(nome não disponível)'))
    $rows | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    Write-Message 'Legenda: N/V = não verificável. "Atribuída" e "Admin consent" (Aplicação) requerem Application.Read.All; o consentimento delegado (oauth2PermissionGrants) requer Directory.Read.All. A coluna "No token" (claim roles) é a fonte de verdade; N/D = roles não determináveis.' -Color DarkGray
    if ($delegatedNames.Count -gt 0) {
        Write-Message 'Permissões delegadas são apenas informativas: o fluxo client credentials só usa permissões de Aplicação (claim roles).' -Color DarkGray
    }
    if ($Inventory.DelegatedConsentState -ne 'Verified' -and $Inventory.DelegatedConsentMessage) {
        Write-Message ('AVISO (consentimento delegado): {0}' -f $Inventory.DelegatedConsentMessage) -Color Yellow
    }
    foreach ($warning in $Inventory.Warnings) {
        Write-Message ('AVISO (inventário): {0}' -f $warning) -Color Yellow
    }
    if ($Inventory.AssignedState -ne 'Verified' -and $Inventory.AssignedMessage) {
        Write-Message ('AVISO (atribuídas): {0}' -f $Inventory.AssignedMessage) -Color Yellow
    }
    if ($Inventory.ConsentState -ne 'Verified' -and $Inventory.ConsentMessage) {
        Write-Message ('AVISO (admin consent): {0}' -f $Inventory.ConsentMessage) -Color Yellow
    }
    if ($Inventory.NameResolution -eq 'WellKnownIds') {
        Write-Message 'AVISO: o service principal do Graph não foi lido; os nomes são resolvidos por IDs bem conhecidos.' -Color Yellow
    }
    if (@($Inventory.AssignedUnresolved).Count -gt 0) {
        Write-Message ('IDs não resolvidos: {0}' -f (@($Inventory.AssignedUnresolved) -join ', ')) -Color DarkGray
    }

    Write-Host ''
    Write-Message 'Necessárias mas ausentes (para os testes de correio):' -Color White
    if (-not $script:RolesKnown) {
        Write-Message ' - Desconhecido: as roles do token não puderam ser determinadas.' -Color Yellow
        return
    }
    if (-not $gap.ReadCovered) {
        Write-Message ' - Leitura: nenhuma de Mail.ReadBasic, Mail.ReadBasic.All, Mail.Read, Mail.ReadWrite está no token.' -Color Yellow
    }
    if (-not $gap.SendCovered) {
        Write-Message ' - Envio: Mail.Send não está no token.' -Color Yellow
    }
    if ($gap.ReadCovered -and $gap.SendCovered) {
        Write-Message ' - Nenhuma: leitura e envio estão cobertos pelo token.' -Color Green
    }
}

#endregion

#region Testes

function Invoke-ConnectionAndPermissionCheck {
    [CmdletBinding()]
    param([switch]$SkipReauthentication)

    if (-not $SkipReauthentication) {
        Write-Section 'Ligação e autenticação'
        Write-Message 'A obter um novo token (client credentials)...'
        if (Update-GraphToken -Force) {
            Set-AuthFailureSuperseded
            Add-TestResult (New-TestResult -Name 'Autenticação (client credentials)' -Status PASS `
                -RequiredPermission 'Credenciais válidas (Tenant ID, Client ID, Client Secret)' `
                -DetectedPermission (Format-RoleList $script:TokenRoles) -Endpoint (Get-TokenEndpointDisplay) `
                -Detail 'Token obtido com sucesso.')
        }
        else {
            # Update-GraphToken já descartou o token/roles anteriores: os testes ficam bloqueados.
            $script:Inventory = $null
            if ($null -ne $script:LastTokenResult) { Add-TestResult (New-AuthFailureResult -TokenResult $script:LastTokenResult) }
            Write-Message 'Os testes de correio ficam bloqueados até uma autenticação bem-sucedida (opção 1).' -Color Yellow
            return
        }
    }

    Show-TokenInfo
    $claimWarnings = @(Get-TokenClaimWarning)
    if ($claimWarnings.Count -eq 0) {
        Add-TestResult (New-TestResult -Name 'Claims do token (aud/tid/appid/roles)' -Status PASS `
            -RequiredPermission 'aud = Microsoft Graph; appid = Client ID' -DetectedPermission (Format-RoleList $script:TokenRoles) `
            -Endpoint 'Local (descodificação do JWT)' -Detail 'Claims consistentes com os dados introduzidos.')
    }
    else {
        Add-TestResult (New-TestResult -Name 'Claims do token (aud/tid/appid/roles)' -Status WARNING `
            -RequiredPermission 'aud = Microsoft Graph; appid = Client ID' -DetectedPermission (Format-RoleList $script:TokenRoles) `
            -Endpoint 'Local (descodificação do JWT)' -ErrorMessage ($claimWarnings -join ' ') `
            -Recommendation 'Confirme o tenant/aplicação e se as permissões de Aplicação têm admin consent.')
    }

    Write-Message 'A recolher o inventário de permissões...'
    $script:Inventory = Get-AppPermissionInventory
    $inventory = $script:Inventory
    Show-PermissionTable -Inventory $inventory
    $gap = Get-PermissionGap -Inventory $inventory
    $tradeOff = 'Opcional: conceda temporariamente Application.Read.All (Aplicação) ou use uma app de diagnóstico com admin consent. O estado "No token" continua a ser fiável sem esta permissão.'
    $grantTradeOff = 'Opcional e apenas informativo: o consentimento delegado requer Directory.Read.All (privilégio elevado). Conceda-a só temporariamente ou numa app de diagnóstico.'

    if ($inventory.AssignedState -eq 'Verified') {
        Add-TestResult (New-TestResult -Name 'Permissões atribuídas no App Registration' -Status PASS `
            -RequiredPermission 'Application.Read.All (opcional)' -DetectedPermission (Format-RoleList $inventory.AssignedApplication) `
            -Endpoint $inventory.AssignedEndpoint -Detail ('Delegadas atribuídas: {0}' -f (Format-RoleList $inventory.AssignedDelegated)))
    }
    else {
        Add-TestResult (New-TestResult -Name 'Permissões atribuídas no App Registration' -Status WARNING `
            -RequiredPermission 'Application.Read.All (opcional)' -DetectedPermission 'não verificável' `
            -Endpoint $inventory.AssignedEndpoint -ErrorMessage $inventory.AssignedMessage -Recommendation $tradeOff)
    }

    if ($inventory.ConsentState -eq 'Verified') {
        $issues = [System.Collections.Generic.List[string]]::new()
        if ($gap.AssignedNotConsented.Count -gt 0) { $issues.Add(('Atribuídas sem admin consent: {0}.' -f ($gap.AssignedNotConsented -join ', '))) }
        if ($gap.ConsentedNotInToken.Count -gt 0) { $issues.Add(('Consentidas mas ausentes do token: {0}.' -f ($gap.ConsentedNotInToken -join ', '))) }
        if ($issues.Count -eq 0) {
            Add-TestResult (New-TestResult -Name 'Admin consent (permissões de Aplicação)' -Status PASS `
                -RequiredPermission 'Application.Read.All (opcional)' -DetectedPermission (Format-RoleList $inventory.ConsentedApplication) `
                -Endpoint $inventory.ConsentEndpoint -Detail 'Consentimento coerente com o registo e com o token.')
        }
        else {
            Add-TestResult (New-TestResult -Name 'Admin consent (permissões de Aplicação)' -Status WARNING `
                -RequiredPermission 'Application.Read.All (opcional)' -DetectedPermission (Format-RoleList $inventory.ConsentedApplication) `
                -Endpoint $inventory.ConsentEndpoint -ErrorMessage ($issues -join ' ') `
                -Recommendation 'Conceda admin consent (API permissions > Grant admin consent). Depois aguarde a propagação e obtenha um novo token (opção 1).')
        }
    }
    else {
        Add-TestResult (New-TestResult -Name 'Admin consent (permissões de Aplicação)' -Status WARNING `
            -RequiredPermission 'Application.Read.All (opcional)' -DetectedPermission 'não verificável' `
            -Endpoint $inventory.ConsentEndpoint -ErrorMessage $inventory.ConsentMessage -Recommendation $tradeOff)
    }

    if ($inventory.DelegatedConsentState -eq 'Verified') {
        Add-TestResult (New-TestResult -Name 'Consentimento delegado (informativo)' -Status PASS `
            -RequiredPermission 'Directory.Read.All (opcional)' -DetectedPermission (Format-RoleList $inventory.ConsentedDelegated) `
            -Endpoint $inventory.DelegatedConsentEndpoint `
            -Detail ('Consentimento de utilizador: {0}. Permissões delegadas não são usadas por client credentials.' -f (Format-RoleList $inventory.UserConsentedDelegated)))
    }
    else {
        Add-TestResult (New-TestResult -Name 'Consentimento delegado (informativo)' -Status WARNING `
            -RequiredPermission 'Directory.Read.All (opcional)' -DetectedPermission 'não verificável' `
            -Endpoint $inventory.DelegatedConsentEndpoint -ErrorMessage $inventory.DelegatedConsentMessage -Recommendation $grantTradeOff)
    }

    if ($inventory.Warnings.Count -gt 0) {
        Add-TestResult (New-TestResult -Name 'Inventário de permissões (paginação)' -Status WARNING `
            -RequiredPermission '-' -DetectedPermission '-' -Endpoint 'GET (coleções paginadas)' `
            -ErrorMessage ($inventory.Warnings -join ' ') `
            -Recommendation 'Resultado incompleto: verifique as permissões diretamente no portal do Entra ID.')
    }

    if (-not $script:RolesKnown) {
        Add-TestResult (New-TestResult -Name 'Capacidades de leitura/envio (claim roles)' -Status WARNING `
            -RequiredPermission (($script:ReadPermissions + $script:SendPermission) -join ' | ') -DetectedPermission 'roles não determináveis' `
            -Endpoint 'Local (claim roles)' -ErrorMessage 'O token não pôde ser descodificado; os testes de correio serão ignorados (SKIPPED).' `
            -Recommendation 'Use a opção 1 para obter um novo token; se persistir, verifique proxies que alterem a resposta de autenticação.')
        return
    }

    $readRoles = @(Get-MatchingTokenRole -Names $script:ReadPermissions)
    $readStatus = if ($readRoles.Count -gt 0) { 'PASS' } else { 'WARNING' }
    Add-TestResult (New-TestResult -Name 'Capacidade de leitura (claim roles)' -Status $readStatus `
        -RequiredPermission ($script:ReadPermissions -join ' | ') -DetectedPermission (Format-RoleList $readRoles) `
        -Endpoint 'Local (claim roles)' `
        -ErrorMessage $(if ($readRoles.Count -eq 0) { 'Necessária mas ausente: nenhuma permissão de leitura no token.' } else { '-' }) `
        -Recommendation $(if ($readRoles.Count -eq 0) { 'Adicione Mail.ReadBasic (metadados) ou Mail.Read (Aplicação), conceda admin consent e obtenha novo token.' } else { '-' }))

    $sendStatus = if ($gap.SendCovered) { 'PASS' } else { 'WARNING' }
    Add-TestResult (New-TestResult -Name 'Capacidade de envio (claim roles)' -Status $sendStatus `
        -RequiredPermission $script:SendPermission -DetectedPermission $(if ($gap.SendCovered) { $script:SendPermission } else { '(nenhuma)' }) `
        -Endpoint 'Local (claim roles)' `
        -ErrorMessage $(if (-not $gap.SendCovered) { 'Necessária mas ausente: Mail.Send não está no token.' } else { '-' }) `
        -Recommendation $(if (-not $gap.SendCovered) { 'Adicione Mail.Send (Aplicação), conceda admin consent e obtenha novo token.' } else { '-' }))
}

function Format-Sender {
    [CmdletBinding()]
    param([AllowNull()][object]$Message)
    $address = Get-SafeProperty $Message @('from', 'emailAddress', 'address')
    $name = Get-SafeProperty $Message @('from', 'emailAddress', 'name')
    if ($address -and $name -and $name -ne $address) { return (Format-DisplayText -Value ('{0} <{1}>' -f $name, $address) -MaxLength 50) }
    if ($address) { return (Format-DisplayText -Value $address -MaxLength 50) }
    return (Format-DisplayText -Value $name -MaxLength 50)
}

function Test-MailRead {
    [CmdletBinding()]
    param()

    Write-Section 'Teste de leitura de e-mails'
    $testName = 'Leitura de e-mails'
    $required = 'Uma de: ' + ($script:ReadPermissions -join ', ')
    if (-not (Test-SessionUsable -TestName $testName -RequiredPermission $required)) { return }
    $readRoles = @(Get-MatchingTokenRole -Names $script:ReadPermissions)
    $detected = Format-RoleList $readRoles

    if ($readRoles.Count -eq 0) {
        Write-Message 'Teste ignorado: o token não contém nenhuma permissão de leitura de correio. Nenhum pedido foi feito ao Graph.' -Color Cyan
        Add-TestResult (New-TestResult -Name $testName -Status SKIPPED -SkipReason MissingPermission `
            -RequiredPermission $required -DetectedPermission $detected -Endpoint 'Nenhum (pedido não efetuado)' `
            -ErrorMessage 'Necessária mas ausente: nenhuma permissão de leitura na claim roles.' `
            -Recommendation 'Adicione Mail.ReadBasic (só metadados) ou Mail.Read (Aplicação), conceda admin consent, aguarde a propagação e obtenha um novo token (opção 1).')
        return
    }
    if (@($readRoles | Where-Object { $_ -notlike 'Mail.ReadBasic*' }).Count -eq 0) {
        Write-Message 'Apenas Mail.ReadBasic*: estão disponíveis metadados (assunto, remetente, datas), mas não o corpo nem anexos.' -Color DarkGray
    }

    $mailbox = Read-Mailbox -Prompt 'Caixa de correio a ler (UPN/e-mail)' -DefaultValue $script:LastMailbox
    $script:LastMailbox = $mailbox
    $relativeUri = (Get-UserResourcePath -Mailbox $mailbox) +
        '/mailFolders/inbox/messages?$top=5&$select=id,subject,from,receivedDateTime&$orderby=receivedDateTime%20desc'
    $endpoint = 'GET ' + $relativeUri

    if (-not (Confirm-Action -Message ("Confirma a leitura dos metadados das 5 mensagens mais recentes da Caixa de Entrada de '{0}'?" -f $mailbox))) {
        Add-TestResult (New-TestResult -Name $testName -Status SKIPPED -SkipReason UserCancelled `
            -RequiredPermission $required -DetectedPermission $detected -Endpoint 'Nenhum (cancelado pelo utilizador)' `
            -ErrorMessage 'Leitura não confirmada pelo utilizador.')
        return
    }

    $response = Invoke-GraphRequest -Method GET -Uri $relativeUri
    if ($response.Success) {
        $messages = @(@(Get-SafeProperty $response.Data 'value') | Where-Object { $null -ne $_ })
        if ($messages.Count -gt 0) {
            $display = foreach ($message in $messages) {
                [pscustomobject]@{
                    'Recebida em' = Format-GraphDate -Value (Get-SafeProperty $message 'receivedDateTime')
                    'De'          = Format-Sender -Message $message
                    'Assunto'     = Format-DisplayText -Value (Get-SafeProperty $message 'subject') -MaxLength 60 -Placeholder '(sem assunto)'
                    'Id'          = Format-DisplayText -Value (Get-SafeProperty $message 'id') -MaxLength 16
                }
            }
            $display | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        }
        else {
            Write-Message 'A Caixa de Entrada não devolveu mensagens (pode estar vazia).' -Color DarkGray
        }
        Add-TestResult (New-TestResult -Name $testName -Status PASS -RequiredPermission $required `
            -DetectedPermission $detected -Endpoint $endpoint `
            -Detail ('{0} mensagem(ns) lida(s) da Caixa de Entrada de {1} (apenas metadados; corpo e anexos não foram pedidos).' -f $messages.Count, $mailbox))
        return
    }

    $guidance = Get-GraphFailureGuidance -Response $response -Operation Read -Mailbox $mailbox
    Add-TestResult (New-TestResult -Name $testName -Status FAIL -RequiredPermission $required `
        -DetectedPermission $detected -Endpoint $endpoint -ErrorMessage $guidance.ErrorMessage `
        -Recommendation $guidance.Recommendation)
}

function Test-MailSend {
    [CmdletBinding()]
    param()

    Write-Section 'Teste de envio de e-mail'
    $testName = 'Envio de e-mail'
    $required = $script:SendPermission
    if (-not (Test-SessionUsable -TestName $testName -RequiredPermission $required)) { return }

    if (-not (Test-TokenRole -Name $script:SendPermission)) {
        Write-Message 'Teste ignorado: o token não contém Mail.Send. Nenhum pedido foi feito ao Graph.' -Color Cyan
        Add-TestResult (New-TestResult -Name $testName -Status SKIPPED -SkipReason MissingPermission `
            -RequiredPermission $required -DetectedPermission '(nenhuma)' -Endpoint 'Nenhum (pedido não efetuado)' `
            -ErrorMessage 'Necessária mas ausente: Mail.Send não está na claim roles.' `
            -Recommendation 'Adicione Mail.Send (Aplicação), conceda admin consent, aguarde a propagação e obtenha um novo token (opção 1).')
        return
    }

    $sender = Read-Mailbox -Prompt 'Caixa remetente (UPN/e-mail)' -DefaultValue $script:LastMailbox
    $script:LastMailbox = $sender
    $recipient = Read-Mailbox -Prompt 'Destinatário (e-mail)'
    $defaultSubject = 'Teste de diagnóstico Microsoft Graph - {0:yyyy-MM-dd HH:mm}' -f (Get-Date)
    $subject = Read-RequiredInput -Prompt 'Assunto' -DefaultValue $defaultSubject `
        -Validator { param($v) $v.Length -le 255 } -ValidationMessage 'O assunto não pode exceder 255 caracteres.'
    $defaultBody = 'Mensagem de teste enviada pela ferramenta Test-EntraAppMailPermissions. Pode ignorar.'
    $bodyText = Read-RequiredInput -Prompt 'Corpo (texto simples, uma linha)' -DefaultValue $defaultBody `
        -Validator { param($v) $v.Length -le 4000 } -ValidationMessage 'O corpo não pode exceder 4000 caracteres.'

    $relativeUri = (Get-UserResourcePath -Mailbox $sender) + '/sendMail'
    $endpoint = 'POST ' + $relativeUri

    Write-Host ''
    Write-Message 'Resumo do envio:' -Color White
    Write-Message ('  Remetente               : {0}' -f $sender)
    Write-Message ('  Destinatário            : {0}' -f $recipient)
    Write-Message ('  Assunto                 : {0}' -f $subject)
    Write-Message ('  Corpo ({0} caracteres)  : {1}' -f $bodyText.Length, (Format-DisplayText -Value $bodyText -MaxLength 80))
    Write-Message  '  Guardar em Itens Enviados: Sim'
    Write-Message ('  Endpoint                : {0}' -f $endpoint)

    if (-not (Confirm-Action -Message 'Confirma o envio?')) {
        Add-TestResult (New-TestResult -Name $testName -Status SKIPPED -SkipReason UserCancelled `
            -RequiredPermission $required -DetectedPermission $script:SendPermission -Endpoint 'Nenhum (cancelado pelo utilizador)' `
            -ErrorMessage 'Envio não confirmado pelo utilizador.')
        return
    }

    $payload = @{
        message = @{
            subject      = $subject
            body         = @{ contentType = 'Text'; content = $bodyText }
            toRecipients = @(@{ emailAddress = @{ address = $recipient } })
        }
        saveToSentItems = $true
    }
    $response = Invoke-GraphRequest -Method POST -Uri $relativeUri -Body $payload -MaxRetries 2

    if ($response.Success -and $response.StatusCode -eq 202) {
        Add-TestResult (New-TestResult -Name $testName -Status PASS -RequiredPermission $required `
            -DetectedPermission $script:SendPermission -Endpoint $endpoint `
            -Detail ('Pedido aceite (HTTP 202). A entrega é assíncrona: confirme na caixa de {0} e em Itens Enviados de {1}.' -f $recipient, $sender))
        return
    }
    if ($response.Success) {
        Add-TestResult (New-TestResult -Name $testName -Status WARNING -RequiredPermission $required `
            -DetectedPermission $script:SendPermission -Endpoint $endpoint `
            -ErrorMessage ('Resposta inesperada: HTTP {0} (esperado 202).' -f $response.StatusCode) `
            -Recommendation 'Confirme se a mensagem chegou ao destinatário.')
        return
    }
    if ($response.OutcomeUnknown) {
        # Erro de rede/timeout (ou HTTP 504) depois de enviar o pedido: o e-mail pode ter sido enviado.
        Add-TestResult (New-TestResult -Name $testName -Status WARNING -RequiredPermission $required `
            -DetectedPermission $script:SendPermission -Endpoint $endpoint `
            -ErrorMessage ('Estado do envio desconhecido. {0}' -f (Format-GraphErrorMessage -Response $response)) `
            -Recommendation ('O pedido pode ter sido processado. Antes de repetir, verifique Itens Enviados de {0} (e a caixa de {1}); o envio não é repetido automaticamente.' -f $sender, $recipient))
        return
    }

    $guidance = Get-GraphFailureGuidance -Response $response -Operation Send -Mailbox $sender
    Add-TestResult (New-TestResult -Name $testName -Status FAIL -RequiredPermission $required `
        -DetectedPermission $script:SendPermission -Endpoint $endpoint -ErrorMessage $guidance.ErrorMessage `
        -Recommendation $guidance.Recommendation)
}

function Get-PermissionRecommendation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Permission,
        [Parameter(Mandatory)][pscustomobject]$Inventory,
        [bool]$ReadCovered
    )
    $name = $Permission.Name
    if (Test-TokenRole -Name $name) { return ('Detetada no token. {0}' -f $Permission.Recommendation) }
    if ($Inventory.ConsentState -eq 'Verified' -and @($Inventory.ConsentedApplication) -contains $name) {
        return 'Consentida mas ausente do token: aguarde a propagação e obtenha um novo token (opção 1).'
    }
    if ($Inventory.AssignedState -eq 'Verified' -and @($Inventory.AssignedApplication) -contains $name) {
        return 'Atribuída sem admin consent: conceda admin consent em API permissions.'
    }
    if (($script:ReadPermissions -contains $name) -and $ReadCovered) {
        return 'Não necessária: a leitura já está coberta por outra permissão no token.'
    }
    return ('Não detetada. {0}' -f $Permission.Recommendation)
}

function Test-MailPermissionMatrix {
    [CmdletBinding()]
    param()

    Write-Section 'Matriz de permissões Mail'
    if (-not (Test-SessionUsable -TestName 'Matriz de permissões Mail' -RequiredPermission 'Mail.* conforme a capacidade pretendida')) { return }
    if ($null -eq $script:Inventory) {
        Write-Message 'A recolher o inventário de permissões...'
        $script:Inventory = Get-AppPermissionInventory
    }
    $inventory = $script:Inventory
    $gap = Get-PermissionGap -Inventory $inventory

    $rows = foreach ($permission in $script:MailPermissionCatalog) {
        $name = $permission.Name
        $detectedLabel = 'Não'
        if (Test-TokenRole -Name $name) { $detectedLabel = 'Sim' }
        $consentedLabel = Get-StateLabel -State $inventory.ConsentState -Present (@($inventory.ConsentedApplication) -contains $name)
        $assignedLabel = Get-StateLabel -State $inventory.AssignedState -Present (@($inventory.AssignedApplication) -contains $name)
        $delegatedLabel = Get-StateLabel -State $inventory.AssignedState -Present (@($inventory.AssignedDelegated) -contains $name)
        [pscustomobject]@{
            'Permissão'          = $name
            'Capacidade'         = $permission.Capability
            'Detetada (token)'   = $detectedLabel
            'Consentida'         = $consentedLabel
            'Atribuída'          = $assignedLabel
            'Delegada atribuída' = $delegatedLabel
        }
    }
    $rows | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
    Write-Message 'Recomendações por permissão:' -Color White
    foreach ($permission in $script:MailPermissionCatalog) {
        Write-Message (' - {0}: {1}' -f $permission.Name, (Get-PermissionRecommendation -Permission $permission -Inventory $inventory -ReadCovered $gap.ReadCovered))
    }

    $mailRoles = @(Get-MatchingTokenRole -Names @($script:MailPermissionCatalog | ForEach-Object { $_.Name }))
    $issues = [System.Collections.Generic.List[string]]::new()
    if ($gap.AssignedNotConsented.Count -gt 0) { $issues.Add(('Atribuídas sem admin consent: {0}.' -f ($gap.AssignedNotConsented -join ', '))) }
    if ($gap.ConsentedNotInToken.Count -gt 0) { $issues.Add(('Consentidas mas ausentes do token: {0}.' -f ($gap.ConsentedNotInToken -join ', '))) }
    if ($inventory.AssignedState -ne 'Verified' -or $inventory.ConsentState -ne 'Verified') {
        $issues.Add('Estados atribuída/consentida não verificáveis sem Application.Read.All.')
    }
    $matrixStatus = if ($issues.Count -eq 0) { 'PASS' } else { 'WARNING' }
    Add-TestResult (New-TestResult -Name 'Matriz de permissões Mail' -Status $matrixStatus `
        -RequiredPermission 'Mail.* conforme a capacidade pretendida' -DetectedPermission (Format-RoleList $mailRoles) `
        -Endpoint 'Local (token) + inventário' -ErrorMessage $(if ($issues.Count -gt 0) { $issues -join ' ' } else { '-' }) `
        -Recommendation 'Mantenha apenas as permissões estritamente necessárias (privilégio mínimo).')

    if (-not (Confirm-Action -Message 'Pretende executar sondagens não destrutivas por capacidade (nada é criado, alterado, apagado ou enviado)?')) {
        Write-Message 'Sondagens não executadas.' -Color DarkGray
        return
    }
    $mailbox = Read-Mailbox -Prompt 'Caixa de correio para as sondagens (UPN/e-mail)' -DefaultValue $script:LastMailbox
    $script:LastMailbox = $mailbox
    if (-not (Confirm-Action -Message ("Confirma as sondagens (apenas leitura de identificadores) sobre '{0}'?" -f $mailbox))) {
        Add-TestResult (New-TestResult -Name 'Sondagens não destrutivas' -Status SKIPPED -SkipReason UserCancelled `
            -Endpoint 'Nenhum (cancelado pelo utilizador)' -ErrorMessage 'Sondagens não confirmadas pelo utilizador.')
        return
    }
    $userPath = Get-UserResourcePath -Mailbox $mailbox

    # Sonda 1: resolução da caixa (User.Read.All, opcional)
    $userUri = $userPath + '?$select=id,userPrincipalName,mail'
    if (Test-TokenRole -Name 'User.Read.All') {
        $user = Invoke-GraphRequest -Method GET -Uri $userUri
        if ($user.Success) {
            Add-TestResult (New-TestResult -Name 'Sonda: resolução da caixa' -Status PASS -RequiredPermission 'User.Read.All' `
                -DetectedPermission 'User.Read.All' -Endpoint ('GET ' + $userUri) `
                -Detail ('UPN: {0} | mail: {1} | id: {2}' -f (Format-DisplayText (Get-SafeProperty $user.Data 'userPrincipalName')),
                    (Format-DisplayText (Get-SafeProperty $user.Data 'mail')), (Format-DisplayText (Get-SafeProperty $user.Data 'id') -MaxLength 13)))
        }
        else {
            $guidance = Get-GraphFailureGuidance -Response $user -Operation ResolveUser -Mailbox $mailbox
            Add-TestResult (New-TestResult -Name 'Sonda: resolução da caixa' -Status FAIL -RequiredPermission 'User.Read.All' `
                -DetectedPermission 'User.Read.All' -Endpoint ('GET ' + $userUri) -ErrorMessage $guidance.ErrorMessage `
                -Recommendation $guidance.Recommendation)
        }
    }
    else {
        Add-TestResult (New-TestResult -Name 'Sonda: resolução da caixa' -Status SKIPPED -SkipReason MissingPermission `
            -RequiredPermission 'User.Read.All (opcional)' -DetectedPermission '(nenhuma)' -Endpoint 'Nenhum (pedido não efetuado)' `
            -ErrorMessage 'User.Read.All não está no token.' -Recommendation 'Opcional: os testes de correio funcionam com o UPN direto.')
    }

    # Sonda 2: leitura mínima (apenas id)
    $readRoles = @(Get-MatchingTokenRole -Names $script:ReadPermissions)
    $probeUri = $userPath + '/mailFolders/inbox/messages?$top=1&$select=id'
    if ($readRoles.Count -gt 0) {
        $probe = Invoke-GraphRequest -Method GET -Uri $probeUri
        if ($probe.Success) {
            $count = @(@(Get-SafeProperty $probe.Data 'value') | Where-Object { $null -ne $_ }).Count
            Add-TestResult (New-TestResult -Name 'Sonda: leitura mínima (apenas id)' -Status PASS `
                -RequiredPermission ('Uma de: ' + ($script:ReadPermissions -join ', ')) -DetectedPermission (Format-RoleList $readRoles) `
                -Endpoint ('GET ' + $probeUri) -Detail ('Leitura possível ({0} identificador(es) devolvido(s)). A sonda valida a capacidade combinada do token, não cada permissão isoladamente.' -f $count))
        }
        else {
            $guidance = Get-GraphFailureGuidance -Response $probe -Operation Read -Mailbox $mailbox
            Add-TestResult (New-TestResult -Name 'Sonda: leitura mínima (apenas id)' -Status FAIL `
                -RequiredPermission ('Uma de: ' + ($script:ReadPermissions -join ', ')) -DetectedPermission (Format-RoleList $readRoles) `
                -Endpoint ('GET ' + $probeUri) -ErrorMessage $guidance.ErrorMessage -Recommendation $guidance.Recommendation)
        }
    }
    else {
        Add-TestResult (New-TestResult -Name 'Sonda: leitura mínima (apenas id)' -Status SKIPPED -SkipReason MissingPermission `
            -RequiredPermission ('Uma de: ' + ($script:ReadPermissions -join ', ')) -DetectedPermission '(nenhuma)' `
            -Endpoint 'Nenhum (pedido não efetuado)' -ErrorMessage 'Nenhuma permissão de leitura no token.' `
            -Recommendation 'Adicione Mail.ReadBasic (metadados) ou Mail.Read (Aplicação) com admin consent.')
    }

    # Sonda 3: escrita (apenas reportada; nunca testada)
    if (Test-TokenRole -Name 'Mail.ReadWrite') {
        Add-TestResult (New-TestResult -Name 'Sonda: escrita (Mail.ReadWrite)' -Status SKIPPED -SkipReason NotTestedByDesign `
            -RequiredPermission 'Mail.ReadWrite' -DetectedPermission 'Mail.ReadWrite' -Endpoint 'Nenhum (não testado por ser destrutivo)' `
            -ErrorMessage 'Detetada no token; intencionalmente não testada (nada é criado, alterado ou apagado).' `
            -Recommendation 'Confirme que a aplicação precisa mesmo de escrita; caso contrário remova Mail.ReadWrite.')
    }

    # Sonda 4: envio (apenas reportado; nunca envia)
    if (Test-TokenRole -Name $script:SendPermission) {
        Add-TestResult (New-TestResult -Name 'Sonda: envio (Mail.Send)' -Status SKIPPED -SkipReason NotTestedByDesign `
            -RequiredPermission $script:SendPermission -DetectedPermission $script:SendPermission -Endpoint 'Nenhum (não envia nesta opção)' `
            -ErrorMessage 'Detetada no token; não foi enviado nenhum e-mail nesta opção.' `
            -Recommendation 'Use a opção 3 para um teste real de envio (com confirmação).')
    }
    else {
        Add-TestResult (New-TestResult -Name 'Sonda: envio (Mail.Send)' -Status SKIPPED -SkipReason MissingPermission `
            -RequiredPermission $script:SendPermission -DetectedPermission '(nenhuma)' -Endpoint 'Nenhum (pedido não efetuado)' `
            -ErrorMessage 'Mail.Send não está no token.' -Recommendation 'Adicione Mail.Send (Aplicação) com admin consent se precisar de enviar.')
    }
}

#endregion

#region Resumo e menu

function Get-ConfigurationRecommendation {
    [CmdletBinding()]
    param()
    $list = [System.Collections.Generic.List[string]]::new()
    $gap = Get-PermissionGap -Inventory $script:Inventory
    $authOk = @($script:Results | Where-Object {
            $_.TestName -eq 'Autenticação (client credentials)' -and $_.Status -eq 'PASS' }).Count -gt 0

    if ($script:SessionBlocked -or -not $authOk) {
        $list.Add('Autenticação: corrija primeiro a causa indicada no teste "Autenticação (client credentials)" e volte a executar.')
    }
    elseif (-not $script:RolesKnown) {
        $list.Add('Roles não determináveis: o token não pôde ser descodificado. Obtenha um novo token e verifique proxies que alterem a resposta.')
    }
    else {
        if (-not $gap.ReadCovered) { $list.Add('Leitura: adicione Mail.ReadBasic (ou Mail.Read se precisar do corpo/anexos) como permissão de Aplicação.') }
        if (-not $gap.SendCovered) { $list.Add('Envio: adicione Mail.Send como permissão de Aplicação.') }
    }
    if ($gap.AssignedNotConsented.Count -gt 0) {
        $list.Add(('Conceda admin consent para: {0} (API permissions > Grant admin consent).' -f ($gap.AssignedNotConsented -join ', ')))
    }
    if ($gap.ConsentedNotInToken.Count -gt 0) {
        $list.Add(('Consentidas mas ausentes do token: {0}. Aguarde a propagação e obtenha um novo token.' -f ($gap.ConsentedNotInToken -join ', ')))
    }
    if ((Test-TokenRole -Name 'Mail.Read') -and -not (Test-TokenRole -Name 'Mail.ReadBasic') -and -not (Test-TokenRole -Name 'Mail.ReadBasic.All')) {
        $list.Add('Privilégio mínimo: se só precisa de metadados, substitua Mail.Read por Mail.ReadBasic.')
    }
    if (Test-TokenRole -Name 'Mail.ReadWrite') {
        $list.Add('Mail.ReadWrite detetada: remova-a se a aplicação não precisa de criar/alterar/apagar mensagens.')
    }
    if (Test-TokenRole -Name 'Application.Read.All') {
        $list.Add('Application.Read.All detetada: se foi concedida apenas para este diagnóstico, remova-a no fim.')
    }
    if (Test-TokenRole -Name 'Directory.Read.All') {
        $list.Add('Directory.Read.All detetada: é uma permissão de privilégio elevado; se foi concedida apenas para este diagnóstico, remova-a no fim.')
    }
    if ($null -ne $script:Inventory -and ($script:Inventory.AssignedState -ne 'Verified' -or $script:Inventory.ConsentState -ne 'Verified')) {
        $list.Add('Para ver os estados atribuída/consentida, conceda temporariamente Application.Read.All ou use uma app de diagnóstico.')
    }
    if (@($script:Results | Where-Object { $_.Status -eq 'WARNING' -and $_.ErrorMessage -like 'Estado do envio desconhecido*' }).Count -gt 0) {
        $list.Add('Houve um envio com estado desconhecido: confirme em Itens Enviados do remetente antes de repetir o teste.')
    }
    if (@($script:Results | Where-Object { $_.Status -eq 'FAIL' -and $_.TestName -ne 'Sonda: resolução da caixa' -and $_.ErrorMessage -match 'HTTP 403' }).Count -gt 0) {
        $list.Add('Houve HTTP 403 com a permissão presente: verifique Application Access Policy / RBAC for Applications no Exchange Online.')
    }

    $list.Add('Fluxo de correção: adicionar a permissão em falta (tipo Aplicação) -> conceder admin consent -> aguardar a propagação -> obter um novo token.')
    $list.Add('Privilégio mínimo: prefira Mail.ReadBasic a Mail.Read quando só precisa de metadados; evite Mail.ReadWrite se não altera mensagens.')
    $list.Add('Restrinja o acesso às caixas com RBAC for Applications no Exchange Online (ou a Application Access Policy, legada).')
    $list.Add('Em produção use certificados, managed identities ou workload identity federation em vez de client secrets.')
    $list.Add('Rode os segredos regularmente, com validade curta, guarde-os num cofre (ex.: Azure Key Vault) e remova segredos antigos.')
    return $list.ToArray()
}

function Write-Summary {
    [CmdletBinding()]
    param()
    Write-Section 'Resumo final'
    $everything = @($script:Results)
    # Falhas de autenticação ultrapassadas por uma autenticação posterior não contam (nem no código de saída).
    $all = @($everything | Where-Object { -not $_.Superseded })
    $supersededCount = $everything.Count - $all.Count
    $pass = @($all | Where-Object { $_.Status -eq 'PASS' }).Count
    $fail = @($all | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warning = @($all | Where-Object { $_.Status -eq 'WARNING' }).Count
    $skipped = @($all | Where-Object { $_.Status -eq 'SKIPPED' })
    $skippedMissing = @($skipped | Where-Object { $_.SkipReason -eq 'MissingPermission' }).Count
    $skippedUser = @($skipped | Where-Object { $_.SkipReason -eq 'UserCancelled' }).Count
    $skippedDesign = @($skipped | Where-Object { $_.SkipReason -eq 'NotTestedByDesign' }).Count
    $skippedToken = @($skipped | Where-Object { $_.SkipReason -eq 'NoValidToken' }).Count

    Write-Host ('  {0,-38}: {1}' -f 'Testes executados', $all.Count)
    Write-Host ('  {0,-38}: ' -f 'PASS') -NoNewline; Write-Host $pass -ForegroundColor Green
    Write-Host ('  {0,-38}: ' -f 'FAIL') -NoNewline; Write-Host $fail -ForegroundColor Red
    Write-Host ('  {0,-38}: ' -f 'SKIPPED (permissões em falta)') -NoNewline; Write-Host $skippedMissing -ForegroundColor Cyan
    Write-Host ('  {0,-38}: ' -f 'SKIPPED (cancelados pelo utilizador)') -NoNewline; Write-Host $skippedUser -ForegroundColor Cyan
    Write-Host ('  {0,-38}: ' -f 'SKIPPED (não testados por segurança)') -NoNewline; Write-Host $skippedDesign -ForegroundColor Cyan
    if ($skippedToken -gt 0) {
        Write-Host ('  {0,-38}: ' -f 'SKIPPED (sem token / roles desconhecidas)') -NoNewline; Write-Host $skippedToken -ForegroundColor Cyan
    }
    Write-Host ('  {0,-38}: ' -f 'WARNING') -NoNewline; Write-Host $warning -ForegroundColor Yellow
    if ($supersededCount -gt 0) {
        Write-Host ('  {0,-38}: {1}' -f 'Falhas de autenticação ultrapassadas', $supersededCount) -ForegroundColor DarkGray
    }

    if ($everything.Count -gt 0) {
        Write-Host ''
        Write-Message 'Resultados:' -Color White
        foreach ($result in $everything) {
            Write-Host '    ' -NoNewline
            if ($result.Superseded) {
                Write-Host ('[{0,-7}] {1} (ultrapassada por uma autenticação posterior; não conta)' -f $result.Status, $result.TestName) -ForegroundColor DarkGray
                continue
            }
            Write-Host ('[{0,-7}]' -f $result.Status) -ForegroundColor (Get-StatusColor -Status $result.Status) -NoNewline
            Write-Host (' {0}' -f $result.TestName)
        }
    }

    Write-Host ''
    Write-Message 'Recomendações de configuração (Entra ID / Exchange Online):' -Color White
    $index = 0
    foreach ($recommendation in (Get-ConfigurationRecommendation)) {
        $index++
        Write-Message ('{0,2}. {1}' -f $index, $recommendation)
    }
    Write-Host ''
}

function Show-Menu {
    [CmdletBinding()]
    param()
    $appName = Format-DisplayText -Value (Get-SafeProperty $script:TokenClaims 'app_displayname') -Placeholder $script:ClientId
    if ($null -eq $script:AccessToken) {
        $tokenLabel = 'sem token válido (use a opção 1)'
    }
    else {
        $tokenLabel = 'faltam {0} min' -f [math]::Floor(($script:TokenExpiresOn - [DateTimeOffset]::UtcNow).TotalMinutes)
    }
    $rolesLabel = if ($script:RolesKnown) { [string]@($script:TokenRoles).Count } else { 'N/D' }
    Write-Host ''
    Write-Host '============================ MENU ============================' -ForegroundColor Cyan
    Write-Host ('  Aplicação: {0} | Token: {1} | Roles: {2}' -f $appName, $tokenLabel, $rolesLabel) -ForegroundColor DarkGray
    Write-Host '  [1] Testar apenas ligação e permissões'
    Write-Host '  [2] Testar leitura de e-mails'
    Write-Host '  [3] Testar envio de e-mails'
    Write-Host '  [4] Testar leitura e envio'
    Write-Host '  [5] Testar permissões específicas de Mail'
    Write-Host '  [6] Sair'
    $maxInvalid = 5
    for ($invalid = 0; $invalid -lt $maxInvalid; $invalid++) {
        $raw = Read-Host -Prompt 'Escolha uma opção (1-6)'
        if ($null -eq $raw) {
            Write-Message 'Fim da entrada (EOF): a sair.' -Color Yellow
            return '6'
        }
        $choice = ([string]$raw).Trim()
        if ($choice -match '^[1-6]$') { return $choice }
        Write-Message 'Opção inválida. Indique um número de 1 a 6.' -Color Yellow
    }
    Write-Message ('{0} opções inválidas seguidas: a sair.' -f $maxInvalid) -Color Yellow
    return '6'
}

function Connect-GraphApp {
    [CmdletBinding()]
    param()
    while ($true) {
        Write-Section 'Credenciais da aplicação'
        $script:TenantId = Read-RequiredInput -Prompt 'Tenant ID (GUID ou domínio, ex.: contoso.onmicrosoft.com)' `
            -Validator { param($v) Test-TenantIdFormat -Value $v } `
            -ValidationMessage 'Tenant ID inválido: indique um GUID ou um domínio (ex.: contoso.onmicrosoft.com).'
        $script:ClientId = Read-RequiredInput -Prompt 'Client ID (Application ID)' `
            -Validator { param($v) Test-GuidFormat -Value $v } `
            -ValidationMessage 'Client ID inválido: tem de ser um GUID (ex.: 11111111-2222-3333-4444-555555555555).'
        $script:ClientSecret = Read-ClientSecret

        Write-Message 'A autenticar no Microsoft Entra ID (client credentials)...'
        $tokenResult = Get-GraphToken -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $script:ClientSecret
        if ($tokenResult.Success) {
            Set-SessionToken -TokenResult $tokenResult
            $tokenResult = $null
            Set-AuthFailureSuperseded
            Write-Message 'Ligação estabelecida com sucesso.' -Color Green
            Add-TestResult (New-TestResult -Name 'Autenticação (client credentials)' -Status PASS `
                -RequiredPermission 'Credenciais válidas (Tenant ID, Client ID, Client Secret)' `
                -DetectedPermission (Format-RoleList $script:TokenRoles) -Endpoint (Get-TokenEndpointDisplay) `
                -Detail 'Token obtido com sucesso.')
            return $true
        }

        Write-Message 'Falha na autenticação.' -Color Red
        Add-TestResult (New-AuthFailureResult -TokenResult $tokenResult)
        $tokenResult = $null
        if ($null -ne $script:ClientSecret) { $script:ClientSecret.Dispose() }
        $script:ClientSecret = $null
        if (-not (Confirm-Action -Message 'Pretende tentar novamente com outras credenciais?')) { return $false }
    }
}

function Invoke-MainMenu {
    [CmdletBinding()]
    param()
    do {
        $choice = Show-Menu
        try {
            switch ($choice) {
                '1' { Invoke-ConnectionAndPermissionCheck }
                '2' { Test-MailRead }
                '3' { Test-MailSend }
                '4' { Test-MailRead; Test-MailSend }
                '5' { Test-MailPermissionMatrix }
                '6' { Write-Message 'A terminar...' }
            }
        }
        catch [System.OperationCanceledException] {
            Write-Message ('Operação cancelada: {0}' -f $_.Exception.Message) -Color Yellow
        }
        catch {
            Add-TestResult (New-TestResult -Name 'Erro inesperado' -Status FAIL `
                -ErrorMessage (Protect-SensitiveText -Text $_.Exception.Message -SingleLine) `
                -Recommendation 'Repita a operação; se persistir, execute com -ShowDebug.')
        }
        finally {
            Clear-SensitiveErrorRecord
        }
    } while ($choice -ne '6')
}

#endregion

#region Principal

$exitCode = 0
$authenticated = $false
try {
    Write-Banner
    $authenticated = Connect-GraphApp
    if ($authenticated) {
        Invoke-ConnectionAndPermissionCheck -SkipReauthentication
        Invoke-MainMenu
    }
    else {
        $exitCode = 2
    }
}
catch [System.OperationCanceledException] {
    Write-Message ('Operação cancelada: {0}' -f $_.Exception.Message) -Color Yellow
    if (-not $authenticated) { $exitCode = 2 }
}
catch {
    Write-Message ('Erro inesperado: {0}' -f (Protect-SensitiveText -Text $_.Exception.Message -SingleLine)) -Color Red
    $exitCode = 3
}
finally {
    try {
        # Primeiro descartar segredo e token (o resumo só precisa de claims, roles, inventário e
        # resultados); assim, mesmo com Ctrl+C durante o resumo, nada sensível fica para trás.
        if ($null -ne $script:ClientSecret) { $script:ClientSecret.Dispose() }
        if ($null -ne $script:AccessToken)  { $script:AccessToken.Dispose() }
        $script:ClientSecret = $null
        $script:AccessToken = $null
        Clear-SensitiveErrorRecord
        try { Write-Summary } catch { Write-Message 'Não foi possível apresentar o resumo.' -Color Yellow }
    }
    finally {
        Clear-SessionSecret
    }
}

if ($exitCode -eq 0 -and @($script:Results | Where-Object { $_.Status -eq 'FAIL' -and -not $_.Superseded }).Count -gt 0) { $exitCode = 1 }
exit $exitCode

#endregion
