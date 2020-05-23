$STARTPATH = "$($PWD.Path)"
if ($MyInvocation.MyCommand.Path) {
    $GLOBAL:CDIR = "$([System.IO.FileInfo]::New($MyInvocation.MyCommand.Path).Directory.FullName)"
    cd $CDIR
}
else {
    $GLOBAL:CDIR = "$($PWD.Path)"
}
Function SeletCustomFolder {
    Add-Type -AssemblyName System.Windows.Forms
    $PICKER = [System.Windows.Forms.FolderBrowserDialog]::new()
    $PICKER.RootFolder = "Desktop"
    $PICKER.ShowNewFolderButton = $true
    $null = $PICKER.ShowDialog()
    return "$($PICKER.SelectedPath)"
}
Function SetEnvVarFolder {
    Param(
        [string]$FOLDER,
        [string]$VARIABLE_NAME
    )
    if (![System.IO.Directory]::Exists($FOLDER)) { $null = [System.IO.Directory]::CreateDirectory($FOLDER) }
    $null = ([System.Diagnostics.Process]@{
        StartInfo = [System.Diagnostics.ProcessStartInfo]@{
            FileName    = "$($PSHOME)\PowerShell.exe";
            Arguments   = " -WindowStyle Hidden -noprofile -nologo -ep RemoteSigned -c [System.Environment]::SetEnvironmentVariable('$($VARIABLE_NAME)','$($FOLDER)','MACHINE')";
            Verb        = "RunAs";
            WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden;
        }
    }).Start()
}

Function Install-Ewr 
{
    [cmdletbinding()]
    Param()
    if ([System.IO.File]::Exists("C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.VisualBasic\v4.0_10.0.0.0__b03f5f7f11d50a3a\Microsoft.VisualBasic.dll")) {
        add-type -path "C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.VisualBasic\v4.0_10.0.0.0__b03f5f7f11d50a3a\Microsoft.VisualBasic.dll"
    }
    if(![System.IO.Directory]::Exists("C:\TEMP\BIN\Execute-WebRequest")){ $null = [System.IO.Directory]::CreateDirectory("C:\TEMP\BIN\Execute-WebRequest") }
    $EXWEBREQ = "C:\TEMP\BIN\Execute-WebRequest"
    if (![System.Environment]::GetEnvironmentVariable("EXWEBREQ", "MACHINE")) {
        Switch (
            [microsoft.visualbasic.Interaction]::MsgBox(
                "We'll need to set an environment variable that points to the location of the Execute-WebRequest local repository.`n`nClick 'Yes' to set environment variable:`n`n`t%EXWEBREQ%`nto:`n`t'$($EXWEBREQ)'`n`nClick 'No' to select another folder.",
                [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                "EXECUTE WEB REQUEST"
            )
        ) {
            "Yes" {
                While (![System.Environment]::GetEnvironmentVariable("EXWEBREQ", "MACHINE")) {
                    SetEnvVarFolder -FOLDER $EXWEBREQ -VARIABLE_NAME 'EXWEBREQ'
                    sleep -s 1
                }
            }
            "No" {
                $ans = "No"
                While ($ans -eq "No") {
                    $EXWEBREQ = SeletCustomFolder
                    $ans = [microsoft.visualbasic.Interaction]::MsgBox(
                        "Click 'Yes' to set environment variable:`n`n`t%EXWEBREQ%`nto:`n`t'$($EXWEBREQ)'`n`nClick 'No' to select another folder.",
                        [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                        "EXECUTE WEB REQUEST"
                    )
                }
                if ($ans -eq "Yes") {
                    While (![System.Environment]::GetEnvironmentVariable("EXWEBREQ", "MACHINE")) {
                        SetEnvVarFolder -FOLDER $EXWEBREQ -VARIABLE_NAME 'EXWEBREQ'
                        sleep -s 1
                    }
                }
            }
        }
    }
    Function Load-MissingAssembly
    {
        [cmdletbinding()]
        Param(
            [string]$AssemblyName
        )
        $SDIR = "$($PWD.Path)"
        if([System.Environment]::GetEnvironmentVariable("EXWEBREQ","MACHINE")){ cd "$([System.Environment]::GetEnvironmentVariable("EXWEBREQ","MACHINE"))" }
        if(
            [System.IO.Directory]::GetFiles("C:\Windows\Microsoft.Net\assembly\GAC_MSIL","*$($AssemblyName).dll",[System.IO.SearchOption]::AllDirectories) -or `
            "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","*$($AssemblyName)*",[System.IO.SearchOption]::AllDirectories))"
        ){
            if([System.IO.Directory]::GetFiles("C:\Windows\Microsoft.Net\assembly\GAC_MSIL","*$($AssemblyName).dll",[System.IO.SearchOption]::AllDirectories)){
                return "$([System.IO.Directory]::GetFiles("C:\Windows\Microsoft.Net\assembly\GAC_MSIL","*$($AssemblyName).dll",[System.IO.SearchOption]::AllDirectories))"
            }
            if("$([System.IO.Directory]::GetDirectories("$($PWD.Path)","*$($AssemblyName)*",[System.IO.SearchOption]::AllDirectories))"){
                cd "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","*$($AssemblyName)*",[System.IO.SearchOption]::AllDirectories))\lib"
                cd "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","net??",[System.IO.SearchOption]::AllDirectories) | sort | select -Last 1)"
                $DLL = "$([System.io.Directory]::GetFiles("$($PWD.Path)","*.dll"))"
                cd "$($SDIR)"
                return $DLL
            }
        } else {
            if(![system.io.file]::Exists("C:\ProgramData\chocolatey\bin\choco.exe")){
                $p = [system.Diagnostics.Process]@{
                    StartInfo=[System.Diagnostics.ProcessStartInfo]@{
                        FileName="$($PSHOME)\PowerShell.exe";
                        Arguments=" -noprofile -nologo -ep remotesigned -c iex (irm 'https://chocolatey.org/install.ps1')";
                        Verb="RunAs";
                    }
                }
                $null = $p.Start()
                $p.WaitForExit()
                while(![system.io.file]::Exists("C:\ProgramData\chocolatey\bin\choco.exe")){ sleep -m 100 }
            }
            if(![System.IO.File]::Exists("C:\ProgramData\chocolatey\lib\NuGet.CommandLine\tools\nuget.exe")){
                $p = [system.Diagnostics.Process]@{
                    StartInfo=[System.Diagnostics.ProcessStartInfo]@{
                        FileName="C:\ProgramData\chocolatey\bin\choco.exe";
                        Arguments=" install NuGet.CommandLine -y";
                        Verb="RunAs";
                    }
                }
                $null = $p.Start()
                $p.WaitForExit()
                while(![System.IO.File]::Exists("C:\ProgramData\chocolatey\lib\NuGet.CommandLine\tools\nuget.exe")){ sleep -m 100 }
            }
            . C:\ProgramData\Chocolatey\lib\NuGet.CommandLine\tools\nuget.exe install $($AssemblyName) -DependencyVersion ignore -OutputDirectory "$($PWD.Path)\Assemblies"
            cd "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","*$($AssemblyName)*",[System.IO.SearchOption]::AllDirectories))\lib"
            cd "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","net??",[System.IO.SearchOption]::AllDirectories) | sort | select -Last 1)"
            $TDIR = "$($PWD.Path)"
            cd $SDIR
            return "$([System.io.Directory]::GetFiles("$($TDIR)","*.dll"))"
        }
    }
    $CR = [System.Text.RegularExpressions.Regex]::New("$([char]13)")
    $LF = [System.Text.RegularExpressions.Regex]::New("$([char]10)")
    if(!("System.Net.Http.HttpClient" -as [type])){
        $DLL = Load-MissingAssembly -AssemblyName "System.Net.Http"
        if($DLL){
            if($DLL.GetType() -eq [object[]]){ $DLL = $DLL[-1] }
            Add-Type -Path $DLL
            if($? -and [array]::IndexOf(@([System.IO.File]::ReadAllLines($PROFILE)),"Add-Type -Path `"$($DLL)`"") -eq -1){ "`nAdd-Type -Path `"$($DLL)`"" | Out-File $PROFILE -Encoding Ascii -Append }
            remove-Variable DLL -ea 0
        }
    }
    if(!("System.Security.Cryptography.ProtectedData" -as [type])){
        $DLL = Load-MissingAssembly -AssemblyName "System.Security.Cryptography.ProtectedData"
        if($DLL){
            if($DLL.GetType() -eq [object[]]){ $DLL = $DLL[-1] }
            Add-Type -Path $DLL
            if($? -and [array]::IndexOf(@([System.IO.File]::ReadAllLines($PROFILE)),"Add-Type -Path `"$($DLL)`"") -eq -1){ "`nAdd-Type -Path `"$($DLL)`"" | Out-File $PROFILE -Encoding Ascii -Append }
            remove-variable DLL -ea 0
        }
    }
}

Install-Ewr
Function Execute-WebRequest
{

    Param(
        [ValidateSet('GET', 'POST', 'HEAD', 'OPTIONS')]
        [String]$METHOD,
        [String]$BODY,
        [string]$ENCRYPTEDBODY,
        [string]$BEARER,
        [string]$CSRF,
        $HEADERS,
        [String]$URI,
        $DEFAULTCOOKIES,
        [switch]$GOOGLEAPI,
        [string]$CONTENT_TYPE,
        [string]$REFERER,
        [switch]$NO_COOKIE,
        [switch]$GET_REDIRECT_URI,
        [System.IO.FileStream]$FILE
    )
    $URI = $URI.ToLower()
    Function Load-MissingAssembly
    {
        [cmdletbinding()]
        Param(
            [string]$AssemblyName
        )
        $SDIR = "$($PWD.Path)"
        if([System.Environment]::GetEnvironmentVariable("EXWEBREQ","MACHINE")){ cd "$([System.Environment]::GetEnvironmentVariable("EXWEBREQ","MACHINE"))" }
        if(
            [System.IO.Directory]::GetFiles("C:\Windows\Microsoft.Net\assembly\GAC_MSIL","*$($AssemblyName).dll",[System.IO.SearchOption]::AllDirectories) -or `
            "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","*$($AssemblyName)*",[System.IO.SearchOption]::AllDirectories))"
        ){
            if([System.IO.Directory]::GetFiles("C:\Windows\Microsoft.Net\assembly\GAC_MSIL","*$($AssemblyName).dll",[System.IO.SearchOption]::AllDirectories)){
                return "$([System.IO.Directory]::GetFiles("C:\Windows\Microsoft.Net\assembly\GAC_MSIL","*$($AssemblyName).dll",[System.IO.SearchOption]::AllDirectories))"
            }
            if("$([System.IO.Directory]::GetDirectories("$($PWD.Path)","*$($AssemblyName)*",[System.IO.SearchOption]::AllDirectories))"){
                cd "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","*$($AssemblyName)*",[System.IO.SearchOption]::AllDirectories))\lib"
                cd "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","net??",[System.IO.SearchOption]::AllDirectories) | sort | select -Last 1)"
                $DLL = "$([System.io.Directory]::GetFiles("$($PWD.Path)","*.dll"))"
                cd "$($SDIR)"
                return $DLL
            }
        } else {
            if(![system.io.file]::Exists("C:\ProgramData\chocolatey\bin\choco.exe")){
                $p = [system.Diagnostics.Process]@{
                    StartInfo=[System.Diagnostics.ProcessStartInfo]@{
                        FileName="$($PSHOME)\PowerShell.exe";
                        Arguments=" -noprofile -nologo -ep remotesigned -c iex (irm 'https://chocolatey.org/install.ps1')";
                        Verb="RunAs";
                    }
                }
                $null = $p.Start()
                $p.WaitForExit()
                while(![system.io.file]::Exists("C:\ProgramData\chocolatey\bin\choco.exe")){ sleep -m 100 }
            }
            if(![System.IO.File]::Exists("C:\ProgramData\chocolatey\lib\NuGet.CommandLine\tools\nuget.exe")){
                $p = [system.Diagnostics.Process]@{
                    StartInfo=[System.Diagnostics.ProcessStartInfo]@{
                        FileName="C:\ProgramData\chocolatey\bin\choco.exe";
                        Arguments=" install NuGet.CommandLine -y";
                        Verb="RunAs";
                    }
                }
                $null = $p.Start()
                $p.WaitForExit()
                while(![System.IO.File]::Exists("C:\ProgramData\chocolatey\lib\NuGet.CommandLine\tools\nuget.exe")){ sleep -m 100 }
            }
            . C:\ProgramData\Chocolatey\lib\NuGet.CommandLine\tools\nuget.exe install $($AssemblyName) -DependencyVersion ignore -OutputDirectory "$($PWD.Path)\Assemblies"
            cd "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","*$($AssemblyName)*",[System.IO.SearchOption]::AllDirectories))\lib"
            cd "$([System.IO.Directory]::GetDirectories("$($PWD.Path)","net??",[System.IO.SearchOption]::AllDirectories) | sort | select -Last 1)"
            $TDIR = "$($PWD.Path)"
            cd $SDIR
            return "$([System.io.Directory]::GetFiles("$($TDIR)","*.dll"))"
        }
    }
    $CR = [System.Text.RegularExpressions.Regex]::New("$([char]13)")
    $LF = [System.Text.RegularExpressions.Regex]::New("$([char]10)")
    if(!("System.Net.Http.HttpClient" -as [type])){
        $DLL = Load-MissingAssembly -AssemblyName "System.Net.Http"
        if($DLL){
            if($DLL.GetType() -eq [object[]]){ $DLL = $DLL[-1] }
            Add-Type -Path $DLL
            if($? -and [array]::IndexOf(@([System.IO.File]::ReadAllLines($PROFILE)),"Add-Type -Path `"$($DLL)`"") -eq -1){ "`nAdd-Type -Path `"$($DLL)`"" | Out-File $PROFILE -Encoding Ascii -Append }
            remove-Variable DLL -ea 0
        }
    }
    if(!("System.Security.Cryptography.ProtectedData" -as [type])){
        $DLL = Load-MissingAssembly -AssemblyName "System.Security.Cryptography.ProtectedData"
        if($DLL){
            if($DLL.GetType() -eq [object[]]){ $DLL = $DLL[-1] }
            Add-Type -Path $DLL
            if($? -and [array]::IndexOf(@([System.IO.File]::ReadAllLines($PROFILE)),"Add-Type -Path `"$($DLL)`"") -eq -1){ "`nAdd-Type -Path `"$($DLL)`"" | Out-File $PROFILE -Encoding Ascii -Append }
            remove-variable DLL -ea 0
        }
    }
    $STARTED = GET-DATE
    While ((([DateTime]::Now - $STARTED) | % totalSeconds) -lt 15) {
        Function Parse-SetCookieHeader {
            [cmdletbinding()]
            Param(
                [System.Net.Http.Headers.HttpResponseHeaders]$HEADERS
            )
            $Collection = [System.Net.CookieCollection]::New()
            @($HEADERS.GetValues("Set-Cookie")).forEach( {
                    $cookie = [System.Net.Cookie]::New()
                    $c = 0
                    $_.split(';').forEach({
                        $str = $_ -replace "^\s+", ''
                        if ($str -match '=') {
                            $PNAME = $str.split('=')[0]
                            $VNAME = $str.split('=')[1]
                            if ($c -eq 0) {
                                $cookie.Name = $PNAME
                                $cookie.Value = $VNAME
                            }
                            if ($PNAME.Contains("Expires")) {
                                $cookie.Expires = ([datetime]$VNAME).ToUniversalTime()
                            }
                            else {
                                if ($PNAME -in @($cookie | gm -memberType Property | % Name)) {
                                    Switch ($PNAME) {
                                        "Path" {
                                            $cookie.Path = $VNAME
                                        }
                                        "Domain" {
                                            $cookie.Domain = $VNAME
                                        }
                                    }
                                }
                            }
                        }
                        $c++
                    })
                $collection.Add($cookie)
            })
            return $collection
        }
        if ($ENCRYPTEDBODY) {
            $BODY = [System.Text.Encoding]::Unicode.GetString(
                [System.Security.Cryptography.ProtectedData]::Unprotect(
                    [System.convert]::FromBase64String($ENCRYPTEDBODY),
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )
        }
        if ($CSRF) {
            $CSRF = [System.Text.Encoding]::Unicode.GetString(
                [System.Security.Cryptography.ProtectedData]::Unprotect(
                    [System.convert]::FromBase64String($CSRF),
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )
        }
        if ($BEARER) {
            $BEARER_TOKEN = [System.Text.Encoding]::Unicode.GetString(
                [System.Security.Cryptography.ProtectedData]::Unprotect(
                    [System.convert]::FromBase64String($BEARER),
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )
        }
        try {
            $TESTURI = [Uri]::New($URI)
        }
        catch {
            $TESTURI = $false
        }
        if (!$URI.StartsWith("http")) {
            $URI = "https://$($URI)"
            try {
                $TESTURI = [Uri]::New($URI)
            }
            catch {
                $TESTURI = $false
            }
        }
        if (!$TESTURI) {
            Write-Host "Malformed Uri: " -foregroundcolor green -nonewline
            Write-Host $URI -foregroundcolor blue 
            Write-host "Please provide another Uri or strike " -foregroundcolor green -nonewline
            write-host 'enter' -foregroundcolor blue -nonewline
            write-host " to cancel" -foregroundcolor green
            $ANS = read-host
            if (!$ANS) {
                break;
            }
            else {
                $URI = $ANS
                try {
                    $TESTURI = [Uri]::New($URI)
                }
                catch {
                    $TESTURI = $false
                }
                if (!$URI.StartsWith("http")) {
                    $URI = "https://$($URI)"
                    try {
                        $TESTURI = [Uri]::New($URI)
                    }
                    catch {
                        $TESTURI = $false
                    }
                }
            }
        }
        if (!$TESTURI) {
            write-host "NOPE" -foregroundColor Red
            break;
        }
        $URI = $TESTURI.AbsoluteUri
        Write-Host "HTTP $($METHOD): " -ForegroundColor Yellow -NoNewline
        Write-Host "$($TESTURI.Host) :: " -ForegroundColor Green -NoNewline
        Write-Host "$($TESTURI.PathAndQuery) HTTP/1.1" -ForegroundColor Green
        $HANDLE = [System.Net.Http.HttpClientHandler]::new()
        $HANDLE.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip, [System.Net.DecompressionMethods]::Deflate
        $HANDLE.SslProtocols = (
            [System.Security.Authentication.SslProtocols]::Tls,
            [System.Security.Authentication.SslProtocols]::Tls11,
            [System.Security.Authentication.SslProtocols]::Tls12
        )
        $HANDLE.UseProxy = $false
        $HANDLE.AllowAutoRedirect = $true
        $HANDLE.MaxAutomaticRedirections = 500
        $COOKIE = [System.Net.CookieContainer]::new()
        if ($DEFAULTCOOKIES) {
            if ($DEFAULTCOOKIES.GETTYPE() -eq [System.Net.CookieCollection]) {
                $DEFAULTCOOKIES.ForEach({
                    $COOKIE.Add($_)
                })
            }
            if ($DEFAULTCOOKIES.GETTYPE() -eq [System.Collections.hashTable]) {
                if ($GOOGLEAPI) {
                    $DEFAULTCOOKIES.Keys.ForEach( {
                        $cook = [system.net.cookie]@{
                            Name   = $_;
                            Value  = $DEFAULTCOOKIES[$_];
                            Path   = "/";
                            Domain = ".google.com"
                        }
                        $Cookie.Add($cook)
                    })
                }
                if (!$GOOGLEAPI) {
                    $DOMAIN = ".$([URI]::New($URI).Host)"
                    $DEFAULTCOOKIES.Keys.ForEach( {
                        $cook = [system.net.cookie]@{
                            Name   = $_;
                            Value  = $DEFAULTCOOKIES[$_];
                            Path   = "/";
                            Domain = $DOMAIN;
                        }
                        $Cookie.Add($cook)
                    })
                }
            }
        }
        $HANDLE.CookieContainer = $COOKIE
        $CLIENT = [System.Net.Http.HttpClient]::new($HANDLE)
        if ($BEARER) {
            $null = $CLIENT.DefaultRequestHeaders.Add("authorization", "Bearer $($BEARER_TOKEN)")
        }
        if ($CSRF) {
            $null = $CLIENT.DefaultRequestHeaders.Add("x-csrf-token", "$($CSRF)")
        }
        if ($HEADERS) {
            if ($HEADERS.gettype() -eq [System.Collections.Specialized.OrderedDictionary]) {
                $HEADERS.keys.forEach({
                    if ($CLIENT.DefaultRequestHeaders.Contains("$($_)")) {
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)", "$($HEADERS["$($_)"])")
                })
            }
            if ($HEADERS.gettype() -eq [System.Net.Http.Headers.HttpResponseHeaders]) {
                $HEADERS.key.forEach( {
                    if ($CLIENT.DefaultRequestHeaders.Contains("$($_)")) {
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)", "$($HEADERS.getValues("$($_)"))")
                })
            }
        }
        if ($CLIENT.DefaultRequestHeaders.Contains("Path")) {
            $null = $CLIENT.DefaultRequestHeaders.Remove("Path")
        }
        if (!$CLIENT.DefaultRequestHeaders.Contains("User-Agent")) {
            $null = $CLIENT.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36")
        }
        $null = $CLIENT.DefaultRequestHeaders.Add("Path", "/$($URI.Split('/')[3..($URI.Split('/').length)] -join '/')")
        if ($REFERER) {
            if ($CLIENT.DefaultRequestHeaders.Contains("Referer")) {
                $null = $CLIENT.DefaultRequestHeaders.Remove("Referer")
            }
            $null = $CLIENT.DefaultRequestHeaders.Add("Referer", $REFERER)
        }
        if ($CONTENT_TYPE) {
            $CLIENT.DefaultRequestHeaders.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new("$($CONTENT_TYPE)"))
        }
        $OBJ = [psobject]::new()
        switch ($METHOD) {
            "GET" {
                $RES = $CLIENT.GetAsync($URI)
                if ($RES.Result.Content) {
                    $S = $RES.Result.Content.ReadAsStringAsync()
                    $HTMLSTRING = $S.Result
                }
                $RESHEAD = $RES.Result.Headers
            }
            "POST" {
                if ($CONTENT_TYPE) {
                    $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "$($URI)")
                    if ($CONTENT_TYPE -eq "application/octet-stream") {
                        $RM.Content = [System.Net.Http.ByteArrayContent]::New($BODY, 0, $Body.Length)
                    } else {
                        $RM.Content = [System.Net.Http.StringContent]::new($BODY, [System.Text.Encoding]::UTF8, "$($CONTENT_TYPE)")
                    }
                    if ($FILE) {
                        $RM.Content = [System.Net.Http.StreamContent]::New($FILE)
                    }
                    $RES = $CLIENT.SendAsync($RM)
                    $RESHEAD = $RES.Result.Headers
                    if ($RES.Result.Content) {
                        $S = $RES.Result.Content.ReadAsStringAsync()
                        $HTMLSTRING = $S.Result
                    }
                }
                if (!$CONTENT_TYPE) {
                    if (!$BODY) {
                        $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "$($URI)")
                        $RM.Content = [System.Net.Http.StringContent]::new($null, [System.Text.Encoding]::UTF8, "application/x-www-form-urlencoded")
                        $RES = $CLIENT.SendAsync($RM)
                        $RESHEAD = $RES.Result.Headers
                        if ($RES.Result.Content) {
                            $S = $RES.Result.Content.ReadAsStringAsync()
                            $HTMLSTRING = $S.Result
                        }
                    }
                    if ($BODY) {
                        $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "$($URI)")
                        $RM.Content = [System.Net.Http.StringContent]::new($BODY, [System.Text.Encoding]::UTF8, "application/x-www-form-urlencoded")
                        $RES = $CLIENT.SendAsync($RM)
                        $RESHEAD = $RES.Result.Headers
                        if ($RES.Result.content) {
                            $S = $RES.Result.Content.ReadAsStringAsync()
                            $HTMLSTRING = $S.Result
                        }
                    }
                }
            }
            "HEAD" {
                $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, "$($URI)")
                $RES = $CLIENT.SendAsync($RM)
                $RESHEAD = $RES.Result.Headers
            }
        }
        if (!$NO_COOKIE) {
            $TO = [DateTime]::Now
            while (
                !$HANDLE.CookieContainer.GetCookies($URI) -or `
                (([DateTime]::Now - $TO) | % totalSeconds) -lt 5
            ) { sleep -m 100 }
        }
        $COOKIES = $HANDLE.CookieContainer.GetCookies($URI)
        if ($RESHEAD) {
            if ($RESHEAD.Contains("Set-Cookie")) {
                @(Parse-SetCookieHeader -HEADERS $RESHEAD).forEach( {
                    if ($_.Name -notin @($COOKIES.forEach( { $_.Name }))) {
                        $COOKIES.Add($_)
                    }
                })
            }
        }
        if ($DEFAULTCOOKIES) {
            @($DEFAULTCOOKIES.WHERE( {
                $_.Name -notin @($COOKIES.forEach( { $_.Name }))
            })).forEach( {
                $COOKIES.Add($_)
            })
        }
        if ($GET_REDIRECT_URI) {
            $TO = [DateTime]::Now
            while (
                !$RES.Result.RequestMessage.RequestUri.AbsoluteUri -or `
                (([DateTime]::Now - $TO) | % totalSeconds) -lt 5
            ) { sleep -m 100 }
            $REDIRECT = $RES.Result.RequestMessage.RequestUri.AbsoluteUri
        }
        $RESHEAD += $RES.Result.Content.Headers
        if ($HTMLSTRING) {
            $DOMOBJ = [System.Activator]::createInstance([TYPE]::getTypeFromCLSID([GUID]::Parse("{25336920-03F9-11cf-8FD0-00AA00686F13}")))
            if ($DOMOBJ | gm -Name IHTMLDocument2_write) {
                $DOMOBJ.IHTMLDocument2_write([System.Text.Encoding]::Unicode.GetBytes($HTMLSTRING))
            }
            else {
                $DOMOBJ.Write([System.Text.Encoding]::Unicode.GetBytes($HTMLSTRING))
            }
        }
        if ($GET_REDIRECT_URI) {
            $OBJ | Add-Member -MemberType NoteProperty -Name RedirectUri -Value $REDIRECT
        }
        $OBJ | Add-Member -MemberType NoteProperty -Name HttpResponseMessage -Value $RES
        $OBJ | Add-Member -MemberType NoteProperty -Name CookieCollection -Value $COOKIES
        $OBJ | Add-Member -MemberType NoteProperty -Name HttpResponseHeaders -Value $RESHEAD
        if ($HTMLSTRING) {
            $OBJ | Add-Member -MemberType NoteProperty -Name HtmlDocument -Value $DOMOBJ
            $OBJ | Add-Member -MemberType NoteProperty -Name ResponseText -Value $HTMLSTRING
        }
        return $OBJ
    }
}
$CR = [System.Text.RegularExpressions.Regex]::New("$([char]13)")
$LF = [System.Text.RegularExpressions.Regex]::New("$([char]10)")
if(![System.IO.Directory]::Exists([System.IO.FileInfo]::New($PROFILE).Directory.FullName)){
    $null = [System.IO.Directory]::CreateDirectory([System.IO.FileInfo]::New($PROFILE).Directory.FullName)
}
if(![System.IO.File]::Exists($PROFILE)){
    "" | Out-File $PROFILE -Encoding Ascii
}
if("Function Execute-WebRequest" -in @([System.IO.File]::ReadAllLines($PROFILE))){
    [Int32]$sindex = [array]::IndexOf([System.IO.File]::ReadAllLines($PROFILE),"Function Execute-WebRequest")
    [Int32]$eindex = [array]::IndexOf(
        @([System.IO.File]::ReadAllLines($PROFILE)[$sindex..(@([System.IO.File]::ReadAllLines($PROFILE)).Count)]),
        @([System.IO.File]::ReadAllLines($PROFILE)[$sindex..(@([System.IO.File]::ReadAllLines($PROFILE)).Count)]).Where({$_ -match "^}$"})[0]
    )
    $Remove_Ewr = @()
    @([System.IO.File]::ReadAllLines($PROFILE))[0..($sindex - 1)].forEach({ $Remove_Ewr += $_  })
    @([System.IO.File]::ReadAllLines($PROFILE))[($sindex + $eindex + 1)..(@([System.IO.File]::ReadAllLines($PROFILE)).Count)].forEach({ $Remove_Ewr += $_ })
    "" | Out-File $PROFILE -Encoding ascii
    $Remove_Ewr -join "`n"  | Out-File $PROFILE -Encoding ascii -Append
}
$LF.Replace($CR.Replace("Function Execute-WebRequest",''),'') | Out-File $PROFILE -Encoding ascii -Append
$LF.Replace($CR.Replace("{",''),'') | Out-File $PROFILE -Encoding ascii -Append
"$(Get-Command Execute-WebRequest | % ScriptBlock)" | Out-File $PROFILE -Encoding ascii -Append
$LF.Replace($CR.Replace("}",''),'') | Out-File $PROFILE -Encoding ascii -Append
