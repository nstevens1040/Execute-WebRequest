

    param(
        [ValidateSet('GET','POST','HEAD','OPTIONS')]
        [string]$METHOD,
        [string]$BODY,
        [string]$ENCRYPTEDBODY,
        [string]$BEARER,
        [string]$CSRF,
        $HEADERS,
        [string]$URI,
        $DEFAULTCOOKIES,
        [switch]$GOOGLEAPI,
        [string]$CONTENT_TYPE,
        [string]$REFERER,
        [switch]$NO_COOKIE,
        [switch]$GET_REDIRECT_URI,
        [switch]$SILENT,
        [bool]$NO_USER_AGENT
    )
    Function Install-Ewr
    {
        Function SelectCustomFolder {
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
        if( [System.IO.File]::Exists("C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.VisualBasic\v4.0_10.0.0.0__b03f5f7f11d50a3a\Microsoft.VisualBasic.dll") ) {
            add-type -path "C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.VisualBasic\v4.0_10.0.0.0__b03f5f7f11d50a3a\Microsoft.VisualBasic.dll"
        }
        if( [System.IO.DirectoryInfo]::New("$($PWD.Path)").Name -eq 'Execute-WebRequest'){ 
            $EXWEBREQ = "$($PWD.Path)"
        } else {
            $EXWEBREQ = "C:\TEMP\BIN\Execute-WebRequest"
        }    
        if (![System.Environment]::GetEnvironmentVariable("EXWEBREQ", "MACHINE")) {
            Switch (
                [microsoft.visualbasic.Interaction]::MsgBox(
                    "We'll need to set an environment variable that points to the location of the Execute-WebRequest local repository.`n`nClick 'Yes' to set environment variable:`n`n`t%EXWEBREQ%`nto:`n`t'$($EXWEBREQ)'`n`nClick 'No' to select another folder.",
                    [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                    "EXECUTE WEB REQUEST"
                )
            ) {
                "Yes" {
                    if(![System.IO.Directory]::Exists($EXWEBREQ)){ $null = [System.IO.Directory]::CreateDirectory($EXWEBREQ) }
                    While (![System.Environment]::GetEnvironmentVariable("EXWEBREQ", "MACHINE")) {
                        SetEnvVarFolder -FOLDER $EXWEBREQ -VARIABLE_NAME 'EXWEBREQ'
                        sleep -s 1
                    }
                }
                "No" {
                    $ans = "No"
                    While ($ans -eq "No") {
                        $EXWEBREQ = SelectCustomFolder
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
    }
    iex (irm "https://raw.githubusercontent.com/nstevens1040/Load-MissingAssembly/master/Load-MissingAssembly.ps1")
    Install-Ewr
    $CR = [System.Text.RegularExpressions.Regex]::New("$([char]13)")
    $LF = [System.Text.RegularExpressions.Regex]::New("$([char]10)")
    if(![System.IO.Directory]::Exists([System.IO.FileInfo]::New($PROFILE).Directory.FullName)){
        $null = [System.IO.Directory]::CreateDirectory([System.IO.FileInfo]::New($PROFILE).Directory.FullName)
    }
    if(![System.IO.File]::Exists($PROFILE)){
        "" | Out-File $PROFILE -Encoding Ascii
    }
    if(!("System.Net.Http.HttpClient" -as [type])){
        $DLL = Load-MissingAssembly -AssemblyName "System.Net.Http" -Environment "EXWEBREQ"
        if($DLL){
            if($DLL.GetType() -eq [object[]]){ $DLL = $DLL[-1] }
            Add-Type -Path $DLL
            if($? -and [array]::IndexOf(@([System.IO.File]::ReadAllLines($PROFILE)),"Add-Type -Path `"$($DLL)`"") -eq -1){ "`nAdd-Type -Path `"$($DLL)`"" | Out-File $PROFILE -Encoding Ascii -Append }
            remove-Variable DLL -ea 0
        }
    }
    if(!("System.Security.Cryptography.ProtectedData" -as [type])){
        $DLL = Load-MissingAssembly -AssemblyName "System.Security.Cryptography.ProtectedData" -Environment "EXWEBREQ"
        if($DLL){
            if($DLL.GetType() -eq [object[]]){ $DLL = $DLL[-1] }
            Add-Type -Path $DLL
            if($? -and [array]::IndexOf(@([System.IO.File]::ReadAllLines($PROFILE)),"Add-Type -Path `"$($DLL)`"") -eq -1){ "`nAdd-Type -Path `"$($DLL)`"" | Out-File $PROFILE -Encoding Ascii -Append }
            remove-variable DLL -ea 0
        }
    }
    if($ENCRYPTEDBODY){
        $BODY = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.Convert]::FromBase64String($ENCRYPTEDBODY),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    if($CSRF){
        $CSRF = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.Convert]::FromBase64String($CSRF),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    if($BEARER){
        $BEARER_TOKEN = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.Convert]::FromBase64String($BEARER),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    if(!$SILENT){
        Write-Host "HTTP $($METHOD): " -ForegroundColor Yellow -NoNewline
        Write-Host "$($URI.Split('/')[2]) :: " -ForegroundColor Green -NoNewline
        Write-Host "$([Uri]::New($URI).PathAndQuery) HTTP/1.1" -ForegroundColor Green
    }
    $HANDLE = [System.Net.Http.HttpClientHandler]::new()
    $HANDLE.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip,[System.Net.DecompressionMethods]::Deflate
    $HANDLE.SslProtocols = (
        [System.Security.Authentication.SslProtocols]::Tls,
        [System.Security.Authentication.SslProtocols]::Tls11,
        [System.Security.Authentication.SslProtocols]::Tls12
    )
    $HANDLE.UseProxy = $false
    $HANDLE.AllowAutoRedirect = $true
    $HANDLE.MaxAutomaticRedirections = 500
    $COOKIE = [System.Net.CookieContainer]::new()
    if($DEFAULTCOOKIES){
        if($DEFAULTCOOKIES.GetType() -eq [System.Net.CookieCollection]){
            $DEFAULTCOOKIES.ForEach({
                    $COOKIE.Add($_)
                })
        }
        if($DEFAULTCOOKIES.GetType() -eq [System.Collections.Hashtable]){
            if($GOOGLEAPI){
                $DEFAULTCOOKIES.Keys.ForEach({
                        $cook = [system.net.cookie]@{
                            Name = $_;
                            Value = $DEFAULTCOOKIES[$_];
                            Path = "/";
                            Domain = ".google.com"
                        }
                        $Cookie.Add($cook)
                    })
            }
            if(!$GOOGLEAPI){
                $DOMAIN = ".$([URI]::New($URI).Host)"
                $DEFAULTCOOKIES.Keys.ForEach({
                        $cook = [system.net.cookie]@{
                            Name = $_;
                            Value = $DEFAULTCOOKIES[$_];
                            Path = "/";
                            Domain = $DOMAIN;
                        }
                        $Cookie.Add($cook)
                    })
            }
        }
        if($DEFAULTCOOKIES.GetType() -eq [String]){
            for($i = 0; $i -lt @($DEFAULTCOOKIES | ConvertFrom-Json).Name.Count; $i++){
                $cook = [System.Net.Cookie]@{
                    Domain= @($DEFAULTCOOKIES | ConvertFrom-Json).Domain[$i];
                    Expired= [bool]@($DEFAULTCOOKIES | ConvertFrom-Json).Expired[$i];
                    Expires= [datetime]@($DEFAULTCOOKIES | ConvertFrom-Json).Expires[$i];
                    Name= @($DEFAULTCOOKIES | ConvertFrom-Json).Name[$i];
                    Path= @($DEFAULTCOOKIES | ConvertFrom-Json).Path[$i];
                    Secure= [bool]@($DEFAULTCOOKIES | ConvertFrom-Json).Secure[$i];
                    Value= @($DEFAULTCOOKIES | ConvertFrom-Json).Value[$i];
                }
                $COOKIE.Add($cook)
            }            
        }
    }
    $HANDLE.CookieContainer = $COOKIE
    $CLIENT = [System.Net.Http.HttpClient]::new($HANDLE)
    if($BEARER){
        $null = $CLIENT.DefaultRequestHeaders.Add("authorization","Bearer $($BEARER_TOKEN)")
    }
    if($CSRF){
        $null = $CLIENT.DefaultRequestHeaders.Add("x-csrf-token","$($CSRF)")
    }
    if(!$CLIENT.DefaultRequestHeaders.Contains("User-Agent") -and !$NO_USER_AGENT){
        $CLIENT.DefaultRequestHeaders.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36")
    }
    if($HEADERS){
        if($HEADERS.GetType() -eq [System.Collections.Specialized.OrderedDictionary]){
            $HEADERS.Keys.ForEach({
                    if($CLIENT.DefaultRequestHeaders.Contains("$($_)")){
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)","$($HEADERS["$($_)"])")
                })
        }
        if($HEADERS.GetType() -eq [System.Net.Http.Headers.HttpResponseHeaders]){
            $HEADERS.key.ForEach({
                    if($CLIENT.DefaultRequestHeaders.Contains("$($_)")){
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)","$($HEADERS.getValues("$($_)"))")
                })
        }
        if($HEADERS.GetType() -eq [string]){
            if(@(($HEADERS | ConvertFrom-Json) | gm -MemberType NoteProperty |% Name)[0] -in @("Key","Value")){
                $hdrs = ($HEADERS | ConvertFrom-Json)
                for($i = 0; $i -lt $hdrs.Key.Count; $i++){
                    Remove-Variable kee,val -ea 0
                    $kee = $hdrs.Key[$i]
                    $val = $hdrs.GetValue($i).Value
                    if($CLIENT.DefaultRequestHeaders.Contains($kee)){
                        $null = $CLIENT.DefaultRequestHeaders.Remove($kee)
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add($kee,$val)
                }
            } else {
                @(@($HEADERS | ConvertFrom-Json) | gm -MemberType NoteProperty |% Name).forEach({
                    if($CLIENT.DefaultRequestHeaders.Contains("$($_)")){
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)", "$(@($HEADERS | ConvertFrom-Json) | % "$($_)")")
                })
            }
        }
    }
    if($CLIENT.DefaultRequestHeaders.Contains("Path")){
        $null = $CLIENT.DefaultRequestHeaders.Remove("Path")
    }
    $null = $CLIENT.DefaultRequestHeaders.Add("Path","$([Uri]::New($URI).PathAndQuery)")
    if($REFERER){
        if($CLIENT.DefaultRequestHeaders.Contains("Referer")){
            $null = $CLIENT.DefaultRequestHeaders.Remove("Referer")
        }
        $null = $CLIENT.DefaultRequestHeaders.Add("Referer",$REFERER)
    }
    if($CONTENT_TYPE){
        $CLIENT.DefaultRequestHeaders.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new("$($CONTENT_TYPE)"))
    }
    $OBJ = [psobject]::new()
    switch ($METHOD){
        "GET" {
            $RES = $CLIENT.GetAsync($URI)
            $S = $RES.Result.Content.ReadAsStringAsync()
            $HTMLSTRING = $S.Result
            $RESHEAD = $RES.Result.Headers
        }
        "POST" {
            if($CONTENT_TYPE){
                $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                $RM.Content = [System.Net.Http.StringContent]::new($BODY,[System.Text.Encoding]::UTF8,"$($CONTENT_TYPE)")
                $RES = $CLIENT.SendAsync($RM)
                $RESHEAD = $RES.Result.Headers
                $S = $RES.Result.Content.ReadAsStringAsync()
                $HTMLSTRING = $S.Result
            }
            if(!$CONTENT_TYPE){
                if(!$BODY){
                    $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                    $RM.Content = [System.Net.Http.StringContent]::new($null,[System.Text.Encoding]::UTF8,"application/x-www-form-urlencoded")
                    $RES = $CLIENT.SendAsync($RM)
                    $RESHEAD = $RES.Result.Headers
                    $S = $RES.Result.Content.ReadAsStringAsync()
                    $HTMLSTRING = $S.Result
                }
                if($BODY){
                    $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                    $RM.Content = [System.Net.Http.StringContent]::new($BODY,[System.Text.Encoding]::UTF8,"application/x-www-form-urlencoded")
                    $RES = $CLIENT.SendAsync($RM)
                    $RESHEAD = $RES.Result.Headers
                    $S = $RES.Result.Content.ReadAsStringAsync()
                    $HTMLSTRING = $S.Result
                }
            }
        }
        "HEAD" {
            $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head,"$($URI)")
            $RES = $CLIENT.SendAsync($RM)
            $RESHEAD = $RES.Result.Headers
        }
    }
    if(!$NO_COOKIE){
        $TO = [datetime]::Now
        While(
            !$HANDLE.CookieContainer.GetCookies($URI) -or `
                 (([datetime]::Now - $TO) | % totalSeconds) -lt 5
        ){ sleep -m 100 }
    }
    $COOKIES = $HANDLE.CookieContainer.GetCookies($URI)
    if($DEFAULTCOOKIES){
        if($DEFAULTCOOKIES.GetType() -eq [System.Net.CookieCollection]){
        @($DEFAULTCOOKIES.Where({
                    $_.Value -notin @($COOKIES.ForEach({ $_.Value }))
                })).ForEach({
                $COOKIES.Add($_)
            })
        }
    }
    if($GET_REDIRECT_URI){
        $TO = [datetime]::Now
        While(
            !$RES.Result.RequestMessage.RequestUri.AbsoluteUri -or `
                 (([datetime]::Now - $TO) | % totalSeconds) -lt 5
        ){ sleep -m 100 }
        $REDIRECT = $RES.Result.RequestMessage.RequestUri.AbsoluteUri
    }
    if($HTMLSTRING){
        $DOMOBJ = [System.Activator]::CreateInstance([type]::getTypeFromCLSID([guid]::Parse("{25336920-03F9-11cf-8FD0-00AA00686F13}")))
        if('IHTMLDocument2_write' -in @($DOMOBJ | gm -MemberType Method | % Name)){
            $DOMOBJ.IHTMLDocument2_write([System.Text.Encoding]::Unicode.GetBytes($HTMLSTRING))
        } else {
            $DOMOBJ.Write([System.Text.Encoding]::Unicode.GetBytes($HTMLSTRING))
        }
    }
    if($GET_REDIRECT_URI){
        $OBJ | Add-Member -MemberType NoteProperty -Name RedirectUri -Value $REDIRECT
    }
    $OBJ | Add-Member -MemberType NoteProperty -Name HttpResponseMessage -Value $RES
    $OBJ | Add-Member -MemberType NoteProperty -Name CookieCollection -Value $COOKIES
    $OBJ | Add-Member -MemberType NoteProperty -Name HttpResponseHeaders -Value $RESHEAD
    if($HTMLSTRING){
        $OBJ | Add-Member -MemberType NoteProperty -Name HtmlDocument -Value $DOMOBJ
        $OBJ | Add-Member -MemberType NoteProperty -Name ResponseText -Value $HTMLSTRING
    }
    return ($OBJ | ConvertTo-Json)

