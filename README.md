# Execute-WebRequest
PowerShell function to perform HTTP requests centered around .NET class System.Net.Http.HttpClient

## Requirements

*   **Microsoft Windows** operating system

        (tested on **Windows 10** Version 1909 OS build 18363.720 and **Windows Server 2016** Version 1607 OS build 14393.3564)

*   **Windows PowerShell**, minimum version 3.0

        (tested PowerShell versions **3.0**, **5.1.14393.3471**, and **5.1.18362.628**. I have not tested PowerShell Core.)

## Installation

*   **Launch PowerShell and run the code below:**

    <pre><code>mkdir C:\TEMP\BIN
    cd C:\TEMP\BIN 
    git clone https://github.com/nstevens1040/Execute-WebRequest.git
    cd Execute-WebRequest
    . .\INSTALL.ps1</code></pre>

## Usage

*   **Here is probably the most complex example I can think of:**
```powershell
"This is super important and must appear, server-side, as POST data." | out-File C:\TEMP\TEST.txt -encoding UTF8
$FILE = [System.IO.File]::OpenRead("C:\TEMP\TEST.txt")
$URI = "https://nanick.hopto.org/file"
$HEADERS = [ordered]@{"x-requested-with"="XMLHttpRequest";}
$COOKIES = [System.Net.CookieCollection]::New()
$COOKIES.Add(
    [System.Net.Cookie]@{
        Name="guest_id";
        Value="v1%3A158994263807059279";
        Path="/";
        Domain=".$([URI]::New($URI).Host)";
    }
)
$BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D_FAKE_TOKEN_1IUq16cHjhLTvJu4FA33AGWWjCpTnA"
$BEARER = [System.Convert]::ToBase64String(
    [System.Security.Cryptography.ProtectedData]::Protect(
        [System.Text.Encoding]::Unicode.GetBytes($BEARER_TOKEN),
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
)
$X_CSRF_TOKEN = "8_fake_csrf_token_e7a5f123dce407"
$CSRF = [System.Convert]::ToBase64String(
    [System.Security.Cryptography.ProtectedData]::Protect(
        [System.Text.Encoding]::Unicode.GetBytes($X_CSRF_TOKEN),
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
)
$RET = Execute-WebRequest -METHOD POST `
-HEADERS $HEADERS `
-URI $URI `
-DEFAULTCOOKIES $COOKIES `
-FILE $FILE `
-BEARER $BEARER `
-CSRF $CSRF `
-CONTENT_TYPE "application/octet-stream" `
-REFERER "https://nanick.hopto.org/" `
-GET_REDIRECT_URI

$RET | ConvertTo-Json

```
