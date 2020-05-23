# Execute-WebRequest
PowerShell function to perform HTTP requests centered around .NET class System.Net.Http.HttpClient

## Requirements

*   **Microsoft Windows** operating system

       (tested on **Windows 10** Version 1909 OS build 18363.720 and **Windows Server 2016** Version 1607 OS build 14393.3564)

*   **Windows PowerShell**, minimum version 3.0

       (tested PowerShell versions **3.0**, **5.1.14393.3471**, and **5.1.18362.628**. I have not tested PowerShell Core.)

## Installation

*   **Launch PowerShell and run the code below:**

    <pre><code>mkdir C:\TEMP\BIN -ea 0
    cd C:\TEMP\BIN 
    git clone https://github.com/nstevens1040/Execute-WebRequest.git
    cd Execute-WebRequest
    . .\INSTALL.ps1</code></pre>  

*   **You can also launch PowerShell and install Execute-WebRequest like this:**
    <pre><code>iex (irm "https://raw.githubusercontent.com/nstevens1040/Execute-WebRequest/master/INSTALL.ps1")</code></pre>  

## Usage

**Basic Example:**        Sending a HTTP GET request to https://nanick.hopto.org/file  
```powershell
$RET = Execute-WebRequest -METHOD GET -URI "https://nanick.hopto.org/file" -NO_COOKIE
```
*Note: The **-NO_COOKIE** switch skips the collection of cookies and allows the command to finish much faster.*  
  
**Complex Example:**        Sending a JSON file via HTTP POST to https://nanick.hopto.org/file, which redirects to https://github.com/nstevens1040/Execute-WebRequest  
```powershell
"{`"JSON`": {`"MESSAGETYPE`": `"TEXT`",`"MESSAGE`": `"This is super important and must appear, server-side, as POST data.`"}}" | Out-File C:\TEMP\TEST.json
$FILE = [System.IO.File]::OpenRead("C:\TEMP\TEST.json")
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
-CONTENT_TYPE "application/json" `
-REFERER "https://nanick.hopto.org/" `
-GET_REDIRECT_URI
```  
Here is the HTTP POST request that the script above creates.  
```
POST /file

x-csrf-token : 8_fake_csrf_token_e7a5f123dce407
x-requested-with : XMLHttpRequest
Path : /file
Connection : Keep-Alive
Content-Length : 234
Accept : application/json
Accept-Encoding : gzip, deflate
Authorization : Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D_FAKE_TOKEN_1IUq16cHjhLTvJu4FA33AGWWjCpTnA
Cookie : guest_id=v1%3A158994263807059279
Host : nanick.hopto.org
Referer : https://nanick.hopto.org/
User-Agent : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36

{"JSON": {"MESSAGETYPE": "TEXT","MESSAGE": "This is super important and must appear, server-side, as POST data."}}
```  
Execute-WebRequest returns a **System.Management.Automation.PSCustomObject**.
The PSCustomObject will always have member objects

| Name                | TypeName                                    |
|---------------------|---------------------------------------------|
| HttpResponseMessage | System.Net.Http.HttpResponseMessage         |
| CookieCollection    | System.Net.CookieCollection                 |
| HtmlDocument        | mshtml.HTMLDocumentClass                    |
| HttpResponseHeaders | System.Net.Http.Headers.HttpResponseHeaders |
  
And, if applicable, it may also include  

| Name                | TypeName                                    |
|---------------------|---------------------------------------------|
| ResponseText        | System.String                               |
| RedirectUri         | System.String                               |
