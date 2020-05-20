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

## Usage

*   **Send HTTP GET request to https://nanick.hopto.org/file. This is likely the simplest example.**

Note: The **-NO_COOKIE** switch skips the collection of cookies and allows the command to finish much faster.
```powershell
$RET = Execute-WebRequest -METHOD GET -URI "https://nanick.hopto.org/file" -NO_COOKIE
```
$RET returns a **System.Management.Automation.PSCustomObject**.
The PSCustomObject will always have member objects

| Name                | TypeName                                                                                                                                                                                                                                                                                                                                                          |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| HttpResponseMessage | `[System.Threading.Tasks.Task`1[[System.Net.Http.HttpResponseMessage, System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a]]]`                                                                                                                                                                                                       |
| CookieCollection    | [System.Net.CookieCollection]                                                                                                                                                                                                                                                                                                                                     |
| HtmlDocument        | [mshtml.HTMLDocumentClass]                                                                                                                                                                                                                                                                                                                                        |
| HttpResponseHeaders | `[System.Collections.Generic.KeyValuePair`2[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Collections.Generic.IEnumerable`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]], mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]][]]` |

*   **HttpResponseMessage** 
*   **Here is probably the most complex example I can think of. The script sends a file to my web server via HTTP POST.**
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
Here is the HTTP POST request that the script above creates.

```
POST /file

x-csrf-token : 8_fake_csrf_token_e7a5f123dce407
x-requested-with : XMLHttpRequest
Path : /file
Content-Length : 72
Accept : application/octet-stream
Accept-Encoding : gzip, deflate
Authorization : Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D_FAKE_TOKEN_1IUq16cHjhLTvJu4FA33AGWWjCpTnA
Cookie : guest_id=v1%3A158994263807059279
Host : nanick.hopto.org
Referer : https://nanick.hopto.org/
User-Agent : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36

This is super important and must appear, server-side, as POST data.

```

Here is what you should see after running $RET | ConvertTo-Json (The object returned from Execute-WebRequest converted to JSON).

```json
{
    "RedirectUri": "https://nanick.hopto.org/file",
    "HttpResponseMessage": {
        "Result": {
            "Version": "1.1",
            "Content": "System.Net.Http.StreamContent",
            "StatusCode": 200,
            "ReasonPhrase": "OK",
            "Headers": "[Transfer-Encoding, System.String[]] [Allow-Cross-Allow-Origin, System.String[]] [Date, System.String[]] [Server, System.String[]]",
            "RequestMessage": "Method: POST, RequestUri: \u0027https://nanick.hopto.org/file\u0027, Version: 1.1, Content: System.Net.Http.StreamContent, Headers:\r\n{\r\n  authorization: Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D_FAKE_TOKEN_1IUq16cHjhLTvJu4FA33AGWWjCpTnA\r\n  x-csrf-token: 8_fake_csrf_token_e7a5f123dce407\r\n  x-requested-with: XMLHttpRequest\r\n  User-Agent: Mozilla/5.0\r\n  User-Agent: (Windows NT 10.0; Win64; x64)\r\n  User-Agent: AppleWebKit/537.36\r\n  User-Agent: (KHTML, like Gecko)\r\n  User-Agent: Chrome/80.0.3987.149\r\n  User-Agent: Safari/537.36\r\n  Path: /file\r\n  Referer: https://nanick.hopto.org/\r\n  Accept: application/octet-stream\r\n  Content-Length: 72\r\n}",
            "IsSuccessStatusCode": true
        },
        "Id": 1347,
        "Exception": null,
        "Status": 5,
        "IsCanceled": false,
        "IsCompleted": true,
        "CreationOptions": 0,
        "AsyncState": null,
        "IsFaulted": false
    },
    "CookieCollection": [
        {
            "Comment": "",
            "CommentUri": null,
            "HttpOnly": false,
            "Discard": false,
            "Domain": ".nanick.hopto.org",
            "Expired": false,
            "Expires": "\/Date(-62135575200000)\/",
            "Name": "guest_id",
            "Path": "/",
            "Port": "",
            "Secure": false,
            "TimeStamp": "\/Date(1589945459244)\/",
            "Value": "v1%3A158994263807059279",
            "Version": 0
        }
    ],
    "HttpResponseHeaders": [
        {
            "Key": "Transfer-Encoding",
            "Value": "chunked"
        },
        {
            "Key": "Allow-Cross-Allow-Origin",
            "Value": "*"
        },
        {
            "Key": "Date",
            "Value": "Wed, 20 May 2020 03:30:59 GMT"
        },
        {
            "Key": "Server",
            "Value": "Microsoft-HTTPAPI/2.0"
        }
    ],
    "HtmlDocument": {
        "Script": {},
        "all": [
            "System.__ComObject",
            "System.__ComObject",
            "System.__ComObject",
            "System.__ComObject"
        ],
        "body": {},
        "activeElement": null,
        "images": [],
        "applets": [],
        "links": [],
        "forms": [],
        "anchors": [],
        "title": "",
        "scripts": [],
        "designMode": "Inherit",
        "selection": {},
        "readyState": "loading",
        "frames": {},
        "embeds": [],
        "plugins": [],
        "alinkColor": "#0000ff",
        "bgColor": "#ffffff",
        "fgColor": "#000000",
        "linkColor": "#0000ff",
        "vlinkColor": "#800080",
        "referrer": null,
        "location": {},
        "lastModified": "05/19/2020 22:34:19",
        "url": "about:blank",
        "domain": null,
        "cookie": null,
        "expando": true,
        "charset": "unicode",
        "defaultCharset": "windows-1252",
        "mimeType": "",
        "fileSize": null,
        "fileCreatedDate": null,
        "fileModifiedDate": null,
        "fileUpdatedDate": null,
        "security": "This type of document does not have a security certificate.",
        "protocol": "Unknown Protocol",
        "nameProp": "",
        "onhelp": null,
        "onclick": null,
        "ondblclick": null,
        "onkeyup": null,
        "onkeydown": null,
        "onkeypress": null,
        "onmouseup": null,
        "onmousedown": null,
        "onmousemove": null,
        "onmouseout": null,
        "onmouseover": null,
        "onreadystatechange": null,
        "onafterupdate": null,
        "onrowexit": null,
        "onrowenter": null,
        "ondragstart": null,
        "onselectstart": null,
        "parentWindow": {},
        "styleSheets": [],
        "onbeforeupdate": null,
        "onerrorupdate": null,
        "documentElement": {},
        "uniqueID": "ms__id3",
        "onrowsdelete": null,
        "onrowsinserted": null,
        "oncellchange": null,
        "ondatasetchanged": null,
        "ondataavailable": null,
        "ondatasetcomplete": null,
        "onpropertychange": null,
        "dir": null,
        "oncontextmenu": null,
        "onstop": null,
        "parentDocument": null,
        "enableDownload": null,
        "baseUrl": null,
        "inheritStyleSheets": null,
        "onbeforeeditfocus": null,
        "onselectionchange": null,
        "namespaces": {},
        "media": null,
        "oncontrolselect": null,
        "URLUnencoded": "about:blank",
        "onmousewheel": null,
        "doctype": null,
        "implementation": {},
        "onfocusin": null,
        "onfocusout": null,
        "onactivate": null,
        "ondeactivate": null,
        "onbeforeactivate": null,
        "onbeforedeactivate": null,
        "compatMode": "BackCompat",
        "nodeType": 9,
        "parentNode": null,
        "childNodes": [
            "System.__ComObject"
        ],
        "attributes": null,
        "nodeName": "#document",
        "nodeValue": null,
        "firstChild": {},
        "lastChild": {},
        "previousSibling": null,
        "nextSibling": null,
        "ownerDocument": null,
        "IHTMLDocument2_Script": {},
        "IHTMLDocument2_all": [
            "System.__ComObject",
            "System.__ComObject",
            "System.__ComObject",
            "System.__ComObject"
        ],
        "IHTMLDocument2_body": {},
        "IHTMLDocument2_activeElement": null,
        "IHTMLDocument2_images": [],
        "IHTMLDocument2_applets": [],
        "IHTMLDocument2_links": [],
        "IHTMLDocument2_forms": [],
        "IHTMLDocument2_anchors": [],
        "IHTMLDocument2_title": "",
        "IHTMLDocument2_scripts": [],
        "IHTMLDocument2_designMode": "Inherit",
        "IHTMLDocument2_selection": {},
        "IHTMLDocument2_readyState": "loading",
        "IHTMLDocument2_frames": {
            "length": 0
        },
        "IHTMLDocument2_embeds": [],
        "IHTMLDocument2_plugins": [],
        "IHTMLDocument2_alinkColor": "#0000ff",
        "IHTMLDocument2_bgColor": "#ffffff",
        "IHTMLDocument2_fgColor": "#000000",
        "IHTMLDocument2_linkColor": "#0000ff",
        "IHTMLDocument2_vlinkColor": "#800080",
        "IHTMLDocument2_referrer": null,
        "IHTMLDocument2_location": {
            "href": "about:blank",
            "protocol": "about:",
            "host": null,
            "hostname": null,
            "port": null,
            "pathname": "blank",
            "search": null,
            "hash": null
        },
        "IHTMLDocument2_lastModified": "05/19/2020 22:34:19",
        "IHTMLDocument2_url": "about:blank",
        "IHTMLDocument2_domain": null,
        "IHTMLDocument2_cookie": null,
        "IHTMLDocument2_expando": true,
        "IHTMLDocument2_charset": "unicode",
        "IHTMLDocument2_defaultCharset": "windows-1252",
        "IHTMLDocument2_mimeType": "",
        "IHTMLDocument2_fileSize": null,
        "IHTMLDocument2_fileCreatedDate": null,
        "IHTMLDocument2_fileModifiedDate": null,
        "IHTMLDocument2_fileUpdatedDate": null,
        "IHTMLDocument2_security": "This type of document does not have a security certificate.",
        "IHTMLDocument2_protocol": "Unknown Protocol",
        "IHTMLDocument2_nameProp": "",
        "IHTMLDocument2_onhelp": null,
        "IHTMLDocument2_onclick": null,
        "IHTMLDocument2_ondblclick": null,
        "IHTMLDocument2_onkeyup": null,
        "IHTMLDocument2_onkeydown": null,
        "IHTMLDocument2_onkeypress": null,
        "IHTMLDocument2_onmouseup": null,
        "IHTMLDocument2_onmousedown": null,
        "IHTMLDocument2_onmousemove": null,
        "IHTMLDocument2_onmouseout": null,
        "IHTMLDocument2_onmouseover": null,
        "IHTMLDocument2_onreadystatechange": null,
        "IHTMLDocument2_onafterupdate": null,
        "IHTMLDocument2_onrowexit": null,
        "IHTMLDocument2_onrowenter": null,
        "IHTMLDocument2_ondragstart": null,
        "IHTMLDocument2_onselectstart": null,
        "IHTMLDocument2_parentWindow": {},
        "IHTMLDocument2_styleSheets": [],
        "IHTMLDocument2_onbeforeupdate": null,
        "IHTMLDocument2_onerrorupdate": null,
        "IHTMLDocument3_documentElement": {},
        "IHTMLDocument3_uniqueID": "ms__id4",
        "IHTMLDocument3_onrowsdelete": null,
        "IHTMLDocument3_onrowsinserted": null,
        "IHTMLDocument3_oncellchange": null,
        "IHTMLDocument3_ondatasetchanged": null,
        "IHTMLDocument3_ondataavailable": null,
        "IHTMLDocument3_ondatasetcomplete": null,
        "IHTMLDocument3_onpropertychange": null,
        "IHTMLDocument3_dir": null,
        "IHTMLDocument3_oncontextmenu": null,
        "IHTMLDocument3_onstop": null,
        "IHTMLDocument3_parentDocument": null,
        "IHTMLDocument3_enableDownload": null,
        "IHTMLDocument3_baseUrl": null,
        "IHTMLDocument3_childNodes": [
            "System.__ComObject"
        ],
        "IHTMLDocument3_inheritStyleSheets": null,
        "IHTMLDocument3_onbeforeeditfocus": null,
        "IHTMLDocument4_onselectionchange": null,
        "IHTMLDocument4_namespaces": {},
        "IHTMLDocument4_media": null,
        "IHTMLDocument4_oncontrolselect": null,
        "IHTMLDocument4_URLUnencoded": "about:blank",
        "IHTMLDocument5_onmousewheel": null,
        "IHTMLDocument5_doctype": null,
        "IHTMLDocument5_implementation": {},
        "IHTMLDocument5_onfocusin": null,
        "IHTMLDocument5_onfocusout": null,
        "IHTMLDocument5_onactivate": null,
        "IHTMLDocument5_ondeactivate": null,
        "IHTMLDocument5_onbeforeactivate": null,
        "IHTMLDocument5_onbeforedeactivate": null,
        "IHTMLDocument5_compatMode": "BackCompat",
        "IHTMLDOMNode_nodeType": null,
        "IHTMLDOMNode_parentNode": null,
        "IHTMLDOMNode_childNodes": null,
        "IHTMLDOMNode_attributes": null,
        "IHTMLDOMNode_nodeName": null,
        "IHTMLDOMNode_nodeValue": null,
        "IHTMLDOMNode_firstChild": null,
        "IHTMLDOMNode_lastChild": null,
        "IHTMLDOMNode_previousSibling": null,
        "IHTMLDOMNode_nextSibling": null,
        "IHTMLDOMNode2_ownerDocument": null
    },
    "ResponseText": "NoContent"
}

```
