<#
.SYNOPSIS
    C段存活主机 7000-9999 端口 Web 服务探测脚本，检测 /FileReceiver 路径。

.说明（务必阅读）
    本脚本仅可用于你拥有明确授权的网络/资产（内部资产梳理、授权渗透测试等）。
    禁止用于未授权的第三方网络扫描。使用前请确认已获得书面授权。

.用法
    在 PowerShell ISE 或 PowerShell 7+ 中运行：
    .\Scan-FileReceiver.ps1 -Subnet 192.168.1 -StartPort 7000 -EndPort 9999 -Threads 200

.参数
    -Subnet     C段前缀，例如 192.168.1（会扫描 192.168.1.1 - 192.168.1.254）
    -StartPort  起始端口，默认 7000
    -EndPort    结束端口，默认 9999
    -Threads    并发线程数（Runspace 数），默认 200
    -Timeout    TCP/HTTP 超时（毫秒），默认 800
    -OutFile    结果输出 CSV 路径
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Subnet,

    [int]$StartPort = 7000,
    [int]$EndPort   = 9999,
    [int]$Threads   = 200,
    [int]$Timeout   = 800,
    [string]$OutFile = ".\FileReceiver_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    # 内网很多主机会屏蔽 ICMP/常见端口，可能导致第一步误判为"不存活"。
    # 如果发现存活主机数偏少/漏了，加上此开关直接对整个C段扫端口，更保险（但更慢）。
    [switch]$SkipHostDiscovery
)

# ---------- 忽略无效 SSL 证书（仅用于探测，不做任何利用行为） ----------
Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy {
    public static void Ignore() {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate { return true; };
    }
}
"@ -ErrorAction SilentlyContinue
[TrustAllCertsPolicy]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor `
    [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls

# ---------- 结果同步集合 ----------
$Results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

# ---------- 存活探测：TCP 快速判活 + ICMP（逻辑直接内联进 ScriptBlock，避免跨 Runspace 传函数失效） ----------
$ipList = 1..254 | ForEach-Object { "$Subnet.$_" }

if ($SkipHostDiscovery) {
    Write-Host "[*] 已跳过存活探测，直接对整个 C 段 ($($ipList.Count) 个IP) 扫端口..." -ForegroundColor Cyan
    $aliveList = $ipList
} else {

Write-Host "[*] 第一步：探测 $Subnet.1 - $Subnet.254 存活主机..." -ForegroundColor Cyan

$aliveHosts = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

$AliveScriptBlock = {
    param($IP, $aliveHosts)

    $isAlive = $false

    # 1. 常见端口快速 TCP 判活
    $commonPorts = @(80, 443, 22, 445, 3389, 8080, 135, 139)
    foreach ($p in $commonPorts) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($IP, $p, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne(300, $false)
            if ($ok -and $client.Connected) {
                $isAlive = $true
                $client.Close()
                break
            }
            $client.Close()
        } catch {}
    }

    # 2. 端口都没命中的话，再补一次 ICMP
    if (-not $isAlive) {
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($IP, 500)
            if ($reply.Status -eq 'Success') { $isAlive = $true }
        } catch {}
    }

    if ($isAlive) { $aliveHosts.Add($IP) }
}

$rsPool1 = [runspacefactory]::CreateRunspacePool(1, $Threads)
$rsPool1.Open()
$jobs1 = foreach ($ip in $ipList) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $rsPool1
    [void]$ps.AddScript($AliveScriptBlock).AddArgument($ip).AddArgument($aliveHosts)
    [PSCustomObject]@{ Pipe = $ps; Handle = $ps.BeginInvoke() }
}
$jobs1 | ForEach-Object {
    try { $_.Pipe.EndInvoke($_.Handle) | Out-Null }
    catch { Write-Host "[!] 存活探测异常: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    $_.Pipe.Dispose()
}
$rsPool1.Close()
$rsPool1.Dispose()

$aliveList = $aliveHosts | Sort-Object -Unique
Write-Host "[+] 存活主机数量: $($aliveList.Count)" -ForegroundColor Green
$aliveList | ForEach-Object { Write-Host "    $_" }

} # end else (SkipHostDiscovery)

if ($aliveList.Count -eq 0) {
    Write-Host "[!] 未发现存活主机，退出。" -ForegroundColor Yellow
    return
}

# ---------- 第二步：端口 + Web 探测 ----------
Write-Host "[*] 第二步：探测端口 $StartPort-$EndPort 并检测 /FileReceiver ..." -ForegroundColor Cyan

$targets = foreach ($ip in $aliveList) {
    foreach ($port in $StartPort..$EndPort) {
        [PSCustomObject]@{ IP = $ip; Port = $port }
    }
}

$ScriptBlock = {
    param($IP, $Port, $Timeout, $Results)

    # 1. TCP 端口连通性
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($IP, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($Timeout, $false)
        if (-not $ok -or -not $client.Connected) {
            $client.Close()
            return
        }
        $client.Close()
    } catch { return }

    # 2. 判断 HTTP / HTTPS，并请求 /FileReceiver
    $schemes = @('http', 'https')
    foreach ($scheme in $schemes) {
        $url = "$scheme`://$IP`:$Port/FileReceiver"
        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method = "GET"
            $req.Timeout = $Timeout
            $req.ReadWriteTimeout = $Timeout
            $req.AllowAutoRedirect = $false
            $req.UserAgent = "Mozilla/5.0 (AssetScan)"
            try {
                $resp = $req.GetResponse()
                $code = [int]$resp.StatusCode
                $resp.Close()
            } catch [System.Net.WebException] {
                if ($_.Exception.Response) {
                    $code = [int]$_.Exception.Response.StatusCode
                    $_.Exception.Response.Close()
                } else {
                    $code = $null
                }
            }

            if ($code -in 200, 403, 405) {
                $Results.Add([PSCustomObject]@{
                    IP     = $IP
                    Port   = $Port
                    Scheme = $scheme
                    URL    = $url
                    Status = $code
                    Time   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                })
                Write-Host "[HIT] $url -> $code" -ForegroundColor Green
            }
            # 只要这个 scheme 能建立 HTTP 通信（不管状态码），就不必再试另一个 scheme
            if ($code) { break }
        } catch {
            # 该 scheme 请求失败（连接被拒/协议不匹配等），尝试下一个 scheme
            continue
        }
    }
}

$rsPool2 = [runspacefactory]::CreateRunspacePool(1, $Threads)
$rsPool2.Open()

$jobs2 = foreach ($t in $targets) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $rsPool2
    [void]$ps.AddScript($ScriptBlock).AddArgument($t.IP).AddArgument($t.Port).AddArgument($Timeout).AddArgument($Results)
    [PSCustomObject]@{ Pipe = $ps; Handle = $ps.BeginInvoke() }
}

$total = $jobs2.Count
$done = 0
foreach ($j in $jobs2) {
    $j.Pipe.EndInvoke($j.Handle) | Out-Null
    $j.Pipe.Dispose()
    $done++
    if ($done % 200 -eq 0) {
        Write-Progress -Activity "扫描进度" -Status "$done / $total" -PercentComplete (($done / $total) * 100)
    }
}
Write-Progress -Activity "扫描进度" -Completed

$rsPool2.Close()
$rsPool2.Dispose()

# ---------- 输出结果 ----------
$finalResults = $Results | Sort-Object IP, Port

if ($finalResults.Count -gt 0) {
    $finalResults | Format-Table -AutoSize
    $finalResults | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] 完成，共 $($finalResults.Count) 条命中记录，已保存至: $OutFile" -ForegroundColor Green
} else {
    Write-Host "[*] 完成，未发现符合条件（200/403/405）的记录。" -ForegroundColor Yellow
}
