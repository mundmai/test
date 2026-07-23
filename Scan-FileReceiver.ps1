<#
.SYNOPSIS
    自定义网段/端口 Web 服务探测脚本，抓取根路径 title / length / 301302跳转目标。

.说明（务必阅读）
    本脚本仅可用于你拥有明确授权的网络/资产（内部资产梳理、授权渗透测试等）。
    禁止用于未授权的第三方网络扫描。使用前请确认已获得书面授权。

.用法（ISE 直接粘贴运行）
    把整段代码粘贴进 PowerShell ISE，直接修改下面【配置区】里的变量值，
    然后按 F5（或点绿色播放按钮）运行即可，不需要在命令行传参数。

.配置区说明
    $Target         目标网段，支持以下写法（留空则忽略，只用 $TargetFile）：
                      C段简写   "192.168.1"                -> 等价于 192.168.1.0/24 (.1-.254)
                      B段简写   "192.168"                   -> 等价于 192.168.0.0/16 (6万+地址)
                      CIDR      "172.16.0.0/16" "10.1.2.0/28" -> 任意掩码
                      IP范围    "192.168.1.1-192.168.3.254"  -> 起止IP范围
                      单个IP    "192.168.1.10"
    $TargetFile     从文件读取目标列表路径，每行一条，写法同上，支持混合。
                    以 # 开头的行当注释忽略，空行忽略。可与 $Target 同时使用，结果合并去重。
                    留空字符串 "" 表示不使用文件。
    $Ports          要探测的端口，支持单个/逗号分隔/范围混合，例如 "80,443,8000-8090,7000-9999"
    $Threads        并发线程数，默认 200
    $Timeout        基础超时（毫秒），默认 1000；https 会在此基础上自动多留一些余量应对TLS握手
    $OutFile        结果保存路径，留空 "" 则不保存文件，只在控制台显示。
                    指定路径时按后缀名决定格式：.csv / .json / 其他(纯文本，制表符分隔)
                    例如 "C:\result.csv"、".\result.json"、".\result.txt"
    $StatusFilter   只记录指定状态码，逗号分隔，例如 "200,403,405"；留空 "" 则记录所有能拿到响应的结果
    $SkipHostDiscovery  $true/$false，是否跳过存活探测直接扫全部目标IP的端口
    $Force          $true/$false，目标IP数量超过65536时是否强制继续
#>

# =====================================================================
# ======================== 【配置区】在此修改 ==========================
# =====================================================================

$Target            = "192.168.1"                # 目标网段/IP/CIDR/范围，留空 "" 则只用 $TargetFile
$TargetFile        = ""                          # IP列表文件路径，例如 "C:\ips.txt"，不用则留空 ""
$Ports             = "80,443,7000-9999"          # 要探测的端口
$Threads           = 200                         # 并发数
$Timeout           = 1000                        # 基础超时(毫秒)，https会自动再加余量
$OutFile           = ""                          # 留空则不保存文件；例如 ".\result.csv" ".\result.json" ".\result.txt"
$StatusFilter      = ""                          # 例如 "200,403,405"，留空则记录所有响应
$SkipHostDiscovery = $false                      # $true 则跳过存活探测，直接扫全部目标IP
$Force             = $false                      # $true 则允许目标IP数超过65536继续执行

# =====================================================================
# ======================== 以下为脚本逻辑，无需修改 =====================
# =====================================================================

# ---------- IP <-> UInt32 互转 ----------
function ConvertTo-UInt32IP([string]$ip) {
    $b = $ip.Split('.')
    return ([uint64]$b[0] * 16777216) + ([uint64]$b[1] * 65536) + ([uint64]$b[2] * 256) + [uint64]$b[3]
}
function ConvertFrom-UInt32IP([uint64]$val) {
    $o1 = [math]::Floor($val / 16777216) % 256
    $o2 = [math]::Floor($val / 65536) % 256
    $o3 = [math]::Floor($val / 256) % 256
    $o4 = $val % 256
    return "$o1.$o2.$o3.$o4"
}

# ---------- 解析 Target，支持 C段简写 / B段简写 / CIDR / IP范围 / 单IP ----------
function Resolve-TargetIPs([string]$target) {
    $target = $target.Trim()

    # CIDR: a.b.c.d/nn
    if ($target -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') {
        $baseIp = $matches[1]; $prefix = [int]$matches[2]
        $ipVal = ConvertTo-UInt32IP $baseIp
        $maskVal = if ($prefix -eq 0) { 0 } else { ([uint64]0xFFFFFFFF -shl (32 - $prefix)) -band 0xFFFFFFFF }
        $network = $ipVal -band $maskVal
        $hostBits = 32 - $prefix
        $count = [uint64][math]::Pow(2, $hostBits)
        $first = $network + 1
        $last = $network + $count - 2
        if ($prefix -ge 31) { $first = $network; $last = $network + $count - 1 } # /31,/32 特殊情况
        return $first..$last | ForEach-Object { ConvertFrom-UInt32IP $_ }
    }

    # IP范围: a.b.c.d-a.b.c.d
    if ($target -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') {
        $startVal = ConvertTo-UInt32IP $matches[1]
        $endVal   = ConvertTo-UInt32IP $matches[2]
        if ($startVal -gt $endVal) { $tmp = $startVal; $startVal = $endVal; $endVal = $tmp }
        return $startVal..$endVal | ForEach-Object { ConvertFrom-UInt32IP $_ }
    }

    # 单个完整IP: a.b.c.d
    if ($target -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return @($target)
    }

    # C段简写: a.b.c -> a.b.c.0/24
    if ($target -match '^\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return 1..254 | ForEach-Object { "$target.$_" }
    }

    # B段简写: a.b -> a.b.0.0/16
    if ($target -match '^\d{1,3}\.\d{1,3}$') {
        $network = ConvertTo-UInt32IP "$target.0.0"
        $first = $network + 1
        $last = $network + 65534
        return $first..$last | ForEach-Object { ConvertFrom-UInt32IP $_ }
    }

    throw "无法识别的目标写法: $target"
}

if ((-not $Target -or $Target.Trim() -eq '') -and (-not $TargetFile -or $TargetFile.Trim() -eq '')) {
    Write-Host "[!] 请在【配置区】至少设置 `$Target 或 `$TargetFile 其中一个。" -ForegroundColor Red
    return
}

$allIps = [System.Collections.Generic.List[string]]::new()

if ($Target -and $Target.Trim() -ne '') {
    try {
        $resolved = Resolve-TargetIPs -target $Target
        $allIps.AddRange([string[]]$resolved)
        Write-Host "[*] `$Target '$Target' 解析出 $($resolved.Count) 个IP" -ForegroundColor Cyan
    } catch {
        Write-Host "[!] $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

if ($TargetFile -and $TargetFile.Trim() -ne '') {
    if (-not (Test-Path $TargetFile)) {
        Write-Host "[!] 找不到文件: $TargetFile" -ForegroundColor Red
        return
    }
    $lines = Get-Content -Path $TargetFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and -not $_.StartsWith('#') }
    $fileIpCount = 0
    foreach ($line in $lines) {
        try {
            $resolved = Resolve-TargetIPs -target $line
            $allIps.AddRange([string[]]$resolved)
            $fileIpCount += $resolved.Count
        } catch {
            Write-Host "[!] 忽略文件中无法识别的行: $line" -ForegroundColor Yellow
        }
    }
    Write-Host "[*] `$TargetFile '$TargetFile' 解析出 $fileIpCount 个IP（共 $($lines.Count) 行）" -ForegroundColor Cyan
}

$ipList = $allIps | Sort-Object -Unique
Write-Host "[*] 目标去重后共 $($ipList.Count) 个IP" -ForegroundColor Cyan

if ($ipList.Count -gt 65536 -and -not $Force) {
    Write-Host "[!] 目标IP数量($($ipList.Count))超过65536，可能耗时很长。确认无误后请把【配置区】里的 `$Force 改成 `$true 再重新运行。" -ForegroundColor Red
    return
}

# ---------- 解析端口参数："80,443,8000-8090,7000-9999" -> 端口数组 ----------
function Parse-PortList([string]$portStr) {
    $ports = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($part in ($portStr -split ',')) {
        $part = $part.Trim()
        if ($part -eq '') { continue }
        if ($part -match '^(\d+)-(\d+)$') {
            $s = [int]$matches[1]; $e = [int]$matches[2]
            if ($s -gt $e) { $tmp = $s; $s = $e; $e = $tmp }
            for ($p = $s; $p -le $e; $p++) { [void]$ports.Add($p) }
        } elseif ($part -match '^\d+$') {
            [void]$ports.Add([int]$part)
        } else {
            Write-Host "[!] 忽略无法识别的端口写法: $part" -ForegroundColor Yellow
        }
    }
    return ($ports | Sort-Object)
}

$PortList = Parse-PortList -portStr $Ports
if ($PortList.Count -eq 0) {
    Write-Host "[!] 端口参数解析为空，请检查 `$Ports 写法。" -ForegroundColor Red
    return
}
Write-Host "[*] 待探测端口数量: $($PortList.Count)" -ForegroundColor Cyan

$StatusFilterList = @()
if ($StatusFilter -and $StatusFilter.Trim() -ne "") {
    $StatusFilterList = $StatusFilter -split ',' | ForEach-Object { [int]$_.Trim() }
    Write-Host "[*] 仅记录状态码: $($StatusFilterList -join ', ')" -ForegroundColor Cyan
}

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
if ($SkipHostDiscovery) {
    Write-Host "[*] 已跳过存活探测，直接对全部 $($ipList.Count) 个IP 扫端口..." -ForegroundColor Cyan
    $aliveList = $ipList
} else {

Write-Host "[*] 第一步：探测 $($ipList.Count) 个IP 的存活情况..." -ForegroundColor Cyan

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
Write-Host "[*] 第二步：探测指定端口并抓取 Web 服务信息 ..." -ForegroundColor Cyan

$targets = foreach ($ip in $aliveList) {
    foreach ($port in $PortList) {
        [PSCustomObject]@{ IP = $ip; Port = $port }
    }
}

$ScriptBlock = {
    param($IP, $Port, $Timeout, $Results, $StatusFilterList)

    # 提取 <title> 的小函数（内联写，避免跨 Runspace 传函数失效的老问题）
    function Get-PageTitle($body) {
        if ([string]::IsNullOrEmpty($body)) { return "" }
        $m = [regex]::Match($body, '<title[^>]*>\s*(.*?)\s*</title>', 'IgnoreCase, Singleline')
        if ($m.Success) {
            $t = [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
            return ($t -replace '\s+', ' ').Trim()
        }
        return ""
    }

    # 发起请求，返回 [状态码, 响应体(最多读2MB用于取title), 长度, 跳转目标]
    function Invoke-Probe($url, $Timeout) {
        $code = $null
        $body = ""
        $length = 0
        $location = ""
        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method = "GET"
            $req.Timeout = $Timeout
            $req.ReadWriteTimeout = $Timeout
            $req.AllowAutoRedirect = $false
            $req.UserAgent = "Mozilla/5.0 (AssetScan)"
            $resp = $null
            try {
                $resp = $req.GetResponse()
            } catch [System.Net.WebException] {
                if ($_.Exception.Response) { $resp = $_.Exception.Response }
            }
            if ($resp) {
                $code = [int]$resp.StatusCode
                if ($resp.Headers["Location"]) { $location = $resp.Headers["Location"] }
                try {
                    $stream = $resp.GetResponseStream()
                    $ms = New-Object System.IO.MemoryStream
                    $buffer = New-Object byte[] 8192
                    $totalRead = 0
                    $maxBytes = 2097152  # 最多读 2MB，避免大文件拖慢扫描
                    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $ms.Write($buffer, 0, $read)
                        $totalRead += $read
                        if ($totalRead -ge $maxBytes) { break }
                    }
                    $bytes = $ms.ToArray()
                    $body = [System.Text.Encoding]::UTF8.GetString($bytes)
                    if ($resp.ContentLength -ge 0) { $length = $resp.ContentLength } else { $length = $totalRead }
                } catch {}
                $resp.Close()
            }
        } catch { }
        return @($code, $body, $length, $location)
    }

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

    # 2. http 和 https 都独立探测（不因为一个成功就跳过另一个，避免漏掉443等TLS端口）
    #    https 握手比明文http慢，单独多给一点超时余量
    $schemes = @(
        @{ Scheme = 'http';  Extra = 0 },
        @{ Scheme = 'https'; Extra = 700 }
    )

    foreach ($s in $schemes) {
        $scheme = $s.Scheme
        $effTimeout = $Timeout + $s.Extra
        $url = "$scheme`://$IP`:$Port/"

        $result = Invoke-Probe -url $url -Timeout $effTimeout
        $code     = $result[0]
        $body     = $result[1]
        $length   = $result[2]
        $location = $result[3]

        if (-not $code) { continue }  # 该 scheme 没拿到响应，跳过，不影响另一个scheme的探测

        $title = Get-PageTitle $body

        $shouldRecord = ($StatusFilterList.Count -eq 0) -or ($code -in $StatusFilterList)

        if ($shouldRecord) {
            $Results.Add([PSCustomObject]@{
                URL      = $url
                Status   = $code
                Title    = $title
                Length   = $length
                Redirect = $location
            })
            $redirInfo = if ($location) { "  -> $location" } else { "" }
            Write-Host "[HIT] $url -> $code  Len:$length  Title:$title$redirInfo" -ForegroundColor Green
        }
    }
}

$rsPool2 = [runspacefactory]::CreateRunspacePool(1, $Threads)
$rsPool2.Open()

$jobs2 = foreach ($t in $targets) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $rsPool2
    [void]$ps.AddScript($ScriptBlock).AddArgument($t.IP).AddArgument($t.Port).AddArgument($Timeout).AddArgument($Results).AddArgument($StatusFilterList)
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
$finalResults = $Results | Sort-Object URL

if ($finalResults.Count -gt 0) {
    $finalResults | Format-Table -AutoSize

    if ($OutFile -and $OutFile.Trim() -ne "") {
        $ext = [System.IO.Path]::GetExtension($OutFile).ToLower()
        switch ($ext) {
            '.csv' {
                $finalResults | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
            }
            '.json' {
                $finalResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutFile -Encoding UTF8
            }
            default {
                $lines = @("URL`tStatus`tTitle`tLength`tRedirect")
                $lines += $finalResults | ForEach-Object { "$($_.URL)`t$($_.Status)`t$($_.Title)`t$($_.Length)`t$($_.Redirect)" }
                $lines | Out-File -FilePath $OutFile -Encoding UTF8
            }
        }
        Write-Host "[+] 完成，共 $($finalResults.Count) 条命中记录，已保存至: $OutFile" -ForegroundColor Green
    } else {
        Write-Host "[+] 完成，共 $($finalResults.Count) 条命中记录（未设置 `$OutFile，未保存文件）。" -ForegroundColor Green
    }
} else {
    Write-Host "[*] 完成，未发现符合条件的记录。" -ForegroundColor Yellow
}
