@echo off
rem Local Network UDP DNS Cache Detection
rem Copyright (c) 2026 Niklas Tecklenborg
rem Released under the MIT License, see LICENSE
if /i "%~1"=="-NoGui" goto console
start "" powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -Command "$t=[IO.File]::ReadAllText('%~f0'); $i=$t.IndexOf('#PS-START'+'#'); & ([scriptblock]::Create($t.Substring($i))) %*"
exit /b
:console
powershell -NoProfile -ExecutionPolicy Bypass -STA -Command "$t=[IO.File]::ReadAllText('%~f0'); $i=$t.IndexOf('#PS-START'+'#'); & ([scriptblock]::Create($t.Substring($i))) %*"
pause
exit /b
#PS-START#
param([switch]$NoGui)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Settings = @{ Samples = 5; Domain = 'example.com' }
$TimeoutMs = 2000

$Resolvers = @(
    @{ Name = 'Cloudflare'; Ip = '1.1.1.1'; Dot = 'one.one.one.one' },
    @{ Name = 'Google'; Ip = '8.8.8.8'; Dot = 'dns.google' },
    @{ Name = 'Quad9'; Ip = '9.9.9.9'; Dot = 'dns.quad9.net' }
)

function New-DnsQuery([string]$name) {
    $bytes = New-Object System.Collections.Generic.List[byte]
    $id = Get-Random -Minimum 0 -Maximum 65536
    $bytes.Add([byte]($id -shr 8)); $bytes.Add([byte]($id -band 255))
    $bytes.AddRange([byte[]](1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($label in $name.Split('.')) {
        $l = [Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$l.Length); $bytes.AddRange($l)
    }
    $bytes.AddRange([byte[]](0, 0, 1, 0, 1))
    return , $bytes.ToArray()
}

function Test-DnsResponse([byte[]]$query, [byte[]]$response) {
    if ($response.Length -lt 12) { return $false }
    if ($response[0] -ne $query[0] -or $response[1] -ne $query[1]) { return $false }
    if (($response[2] -band 0x80) -eq 0) { return $false }
    $rcode = $response[3] -band 15
    return ($rcode -eq 0 -or $rcode -eq 3)
}

function New-RandomName {
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    $label = 'u' + (-join (1..11 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] }))
    return "$label.$($Settings.Domain)"
}

function Measure-Series([scriptblock]$once) {
    $times = @()
    for ($i = 1; $i -le $Settings.Samples; $i++) {
        $ms = & $once
        if ($null -eq $ms) { return $null }
        $times += $ms
    }
    return [math]::Round(($times | Measure-Object -Minimum).Minimum, 1)
}

function Invoke-Ping([string]$ip) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $task = $client.ConnectAsync($ip, 443)
        if (-not $task.Wait($TimeoutMs) -or -not $client.Connected) { return $null }
        $sw.Stop()
        return $sw.Elapsed.TotalMilliseconds
    } catch { return $null } finally { $client.Close() }
}

function Invoke-Udp([string]$ip, [string]$name) {
    $udp = New-Object Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($ip, 53)
        $q = New-DnsQuery $name
        $sw = [Diagnostics.Stopwatch]::StartNew()
        [void]$udp.Send($q, $q.Length)
        $remote = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $udp.Receive([ref]$remote)
        $sw.Stop()
        if (-not (Test-DnsResponse $q $r)) { return $null }
        return $sw.Elapsed.TotalMilliseconds
    } catch { return $null } finally { $udp.Close() }
}

function Read-Exact($stream, [int]$count) {
    $buf = New-Object byte[] $count
    $got = 0
    while ($got -lt $count) {
        $n = $stream.Read($buf, $got, $count - $got)
        if ($n -le 0) { throw 'closed' }
        $got += $n
    }
    return , $buf
}

function Measure-Dot([string]$hostName) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout = $TimeoutMs
        $task = $client.ConnectAsync($hostName, 853)
        if (-not $task.Wait($TimeoutMs)) { return $null }
        $ssl = New-Object Net.Security.SslStream($client.GetStream(), $false)
        $ssl.AuthenticateAsClient($hostName, $null, [Security.Authentication.SslProtocols]::Tls12, $true)
        return Measure-Series {
            $q = New-DnsQuery $Settings.Domain
            $framed = [byte[]](@([byte]($q.Length -shr 8), [byte]($q.Length -band 255)) + $q)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $ssl.Write($framed, 0, $framed.Length)
            $ssl.Flush()
            $len = Read-Exact $ssl 2
            $resp = Read-Exact $ssl (($len[0] -shl 8) + $len[1])
            $sw.Stop()
            if (-not (Test-DnsResponse $q $resp)) { return $null }
            return $sw.Elapsed.TotalMilliseconds
        }
    } catch { return $null } finally { $client.Close() }
}

function Get-Vote($udp, $ref, [double]$ratio, [int]$gap) {
    if ($null -eq $ref) { return 'no vote' }
    if ($udp -lt $ref * $ratio -and ($ref - $udp) -ge $gap) { return 'cache' }
    return 'no cache'
}

function Invoke-Check($resolver, [scriptblock]$progress) {
    $refs = @()
    & $progress "$($resolver.Name): Ping ..."
    $refs += [pscustomobject]@{ Name = 'Ping (TCP 443)'; Ms = (Measure-Series { Invoke-Ping $resolver.Ip }); Ratio = 0.7; Gap = 2 }
    & $progress "$($resolver.Name): DoT ..."
    $refs += [pscustomobject]@{ Name = 'DoT'; Ms = (Measure-Dot $resolver.Dot); Ratio = 0.7; Gap = 2 }
    & $progress "$($resolver.Name): UDP random subdomain ..."
    $refs += [pscustomobject]@{ Name = 'UDP random subdomain'; Ms = (Measure-Series { Invoke-Udp $resolver.Ip (New-RandomName) }); Ratio = 0.45; Gap = 4 }
    $working = @($refs | Where-Object { $null -ne $_.Ms })
    $udp = $null
    if ($working.Count -ge 2) {
        & $progress "$($resolver.Name): UDP ..."
        $udp = Measure-Series { Invoke-Udp $resolver.Ip $Settings.Domain }
    }
    $intercepted = 0
    $clean = 0
    foreach ($r in $refs) {
        if ($null -eq $r.Ms -or $null -eq $udp) {
            $r | Add-Member -NotePropertyName Vote -NotePropertyValue 'no vote'
            $r | Add-Member -NotePropertyName Limit -NotePropertyValue ''
            continue
        }
        $vote = Get-Vote $udp $r.Ms $r.Ratio $r.Gap
        $r | Add-Member -NotePropertyName Vote -NotePropertyValue $vote
        $limit = [math]::Round([math]::Min($r.Ms * $r.Ratio, $r.Ms - $r.Gap), 1)
        $text = if ($vote -eq 'cache') { 'Baseline is below the limit of {0:N1} ms' } else { 'Baseline is not below the limit of {0:N1} ms' }
        $r | Add-Member -NotePropertyName Limit -NotePropertyValue ($text -f $limit)
        if ($vote -eq 'cache') { $intercepted++ } else { $clean++ }
    }
    $cast = $intercepted + $clean
    $verdict = 'Inconclusive'
    if ($null -ne $udp) {
        if ($intercepted * 2 -gt $cast) { $verdict = 'Cache detected' }
        elseif ($clean * 2 -gt $cast) { $verdict = 'No cache detected' }
    }
    return [pscustomobject]@{ Resolver = $resolver.Name; Refs = $refs; Udp = $udp; Intercepted = $intercepted; Clean = $clean; Failed = @($refs | Where-Object { $_.Vote -eq 'no vote' }).Count; Verdict = $verdict }
}

function Invoke-Selected([string]$name, [scriptblock]$progress) {
    $resolver = $Resolvers | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    return Invoke-Check $resolver $progress
}

function Format-Ms($v) { if ($null -eq $v) { return 'failed' } else { return ('{0:N1} ms' -f $v) } }

if ($NoGui) {
    $result = Invoke-Selected 'Cloudflare' { param($t) Write-Host $t }
    Write-Host ''
    Write-Host "Resolver: $($result.Resolver)"
    Write-Host "UDP: $(Format-Ms $result.Udp)"
    foreach ($r in $result.Refs) { Write-Host ("{0,-22} {1,-16} {2,-14} {3}" -f $r.Name, (Format-Ms $r.Ms), $r.Vote, $r.Limit) }
    Write-Host "Votes: $($result.Intercepted) cache, $($result.Clean) no cache, $($result.Failed) failed"
    Write-Host "Result: $($result.Verdict)"
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object Windows.Forms.Form
$form.Text = 'Cache detection test'
$form.Size = New-Object Drawing.Size(760, 580)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object Drawing.Font('Segoe UI', 10)

$mode = New-Object Windows.Forms.ComboBox
$mode.DropDownStyle = 'DropDownList'
[void]$mode.Items.AddRange(@($Resolvers | ForEach-Object { $_.Name }))
$mode.SelectedIndex = 0
$mode.Location = New-Object Drawing.Point(12, 14)
$mode.Width = 120

$reload = New-Object Windows.Forms.Button
$reload.Text = 'Start'
$reload.Location = New-Object Drawing.Point(144, 12)
$reload.Size = New-Object Drawing.Size(100, 30)

$status = New-Object Windows.Forms.Label
$domainLabel = New-Object Windows.Forms.Label
$domainLabel.Text = 'Domain:'
$domainLabel.Location = New-Object Drawing.Point(256, 18)
$domainLabel.AutoSize = $true

$domainBox = New-Object Windows.Forms.TextBox
$domainBox.Text = $Settings.Domain
$domainBox.Location = New-Object Drawing.Point(322, 14)
$domainBox.Width = 140

$samplesLabel = New-Object Windows.Forms.Label
$samplesLabel.Text = 'Queries:'
$samplesLabel.Location = New-Object Drawing.Point(474, 18)
$samplesLabel.AutoSize = $true

$samplesBox = New-Object Windows.Forms.NumericUpDown
$samplesBox.Minimum = 1
$samplesBox.Maximum = 50
$samplesBox.Value = $Settings.Samples
$samplesBox.Location = New-Object Drawing.Point(548, 14)
$samplesBox.Width = 60

$status.Location = New-Object Drawing.Point(12, 366)
$status.AutoSize = $true
$status.Text = 'Ready'

$list = New-Object Windows.Forms.ListView
$list.View = 'Details'
$list.FullRowSelect = $true
$list.GridLines = $true
$list.Location = New-Object Drawing.Point(12, 56)
$list.Size = New-Object Drawing.Size(720, 190)
[void]$list.Columns.Add('Reference', 190)
[void]$list.Columns.Add('Fastest', 100)
[void]$list.Columns.Add('Vote', 120)
[void]$list.Columns.Add('Explanation', 290)

function New-SummaryLabel([int]$width, [Drawing.Font]$font, $color) {
    $l = New-Object Windows.Forms.Label
    $l.Size = New-Object Drawing.Size($width, 28)
    $l.Margin = New-Object Windows.Forms.Padding(0)
    $l.TextAlign = 'MiddleLeft'
    $l.Font = $font
    if ($color) { $l.ForeColor = $color }
    return $l
}

$boldFont = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
$iconFont = New-Object Drawing.Font('Segoe MDL2 Assets', 14)
$summary = New-Object Windows.Forms.FlowLayoutPanel
$summary.Location = New-Object Drawing.Point(12, 258)
$summary.Size = New-Object Drawing.Size(720, 28)
$summary.Visible = $false
$voteTitle = New-SummaryLabel 70 $boldFont $null
$voteTitle.Text = 'Votes:'
$badIcon = New-SummaryLabel 28 $iconFont ([Drawing.Color]::FromArgb(191, 87, 0))
$badIcon.Text = [string][char]0xE7BA
$badText = New-SummaryLabel 140 $boldFont $null
$okIcon = New-SummaryLabel 28 $iconFont ([Drawing.Color]::ForestGreen)
$okIcon.Text = [string][char]0xE930
$okText = New-SummaryLabel 140 $boldFont $null
$failIcon = New-SummaryLabel 28 $iconFont ([Drawing.Color]::Gray)
$failIcon.Text = [string][char]0xEA39
$failText = New-SummaryLabel 140 $boldFont $null
$summary.Controls.AddRange(@($voteTitle, $badIcon, $badText, $okIcon, $okText, $failIcon, $failText))

$verdict = New-Object Windows.Forms.Label
$verdict.Location = New-Object Drawing.Point(12, 296)
$verdict.Size = New-Object Drawing.Size(720, 60)
$verdict.TextAlign = 'MiddleCenter'
$verdict.Font = New-Object Drawing.Font('Segoe UI', 20, [Drawing.FontStyle]::Bold)

$note = New-Object Windows.Forms.Label
$note.Location = New-Object Drawing.Point(12, 394)
$note.Size = New-Object Drawing.Size(720, 110)
$note.ForeColor = [Drawing.Color]::Gray
$note.Text = "How the vote works:`r`n" +
    "Each reference (Ping, DoT, UDP random subdomain) votes 'cache' if UDP is much faster than it, otherwise 'no cache'.`r`n" +
    "Ping and DoT: UDP must be under 70% of the reference time and at least 2 ms faster.`r`n" +
    "UDP random subdomain: UDP must be under 45% of the reference time and at least 4 ms faster (random names cannot be cached).`r`n" +
    "The fastest query of each series counts. More than half of the votes decide."

$form.Controls.AddRange(@($mode, $reload, $domainLabel, $domainBox, $samplesLabel, $samplesBox, $status, $list, $summary, $verdict, $note))

$run = {
    $reload.Enabled = $false
    $list.Items.Clear()
    $summary.Visible = $false
    $verdict.Text = ''
    $verdict.BackColor = [Drawing.Color]::Transparent
    $verdict.ForeColor = [Drawing.SystemColors]::ControlText
    $progress = { param($t) $status.Text = $t; [Windows.Forms.Application]::DoEvents() }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $name = $domainBox.Text.Trim()
        if (-not $name) { throw 'Enter a domain' }
        $Settings.Domain = $name
        $Settings.Samples = [int]$samplesBox.Value
        $result = Invoke-Selected $mode.SelectedItem $progress
        $item = $list.Items.Add('UDP')
        [void]$item.SubItems.Add((Format-Ms $result.Udp)); [void]$item.SubItems.Add(''); [void]$item.SubItems.Add('Baseline')
        foreach ($r in $result.Refs) {
            $item = $list.Items.Add($r.Name)
            [void]$item.SubItems.Add((Format-Ms $r.Ms)); [void]$item.SubItems.Add($r.Vote); [void]$item.SubItems.Add($r.Limit)
            if ($r.Vote -eq 'cache') { $item.ForeColor = [Drawing.Color]::FromArgb(191, 87, 0) }
            elseif ($r.Vote -eq 'no cache') { $item.ForeColor = [Drawing.Color]::ForestGreen }
            else { $item.ForeColor = [Drawing.Color]::Gray }
        }
        $badText.Text = "$($result.Intercepted) cache"
        $okText.Text = "$($result.Clean) no cache"
        $failText.Text = "$($result.Failed) failed"
        $summary.Visible = $true
        $verdict.Text = $result.Verdict
        switch ($result.Verdict) {
            'No cache detected' { $verdict.BackColor = [Drawing.Color]::FromArgb(27, 94, 32); $verdict.ForeColor = [Drawing.Color]::White }
            'Cache detected' { $verdict.BackColor = [Drawing.Color]::FromArgb(191, 87, 0); $verdict.ForeColor = [Drawing.Color]::White }
            default { $verdict.BackColor = [Drawing.Color]::FromArgb(235, 235, 235) }
        }
        $watch.Stop()
        $status.Text = "Done ($($result.Resolver)) in {0:N1} s" -f $watch.Elapsed.TotalSeconds
    } catch {
        $status.Text = "Error: $($_.Exception.Message)"
    }
    $reload.Enabled = $true
}

$reload.Add_Click($run)
[void]$form.ShowDialog()
