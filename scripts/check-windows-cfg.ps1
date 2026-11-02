# Copyright (c) Microsoft. All rights reserved.

#Requires -Version 7.4
[CmdletBinding(DefaultParameterSetName = 'Native')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Native')]
    [string] $Dll,
    [Parameter(Mandatory, ParameterSetName = 'Package')]
    [string] $Package,
    [Parameter(Mandatory, ParameterSetName = 'Package')]
    [string] $ExpectedDll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$maxNativeBytes = 64MB

# Same PE metadata checks as agent-hooks v0.1.0-beta.3.
function Assert-ControlFlowGuard {
    param([System.IO.Stream] $Stream, [string] $Artifact)

    if ($Stream.Length -eq 0 -or $Stream.Length -gt $maxNativeBytes) {
        throw "${Artifact}: native asset must be between 1 byte and 64 MiB."
    }
    $reader = [System.Reflection.PortableExecutable.PEReader]::new(
        $Stream, [System.Reflection.PortableExecutable.PEStreamOptions]::LeaveOpen)
    try {
        $header = $reader.PEHeaders.PEHeader
        if ($null -eq $header -or [int] $header.Magic -ne 0x20b -or
            [int] $reader.PEHeaders.CoffHeader.Machine -ne 0x8664) {
            throw "${Artifact}: expected an AMD64 PE32+ native DLL."
        }
        if (([int] $header.DllCharacteristics -band 0x4040) -ne 0x4040) {
            throw "${Artifact}: GuardCF and DynamicBase must both be enabled."
        }
        $directory = $header.LoadConfigTableDirectory
        if ($directory.RelativeVirtualAddress -eq 0 -or $directory.Size -lt 0x94) {
            throw "${Artifact}: missing or truncated CFG load configuration."
        }
        # IMAGE_LOAD_CONFIG_DIRECTORY64 through GuardFlags.
        [byte[]] $config = $reader.GetSectionData(
            $directory.RelativeVirtualAddress).GetContent(0, 0x94)
        $size = [BitConverter]::ToUInt32($config, 0)
        $check = [BitConverter]::ToUInt64($config, 0x70)
        $dispatch = [BitConverter]::ToUInt64($config, 0x78)
        $table = [BitConverter]::ToUInt64($config, 0x80)
        $count = [BitConverter]::ToUInt64($config, 0x88)
        $flags = [BitConverter]::ToUInt32($config, 0x90)
        if ($size -lt 0x94 -or $check -eq 0 -or $dispatch -eq 0 -or
            $table -eq 0 -or $count -eq 0 -or ($flags -band 0x500) -ne 0x500) {
            throw "${Artifact}: missing CFG instrumentation or function-table metadata."
        }
        $stride = 4 + ($flags -shr 28)
        if ($table -lt $header.ImageBase -or
            $table - $header.ImageBase -ge $header.SizeOfImage -or
            $count -gt $header.SizeOfImage / $stride) {
            throw "${Artifact}: invalid CFG function-table bounds."
        }
        $null = $reader.GetSectionData([int] ($table - $header.ImageBase)).GetContent(
            0, [int] ($count * $stride))
        $Stream.Position = 0
        [pscustomobject] @{
            artifact = $Artifact
            sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Stream))
            machine = 'AMD64'
            guardCF = $true
            dynamicBase = $true
            guardCFFunctionCount = $count
            guardFlags = ('0x{0:X}' -f $flags)
        }
    }
    finally {
        $reader.Dispose()
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Native') {
    $stream = [IO.File]::OpenRead((Resolve-Path -LiteralPath $Dll).ProviderPath)
    try {
        Assert-ControlFlowGuard -Stream $stream -Artifact $Dll | ConvertTo-Json -Compress
    }
    finally {
        $stream.Dispose()
    }
}
else {
    $archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Package).ProviderPath)
    try {
        $asset = 'runtimes/win-x64/native/agent_control_spec_ffi.dll'
        $entries = @($archive.Entries | Where-Object { $_.FullName -ceq $asset })
        if ($entries.Count -ne 1 -or $entries[0].Length -eq 0 -or
            $entries[0].Length -gt $maxNativeBytes) {
            throw "${Package}: expected exactly one nonempty $asset, at most 64 MiB."
        }
        $source = $entries[0].Open()
        $payload = [IO.MemoryStream]::new()
        try {
            $buffer = [byte[]]::new(81920)
            while ($payload.Length -lt $entries[0].Length) {
                $remaining = [int] [Math]::Min($buffer.Length, $entries[0].Length - $payload.Length)
                $read = $source.Read($buffer, 0, $remaining)
                if ($read -eq 0) { throw "${Package}: truncated native payload." }
                $payload.Write($buffer, 0, $read)
            }
            if ($source.ReadByte() -ne -1) { throw "${Package}: native payload exceeds its declared length." }
            $payload.Position = 0
            $result = Assert-ControlFlowGuard -Stream $payload -Artifact "${Package}!$asset"
            if ($result.sha256 -ne (Get-FileHash -LiteralPath $ExpectedDll -Algorithm SHA256).Hash) {
                throw "${Package}: native payload does not match the staged release DLL."
            }
            $result | ConvertTo-Json -Compress
        }
        finally {
            $payload.Dispose()
            $source.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
}
