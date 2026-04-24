function Resolve-TestbenchAdapter {
    param(
        [string]$AdapterGuid
    )

    if ($AdapterGuid) {
        $normalizedGuid = $AdapterGuid.Trim('{}').ToLowerInvariant()
        $adapter = Get-NetAdapter -IncludeHidden |
            Where-Object { $_.InterfaceGuid.Guid.ToString().ToLowerInvariant() -eq $normalizedGuid } |
            Select-Object -First 1

        if (-not $adapter) {
            throw "Could not find adapter with GUID {$normalizedGuid}."
        }

        return $adapter
    }

    $defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1

    if (-not $defaultRoute) {
        throw "Could not resolve the active IPv4 default route."
    }

    $adapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction Stop
    if (-not $adapter) {
        throw "Could not resolve the default-route adapter for ifIndex $($defaultRoute.InterfaceIndex)."
    }

    return $adapter
}

function Ensure-WinpkFilterBinding {
    param(
        [string]$AdapterGuid
    )

    $adapter = Resolve-TestbenchAdapter -AdapterGuid $AdapterGuid
    Write-Host "Using adapter '$($adapter.Name)' (ifIndex=$($adapter.IfIndex), GUID={$($adapter.InterfaceGuid.Guid)}) for WinpkFilter validation"

    $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID "nt_ndisrd" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $binding) {
        throw "WinpkFilter binding 'nt_ndisrd' is not installed on adapter '$($adapter.Name)'."
    }

    $service = Get-Service -Name "NDISRD" -ErrorAction SilentlyContinue
    if (-not $service) {
        throw "WinpkFilter driver service 'NDISRD' is not installed."
    }

    if ($service.Status -ne "Running") {
        Write-Host "Starting WinpkFilter driver service 'NDISRD'..."
        Start-Service -Name "NDISRD" -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds(10)
        do {
            Start-Sleep -Milliseconds 250
            $service = Get-Service -Name "NDISRD" -ErrorAction Stop
        } while ($service.Status -ne "Running" -and (Get-Date) -lt $deadline)

        if ($service.Status -ne "Running") {
            throw "WinpkFilter driver service 'NDISRD' did not reach Running state."
        }
    }

    if (-not $binding.Enabled) {
        Write-Host "Enabling WinpkFilter binding on '$($adapter.Name)'..."
        Enable-NetAdapterBinding -Name $adapter.Name -ComponentID "nt_ndisrd" -Confirm:$false -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 2
        $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID "nt_ndisrd" -ErrorAction Stop |
            Select-Object -First 1
        if (-not $binding.Enabled) {
            throw "Failed to enable WinpkFilter binding on adapter '$($adapter.Name)'."
        }
    }

    Write-Host "WinpkFilter binding is enabled on '$($adapter.Name)'."
    return $adapter
}
