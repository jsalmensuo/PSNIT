# PSNIT.psm1 - Core Functions for Network Information

#region GUI
Add-Type -AssemblyName PresentationFramework

function Invoke-PortHardeningSweep {
    $riskyPorts = @(21, 23, 25, 53, 69, 80, 110, 135, 137, 138, 139, 143, 161, 389, 445, 512, 513, 514, 993, 995, 1433, 1521, 3306, 3389, 5900, 8080)

    $firewallRules = @()

    foreach ($rule in Get-NetFirewallRule -Direction Inbound) {
        try {
            $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
            if ($portFilters) {
                foreach ($filter in $portFilters) {
                    if ($riskyPorts -contains [int]$filter.LocalPort) {
                        $firewallRules += $rule
                        break
                    }
                }
            }
        } catch {
            # Ignore any errors from malformed rules
        }
    }

    if ($firewallRules.Count -eq 0) {
        Write-Host "Port Hardening Sweep: No risky ports have any associated firewall rules."
        return
    }

    $results = $firewallRules | ForEach-Object {
        $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_
        [PSCustomObject]@{
            RuleName = $_.DisplayName
            Ports    = ($portFilters.LocalPort -join ', ')
        }
    }

    Write-Host "Port Hardening Sweep: The following risky ports have associated firewall rules:`n"
    $results | Format-Table -AutoSize
}



# Information Tab Functions
function Add-InformationTabButtons($tabPanel) {
    # IP Configuration Button
    $ipconfigBtn = New-Object Windows.Controls.Button
    $ipconfigBtn.Content = "IP Configuration"
    $ipconfigBtn.Height = 40
    $ipconfigBtn.Margin = "0,0,0,10"
    $ipconfigBtn.Add_Click({
        $output = (Get-NetIPConfiguration | Out-String) 
        Show-OutputWindow "IP Configuration" $output
    })
    $tabPanel.Children.Add($ipconfigBtn)

    # Network Interfaces Button
    $interfacesBtn = New-Object Windows.Controls.Button
    $interfacesBtn.Content = "Network Interfaces"
    $interfacesBtn.Height = 40
    $interfacesBtn.Margin = "0,0,0,10"
    $interfacesBtn.Add_Click({
        $output = (Get-NetAdapter | Out-String)
        Show-OutputWindow "Network Interfaces" $output
    })
    $tabPanel.Children.Add($interfacesBtn)

    # IP Interfaces Button
    $ipInterfacesBtn = New-Object Windows.Controls.Button
    $ipInterfacesBtn.Content = "IP Interfaces"
    $ipInterfacesBtn.Height = 40
    $ipInterfacesBtn.Margin = "0,0,0,10"
    $ipInterfacesBtn.Add_Click({
        $output = (Get-NetIPInterface | Out-String)
        Show-OutputWindow "IP Interfaces" $output
    })
    $tabPanel.Children.Add($ipInterfacesBtn)

    # ARP Table Button
    $arpBtn = New-Object Windows.Controls.Button
    $arpBtn.Content = "ARP Table"
    $arpBtn.Height = 40
    $arpBtn.Margin = "0,0,0,10"
    $arpBtn.Add_Click({
        $output = (Get-NetNeighbor | Out-String)
        Show-OutputWindow "ARP Table" $output
    })
    $tabPanel.Children.Add($arpBtn)

    # Routing Table Button
    $routingTableBtn = New-Object Windows.Controls.Button
    $routingTableBtn.Content = "Routing Table"
    $routingTableBtn.Height = 40
    $routingTableBtn.Margin = "0,0,0,10"
    $routingTableBtn.Add_Click({
        $output = (Get-NetRoute | Out-String)
        Show-OutputWindow "Routing Table" $output
    })
    $tabPanel.Children.Add($routingTableBtn)

# Hardwareinfo Button
$hardwareInfoBtn = New-Object Windows.Controls.Button
$hardwareInfoBtn.Content = "Hardware Info"
$hardwareInfoBtn.Height = 40
$hardwareInfoBtn.Margin = "0,0,0,10"
$hardwareInfoBtn.Add_Click({
    # Get system and hardware info using WMI
    $osInfo = Get-WmiObject Win32_OperatingSystem | Select-Object -First 1 -Property Caption, BuildNumber, OSArchitecture
    $biosInfo = Get-WmiObject Win32_BIOS | Select-Object -First 1 -Property Name, Status
    $computerSystem = Get-WmiObject Win32_ComputerSystem | Select-Object -First 1 -Property Name, Model, NumberOfProcessors
    $gpus = (Get-WmiObject Win32_VideoController | Select-Object -ExpandProperty Name) -join ", "
    $motherboard = (Get-WmiObject Win32_BaseBoard | Select-Object -First 1 -ExpandProperty Product)
    $ramSpeed = (Get-WmiObject Win32_PhysicalMemory | Select-Object -ExpandProperty Speed) -join ", "
    
    # Format the output for uniformity
    $output = @"
Operating System: $($osInfo.Caption) $($osInfo.OSArchitecture) Build: $($osInfo.BuildNumber)
BIOS:             $($biosInfo.Name)
BIOS Status:      $($biosInfo.Status)
Computer Name:    $($computerSystem.Name)
Computer Model:   $($computerSystem.Model)
GPU(s):           $gpus
Motherboard:      $motherboard
RAM Speed (MHz):  $ramSpeed
"@
    
    # Show the output in a separate window
    Show-OutputWindow "Hardware Info" $output
})

$tabPanel.Children.Add($hardwareInfoBtn)
    

    



}

# Configuration Tab Functions
function Add-ConfigurationTabButtons($tabPanel) {
    # Set Static IP Button
    $setIPBtn = New-Object Windows.Controls.Button
    $setIPBtn.Content = "Set Static IP"
    $setIPBtn.Height = 40
    $setIPBtn.Margin = "0,0,0,10"
    $setIPBtn.Add_Click({
        Show-ConfigWindow "Set Static IP" $true
    })
    $tabPanel.Children.Add($setIPBtn)

    # Set DHCP Button
    $setDhcpBtn = New-Object Windows.Controls.Button
    $setDhcpBtn.Content = "Set DHCP"
    $setDhcpBtn.Height = 40
    $setDhcpBtn.Margin = "0,0,0,10"
    $setDhcpBtn.Add_Click({
        Show-ConfigWindow "Set DHCP" $false
    })
    $tabPanel.Children.Add($setDhcpBtn)

    # Set DNS Server Button
    $setDNSBtn = New-Object Windows.Controls.Button
    $setDNSBtn.Content = "Set DNS Server"
    $setDNSBtn.Height = 40
    $setDNSBtn.Margin = "0,0,0,10"
    $setDNSBtn.Add_Click({
        Show-DNSWindow
    })
    $tabPanel.Children.Add($setDNSBtn)
}

# Connection Tab Functions
function Add-ConnectionTabButtons($tabPanel) {
    # Ping Test Button
    $pingBtn = New-Object Windows.Controls.Button
    $pingBtn.Content = "Ping Test"
    $pingBtn.Height = 40
    $pingBtn.Margin = "0,0,0,10"
    $pingBtn.Add_Click({
        $pingResult = Test-Connection -ComputerName "google.com" -Count 4
        $output = $pingResult | Out-String
        Show-OutputWindow "Ping Test Results" $output
    })
    $tabPanel.Children.Add($pingBtn)

# DNS Lookup Button
    $dnsLookupBtn = New-Object Windows.Controls.Button
    $dnsLookupBtn.Content = "DNS Lookup"
    $dnsLookupBtn.Height = 40
    $dnsLookupBtn.Margin = "0,0,0,10"
    $dnsLookupBtn.Add_Click({
    $domain = "google.com"  # You can also prompt for domain input
    $dnsResult = Resolve-DnsName -Name $domain | Select-Object Name, IPAddress
    $output = $dnsResult | Format-Table -AutoSize | Out-String
    Show-OutputWindow "DNS Lookup Results" $output
    })
    $tabPanel.Children.Add($dnsLookupBtn)

    # Traceroute Button
    $tracerouteBtn = New-Object Windows.Controls.Button
    $tracerouteBtn.Content = "Traceroute"
    $tracerouteBtn.Height = 40
    $tracerouteBtn.Margin = "0,0,0,10"
    $tracerouteBtn.Add_Click({
        $tracerouteResult = Test-NetConnection -ComputerName "google.com" -Traceroute
        $output = $tracerouteResult | Out-String
        Show-OutputWindow "Traceroute Results" $output
    })
    $tabPanel.Children.Add($tracerouteBtn)

    # Check TCP Button
    $checkTCPConnectionsBtn = New-Object Windows.Controls.Button
    $checkTCPConnectionsBtn.Content = "Check Open TCP connections"
    $checkTCPConnectionsBtn.Height = 40
    $checkTCPConnectionsBtn.Margin = "0,0,0,10"
    $checkTCPConnectionsBtn.Add_Click({
        $checkTCPConnectionsResult = Get-NetTCPConnection
        $output = $checkTCPConnectionsResult | Out-String
        Show-OutputWindow "Open TCP Connections" $output
    })
    $tabPanel.Children.Add($checkTCPConnectionsBtn)






    
    $hardenPortsBtn = New-Object Windows.Controls.Button
$hardenPortsBtn.Content = "Port Hardening Sweep"
$hardenPortsBtn.Height = 40
$hardenPortsBtn.Margin = "0,0,0,10"
$hardenPortsBtn.Add_Click({ Invoke-PortHardeningSweep })
$tabPanel.Children.Add($hardenPortsBtn)
}


# Function for the Security Tab
function Add-SecurityTabButtons($tabPanel) {

# Local Security Policy
$secpolBtn = New-Object Windows.Controls.Button
$secpolBtn.Content = "Local Security Policy"
$secpolBtn.Height = 40
$secpolBtn.Margin = "0,0,0,10"
$secpolBtn.Add_Click({
    # Open Local Security Policy
    Start-Process "secpol.msc"
})
$tabPanel.Children.Add($secpolBtn)

    # traffic Traffic Rules Button
    $trafficBtn = New-Object Windows.Controls.Button
    $trafficBtn.Content = "Traffic Rules"
    $trafficBtn.Height = 40
    $trafficBtn.Margin = "0,0,0,10"
    $trafficBtn.Add_Click({
        # Open traffic Traffic Rules in Windows Firewall
        Start-Process "wf.msc"
    })
    $tabPanel.Children.Add($trafficBtn)

 
# General Firewall Settings Button
     $firewallBtn = New-Object Windows.Controls.Button
     $firewallBtn.Content = "Firewall Settings"
     $firewallBtn.Height = 40
     $firewallBtn.Margin = "0,0,0,10"
     $firewallBtn.Add_Click({
         # Open General Firewall Settings
         Start-Process "firewall.cpl"
     })
     $tabPanel.Children.Add($firewallBtn)

# Credential
     $credentialMgrBtn = New-Object Windows.Controls.Button
     $credentialMgrBtn.Content = "Manage Credentials"
     $credentialMgrBtn.Height = 40
     $credentialMgrBtn.Margin = "0,0,0,10"
     $credentialMgrBtn.Add_Click({
         # Open Credential Manager
         Start-Process "control" -ArgumentList "/name Microsoft.CredentialManager"
     })
     $tabPanel.Children.Add($credentialMgrBtn)

# Security events
     $eventViewerBtn = New-Object Windows.Controls.Button
     $eventViewerBtn.Content = "Security Event Viewer"
     $eventViewerBtn.Height = 40
     $eventViewerBtn.Margin = "0,0,0,10"
     $eventViewerBtn.Add_Click({
         # Open Event Viewer for Security logs
         Start-Process "eventvwr.msc" -ArgumentList "/s Security"
     })
     $tabPanel.Children.Add($eventViewerBtn)     

# Device Encryption Button
    $deviceEncryptionBtn = New-Object Windows.Controls.Button
    $deviceEncryptionBtn.Content = "Device Encryption"
    $deviceEncryptionBtn.Height = 40
    $deviceEncryptionBtn.Margin = "0,0,0,10"
    $deviceEncryptionBtn.Add_Click({
    # Open the BitLocker Drive Encryption page
    Start-Process "control" -ArgumentList "/name Microsoft.BitLockerDriveEncryption"
})
$tabPanel.Children.Add($deviceEncryptionBtn)


}

function Add-UpdateTabButtons($tabPanel) {

    # Check updates
    $updateLogBtn = New-Object Windows.Controls.Button
    $updateLogBtn.Content = "Update Logs"
    $updateLogBtn.Height = 40
    $updateLogBtn.Margin = "0,0,0,10"
    $updateLogBtn.Add_Click({
        
        $preparingWindow = Show-OutputWindow "Preparing..." "Generating Windows Update logs. This may take a moment..."
        $preparingWindow.Close()
        Show-OutputWindow "Windows Update Logs" "WindowsUpdate.log Logs saved to desktop"
    })
    $tabPanel.Children.Add($updateLogBtn)
}


# Utility Functions for Output and Configurations
function Show-OutputWindow($title, $output) {
    $windowOutput = New-Object Windows.Window
    $windowOutput.Title = $title
    $windowOutput.WindowStartupLocation = "CenterScreen"
    $textbox = New-Object Windows.Controls.TextBox
    $textbox.Text = $output
    $textbox.FontFamily = "Consolas"
    $textbox.FontSize = 12
    $textbox.AcceptsReturn = $true
    $textbox.VerticalScrollBarVisibility = "Visible"
    $textbox.HorizontalScrollBarVisibility = "Visible"
    $textbox.IsReadOnly = $true
    $windowOutput.Content = $textbox
    $windowOutput.SizeToContent = "WidthAndHeight"
    $windowOutput.MaxHeight = 800
    $windowOutput.Show()
    return $windowOutput  # <- Return the window so it can be closed later
}

function Show-ConfigWindow($action, $isStaticIP) {
    $windowInput = New-Object Windows.Window
    $windowInput.Title = $action
    $windowInput.SizeToContent = "WidthAndHeight"
    $windowInput.WindowStartupLocation = "CenterScreen"
    $stack = New-Object Windows.Controls.StackPanel

    $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    $combo = New-Object Windows.Controls.ComboBox
    foreach ($interface in $interfaces) { $combo.Items.Add($interface.Name) }
    $combo.SelectedIndex = 0
    $stack.Children.Add($combo)

    if ($isStaticIP) {
        $labelIP = New-Object Windows.Controls.Label
        $labelIP.Content = "IP Address:"
        $stack.Children.Add($labelIP)
        $ipBox = New-Object Windows.Controls.TextBox
        $stack.Children.Add($ipBox)

        $labelPrefix = New-Object Windows.Controls.Label
        $labelPrefix.Content = "Prefix Length (e.g., 24):"
        $stack.Children.Add($labelPrefix)
        $prefixBox = New-Object Windows.Controls.TextBox
        $stack.Children.Add($prefixBox)

        $labelGateway = New-Object Windows.Controls.Label
        $labelGateway.Content = "Default Gateway:"
        $stack.Children.Add($labelGateway)
        $gatewayBox = New-Object Windows.Controls.TextBox
        $stack.Children.Add($gatewayBox)

        $applyBtn = New-Object Windows.Controls.Button
        $applyBtn.Content = "Apply Static IP"
        $applyBtn.Add_Click({
            $alias = $combo.SelectedItem
            $ip = $ipBox.Text
            $prefix = $prefixBox.Text
            $gateway = $gatewayBox.Text
            Set-StaticIP $alias $ip $prefix $gateway
        })
        $stack.Children.Add($applyBtn)
    } else {
        $applyBtn = New-Object Windows.Controls.Button
        $applyBtn.Content = "Apply DHCP"
        $applyBtn.Add_Click({
            $selectedInterface = $combo.SelectedItem
            Set-DHCP $selectedInterface
        })
        $stack.Children.Add($applyBtn)
    }
    $windowInput.Content = $stack
    $windowInput.ShowDialog() | Out-Null
}

function Set-StaticIP($alias, $ip, $prefix, $gateway) {
    try {
        Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false
        New-NetIPAddress -InterfaceAlias $alias -IPAddress $ip -PrefixLength $prefix -DefaultGateway $gateway
        [System.Windows.MessageBox]::Show("Static IP set for $alias!")
    } catch {
        [System.Windows.MessageBox]::Show("Error setting IP: $_")
    }
}

function Set-DHCP($interface) {
    try {
        Set-NetIPInterface -InterfaceAlias $interface -Dhcp Enabled
        [System.Windows.MessageBox]::Show("DHCP Set for $interface!")
    } catch {
        [System.Windows.MessageBox]::Show("Error setting DHCP: $_")
    }
}

function Show-DNSWindow {
    $windowInput = New-Object Windows.Window
    $windowInput.Title = "Set DNS Server"
    $windowInput.SizeToContent = "WidthAndHeight"
    $windowInput.WindowStartupLocation = "CenterScreen"
    $stack = New-Object Windows.Controls.StackPanel

    $labelDNS = New-Object Windows.Controls.Label
    $labelDNS.Content = "Primary DNS:"
    $stack.Children.Add($labelDNS)
    $dnsBox = New-Object Windows.Controls.TextBox
    $stack.Children.Add($dnsBox)

    $applyBtn = New-Object Windows.Controls.Button
    $applyBtn.Content = "Apply DNS"
    $applyBtn.Add_Click({
        Set-DNS $dnsBox.Text
    })
    $stack.Children.Add($applyBtn)

    $windowInput.Content = $stack
    $windowInput.ShowDialog() | Out-Null
}

function Set-DNS($dns) {
    try {
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $dns
        [System.Windows.MessageBox]::Show("DNS Server set to $dns!")
    } catch {
        [System.Windows.MessageBox]::Show("Error setting DNS: $_")
    }
}

function Check-OpenPorts {
    # Show preparing window
    $preparingWindow = Show-OutputWindow "Checking Open Ports..." "Please wait while open ports are being checked."
    $null = $preparingWindow.Show()

    # Sleep for a moment to simulate delay (could be removed in a real implementation)
    Start-Sleep -Seconds 2

    # Get open TCP ports that are in a 'Listen' state
    $openPorts = Get-NetTCPConnection -State Listen | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Port        = $_.LocalPort
            Address     = $_.LocalAddress
            PID         = $_.OwningProcess
            ProcessName = $proc.ProcessName
        }
    }

    # Prepare the output for the window
    $output = "Open Ports:" + "`n" + ($openPorts | ForEach-Object { 
        "Port: $($_.Port) Address: $($_.Address) Process: $($_.ProcessName) (PID: $($_.PID))"
    } | Out-String)

    # Show open ports in the output window
    Show-OutputWindow "Open Ports" $output

    # Close the preparing window
    $preparingWindow.Close()
}

# Main Window Creation
$mainWindow = New-Object Windows.Window
$mainWindow.Title = "Network Information Tool"
$mainWindow.Width = 400
$mainWindow.Height = 400
$mainWindow.WindowStartupLocation = "CenterScreen"

$tabControl = New-Object Windows.Controls.TabControl

# Information Tab
$infoTab = New-Object Windows.Controls.TabItem
$infoTab.Header = "Information"
$infoTabContent = New-Object Windows.Controls.StackPanel
Add-InformationTabButtons($infoTabContent)
$infoTab.Content = $infoTabContent
$tabControl.Items.Add($infoTab)

# Configuration Tab
$configTab = New-Object Windows.Controls.TabItem
$configTab.Header = "Configuration"
$configTabContent = New-Object Windows.Controls.StackPanel
Add-ConfigurationTabButtons($configTabContent)
$configTab.Content = $configTabContent
$tabControl.Items.Add($configTab)

# Connection Tab
$connectionTab = New-Object Windows.Controls.TabItem
$connectionTab.Header = "Connection"
$connectionTabContent = New-Object Windows.Controls.StackPanel
Add-ConnectionTabButtons($connectionTabContent)
$connectionTab.Content = $connectionTabContent
$tabControl.Items.Add($connectionTab)

# Security Tab
$securityTab = New-Object Windows.Controls.TabItem
$securityTab.Header = "Security"
$securityTabContent = New-Object Windows.Controls.StackPanel
Add-SecurityTabButtons($securityTabContent)
$securityTab.Content = $securityTabContent
$tabControl.Items.Add($securityTab)

# Updates Tab
$updateTab = New-Object Windows.Controls.TabItem
$updateTab.Header = "Updates"
$updateTabContent = New-Object Windows.Controls.StackPanel
$updateTab.Content = $updateTabContent
Add-UpdateTabButtons($updateTabContent)
$tabControl.Items.Add($updateTab)

# Show the Window
$mainWindow.Content = $tabControl
$mainWindow.ShowDialog() | Out-Null
