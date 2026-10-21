# Packaged AppContainer proxy

> **Audience:** MXC consumers and developers

Run the proxy in an MSIX package with AppContainer isolation.
Read the [shared setup and limits](README.md) before following these steps.

The package must provide its own proxy executable, signing, and assets.
The firewall declaration and its `runFullTrust` capability are commented out.
Enable both only for the
[August 2026 builds requiring a rule](README.md#loopback-proxy-firewall-requirements).
Leave them commented out on fixed builds.

## Package and start the proxy

```xml
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
  xmlns:desktop2="http://schemas.microsoft.com/appx/manifest/desktop/windows10/2"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  IgnorableNamespaces="uap uap10 desktop2 rescap">
  <Identity Name="Contoso.AgentProxy" Publisher="CN=Contoso" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Agent Proxy</DisplayName>
    <PublisherDisplayName>Contoso</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
  </Properties>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0" />
  </Dependencies>
  <Capabilities>
    <Capability Name="internetClient" />
    <Capability Name="privateNetworkClientServer" />
    <!-- Enable only with the August 2026 firewall declaration below. -->
    <!-- <rescap:Capability Name="runFullTrust" /> -->
  </Capabilities>
  <!-- August 2026 only: KB5120998 (24H2/25H2) or KB5120996 (26H1).
       Leave disabled once the fixed update is installed. -->
  <!--
  <Extensions>
    <desktop2:Extension Category="windows.firewallRules">
      <desktop2:FirewallRules Executable="proxy.exe">
        <desktop2:Rule Direction="in" IPProtocol="TCP" Profile="all"
          LocalPortMin="8080" LocalPortMax="8080" />
      </desktop2:FirewallRules>
    </desktop2:Extension>
  </Extensions>
  -->
  <Applications>
    <Application Id="Proxy" Executable="proxy.exe"
      uap10:RuntimeBehavior="packagedClassicApp" uap10:TrustLevel="appContainer">
      <uap:VisualElements DisplayName="Agent Proxy"
        Description="HTTP proxy for contained workloads" BackgroundColor="transparent"
        Square150x150Logo="Assets\Logo.png" Square44x44Logo="Assets\Logo.png"
        AppListEntry="none" />
    </Application>
  </Applications>
</Package>
```

See the Microsoft Learn
[package manifest schema reference](https://learn.microsoft.com/uwp/schemas/appxpackage/uapmanifestschema/schema-root)
for package identity, signing, assets, and application metadata.
Uncomment `runFullTrust` when enabling the firewall extension;
`TrustLevel="appContainer"` still runs the proxy in an AppContainer.

If the firewall rule is needed, its port must match
`network.runtimeConfig.networkProxy`. The example uses port 8080.

After installing the package, retrieve its exact Package Family Name:

```powershell
Get-AppxPackage -Name Contoso.AgentProxy |
  Select-Object -ExpandProperty PackageFamilyName
```

Use the returned Package Family Name verbatim for `allowedProxyPeer`.

Start the installed application through package activation so the proxy has
the package identity and AppContainer trust level declared in the manifest.
Have it listen on `127.0.0.1:8080`, matching the SDK settings below.

## Configure the MXC client

Run this Node SDK V1 request, replacing `<PackageFamilyName>` with the value
returned above:

```typescript
import { run, type ContainerRequest } from '@microsoft/mxc-sdk/v1';

const request: ContainerRequest = {
  command:
    `powershell.exe -NoLogo -NoProfile -NonInteractive -Command "` +
    `$ErrorActionPreference = 'Stop'; ` +
    `$http = New-Object -ComObject WinHttp.WinHttpRequest.5.1; ` +
    `$http.SetTimeouts(5000,5000,5000,5000); ` +
    `$http.Open('GET','https://example.com/',$false); ` +
    `$http.Send(); ` +
    `if ($http.Status -ne 200) { throw ('HTTP status ' + $http.Status) }; ` +
    `Write-Output $http.Status"`,
  containment: {
    type: 'processcontainer',
    config: {
      network: { allowedProxyPeer: '<PackageFamilyName>' },
    },
  },
  timeoutMs: 30_000,
  // Windows PowerShell needs Win32k system calls during startup.
  ui: { disable: false },
  network: {
    egress: { default: 'deny' },
    ingress: { default: 'allow', hostLoopback: 'deny' },
    runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
  },
};

const result = await run(request);
console.log(result);
```
