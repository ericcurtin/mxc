# Unpackaged AppContainer proxy

> **Audience:** MXC consumers and developers

Run the proxy in a per-user AppContainer profile without an MSIX package.
Read the [shared setup and limits](README.md) before following these steps.

## Prepare and start the proxy

- Create a per-user profile with
  [CreateAppContainerProfile](https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createappcontainerprofile).
  For example, use `Contoso.AgentProxy` as the profile name.

- Launch the proxy in that profile with the profile SID and the required
  capabilities in
  [SECURITY_CAPABILITIES](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-security_capabilities).
  Creating the profile alone does not run an executable in an AppContainer.

- Grant `privateNetworkClientServer` for communication with the MXC client.
  Also grant `internetClient` if the proxy forwards to external destinations.

- Check the
  [Windows build requirements](README.md#loopback-proxy-firewall-requirements).
  On builds requiring a rule, arrange an installer- or administrator-owned
  inbound TCP rule scoped to the proxy's profile SID, executable, and port.
  See the Windows
  [firewall rule reference](https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule).
  On fixed builds, no additional rule is needed.

- Have the proxy listen on `127.0.0.1:8080`, matching the SDK settings below.

The profile is per user. Create or resolve it for the user running the proxy.
Pass its profile name to MXC; do not pass the display name, executable path,
or SID string.

## Configure the MXC client

Run this Node SDK V1 request, with the profile name created above:

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
      network: { allowedProxyPeer: 'Contoso.AgentProxy' },
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
