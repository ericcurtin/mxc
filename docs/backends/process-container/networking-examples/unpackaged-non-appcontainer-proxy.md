# Unpackaged non-AppContainer proxy

> **Audience:** MXC consumers and developers

Run the proxy as an ordinary Windows application, without a package or
AppContainer profile. Read the [shared setup and limits](README.md) first.

## Start the proxy

- Check `probes.baseContainerSupportsIdentitylessLoopbackProxy` on the target
  host and probe the complete request. See [host support](../networking.md#check-the-target-host).

- Start your HTTP/S proxy and have it listen on `127.0.0.1:8080`.
  No package installation, AppContainer profile, or additional inbound firewall
  rule is needed for this deployment.

## Configure the MXC client

Run this Node SDK V1 request. Leave `allowedProxyPeer` unset and allow host
loopback:

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
  containment: { type: 'processcontainer' },
  timeoutMs: 30_000,
  // Windows PowerShell needs Win32k system calls during startup.
  ui: { disable: false },
  network: {
    egress: { default: 'deny' },
    ingress: { default: 'allow', hostLoopback: 'allow' },
    runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
  },
};

const result = await run(request);
console.log(result);
```

This option is for development and testing: MXC restricts the client's outbound
connections to the proxy's address and port, but cannot verify which process
owns the port. Do not rely on this mode for host-to-container listener access;
see the [inbound limitation](../networking.md#identity-less-loopback-proxy).
