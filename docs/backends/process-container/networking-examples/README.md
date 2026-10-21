# ProcessContainer networking examples

> **Audience:** MXC consumers and developers

Choose how to run the proxy, then follow its setup guide:

| Proxy deployment | Guide |
|---|---|
| MSIX package with AppContainer isolation | [Packaged AppContainer proxy](packaged-appcontainer-proxy.md) |
| AppContainer profile without an MSIX package | [Unpackaged AppContainer proxy](unpackaged-appcontainer-proxy.md) |
| MSIX package without AppContainer isolation | [Packaged non-AppContainer proxy](packaged-non-appcontainer-proxy.md) |
| No package or AppContainer profile, for development and testing | [Unpackaged non-AppContainer proxy](unpackaged-non-appcontainer-proxy.md) |

## Shared setup

The host application supplies and runs the proxy outside the MXC client
container. These examples use an HTTP proxy listening at `127.0.0.1:8080`:

- `127.0.0.1` is the loopback address on the same Windows host.
- `8080` is the port where the proxy accepts connections.
- `http://127.0.0.1:8080` is the URL to put in
  `network.runtimeConfig.networkProxy`. It must match the proxy's listening
  address and port.

Both packaged deployments use the installed Package Family Name for
`containment.config.network.allowedProxyPeer`. The unpackaged AppContainer
deployment uses its profile name. Without either identity, omit
`allowedProxyPeer`.

Start the proxy and wait until it is listening before starting the workload.
Keep it running until the workload exits.

Each guide supplies a complete Node SDK V1 `ContainerRequest` and calls `run`.
The PowerShell payload uses WinHTTP to request `https://example.com/`.
Configure your proxy to allow that site, or replace the URL with one it permits.
See the [SDK quickstart](../../../../sdk/node/README.md#run-to-completion) for
installation and execution.

The examples set `ui.disable: false` because Windows PowerShell needs Win32k
system calls during startup. Clipboard and input-injection permissions remain
restricted by default.

For HTTP/S clients inside the container, prefer WinHTTP or a library that
queries Windows proxy settings through Windows APIs. MXC also sets proxy
environment variables for other clients. See
[HTTP client behavior](../networking.md#http-client-behavior).

## Loopback proxy firewall requirements

For identity-scoped ProcessContainer proxies, an additional inbound firewall
rule is required from the initial build until the fixed build below.
The fix applies to both packaged proxies and unpackaged AppContainer proxies.

| Windows 11 release | Initial build requiring a rule | No additional rule needed starting with |
|---|---|---|
| 24H2 | 26100.9278 | 26100.9550 |
| 25H2 | 26200.9278 | 26200.9550 |
| 26H2 | Not required from the first supported build | 26300.9550 |
| 26H1 | 28000.2804 | 28000.3086 |

Identity-less proxies do not require this additional rule.
Existing administrator-managed firewall restrictions still apply in either case.

## Shared limits

- **Client access:** MXC restricts the client container's outbound connections
  to the proxy's address and port, even if the client ignores proxy settings.
  It does not set the external proxy's filesystem or outbound network
  permissions. Configure those separately.

- **Proxy identity:** packaged and AppContainer proxies provide additional
  protection. Windows checks that the receiving process belongs to the package
  or AppContainer profile named by `allowedProxyPeer`, not just that it owns
  the listening address and port. Prefer these deployments over an identity-less
  proxy.

- **Proxy isolation:** package identity identifies the proxy; it does not
  provide AppContainer isolation. Only the AppContainer deployments provide
  that isolation for the proxy process.

For network policy and troubleshooting, see [ProcessContainer networking](../networking.md).
