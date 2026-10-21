# ProcessContainer networking

> **Audience:** MXC consumers and developers

This guide covers network access for the Windows ProcessContainer backend.
Examples use the [Node SDK V1](../../api-reference/node/v1/README.md).
Pass each `network` value as `ContainerRequest.network` and select
`containment: { type: 'processcontainer' }`. Supply the workload's command and
filesystem permissions as shown in the [SDK quickstart](../../../sdk/node/README.md#run-to-completion).

## Choose the connection you need

| Workload needs | Use |
|---|---|
| Internet access to selected destinations | [Direct egress](#direct-egress) with IP/CIDR and port rules |
| A service on the same host, or another BaseContainer | [Host loopback](#host-loopback) |
| One HTTP/S proxy | [Proxy-only egress](#proxy-only-egress) |
| Internal services or a browser's debugging port | [Known issue: intra-container loopback](#known-issue-intra-container-loopback) |
| No external network access | Leave the proxy and peer unset; omit network policy or set egress, ingress, and host loopback to `deny`. |

## Check the target host

Install the applicable Windows updates; see
[Windows OS-version support](os-version-support.md).
Use the public SDK's request-aware probe on the machine that will run the workload.

| Windows probe result | Meaning |
|---|---|
| `tier: "base-container"` | BaseContainer is selected; individual network features still need host support. |
| `probes.baseContainerSupportsIngressHostLoopbackAllow` | Bidirectional host loopback, including container listeners and connections between BaseContainers |
| `probes.baseContainerSupportsIdentitylessLoopbackProxy` | An unpackaged, non-AppContainer loopback proxy can be used without a peer identity. This does not establish general bidirectional loopback support. |

When the bidirectional-loopback fact is `false`, a BaseContainer can still
connect to supported loopback listeners outside BaseContainers, but not to
listeners inside another BaseContainer. When it is `true`, containers can also
host loopback servers reachable from the host or other BaseContainers.
The connection must still satisfy network policy and firewall rules.

A successful probe checks request support, not listener readiness, proxy
identity, firewall authorization, or application connectivity.
MXC rejects policy it cannot enforce before launching the workload.

## Direct egress

Use deny-default egress with explicit destinations. For example, allow HTTPS
to one public IP range:

```typescript
import type { NetworkPolicy } from '@microsoft/mxc-sdk/v1';

const network: NetworkPolicy = {
  egress: {
    default: 'deny',
    allow: [
      {
        to: [{ cidr: '140.82.112.0/20' }],
        ports: [{ protocol: 'tcp', port: 443 }],
      },
    ],
  },
  ingress: { default: 'deny', hostLoopback: 'deny' },
};
```

- Windows Filtering Platform (WFP) enforces outbound rules per container.
  An explicit deny takes precedence over an allow.

- Rules select numeric IP addresses or CIDR ranges, protocols, and ports.
  They do not filter by hostname, URL, or application protocol.

- Private-network access requires `network.ingress.default: "allow"`.
  Windows grants private-network client and server access together, so this
  also permits private-network inbound traffic. Egress rules still restrict
  outbound destinations.

- There are no inbound CIDR or port rules. `network.ingress.default` and
  `network.ingress.hostLoopback` are allow/deny controls.

## Host loopback

To reach a host service directly, allow its loopback IP and port in
`network.egress.allow` and set `network.ingress.hostLoopback` to `"allow"`.
An egress rule alone does not authorize crossing the host-loopback boundary.

**Host loopback is bidirectional, not an outbound-only exception.**
Where supported, it also lets host processes and other BaseContainers connect
to listeners inside the container. There are no inbound port restrictions.
The other container's policy and the listener's firewall authorization must
also permit the connection.

For one HTTP/S proxy address and port, prefer proxy-only egress instead of
general host-loopback access.

## Proxy-only egress

Set `network.runtimeConfig.networkProxy` to the URL where the proxy listens,
such as `http://127.0.0.1:8080`: address `127.0.0.1`, port `8080`.
**MXC blocks client-container traffic to every other address and port.**
This restriction is enforced even if the workload ignores the proxy settings.
The caller runs the proxy outside the MXC client container.

| Setting | Requirement |
|---|---|
| `network.runtimeConfig.networkProxy` | The URL matching the proxy's loopback listening address and port |
| `network.egress.default` | `deny`, with no direct egress allow or deny rules |
| `network.ingress.default` | `allow`, required for proxy communication; proxy-only policy restricts outbound connections to the configured proxy address and port |
| `containment.config.network.allowedProxyPeer` | Package Family Name or AppContainer profile name, when the proxy has one |
| `network.ingress.hostLoopback` | `deny` with a named peer; `allow` without one |

The caller must start the proxy first, wait for its listener, and keep it alive
until the workload exits. Bind it only to the configured loopback address and port.
MXC does not create the proxy or control its own outbound access.

### Proxy deployment choices

For common setup and step-by-step guides, start with the
[networking examples](networking-examples/README.md).
Peer identity, proxy isolation, and firewall authorization are separate protections:

| Proxy deployment | `allowedProxyPeer` | `hostLoopback` | Proxy protection |
|---|---|---|---|
| [Packaged AppContainer](networking-examples/packaged-appcontainer-proxy.md) | Installed Package Family Name | `deny` | AppContainer isolation and package identity |
| [Unpackaged AppContainer](networking-examples/unpackaged-appcontainer-proxy.md) | AppContainer profile name | `deny` | AppContainer isolation and profile identity |
| [Packaged non-AppContainer](networking-examples/packaged-non-appcontainer-proxy.md) | Installed Package Family Name | `deny` | Package identity; no AppContainer isolation |
| [Unpackaged non-AppContainer](networking-examples/unpackaged-non-appcontainer-proxy.md) | Omit | `allow` | No proxy identity binding or AppContainer isolation |

**Prefer a packaged or AppContainer proxy.** With `allowedProxyPeer`, Windows
checks that the process receiving the loopback connection belongs to the named
package or AppContainer profile. An unrelated process at the same address and
port is not an authorized peer.

AppContainer isolation also restricts the proxy itself; package identity alone
does not. An identity-less proxy has no peer identity check and is intended for
development and testing.

### Proxy identity and firewall authorization

**Identity-scoped proxies:** an additional inbound firewall rule is needed on
the initial ProcessContainer builds, but not on the
[fixed Windows builds](networking-examples/README.md#loopback-proxy-firewall-requirements).
This applies to packaged proxies and unpackaged proxies running in an AppContainer.

**Identity-less proxies:** no additional firewall rule is needed.
Existing administrator-managed firewall restrictions still apply.

- `allowedProxyPeer` authorizes a package family or AppContainer profile.
  It does not create the profile, launch the proxy, or install a firewall rule.

- Where a rule is required, a packaged proxy supplies its package-owned inbound
  firewall declaration. An unpackaged AppContainer needs an installer- or
  administrator-owned rule scoped to its profile SID, executable, and port.

- AppContainer proxies need `privateNetworkClientServer` to communicate with
  the client, plus `internetClient` when forwarding to external destinations.

- If the host requires the rule, arrange authorization with the installer or
  administrator. Do not broaden the client's policy to compensate for a missing rule.

### Identity-less loopback proxy

For an unpackaged proxy without AppContainer isolation, omit `allowedProxyPeer`:

```typescript
import type { NetworkPolicy } from '@microsoft/mxc-sdk/v1';

const network: NetworkPolicy = {
  egress: { default: 'deny' },
  ingress: { default: 'allow', hostLoopback: 'allow' },
  runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
};
```

Check `probes.baseContainerSupportsIdentitylessLoopbackProxy` or the
`identitylessLoopbackProxy` capability in backend discovery. Probe the complete
request as well; other features may have separate requirements.
This path does not require an additional firewall rule,
but independently managed host firewall restrictions still apply.

**Inbound limitation:** identity-less proxy mode can permit connections to
the proxy while host-to-container listener connections time out. Do not rely
on this mode for hosting a loopback server inside the client container.

### HTTP client behavior

- **Recommended:** use WinHTTP, or an HTTP/S library that explicitly queries
  Windows proxy configuration through Windows APIs. MXC configures these
  settings per container.

- **Environment-based clients:** MXC also sets `HTTP_PROXY` and `HTTPS_PROXY`
  for libraries that use proxy environment variables. Confirm that the
  library honors them.

- **Network restriction:** the workload can connect only to the configured
  proxy address and port. Ignoring proxy settings or opening sockets directly
  does not permit access to other destinations. The proxy must validate all
  traffic received at its allowed address and port.

- **Protocol:** proxy configuration is not transparent TCP/UDP redirection.
  The client must use the proxy's supported HTTP/S protocol.

For a public proxy, multiple proxy addresses or ports, or another protocol,
use direct egress rules instead. Add host-loopback access only when needed.

## Known issue: intra-container loopback

Connections to a TCP loopback listener inside the same container can fail with
`EACCES`, even with egress allowed. This is a known Windows issue tracked in
[#1505](https://github.com/microsoft/mxc/issues/1505).
A fix is planned for a future Windows release; the target release and build
are **TBD**.

Allowing `127.0.0.1/32` is not a reliable workaround. Do not enable general host
loopback just to make internal sockets work.

## Troubleshooting

| Symptom | Check |
|---|---|
| The request is rejected before launch | Probe the complete request on the target host. Check proxy/peer settings, required ingress values, and whether direct rules were combined with proxy mode. |
| Probe succeeds, but the proxy times out | Listener readiness, exact address and port, running package/profile identity, and inbound firewall authorization |
| Public connections work, private destinations do not | `ingress.default` must be `allow` for private-network access; check egress rules too. |
| A host service is unreachable despite a loopback egress rule | Host-loopback authorization is separate from the egress rule. |
| A container listener is unreachable | Bidirectional loopback support, both containers' policies, firewall rules, and the identity-less proxy inbound limitation |
| An application hangs or gets `EACCES` when connecting to its own listener | [Known Windows loopback issue](#known-issue-intra-container-loopback) |
| HTTP requests ignore the configured proxy | Prefer WinHTTP or a library that queries Windows proxy settings. For environment-based clients, confirm the library honors `HTTP_PROXY` and `HTTPS_PROXY`. |
