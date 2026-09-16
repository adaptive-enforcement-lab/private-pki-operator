# private-pki-operator

![Version: 0.1.21](https://img.shields.io/badge/Version-0.1.21-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.21](https://img.shields.io/badge/AppVersion-0.1.21-informational?style=flat-square)

Kubernetes operator that automates root CA rotation for a cert-manager + trust-manager PKI hierarchy. Implements a dual-trust window state machine (Idle → PreservingOldRoot → DualTrustActive → AwaitingReissuance → VerifyingChain → Complete) to ensure zero-gap trust during CA key rollover.

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| Mark Cheret | <mark@cheret.de> |  |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| image.repository | string | `"ghcr.io/adaptive-enforcement-lab/private-pki-operator"` | Operator image repository. Built and pushed via `make build-push` in ci/private-pki-operator (see its Makefile). |
| image.tag | string | `""` | Image tag. appVersion tracks the chart's own version, not the operator's — it is NOT a valid image tag. Set this explicitly in the consuming cluster's own values file. |
| installCRDs | bool | `true` | Install CRDs as part of chart deployment. Set to false if CRDs are managed externally (e.g. by another tool or chart). |
| metrics.bindAddress | string | `":8080"` | Address the metrics endpoint binds to. Set to "0" to disable the metrics server. |
| metrics.podMonitoring.enabled | bool | `true` | Create a prometheus-operator PodMonitor resource to scrape the metrics endpoint. Prometheus scrapes pods directly, so no Service is needed in front of the port. |
| metrics.podMonitoring.interval | string | `"60s"` | Scrape interval for the operator metrics endpoint. Rotations are minutes-long state machines, so a sub-minute interval buys nothing and costs samples. |
| metrics.port | int | `8080` | Container port exposed for the metrics endpoint. Must match the port in bindAddress. |
| metrics.secure | bool | `false` | Serve metrics over HTTPS with Kubernetes authn/authz filtering. Left false: the endpoint is reachable only from inside the cluster, and enabling it additionally requires TokenReview/SubjectAccessReview RBAC and scrape-side TLS trust, which this chart does not yet wire up. |
| namespace | string | `"cert-manager"` | Namespace for the operator itself (must be the trust-manager trust namespace). |
| pkirotation.enabled | bool | `false` | Register the rotation watcher for the platform root CA. Off by default so the chart can be installed without taking ownership of a cluster's trust root; enable it through the consuming cluster's own values file. |
| pkirotation.reissuanceTimeout | string | `"15m"` | Maximum time to wait for intermediate CA re-issuance before emitting a Warning. |
| pkirotation.rootCA.certificateName | string | `"private-root-ca"` | Name of the cert-manager Certificate representing the root CA. |
| pkirotation.rootCA.certificateNamespace | string | `"cert-manager"` | Namespace of the root CA Certificate (always cert-manager for platform PKI). |
| pkirotation.trustBundle.name | string | `"private-root-ca"` | Name of the cluster-scoped trust-manager Bundle resource. |
| pkirotation.trustBundle.stagingConfigMap.name | string | `"private-root-ca-trust-anchor"` | Name of the staging ConfigMap the operator manages. Must NOT be the cert-manager-managed Secret — this ConfigMap is owned by the operator. |
| pkirotation.trustBundle.stagingConfigMap.namespace | string | `"cert-manager"` | Namespace of the staging ConfigMap (trust-manager trust namespace). |
| resources.limits.cpu | string | `"500m"` | CPU limit. Headroom for a rotation cascade, which walks the whole certificate tree in a burst. |
| resources.limits.memory | string | `"128Mi"` | Memory limit. Deliberately close to the request: a cache that grows past this indicates the watch set has expanded unexpectedly, and failing loudly beats silently consuming the node. |
| resources.requests.cpu | string | `"10m"` | CPU request. The operator is idle almost all the time — it reconciles on Secret and Certificate events, not on a timer — so the request is sized for scheduling rather than for throughput. |
| resources.requests.memory | string | `"64Mi"` | Memory request. Sized for the informer caches, which hold Certificates and Secrets cluster-wide and dominate the footprint. |
| securityContext.allowPrivilegeEscalation | bool | `false` | Block setuid escalation. Nothing in the image is setuid, so this closes a door that is never used rather than constraining anything. |
| securityContext.capabilities.drop | list | `["ALL"]` | Drop every Linux capability. This process makes API calls and nothing else; it needs none of them. |
| securityContext.privileged | bool | `false` | Never privileged. Stated explicitly rather than left to the default so the posture is auditable from values.yaml alone. |
| securityContext.readOnlyRootFilesystem | bool | `true` | Immutable root filesystem. The operator writes nothing to disk — no cache, no temp files — so a writable filesystem would only ever serve an attacker. |
| securityContext.runAsGroup | int | `65532` | GID to run as, matching the image's group. |
| securityContext.runAsNonRoot | bool | `true` | Refuse to start as UID 0. The operator needs no root capability; it reads Secrets and patches Certificates through the API server. |
| securityContext.runAsUser | int | `65532` | UID to run as. 65532 is the nonroot user baked into the distroless base image (Dockerfile: USER 65532:65532); declaring it here means the manifest asserts what the image already does rather than trusting it. |
| securityContext.seccompProfile.type | string | `"RuntimeDefault"` | Seccomp profile. RuntimeDefault blocks the syscalls a controller never issues, which is the cheapest real reduction in kernel attack surface here. |
| trustBundle.intermediateCAConfigMap | string | `"private-intermediate-ca"` | ConfigMap holding the intermediate CA bundle distributed by trust-manager. |
| trustBundle.rootCAConfigMap | string | `"private-root-ca"` | ConfigMap holding the root CA bundle distributed by trust-manager. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
