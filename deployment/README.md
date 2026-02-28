# eghostbuster Helm Chart

A Helm chart for deploying eghostbuster, an eBPF-based tool for detecting and cleaning up stale kernel resources.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Nodes with Linux kernel 5.8+ (BTF and CO-RE support)
- Nodes with BTF enabled (`/sys/kernel/btf/vmlinux`)

## Installation

### Add the Helm repository

```bash
helm repo add eghostbuster https://github.com/fcappa/eghostbuster/releases/download/charts
helm repo update
```

### Install the chart

```bash
helm install eghostbuster eghostbuster/eghostbuster
```

With custom values:

```bash
helm install eghostbuster eghostbuster/eghostbuster \
  --set config.closeWaitTimeout=600 \
  --set config.verbose=true
```

## Configuration

The following table lists the configurable parameters of the eghostbuster chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository | `quay.io/rh-ee-fcappa/eghostbuster` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag | Chart version |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `config.closeWaitTimeout` | TCP CLOSE_WAIT cleanup timeout in seconds | `300` |
| `config.verbose` | Enable verbose logging | `false` |
| `config.netns` | Network namespace to monitor (empty = all) | `` |
| `nodeSelector` | Node selector for pod assignment | `{}` |
| `tolerations` | Tolerations for pod assignment | `[]` |
| `affinity` | Affinity for pod assignment | `{}` |

## Usage

Once installed, eghostbuster will run as a DaemonSet on all nodes and automatically monitor and clean up stale kernel resources.

Check the status:

```bash
kubectl get daemonset -l app.kubernetes.io/name=eghostbuster
kubectl logs -l app.kubernetes.io/name=eghostbuster
```

## Uninstallation

```bash
helm uninstall eghostbuster
```