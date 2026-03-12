# Sovereign architecture overview

## Overview

The Sovereign ecosystem runs on a small self-hosted infrastructure designed for operational simplicity, transparency, and long-term maintainability.

The system is intentionally distributed across two primary hosts.

## Infrastructure nodes

### Raspberry Pi node

The Raspberry Pi serves as the cloud-facing infrastructure node.

Typical responsibilities include:

- reverse proxy routing
- public domain exposure
- Nextcloud services
- platform entry points

This node acts as the externally reachable gateway of the system.

### Beelink node

The Beelink mini-PC hosts several application workloads and operational services.

Typical responsibilities include:

- application runtime environments
- development environments
- internal service workloads
- experimental or evolving applications

Separating workloads across nodes reduces operational coupling and allows services to evolve independently.

## Application placement

Current application placement is structured as follows:

| Application | Host |
|------|------|
| Sovereign Planta | Raspberry Pi |
| Sovereign Finance | Beelink |
| Sovereign Strength | Beelink |

Applications are kept operationally independent even when they share architectural principles.

## Network model

External traffic typically flows through the Raspberry Pi node.

Typical request flow:

1. user accesses a public domain
2. reverse proxy receives the request
3. request is routed to the correct service
4. service responds to the client

This allows the system to expose only the necessary entry points.

## Data philosophy

Across the ecosystem, the following data principles apply:

- data should remain human-readable where possible
- storage should remain inspectable
- backups should remain simple
- applications should not depend on opaque external services

This philosophy supports long-term independence and recoverability.

## Operational goals

The infrastructure aims to remain:

- understandable
- debuggable
- portable
- resilient
- maintainable by a single operator

The system deliberately favors clarity over maximal automation.

## Future evolution

The architecture may evolve over time through:

- additional application nodes
- containerized services
- improved backup automation
- infrastructure monitoring
- service health checks

Any expansion should preserve the core design philosophy of simplicity and operational transparency.
