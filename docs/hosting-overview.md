# Sovereign hosting overview

## Overview

The Sovereign ecosystem is hosted on a small self-managed infrastructure consisting primarily of two machines:

- Raspberry Pi
- Beelink mini-PC

Each node has a defined operational role.

The hosting model favors clarity, separation of responsibilities, and operational simplicity.

## Raspberry Pi node

The Raspberry Pi functions as the externally reachable infrastructure node.

Typical responsibilities include:

- public-facing services
- reverse proxy routing
- domain entry points
- Nextcloud instance
- lightweight application hosting

Example services on this node may include:

- Nextcloud
- Sovereign Planta
- reverse proxy configuration
- TLS termination

This node acts as the gateway between the internet and internal services.

## Beelink node

The Beelink mini-PC hosts internal application workloads and development environments.

Typical responsibilities include:

- application runtime environments
- development and experimentation
- internal services
- non-public workloads

Current examples include:

- Sovereign Finance
- Sovereign Strength

This separation keeps the cloud-facing node simple while allowing heavier workloads to run elsewhere.

## Domain routing

Public domains are typically routed through the Raspberry Pi node.

Example pattern:

| Domain | Service |
|------|------|
| plants.innosocia.dk | Sovereign Planta |
| cloud.innosocia.dk | Nextcloud |

Additional application endpoints may be added as the ecosystem evolves.

## Data management

Application data is stored locally on the host where the application runs.

Principles include:

- human-readable storage where possible
- simple backup procedures
- separation of runtime data from repository documentation

Backups should include:

- application code
- application data directories
- configuration files
- relevant service definitions

## Operational philosophy

The hosting model follows several principles:

- avoid unnecessary infrastructure complexity
- prefer explicit configuration over hidden automation
- keep services inspectable and debuggable
- ensure a single operator can maintain the system

The goal is long-term durability rather than maximal technical sophistication.

## Future evolution

Future hosting improvements may include:

- improved automated backups
- infrastructure monitoring
- additional service isolation
- container-based deployments
- additional nodes if the ecosystem grows
