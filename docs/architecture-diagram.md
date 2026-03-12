# Sovereign architecture diagram

## Overview

The diagram below shows the current high-level structure of the Sovereign ecosystem.

```mermaid
flowchart TD
    U[User] --> D[Public domains]

    D --> PI[Raspberry Pi]
    D --> B[Beelink]

    subgraph PI_NODE [Raspberry Pi node]
        RP[Reverse proxy]
        NC[Nextcloud]
        SP[Sovereign Planta]
    end

    subgraph B_NODE [Beelink node]
        SF[Sovereign Finance]
        SS[Sovereign Strength]
        SM[Sovereign Mind - planned]
    end

    PI --> RP
    RP --> NC
    RP --> SP

    B --> SF
    B --> SS
    B --> SM
```
## Notes

- Raspberry Pi acts as the cloud-facing node.

- Beelink hosts selected application workloads.

- Sovereign Mind is currently planned but not yet implemented.

Applications remain operationally independent.
