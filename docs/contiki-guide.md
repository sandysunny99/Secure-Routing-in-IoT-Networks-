# Optional: Running with Real Contiki-NG + Cooja

This guide is for **academic reference only**. The main simulation runs in Python without Contiki-NG.

---

## Prerequisites

- Ubuntu 20.04+ (or WSL2 on Windows)
- Java JDK 11+
- ARM GCC toolchain
- Git

## 1. Install Contiki-NG

```bash
git clone https://github.com/contiki-ng/contiki-ng.git
cd contiki-ng
git submodule update --init --recursive
```

## 2. Start Cooja Simulator

```bash
cd tools/cooja
./gradlew run
```

## 3. Load RPL-UDP Example

1. File → New Simulation → Name: "RPL-Attack-Demo"
2. Motes → Add → Create new type → Cooja Mote
3. Browse to: `examples/rpl-udp/udp-server.c` (for root)
4. Add 1 server mote (root node)
5. Create another type: `examples/rpl-udp/udp-client.c`
6. Add 6 client motes (sensor nodes)

## 4. Attack Hook (Modify udp-client.c)

To simulate a sinkhole attack, add this to one client node's firmware:

```c
/* In rpl-dag.c or project-conf.h */
#ifdef ATTACK_MODE

/* Force low rank advertisement */
#include "net/routing/rpl-lite/rpl.h"

void attack_inject_fake_rank(void) {
    /* Override rank to appear as root-adjacent */
    curr_instance.dag.rank = RPL_MIN_HOPRANKINC;
    LOG_WARN("ATTACK: Advertising fake rank %u\n", curr_instance.dag.rank);
}

/* Drop forwarded packets */
static int should_drop_packet(void) {
    /* 80% drop rate */
    return (random_rand() % 100) < 80;
}

#endif /* ATTACK_MODE */
```

Add to `project-conf.h`:
```c
#define ATTACK_MODE 1
```

## 5. Detection Hook (Modify udp-server.c)

```c
/* Simple rank verification at root */
#define TRUST_THRESHOLD 40  /* out of 100 */

static uint8_t trust_scores[MAX_NODES];

void check_rank_anomaly(uint16_t node_id, uint16_t reported_rank) {
    /* Expected rank based on hop count */
    uint16_t expected_min = RPL_MIN_HOPRANKINC * 2;

    if (reported_rank < expected_min) {
        LOG_WARN("ALERT: Node %u rank %u is suspicious (expected >= %u)\n",
                 node_id, reported_rank, expected_min);
        trust_scores[node_id] -= 20;

        if (trust_scores[node_id] < TRUST_THRESHOLD) {
            LOG_WARN("SECURE: Node %u flagged as malicious (trust=%u)\n",
                     node_id, trust_scores[node_id]);
        }
    }
}
```

## 6. Cooja .csc Configuration

Save this as `rpl-attack.csc` and open in Cooja:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<simconf>
  <simulation>
    <title>RPL Sinkhole Attack Demo</title>
    <randomseed>123456</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
    </radiomedium>
    <!-- Add mote definitions here based on your setup -->
  </simulation>
</simconf>
```

## 7. Extracting Logs

Cooja logs can be exported from Mote Output → File → Save to file.
The Python simulation in this project replicates the same behavior.

---

*This section is optional — the main project runs entirely in Python.*
