import re
import sys
import csv
from collections import defaultdict


if len(sys.argv) != 2:
    print("Usage: python3 rpl_rank_ids.py <logfile>")
    sys.exit(1)


logfile = sys.argv[1]


# =============================
# COLORS
# =============================

GREEN="\033[92m"
RED="\033[91m"
YELLOW="\033[93m"
CYAN="\033[96m"
RESET="\033[0m"



# =============================
# STORAGE
# =============================


# ultimo rank conosciuto
node_rank = {}

# storico rank per nodo
rank_history = defaultdict(list)


# child -> parent
parents = {}



# timestamp
last_time = {}



# =============================
# TIME
# =============================

def to_seconds(t):

    m,s=t.split(":")

    return int(m)*60+float(s)



# =============================
# IPv6 extraction
# =============================

def ipv6_to_node(ip):

    m=re.search(
        r"fd00::20([0-9a-f]+):",
        ip
    )

    if m:
        return int(m.group(1),16)

    return None



def linklocal_to_node(ip):

    m=re.search(
        r"fe80::20([0-9a-f]+):",
        ip
    )

    if m:
        return int(m.group(1),16)

    return None



# =============================
# PARSER
# =============================


with open(logfile) as f:


    for line in f:


        tm=re.search(
            r"(\d+:\d+\.\d+)",
            line
        )

        if not tm:
            continue


        time=to_seconds(tm.group(1))



        nm=re.search(
            r"ID:(\d+)",
            line
        )

        if not nm:
            continue


        receiver=int(nm.group(1))



        # =========================
        # DIO received
        # =========================


        m=re.search(
            r"received a (?:unicast|multicast)-DIO from ([^,]+).*rank (\d+)",
            line
        )


        if m:


            sender_ip=m.group(1)

            rank=int(m.group(2))


            sender=linklocal_to_node(sender_ip)


            if sender is not None:


                node_rank[sender]=rank


                rank_history[sender].append(
                    (
                        time,
                        rank
                    )
                )


                last_time[sender]=time



        # =========================
        # DAO received
        # =========================


        m=re.search(
            r"received a DAO from (fd00::[^\s]+).*parent (fd00::[^\s]+)",
            line
        )


        if m:


            child=ipv6_to_node(
                m.group(1)
            )

            parent=ipv6_to_node(
                m.group(2)
            )


            if child and parent:


                parents[child]=parent





# =============================
# REPORT
# =============================


print()

print(
    CYAN+
    "========== RPL IDS ANALYSIS =========="
    +
    RESET
)



print()

print(
    CYAN+
    "Known node ranks:"
    +
    RESET
)


for n,r in sorted(node_rank.items()):

    print(
        f"Node {n}: rank={r}"
    )



print()

print(
    CYAN+
    "Observed parents:"
    +
    RESET
)


for child,parent in sorted(parents.items()):

    print(
        f"Node {child} -> parent {parent}"
    )





# =============================
# IDS 1
# Rank consistency
# =============================


print()

print(
    CYAN+
    "---------- Rank consistency ----------"
    +
    RESET
)



alerts=[]



for child,parent in sorted(parents.items()):


    if child not in node_rank:
        continue


    if parent not in node_rank:
        continue



    child_rank=node_rank[child]

    parent_rank=node_rank[parent]



    print(
        f"Node {child}: "
        f"parent={parent} "
        f"parent_rank={parent_rank} "
        f"node_rank={child_rank}"
    )



    if parent_rank >= child_rank:


        print(
            RED+
            f"  [ALERT] invalid rank relation {child}->{parent}"
            +
            RESET
        )


        alerts.append(
            (
                child,
                child_rank,
                parent,
                parent_rank
            )
        )





# =============================
# IDS 2
# Rank drop detection
# =============================


print()

print(
    CYAN+
    "---------- Rank anomaly detection ----------"
    +
    RESET
)



rank_alerts=[]



for node,history in sorted(rank_history.items()):


    if len(history)<2:
        continue



    previous=history[0][1]


    for t,r in history[1:]:


        if r < previous:


            print(
                YELLOW+
                f"Node {node}: rank changed {previous} -> {r} "
                f"at {t:.3f}s"
                +
                RESET
            )


            # grande riduzione = sospetta

            if previous-r > 100:


                print(
                    RED+
                    "  [ALERT] suspicious rank decrease"
                    +
                    RESET
                )


                rank_alerts.append(node)



        previous=r





# =============================
# FINAL
# =============================


print()


if alerts or rank_alerts:


    print(
        RED+
        "[ALERT] Possible RPL rank attack detected"
        +
        RESET
    )


    if alerts:

        print(
            "Rank inconsistencies (C-ID, C-rank, P-ID, P-rank):",
            alerts
        )


    if rank_alerts:

        print(
            "Suspicious rank changes (IDs):",
            set(rank_alerts)
        )


else:


    print(
        GREEN+
        "No RPL anomalies detected"
        +
        RESET
    )



# =============================
# CSV
# =============================


with open(
    "ids_sinkhole_results.csv",
    "w",
    newline=""
) as f:


    w=csv.writer(f)


    w.writerow(
        [
            "node",
            "rank",
            "time"
        ]
    )


    for node,h in rank_history.items():

        for t,r in h:

            w.writerow(
                [
                    node,
                    r,
                    t
                ]
            )


print()

print(
    "CSV saved as ids_sinkhole_results.csv"
)