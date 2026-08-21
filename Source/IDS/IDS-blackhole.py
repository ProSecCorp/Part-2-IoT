import re
import csv
import statistics
import sys
from collections import defaultdict


if len(sys.argv) != 2:
    print("Usage: python3 analyze_log.py <logfile>")
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

generated = {}
responses = {}
sink_received = {}



# IDS

received_forward = defaultdict(int)
forwarded = defaultdict(int)

parents = defaultdict(set)



# =============================
# TIME
# =============================

def to_seconds(t):

    m,s=t.split(":")
    return int(m)*60+float(s)



# =============================
# IPv6 node extraction
# =============================

def ipv6_to_node(ip):

    m=re.search(
        r"fd00::20([0-9a-f]+):",
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


        node=int(nm.group(1))



        # ---------------------
        # Application send
        # ---------------------

        m=re.search(
            r"Sending request (\d+)",
            line
        )

        if m:

            seq=int(m.group(1))

            generated[(node,seq)] = time



        # ---------------------
        # Sink receive
        # ---------------------

        m=re.search(
            r"Received request 'hello (\d+)'.*from (fd00::[^\s]+)",
            line
        )


        if m and node==1:

            seq=int(m.group(1))

            src=ipv6_to_node(m.group(2))

            if src:

                sink_received[(src,seq)] = time



        # ---------------------
        # Client response
        # ---------------------

        m=re.search(
            r"Received response 'hello (\d+)'",
            line
        )

        if m:

            seq=int(m.group(1))

            responses[(node,seq)] = time



        # ---------------------
        # IDS: packet received for forwarding
        # ---------------------

        if "Forwarding packet to next hop" in line:

            received_forward[node]+=1



        # ---------------------
        # IDS: actual forwarding
        # ---------------------

        if "OUTPUT packet from" in line:

            forwarded[node]+=1



        # ---------------------
        # RPL parent learning
        # ---------------------

        m=re.search(
            r"parent fe80::205:5:5:5",
            line
        )

        if m:

            parents[node].add(5)



# =============================
# METRICS
# =============================


generated_n=len(generated)

sink_n=len(sink_received)

delivered_n=len(responses)


routing_pdr=sink_n/generated_n if generated_n else 0

app_pdr=delivered_n/generated_n if generated_n else 0



delays=[]


for k,t in generated.items():

    if k in responses:

        delays.append(
            responses[k]-t
        )



duration=max(generated.values())-min(generated.values()) \
    if generated else 0


throughput=sink_n/duration if duration>0 else 0



# =============================
# CSV
# =============================

with open("ids_blackhole_results.csv","w",newline="") as f:

    w=csv.writer(f)

    w.writerow(
        [
            "node",
            "seq",
            "send",
            "sink",
            "response",
            "delay"
        ]
    )


    for k in sorted(generated):

        n,s=k

        delay=""

        if k in responses:
            delay=responses[k]-generated[k]


        w.writerow(
            [
                n,
                s,
                generated[k],
                sink_received.get(k,""),
                responses.get(k,""),
                delay
            ]
        )



# =============================
# REPORT
# =============================


print()
print(CYAN+"========== RESULTS =========="+RESET)

print(f"Packets generated      : {generated_n}")
print(f"Packets reached sink   : {sink_n}")
print(f"Packets delivered      : {delivered_n}")

print()

print(
    f"PDR routing            : {routing_pdr:.4f}"
)

print(
    f"PDR end-to-end         : {app_pdr:.4f}"
)



if delays:

    print()

    print(
        f"Average delay (s)      : {statistics.mean(delays):.6f}"
    )

    print(
        f"Minimum delay (s)      : {min(delays):.6f}"
    )

    print(
        f"Maximum delay (s)      : {max(delays):.6f}"
    )


print()

print(
    f"Throughput             : {throughput:.3f} pkt/s"
)



# =============================
# IDS
# =============================


print()
print(CYAN+"========== IDS ANALYSIS =========="+RESET)



suspects=[]


for node in sorted(received_forward):


    rx=received_forward[node]

    tx=forwarded[node]


    ratio=tx/rx if rx else 0



    print(
        f"Node {node}: received={rx} forwarded={tx} ratio={ratio:.2f}"
    )


    if rx>5 and ratio < 0.6:

        suspects.append(node)



print()


if suspects:

    print(
        RED+
        "[ALERT] Malicious forwarding behaviour detected"
        +
        RESET
    )


    print(
        "Suspected malicious nodes:",
        suspects
    )

else:

    print(
        GREEN+
        "No malicious behaviour detected"
        +
        RESET
    )



print()

print(
    "CSV saved as ids_blackhole_results.csv"
)