#show table.cell.where(y: 0): strong
#set table(
  stroke: (x, y) => if y == 0 {
    (bottom: 0.7pt + black)
  },
  align: (x, y) => (
    if x > 0 { center } else { left }
  ),
)


#title("Overview of Network Mapper (" + `nmap` + ") and how we can use it")

= What is it?
A command-line tool that sends specifically designed packets to hosts on a network and analyses the responses to gather information such as:
- Whether a host is up
- Which ports are open/closed/filtered
- Which services are running on which ports
- What OS or device the host is

= Primary Uses
- Network discovery (finding devices on a network)
- Port scanning (seeing which services are open)
- Service and version detection
- Operating system fingerprinting
- Security auditing, pen testing

= Legality?
Yes, conditionally:
- Scanning networks you own #sym.checkmark
- Scanning with permission #sym.checkmark
- Scanning unauthorised systems #sym.crossmark
Nmap can *look like an attack* so need to use responsibly.

\
= Examples
== Host Discovery
Find machines on a network (`142.250.151.0/24`)

```bash
nmap -sn 142.250.151.0/24  # www.google.com
```
```
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-25 15:15 +0000
Nmap scan report for st-in-f0.1e100.net (142.250.151.0)
Host is up (0.038s latency).
... cont up to 142.250.151.255
Nmap done: 256 IP addresses (256 hosts up) scanned in 7.41 seconds
```

== Port Scanning
Discover open ports on a host

```bash nmap 142.250.151.101```
```
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-25 15:15 +0000
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 46.50% done; ETC: 15:16 (0:00:22 remaining)
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 46.72% done; ETC: 15:16 (0:00:22 remaining)
Nmap scan report for st-in-f101.1e100.net (142.250.151.101)
Host is up (0.061s latency).

PORT      STATE SERVICE
1/tcp     open  tcpmux
3/tcp     open  compressnet
4/tcp     open  unknown
... cont up to 65389/tcp
Nmap done: 1 IP address (1 host up) scanned in 36.33 seconds
```

or scan multiple hosts

```bash
nmap 142.250.151.0/24
nmap 142.250.151.10-20
```

\
= Scan Techniques
== TCP Scan Types
#table(
  columns: 3,
  table.header([Option], [Type], [Description]),
  [`-sS`], [SYN], [Steath scan],
  [`-sT`], [TCP connect], [Uses OS `connect()` syscall],
  [`-sA`], [ACK scan], [Determines firewall rules],
  [`-sF`], [FIN scan], [Used for steath evasion],
)

== UDP Scan
```bash nmap -sU 192.168.1.10```

Slower, because UDP responses often require timeouts.

\
= Nmap Script Engine (NSE)
Subsystem within `nmap` that allows users to run scripts written in *Lua* to automate tasks.
\ `nmap` installations come with *600-1000+* scripts preinstalled used for:

- Service enumeration
- Vulnerability detection
- Exploitation
- Information gathering
- Brute force attacks
- IDS/IPS evasion
- Discovery automation

Scripts are parallelised, performant, loaded at run-time and support nearly all protocol libs, making them very general.

\
= Our Use-Case
#quote(
  block: true,
  [_nmap, a tool to monitor ports on a given IP to capture the latencies of various clients in a subnet. If we structurally gather this type of data from a subnet, we will be able to record it over the time, and turn this into a time dependent fingerprint of network clients. If a new client joins the subnet and accidentally or intentionnally captures an IP, with the help of fingerprint comparison, we will be able to tell._],
)

AKA

Use `nmap` to *repeatedly measure latency (RTT) to hosts in a subnet*, record the results over time, and build a _latency fingerprint_ of each client.
Later, if a new device pretends to be an existing IP, you can detect it by comparing the latency profile to historical data.

== Why This Is Possible
`namp` can:
- Ping hosts using various techniques (ICMP, ARP, TCP SYN probes)
- Measure RTT

`namp` measures latency at several stages:
- *Host discovery (ping scan)*
- ICMP echo RTT
- TCP SYN #sym.arrow SYN/ACK RTT
- ARP RTT (on local subnets)
\
- *Port scan phase*
For each port:
- Time until SYN/ACK (open)
- Time until RST (closed)
- Time until timeout (filtered)
\
- *Service probe phase*
For services it also measures _Application-layer negotiation RTT_

All of these timings can be exported as XML for easy parsing.

== Latency into Fingerprinting
For each scan and each host we store time-series data:
- Min RTT
- Max RTT
- Mean RTT
- Standard deviation
- Jitter (#sym.Delta between successive scans)
- SRTT (smoothed RTT, weighted average)


== ML for Detecting Spoofing
This is an anomaly/change detection problem on per-IP time-series (or multivariate if we collect multiple ports)

=== Simple statistical detectors
- Threshold on mean/min RTT change
  - i.e. if $|text("mean_now") - text("mean_hist")| > alpha * text("std_hist")$.
  - Choose some #sym.alpha.
- Cumulative sum test to detect shifts in mean.
- Exponential weighted moving average
  - Detect gradual drift vs abrupt change


=== Unsupervised anomaly detection
Using only "good" historical data detect deviations.

/ Isolation Forest: Learn "normal" and assign anomaly scores (used in DeSFAM).
/ SVM: Fit a boundary around normal data.
/ Guassian Mixture Models: kinda like clustering.
/ Autoencoders: Train encoder to reconstruct fingerprints, then detect reconstruct error.
/ Dynamic Time Wrapping (DTW): compute DTW distance between new time-series and historical ones, then use k-NN or threshold to detect anomalies.

\
=== Supervised classification
Have labeled data of "same device", "different device" (harder to obtain data but could have better results).

To create data will need ready made dataset or to synthesise using local simulation or lots of hardware devices.
Also quality of data is very important.

/ Random Forest:
/ Logistic Regression:
/ Neural Networks:
/ Sequence Models:
\
Time series models:
/ ARIMA / SARIMA: Forecast next RTT; large residuals #sym.arrow anomaly. Good for univariate per-IP.
/ State-space / Kalman filters: Track latent state of RTT and flag when residuals exceed bounds.
/ Hidden Markov Models (HMM): Model discrete device "states" and transitions; a new device may cause unlikely state transition sequences.
/ LSTM / GRU / Transformer: Use raw RTT sequences to predict the next sequence or classify the sequence as same/different.
