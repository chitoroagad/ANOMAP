#import "template/template.typ": *

#show table.cell.where(y: 0): strong
#set table(
  stroke: (x, y) => if y == 0 {
    (bottom: 0.7pt + black)
  },
)

#let title = [
]
#let authors = (
  (
    // Should I use string or content? It doesn't matter
    name: "Darius Chitoroaga",
    email: "darius.chitoroaga@pm.me",
    affiliation: (
      department: [Department of Computer Science],
      institution: [University College London],
      country: "United Kingdom",
    ),
    orcid: "0000-0000-0000-0000",
    // mark: super(sym.suit.diamond),
  ),
)

#let conference = (
  name: [ACM TOG],
  // short: [SOSP ’25],
  // year: [2025],
  // date: [October 13–16],
  // venue: [Seoul, Republic of Korea],
)
// #let ccs = (
//   (
//     generic: [Software and its engineering],
//     specific: ([Virtual machines], [Virtual memory]),
//   ),
//   (
//     generic: [Computer systems organization],
//     specific: ([Heterogeneous (hybrid) systems],),
//   ),
// )

#show: acmart.with(
  format: "acmsmall",
  title: "A Tool to Detect IP Spoofing for System Admins",
  authors: {
    (
      (
        name: "Darius Chitoroaga",
        email: "darius.chitoroaga.22@ucl.ac.uk",
        orcid: "0000-0000-0000-0000",
        affiliation: (
          institution: "University College London",
          city: "London",
          country: "United Kingdom",
        ),
      ),
    )
  },
  shortauthors: "Chitoroaga et al.",
  // control max number of columns for authors and affiliation
  // conference: conference,
  copyright: none,
  // Set review to submission ID for the review process or to "none" for the final version.
  // review: [\#001],
  acmJournal: "JACM",
  acmVolume: 37,
  acmNumber: 4,
  acmArticle: 111,
  acmMonth: 8,
  acmYear: 2025,
)


= Abstract
#lorem(15)
// The process of scientific writing is often tangled up with the intricacies of typesetting, leading to frustration and wasted time for researchers. In this paper, we introduce Typst, a new typesetting system designed specifically for scientific writing.
// Typst untangles the typesetting process, allowing researchers to compose papers faster. In a series of experiments we demonstrate that Typst offers several advantages, including faster document creation, simplified syntax, and increased ease-of-use.

// #acmart-ccs(ccs)
// #acmart-keywords(keywords)
// #acmart-ref(to-string(title), authors, conference, doi)

= Introduction
We aim to create a multi-tool for monitoring subnets for IP spoofing using Machine Learning techniques.

== Investigation

=== Data Sources
The most important part of any ML solution is having good data.
What we have been looking for is RTT and port scan data from a normally operating subnet using `nmap`.

_We could also use traceroutes, maybe..._

However, this only allows us to use unsupervised ML methods since we have no labelled data, only normal operations.
To use supervised ML methods we would need to have accurately labelled data, which is where we run into some issues.
- Security attacks are always evolving and adapting, therefore is we have data that we 'know' is spoofed, attackers could use
different methods in the future that do not have the same signature on the network and therefore completely bypass our
models.
- Further, to get data that is spoofed we would need to simulate known spoofing methods which are likely not in
use since they are known.
- To create a simulation of a normally operating subnet is not trivial and would require significant development.

Therefore, for the moment, we have decided to focus solely on unsupervised methods.

Now we run into ethical issues:
- Continuous pinging and port scanning is considered unethical since it produces a fairly large load on the target
subnet, using up resources.
- These types of ping are also usually associated with cyberattacks and therefore would rightfully cause stress for
the admin of the target subnet.

Therefore, we should only ping on approved subnets:
- Home networks on a router that we own.
- Research resources that allow researchers to gather data of this type.
Or precompiled datasets, though these may be out of date.

==== Home Subnets
We have gathered half a days worth of pings on a home network but this is may not be very useful since
there are at most 8 devices every connected to the subnet.


==== External Sources
/ #link(
    "https://peering.ee.columbia.edu/",
  )[PEERING]: A system that provides safe and easy
access for researchers and educators to the Internet's BGP routing system. However, it is against their terms of use to
regularly ping using something like `nmap`.
/ #link(
    "https://search.censys.io/",
  )[Censys]: A platform that provides real-time intelligence about the whole internet.
Requires deeper dive into what kind of data we can access.
/ #link(
    "https://www.shodan.io/",
  )[Shodan]: Very similar to Censys, but with more focus on IoT. Calls itself
the "Search Engine for the Internet of Everything".
/ #link(
    "https://www.shadowserver.org/",
  )[Shadowserver]: This foundation provides free daily reports and
datasets on open services and vulnerabilities.
/ #link(
    "https://atlas.ripe.net/",
  )[RIPE Atlas]: This service allows researchers to schedule `ping`s and `traceroutes` to
volunteer devices worldwide but does not allow the use of tools like `nmap` or anything that looks like an attack
or scan.

=== Wake-on-LAN
A networking standard that allows a computer to be remotely powered on or awakened from a low-power state,
using a specially crafted "magic packet".
This technology operates on the link layer so functions separately from IP addresses and relies on the
devices' MAC address.

For WoL to work the Network Interface Controller (NIC) must remain powered on during low-power states.
This feature must be enabled from the BIOS/UEFI settings on the device.


=== Detecting Devices Connected Through an Authorised Device
Tracking computers connected through another device is difficult because the "gateway" device is designed to hide them.
However, `nmap` provides specific features that can detect "leakage" from hidden devices by analysing packet headers.

==== IP ID Sequence Analysis (`-O` `-v`)
This is the most reliable method for detecting multiple devices behind a single IP.
Every device generates IP packets with a unique ID number.
Most operating systems increment this number for every packet they send.

If multiple devices are sharing one IP connection, their IP IDs will interleave or show gaps, confusing Nmap's detection engine.


==== TTL Analysis
If scanning a single IP gives packets with different TTLs it is a strong indicator that there is a router forwarding traffic.

==== The `ipidseq` Script
Nmap has a dedicated script specifically designed to classify the IP ID generation method, which helps
in identifying these "zombie" hosts or NATed environments

==== Inconsistent OS Fingerprints
When you run OS detection against a NATed IP, Nmap receives responses from potentially different devices on different ports.
Port 80 might be forwarded to a Linux server (TTL 64), while Port 3389 is forwarded to a Windows box (TTL 128).

=== Fingerprinting
==== Decide invariants
*Stable identity features that shouldn't change much*
- OS family + version (Linux 5.10)
- Device type hint (rounter/gateway/printer)
- Vendor from MAC address (Technicolor Delivery Technologies Belgium NV)
- Typical open ports
- Typical services per port (nginx on 80/443/8080)

*Volatile features*
- Uptime
- Exact TTL
- Ephemeral ports (49152)
- Number of closed ports

_Should not let volatile features dominate embeddings_

==== Normalise data into a canonical representation
Small models need focused data to be useful. Should use a normalised schema such as:
```json
{
  "os": "linux",
  "os_version": "4.14",
  "distribution": "openwrt",
  "device_vendor": "technicolor",
  "open_ports": [53,80,139,443,445,631,5000,6699,8080,9000,49152],
  "services": {
    "53": "dns",
    "80": "http-nginx",
    "443": "https-nginx",
    "8080": "http-nginx",
    "139": "netbios",
    "445": "smb",
    "631": "ipp",
    "5000": "upnp"
  },
  "web_stack": ["nginx"],
  "smb_exposed": true,
  "printer_protocol": true,
  "upnp_exposed": true
}
```

==== Create Multiple Embeddings
Use separate embeddings for different semantic groups.
This allows us to explain similarity/difference later.
Also means models don't get overloaded.

#table(
  columns: 2,
  table.header([Group], [Purpose]),
  [OS embedding], [Device class similarity],
  [Port-set embedding], [Network posture],
  [Service-stack embedding], [Application exposure],
)

/ *OS*: `Operating system: OpenWrt 19.07, Linux kernel 4.14, embedded router`
/ *Ports*: `Open TCP ports: 53, 80, 139, 443, 445, 631, 5000, 6699, 8080, 9000, 49152`
/ *Services*: `Services detected: DNS, nginx HTTP, nginx HTTPS, SMB, NetBIOS, IPP printing, UPnP`

_Should test which parts should be paired, since could be useful to pair ports and the services running on them._

==== Fingerprinting using similarity
Networking data is often varied and hosts can change values for any reason, so classifying hosts is
unlikely to be successful. Therefore, we rely on cosine similarity between embeddings. The similarities
between different embedding classes can have different weights (OS > ports > services).

==== Catching anomalies
Use *delta-based scoring* based on an initial baseline for some host.
i.e. for a certain host the baseline may be:
- Ports: {53,80,443,139,445,631,5000,8080}
- Services: nginx, SMB, IPP
- OS: OpenWrt

*Structural Anomalies*
- New port appears
- Service mismatch (`ssh` on 8080)
- HTTP server changes from nginx to Apache

*Semantic Anomalies*
- Port profile embedding drifts from baseline
- Service description no longer matches "router-like" (based on device hint)
- OS embedding changes family

==== Architecture (Pipeline)
Nmap #sym.arrow Normalise #sym.arrow Feature Groups #sym.arrow Embeddings #sym.arrow

Similarity vs baseline #sym.arrow Drift / Anomaly score #sym.arrow LLM takes action / summary

#bibliography(
  "refs.bib",
  title: "References",
  style: "association-for-computing-machinery",
)

#colbreak(weak: true)
#set heading(numbering: "A.a.a")

= Artifact Appendix
In this section we show how to reproduce our findings.
