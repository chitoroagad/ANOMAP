#import "@preview/clean-acmart:0.0.1": (
  acmart, acmart-ccs, acmart-keywords, acmart-ref, to-string,
)

#let cuhk = super(sym.suit.spade)
#let title = [
  A Tool to Detect IP Spoofing for System Admins
]
#let authors = (
  (
    // Should I use string or content? It doesn't matter
    name: "Darius Chitoroaga",
    email: "darius.chitoroaga@pm.me",
    department: [Department of Computer Science],
    institute: [University College London],
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
#let doi = "https://doi.org/10.1145/0000000000"
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
  title: title,
  authors: authors,
  // control max number of columns for authors and affiliation
  // conference: conference,
  // doi: doi,
  // copyright: "cc",
  // Set review to submission ID for the review process or to "none" for the final version.
  // review: [\#001],
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

=== Fingerprinting Methods



#bibliography(
  "refs.bib",
  title: "References",
  style: "association-for-computing-machinery",
)

#colbreak(weak: true)
#set heading(numbering: "A.a.a")

= Artifact Appendix
In this section we show how to reproduce our findings.
