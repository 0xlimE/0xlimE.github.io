---
layout: post
title:  "Analysis of security.txt Adoption Across .dk Domains"
date:   2025-06-24 11:17:42 +0200
categories: security-research
draft: false
---

> “When security risks in web services are discovered by independent security researchers who understand the severity of the risk, they often lack the channels to disclose them properly. As a result, security issues may be left unreported. security.txt defines a standard to help organizations define the process for security researchers to disclose security vulnerabilities securely.”
>
> – [securitytxt.org](https://securitytxt.org/)

I have recently been curious about how mature Danish companies are in regards to their vulnerability disclosure process. `security.txt` files provide a standardized way for organizations to communicate this process to security researchers. As defined in [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html), these files should be accessible at either `/security.txt` or `/.well-known/security.txt`.

To assess the adoption of `security.txt` among Danish organizations, I scanned the unofficial list of 1,212,913 `.dk` domains from [wallnot.dk](https://wallnot.dk/dotdk/) using `httpx`, checking both standard locations for the file.

Initially, the scan found 1,413 domains returning a `200 OK` response. However, after making another sweep with extra checks for implementations not strictly following RFC 9116, the number of domains with a `security.txt` file increased significantly.

The final result? **2,746** out of 1,212,913 domains (a whopping **0.22%**) expose a `security.txt` file.

It's important to note that not all `200 OK` responses contained valid `security.txt` files; some servers returned HTML pages or other content. To filter for valid files, I processed each response to verify it began with either the `Contact` or `Expires` fields as required by the specification. This validation was necessary to distinguish actual `security.txt` files from other content like Apache default pages or "domain parked" responses.

The analysis also revealed that many domains share identical `security.txt` content, typically because they use the same hosting provider or are managed by the same organization. To present this data more clearly, I grouped domains by their `security.txt` content (excluding the `Expires` directive) to identify patterns in how Danish organizations implement their disclosure processes.

Now, this does not say that much in itself, because not all these domains are active, not all of them are associated with a company, and not all of them even expose a web server on port 443. Additionally, the domain list is not exhaustive, so it's not all `.dk` domains.

Still, I thought it was interesting to go through this data. When we are talking about an increased focus on Cybersecurity in Denmark, I think these are metrics that make sense to track.

The full results, with domains grouped by their shared `security.txt` content, are available on [my GitHub](https://github.com/0xlimE/dk_security.txt)
