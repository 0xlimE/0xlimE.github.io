---
layout: post
title:  "Getting unlimited free GLS/BRING package labels but not for a bounty :o)"
date:   2024-08-21 11:17:42 +0200
categories: security-research
draft: false
---

Recently I was doing Bug Bounty hunting on a private program that I really enjoy hacking on! It is a marketplace app that allows creating listings, sending messages and if you agree on a deal: buy package labels for quick shipping of that Pink Floyd record you sold for 39dkk ;-)

Anyway, the main app exists at https://marketplace-app.dk (cover of course), where going through the purchase flow of shipping labels worked pretty nice and was secure.

However there was also a subdomain for QA testing, at https://qa01.marketplace-app.dk/, a complete copy of the main app, just with testing data. I signed up for an account here and poked around, and tried to go through the flow of buying a package label and was greeted with this screen:

![alt text](pcakagelabel.png)

Alright sure, let me just try to put in the test credit card and see what happens. So I did this and actually got a checkout screen:

![alt text](acceptedpackage.png)

Doing the same with GLS, setting my own mail as the recipient, I actually got an email from GLS lol:
![alt text](guenagnueia.png)

Triage did not really buy it initially, they said they thought this was just test labels and that there was no actual registry at GLS or the other logistics companies. So in order to hunt this bounty I actually went out and sent myself an empty package lol
![alt text](packagesent.png)

I got a receipt on SMS that I handed in the package

![alt text](smsfromgls.png)

So I waited a few days to pick up my own empty box and let the triage know, they understood it and changed the potential payout ;-)

![alt text](triage2222.png)

So it went on to the customer who mentioned they wanted to investigate, but in bug bounty it does not always go the direction you want, and it was marked as an accepted risk, oh well!

![alt text](finaldecision2.png)
