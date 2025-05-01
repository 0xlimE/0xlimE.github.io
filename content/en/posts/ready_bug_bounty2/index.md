---
title: "A fundamental misunderstanding on when you are \"ready\" for bug bounty hunting. Part 2"
date: 2025-04-02  # Use the original post date
draft: false
tags: ["Bug bounty"]
---
***This post was originally made for the bugbounty subreddit that I lurk extensively, see it here***: https://www.reddit.com/r/bugbounty/comments/1jlqpo1/a_fundamental_misunderstanding_on_when_you_are/


----
Some weeks ago I made this post: https://www.reddit.com/r/bugbounty/comments/1i2k79f/a_fundamental_misunderstanding_on_when_you_are/ which outlined my opinion that you do not need to complete a full HackTheBox or Portswigger course to jump into hunting for vulnerabilities. The central part of the post was this point: **You are ready for bug bounty hunting when you have signed up on a platform and have agreed with the terms of the program.**


After now spending some time on this subreddit and various discord servers, talking to different *triagers*, I now want to make an amendment to my original statement.


**You are ready for bug bounty hunting when you have signed up on a platform and have agreed with the terms of the program _AND have the minimal understanding of what impactful vulnerabilities are._**


From speaking with triagers and program managers, there is simply an overwhelming amount of non-impactful and useless findings that are being sent through these programs every single day. I recently saw a post on here about a person who had managed to get an ATO as informative, how? The guy thought that it was an actual finding that stealing someone's auth cookie (PHPSESSID) could lead to account takeover. This is a fundamental non-understanding of web technologies and how authentication works. This person was, according to the original statement, "ready" for bug bounty hunting, but the reality is that they were not and falsely hyped themselves up for a critical bug but in reality just ended up disappointed and wasting triager time.


So when can you actually know if you are "ready"? Well, you need to have a basic understanding of web (because it is mostly web) technologies and what constitutes an **impactful vulnerability**. This means that you need to be able to differentiate between what Burpsuite and ChatGPT hype up as a "Severe vulnerability in the form of a missing `x-xss-protection` header" and an actual vulnerability.


I would like to highlight 3 steps you should follow before starting to send in reports to bug bounty programs.


**The first step** is to understand how web applications actually work. You need to know the basics of HTTP requests/responses, cookies, sessions, and authentication mechanisms. If you don't understand that a session cookie is literally how the server identifies you and that stealing it naturally leads to account access (which isn't a vulnerability), you're missing fundamental knowledge. Learn how browsers interact with servers, how data is transmitted, and how user authentication is maintained across requests. This foundation will help you distinguish between normal application behavior and actual security issues.


**The second step** is to get a fundamental understanding of what constitutes an impactful finding. This is where most beginners fail miserably. You must be able to differentiate between what's technically possible and what constitutes an actual security risk. "I can see my own user ID in a request" is not a vulnerability. Learn to ask: "What actual harm could come from this?"


**The third step** is to **READ THE SCOPE OF THE PROGRAM**. Most often there is a long list of Out-of-scope and non-impactful vulnerabilities, such as `physical attacks`, `missing security headers`, and `phishing`. Additionally, it is also just in general a good idea to read and understand the scope thoroughly to not submit out-of-scope vulnerabilities.


The /r/bugbounty subreddit is filled with people complaining about "informational" ratings or rejected reports because they fundamentally misunderstand what constitutes a vulnerability. They create elaborate reports about theoretical issues (like the guy who reported that the site was available over http instead of https) with minimal real-world impact, then get frustrated when programs don't pay out.


Remember: Bug bounty programs exist to identify and fix actual security risks, not to serve as paid training grounds. 


You don't need to be an expert in everything, but you do need to understand the basics of what you're doing and why it matters. Without this foundation, you're essentially throwing darts blindfolded and hoping to hit something valuable, and wasting triagers and program managers time in the process.


TL;DR: You don't need to be a security expert to start bug bounty hunting, but you do need a basic understanding of web security concepts, impact assessment, and professional conduct. Without these, you'll likely join the chorus of voices complaining about rejections rather than celebrating valid findings.