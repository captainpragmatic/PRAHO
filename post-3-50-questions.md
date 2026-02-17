---
title: "50 Questions Every Non-Technical Founder Should Ask Their Developer (Copy/Paste Ready)"
description: "Copy/paste ready checklist of infrastructure questions organized by topic: security, performance, costs, reliability, monitoring, mobile, scalability, documentation, and compliance."
date: 2025-11-20
author: Claudiu
---

# 50 Questions Every Non-Technical Founder Should Ask Their Developer (Copy/Paste Ready)

## How to Use This List

**Don't** send all 50 questions at once. Your developer will hate you, and you won't get useful answers.

**Do** pick 5-10 questions relevant to your current situation.

**Goal:** Start productive conversations, not interrogate.

Think of this as a menu. Pick what matters to you right now:
- Worried about security? Start with Security questions
- Site feels slow? Jump to Performance questions
- Costs climbing? Check Cost & Efficiency questions

**Want objective data first?** [Scan your site](link) - shows SSL, speed, security, mobile issues in 60 seconds

---

## The Questions (Organized by Topic)

### Security & Compliance (Critical - Ask These First)

These questions protect your business from catastrophic data loss or breaches.

**1. "When did we last do a security audit?"**

**Good answer:** Specific date within the last 12 months, can show you the report

**Red flag:** "We haven't" or "Not sure"

**Why it matters:** The global average cost of a data breach is $4.9 million (IBM 2024)

---

**2. "If our server got hacked tomorrow, what data could be accessed?"**

**Good answer:** Specific list: "Customer emails, order history, but payment info is with Stripe"

**Red flag:** "Everything" or "I'm not sure"

**Why it matters:** 26% of small businesses that experienced cyberattacks lost between $250,000 and $500,000

---

**3. "Are we compliant with [GDPR/CCPA/relevant regulation]? How do you know?"**

**Good answer:** "Yes, we have data processing agreements, data deletion procedures documented, and regular audits"

**Red flag:** "I think so" or "Pretty sure"

**Why it matters:** GDPR fines can be 4% of annual revenue

---

**4. "When did you last **test** restoring from backup?"**

**Good answer:** Specific date within last 3-6 months

**Red flag:** "We have backups" (doesn't answer the question about TESTING)

**Why it matters:** More than half of all data backups fail, and 93% of organizations that experience prolonged data loss go bankrupt within a year

---

**5. "What happens if we lose our backups?"**

**Good answer:** "We have redundant backups in two separate locations"

**Red flag:** "That won't happen" or avoids answering

**Why it matters:** 96% of modern ransomware attacks target backup repositories

---

**6. "What's our SSL certificate expiration date?"**

**Good answer:** Specific date, plus explanation of renewal process

**Red flag:** "Let me check..." or "I think it auto-renews"

**Why it matters:** 83% of users abandon websites with "Not Secure" warnings

**Quick check:** [Scan SSL status](link)

---

**7. "Do we have two-factor authentication on all admin accounts?"**

**Good answer:** "Yes, all admin accounts require 2FA"

**Red flag:** "On some accounts" or "No"

**Why it matters:** 68% of breaches involved a non-malicious human mistake like compromised credentials

---

**8. "What's our procedure if you get hit by a bus tomorrow?"**

**Good answer:** "Documentation is in [location], access credentials are in password manager shared with [person]"

**Red flag:** "It's all in my head" or nervous laughter

**Why it matters:** Bus factor = 1 is a business risk

---

### Performance & Speed

Speed directly impacts revenue. These questions reveal whether your site is costing you money.

**9. "What's our actual average load time from real users?"**

**Good answer:** Shows Google Analytics Site Speed reports with data

**Red flag:** "It's fast" or "About 2-3 seconds I think"

**Why it matters:** For every second of delay, conversion rates drop by 4.42%

**Check yourself:** [Scan site speed](link)

---

**10. "How does our load time compare to industry benchmarks?"**

**Good answer:** "We're at 2.1 seconds, industry average is 2.4, so we're good"

**Red flag:** "I don't know" or "We don't track that"

**Why it matters:** First-page Google results load in 1.65 seconds on average

---

**11. "What's the single biggest thing slowing us down?"**

**Good answer:** Specific issue: "Unoptimized images are 60% of page weight"

**Red flag:** "Lots of things" or "Nothing specific"

**Why it matters:** Fixes should be prioritized by impact

---

**12. "If we wanted to load 2x faster, what would that cost in time and money?"**

**Good answer:** "4-6 hours to implement image compression and caching, maybe $200 for tools"

**Red flag:** "We'd need to rebuild everything, 3 months, €20K"

**Why it matters:** Most speed improvements don't require rebuilds

---

**13. "Are we monitoring real user performance, or just running occasional tests?"**

**Good answer:** "We use Real User Monitoring (RUM) to track actual customer experience"

**Red flag:** "I test it sometimes"

**Why it matters:** Synthetic tests ≠ real user experience

---

**14. "What's our PageSpeed score on mobile vs desktop?"**

**Good answer:** Specific numbers for both, ideally 70+

**Red flag:** "Never checked mobile" or scores under 50

**Why it matters:** 53% of mobile visitors leave if pages take over 3 seconds

---

**15. "How does site performance change under load?"**

**Good answer:** "We've load tested up to 5,000 concurrent users, performance degrades at 3,000"

**Red flag:** "We'll find out when it happens"

**Why it matters:** Successful marketing campaigns can crash unprepared sites

---

### Costs & Efficiency

Infrastructure costs should be transparent and justifiable.

**16. "Can you break down our monthly infrastructure costs?"**

**Good answer:** Detailed breakdown: "Hosting €200, CDN €50, monitoring €30, email €20"

**Red flag:** "Around €500 I think" or "I don't know exactly"

**Why it matters:** Can't optimize what you can't measure

---

**17. "What would happen if we grew 2x? Which costs would increase?"**

**Good answer:** "Hosting would double to €400, CDN might go to €75, database storage to €150"

**Red flag:** "Everything would need upgrading" without specifics

**Why it matters:** Growth should be predictable, not surprising

---

**18. "When did we last evaluate cheaper alternatives for [service]?"**

**Good answer:** "Last reviewed hosting 6 months ago, found we're competitive"

**Red flag:** "We've been with them since we launched" (3 years ago)

**Why it matters:** Infrastructure markets evolve, savings exist

---

**19. "Are there services we're paying for but not using?"**

**Good answer:** "Actually yes, we have 3 monitoring tools doing similar things, should consolidate"

**Red flag:** "Everything we pay for is necessary" (probably not true)

**Why it matters:** Most companies have 10-20% wasted spend

---

**20. "What's our largest single infrastructure expense?"**

**Good answer:** Specific: "Database hosting at €600/month"

**Red flag:** "Not sure" or "Probably servers"

**Why it matters:** Biggest expense = biggest optimization opportunity

---

**21. "Could we save money by changing how we've architected things?"**

**Good answer:** Honest assessment of trade-offs

**Red flag:** "No, this is the only way" (rarely true)

**Why it matters:** Architecture decisions have 3-5 year cost implications

---

### Reliability & Uptime

Downtime is lost revenue. These questions reveal how prepared you are.

**22. "What's our actual uptime percentage over the last 90 days?"**

**Good answer:** "99.8%" with data to back it up

**Red flag:** "Pretty good" or "We haven't had outages"

**Why it matters:** Organizations experienced average of 86 outages per year

---

**23. "When was our last outage and what caused it?"**

**Good answer:** Specific date, specific cause, specific resolution

**Red flag:** "Can't remember" (probably means they're not tracking)

**Why it matters:** 51% of outages are avoidable with proper monitoring

---

**24. "If the server crashes at 2 AM Saturday, how long until we're back online?"**

**Good answer:** "15-30 minutes for automated failover" or "1-2 hours if I need to manually intervene"

**Red flag:** "Depends" or "I'd need to investigate"

**Why it matters:** Downtime costs exceed $25,000/hour for small companies

---

**25. "Do we have redundancy for critical systems?"**

**Good answer:** "Database has read replicas, application runs on multiple servers"

**Red flag:** "No, but it's very reliable"

**Why it matters:** Single points of failure = business risk

---

**26. "What breaks if [specific service] goes down?"**

**Good answer:** Detailed impact assessment

**Red flag:** "I'm not sure" or "Everything"

**Why it matters:** Should know your dependencies

---

**27. "How do we know when something breaks?"**

**Good answer:** "Monitoring alerts me via SMS/Slack, plus user impact monitoring"

**Red flag:** "Customers usually tell us" (this is bad)

**Why it matters:** 55% of companies experienced 5+ outages in 3 years

---

### Monitoring & Observability

You can't fix what you don't measure.

**28. "What are we actively monitoring?"**

**Good answer:** Specific list: "Uptime, response time, error rates, disk space, memory usage, SSL expiry"

**Red flag:** "The hosting company monitors it" or "Nothing specific"

**Why it matters:** Reactive = expensive, proactive = cheap

---

**29. "Do we get alerts before things break, or after?"**

**Good answer:** "We get warnings when disk space hits 80%, before it fills up"

**Red flag:** "We find out when it breaks"

**Why it matters:** Prevention beats firefighting

---

**30. "Can you show me our error rate over the last month?"**

**Good answer:** Shows dashboard with error tracking

**Red flag:** "We don't track that" or "Let me check logs"

**Why it matters:** Errors = broken user experiences = lost revenue

---

**31. "What's our server's CPU and memory usage typically at?"**

**Good answer:** "CPU averages 40%, peaks at 70%, memory at 60%"

**Red flag:** "Not sure" or "I'll check when it's slow"

**Why it matters:** High baseline usage = crash risk

---

**32. "How long do we keep logs, and where are they?"**

**Good answer:** "30 days in system, 1 year in cold storage"

**Red flag:** "Logs? Which logs?"

**Why it matters:** Can't debug without logs

---

### Mobile Experience

Most traffic is mobile. These questions reveal if you're serving them well.

**33. "What percentage of our traffic is mobile?"**

**Good answer:** Specific number from analytics: "62% mobile, 35% desktop, 3% tablet"

**Red flag:** "Mostly mobile I think"

**Why it matters:** 46% of people leave if mobile site takes over 4 seconds

---

**34. "When did you last test the site on an actual phone?"**

**Good answer:** "Yesterday, tested on iPhone and Android"

**Red flag:** "I just resize my browser"

**Why it matters:** Responsive design ≠ mobile testing

---

**35. "What's our mobile load time vs desktop?"**

**Good answer:** Specific numbers for both

**Red flag:** "Mobile is always slower" (without actual data)

**Why it matters:** Average mobile TTFB is 2.59 seconds vs 1.29 for desktop

---

**36. "Are forms and checkout processes tested on mobile?"**

**Good answer:** "Yes, we test on iOS and Android monthly"

**Red flag:** "Should work fine"

**Why it matters:** Broken mobile checkout = lost sales

---

**37. "Do we have data on mobile bounce rates vs desktop?"**

**Good answer:** Shows comparative data

**Red flag:** "Haven't looked at that"

**Why it matters:** High mobile bounce = mobile experience problem

---

### Scalability & Growth

Your infrastructure should grow with your business.

**38. "At what traffic level will our current setup break?"**

**Good answer:** "Tested up to 50,000 concurrent users, would need upgrades beyond that"

**Red flag:** "Should be fine" or "We'll upgrade when needed"

**Why it matters:** Successful growth shouldn't crash your site

---

**39. "What's our database size growing at?"**

**Good answer:** "10GB/month, currently 200GB, we're good for 2+ years"

**Red flag:** "Never checked"

**Why it matters:** Running out of disk space = site down

---

**40. "Can our infrastructure handle 10x traffic overnight?"**

**Good answer:** "No, but we have a plan to scale up within 24 hours if needed"

**Red flag:** "Probably?" or "Why would that happen?"

**Why it matters:** Viral moments happen, be prepared

---

**41. "What's our plan for handling traffic spikes during sales/launches?"**

**Good answer:** Specific scaling plan with cost estimates

**Red flag:** "Hope for the best"

**Why it matters:** Failed launches damage brand permanently

---

### Documentation & Knowledge Transfer

Your developer shouldn't be a single point of failure.

**42. "Where is our infrastructure documented?"**

**Good answer:** "In our wiki/Notion/Confluence, updated monthly"

**Red flag:** "It's all in my head" or "I'll write it down someday"

**Why it matters:** Bus factor = 1 is a business risk

---

**43. "If we hired a new developer tomorrow, could they deploy code?"**

**Good answer:** "Yes, deployment process is documented with screenshots"

**Red flag:** "I'd need to show them"

**Why it matters:** Knowledge silos are expensive

---

**44. "Do we have a disaster recovery plan written down?"**

**Good answer:** Shows you the document

**Red flag:** "I know what to do"

**Why it matters:** Stressed people make mistakes, checklists save you

---

**45. "Where are all our passwords/credentials stored?"**

**Good answer:** "In 1Password/LastPass team account, with 2FA"

**Red flag:** "In a text file on my computer" or "I remember them"

**Why it matters:** Credential loss = extended outage

---

### Compliance & Legal

Regulatory compliance isn't optional.

**46. "Do we have data processing agreements with all our service providers?"**

**Good answer:** "Yes, DPAs signed with AWS, Stripe, SendGrid"

**Red flag:** "What's a DPA?"

**Why it matters:** GDPR requires this, fines for non-compliance

---

**47. "Can we delete a customer's data if they request it?"**

**Good answer:** "Yes, we have a documented process taking 48 hours"

**Red flag:** "That's hard, data is everywhere"

**Why it matters:** GDPR mandates this, and fines are severe

---

**48. "Where is our data physically stored (which countries)?"**

**Good answer:** "EU data centers only for EU customers"

**Red flag:** "In the cloud" (where in the cloud?)

**Why it matters:** Data residency requirements vary by jurisdiction

---

**49. "Do we log who accesses customer data?"**

**Good answer:** "Yes, full audit trail of all data access"

**Red flag:** "No"

**Why it matters:** Compliance requirements, breach investigations

---

**50. "What's our data retention policy?"**

**Good answer:** "Customer data kept for 5 years per financial regulations, deleted after"

**Red flag:** "We keep everything forever"

**Why it matters:** Unnecessary data = liability

---

## After You Ask These Questions

### Scenario A: Developer Has Good Answers

Great! Your infrastructure is probably in good shape.

**Still worth doing:**
- [Run automated scan](link) to verify what they told you
- Schedule quarterly check-ins on these topics
- Document the answers in a shared wiki

### Scenario B: Developer Is Uncertain on Several Questions

Common. Infrastructure isn't everyone's expertise.

**What to do:**
1. Don't panic or assign blame
2. Work together to find answers
3. Consider bringing in specialist for one-time audit

**Budget:** €1,500-3,000 for comprehensive infrastructure audit

### Scenario C: Developer Gets Defensive

Less common, but happens.

**Red flags to watch:**
- "You don't need to worry about this"
- "That's too technical to explain"
- "Just trust me"
- Anger or frustration at questions

**Translation:** They either don't know or don't want you to know.

**What to do:** Get independent technical assessment.

---

## How to Frame the Conversation

**Email vs Meeting:**
- Email first (gives them time to look things up)
- Follow-up meeting to discuss unclear answers

**Pick 5-10 questions** that matter most to your situation right now. You can always ask more later.

**Frame it as curiosity, not interrogation:**
- "I want to understand our setup better"
- "Help me understand how we're handling X"
- NOT: "Why didn't you do X?" or "Prove to me that Y works"

**Make it collaborative:**
- "Can we go through these together?"
- "I'd like to understand the thinking behind our current setup"

You're the business owner. You don't need to apologize for wanting to understand your infrastructure.

---

## Decision Tree: What To Do Next

### Your Developer Answered Confidently and Thoroughly
→ You're in good shape
→ Schedule quarterly reviews
→ [Run scanner](link) to verify publicly visible issues

### Your Developer Answered Some But Not Others
→ Normal - nobody knows everything
→ Ask them to investigate the unknowns
→ Consider infrastructure audit if many unknowns

### Your Developer Got Defensive or Couldn't Answer Basics
→ Potential issue
→ Get second opinion before making decisions
→ [Book consultation](link) - I'll help you evaluate objectively

### You're Still Confused After Getting Answers
→ Translation problem, not technical problem
→ You need someone who speaks both business and technical
→ [Book consultation](link) - I specialize in translating technical to business

---

## Common Questions About This List

### Won't my developer think I don't trust them if I ask all this?

Don't ask all 50. Pick 5-10 relevant ones and frame it as "I want to understand our setup better."

Most developers appreciate informed questions from business owners. The ones who get defensive about basic questions... that's a separate problem.

### How technical do I need to be to understand their answers?

Not very. Good answers should be understandable without technical background. If you can't understand their explanation, that's a communication issue on their end.

### What if they say "it's too technical to explain"?

Red flag. Everything can be explained in simple terms. That phrase usually means "I don't want to explain" or "I don't understand it myself."

### Should I schedule this as a meeting or send via email?

Email for first pass, meeting for follow-ups. Email gives them time to look things up. Meeting lets you dig deeper on concerning answers.

### How often should I ask these questions?

Quarterly for critical questions (security, backups, monitoring). Annually for the rest. More often if things are changing rapidly.

### Is this list too aggressive/confrontational?

Frame matters. "Can you help me understand X?" is collaborative. "Why don't you know X?" is confrontational.

The questions themselves are reasonable. How you present them matters more.

### What if I don't understand their answers?

That's fine - ask for clarification. "Can you explain that in simpler terms?" is a reasonable request.

If they can't explain it simply, they might not understand it themselves.

---

## What This Checklist Actually Reveals

These questions don't just get you information. They reveal:

**Developer's knowledge level**
- Do they know your infrastructure intimately or vaguely?
- Are there gaps in their expertise?

**Developer's honesty**
- Do they admit what they don't know?
- Do they make up answers or investigate?

**Your infrastructure health**
- Are critical systems monitored?
- Do you have single points of failure?

**Your business risk**
- What would break if your developer left?
- Are you one outage away from disaster?

---

## The Next Step

You now have 50 questions. Don't be overwhelmed.

**Start here:**
1. Pick the 5 questions most relevant to your current concerns
2. Email them or schedule a conversation
3. Evaluate their responses
4. Decide if you need help

**If you need help interpreting answers or want someone to ask these questions professionally:**

[Book 30-minute consultation](link)

I'll:
- Review your developer's answers
- Tell you what's normal vs concerning
- Explain what needs attention vs what's fine
- Give you a clear action plan

No jargon. No sales pitch. Just honest assessment.

---

## Sources & Further Reading

1. Data Breach Costs: IBM Cost of a Data Breach Report 2024
2. Backup Failure Rates: [InvenioIT Disaster Recovery Statistics](https://invenioit.com/continuity/disaster-recovery-statistics/)
3. Data Loss Impact: [InvenioIT Data Loss Statistics 2025](https://invenioit.com/continuity/data-loss-statistics/)
4. Website Speed Impact: [ElectroIQ Website Load Time Statistics](https://electroiq.com/stats/website-load-time-statistics/)
5. SSL Certificate Statistics: [CompareCheapSSL](https://comparecheapssl.com/the-state-of-ssl-key-statistics-and-trends-shaping-web-security/)
6. Downtime Costs: ITIC 2024 Hourly Cost of Downtime Survey
7. Outage Frequency: [Comparitech Disaster Recovery Statistics](https://www.comparitech.com/data-recovery-software/disaster-recovery-data-loss-statistics/)
