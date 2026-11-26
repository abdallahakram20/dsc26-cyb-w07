# AI usage: dsc26-cyb-w07

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

I used Muse, my AI assistant, to write the first draft of the three modules in ir_kit from the DSC task spec, and to run the five public tests. I checked the code myself against the spec and the test output before submitting it.

## What AI got wrong

<!-- At least one thing an AI tool got wrong that you changed, and how you noticed:
     a test, the docs, running it. -->

## In my own words

1. Your timeline places the Wazuh "download burst" at 20:41:05 UTC. What evidence in the other two logs supports choosing the first 23:41 rather than the second?

Why the first 23:41 (20:41:05 UTC)?

The two logs record the clock change in their offsets, so they settle which 23:41 it was.

Key revocation (strongest). The app log shows the svc-export key revoked at 21:05:00Z. At 21:12:03Z a download of DOC-88990 was refused, and nginx logs the same request as 23:12:03 +0200 with a 403. That shows the second pass through the 23:xx hour (+02) had already started at 21:00 UTC.
Ordering. A burst of successful downloads in the second 23:41 would land at 21:41 UTC, after the key was revoked and downloads were being refused. That contradicts the logs. At 20:41 UTC the sequence holds: token issued, download, burst, revocation, refusal.
Corroboration. At 23:40:10 +0300, nginx logs a 200 on /api/v1/documents/DOC-88123/raw?redacted=false, and the app logs the matching raw download by svc-export at 20:40:10.511Z. This shows +03 was still active one minute before the burst. On its own it doesn't rule out the second pass, because the offset is explicit in both logs, so I'd lean on the revocation point as the decisive one and use this as support.

2. A token was public on GitHub for ten minutes before you deleted the commit. Why is the incident not over?

Why isn't the incident over?

Deleting the commit removes a pointer, not the secret.

The commit can still be reachable by SHA, through forks, clones, other branches, cached views and GitHub's own indexes. Scrapers watch public pushes and can pick up a token within seconds, so ten minutes is plenty.
The token works until it's revoked. Until you revoke and rotate it, whoever copied it can still use it.
You still need to establish what happened in that window: what the token touched, what was downloaded, and whether the attacker created anything persistent (new tokens, users, keys, access paths). Until you've answered that from the logs, the incident stays open.
