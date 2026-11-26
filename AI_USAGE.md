# AI usage: dsc26-cyb-w07

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

I used Muse, my AI assistant, to write the first draft of the three modules in ir_kit from the DSC task spec, and to run the five public tests. I checked the code myself against the spec and the test output before submitting it.

## What AI got wrong

Muse first tried to commit the starter without a git identity set, so the commit failed with an author identity error. I set the name and email in the repo and ran the commit again, and it went through.

Muse also first misread a nested JSON spot check as a failure, because the sample line did not start with a brace and went through plain text redaction instead of the structural path. I re-ran the check with a real JSON line, and the nested Password field came back as [REDACTED:field] with null and empty values kept.

## In my own words

1. Your timeline places the Wazuh "download burst" at 20:41:05 UTC. What evidence in the other two logs supports choosing the first 23:41 rather than the second?

The app log shows the svc-export key revoked at 21:05:00Z, and at 21:12:03Z a DOC-88990 download was refused, with nginx logging the same request as 23:12:03 +0200 with a 403, so the second pass through the 23:xx hour had already started and a burst at 21:41 UTC would come after the revocation. At 20:41 UTC the order holds: nginx logged a 200 on DOC-88123 at 23:40:10 +0300 and the app logged the matching raw download at 20:40:10.511Z, one minute before the burst.

2. A token was public on GitHub for ten minutes before you deleted the commit. Why is the incident not over?

Deleting the commit removes a pointer, not the secret, because it can still be reached by SHA, through forks, clones, other branches, cached views and GitHub indexes, and scrapers can grab a token within seconds. The token works until it is revoked and rotated, and the incident stays open until the logs show what it touched, what was downloaded, and whether anything persistent was created.
