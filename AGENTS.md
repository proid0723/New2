# Notes for coding agents

- Read `HANDOFF.md` in the private repository `proid0723/New2_config` first if you can access it.
  It has the context, the owner's rules and the open items. Settings (`feeds.json`) live there too.
- Never put sources, keywords, category names, prompts, chat ids or tokens in this public repository,
  its tests, commit messages or logs. Tests use neutral example topics.
- Work on the branch `claude/jolly-knuth-ufiqq1` (the default branch). Run
  `python3 -m unittest discover -s tests` before every push; it must pass.
- Keep it free to run: GitHub Actions on this public repository, the Gemini free tier, cron-job.org.
  No paid services, no workflows in the private repository, no self-hosted runners here.
- Test messages go only to the admin (the `test_me` run). Never message subscribers to test.
- The only third-party package is `cryptography` (pinned with hashes in `requirements.txt`); keep
  everything else in the standard library. Update the hashes when changing its version.
- The owner reads Korean; explain changes in plain Korean and give times in KST.
