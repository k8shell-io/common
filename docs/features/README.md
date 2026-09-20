# Feature contract specs

Per-feature, short-lived contract specs for work that crosses service
boundaries — e.g. `api-server` designing an endpoint that `frontend` needs to
consume. See `CLAUDE-SHARED.md`'s "Cross-service feature contracts" section
for the full convention.

One folder per feature: `<feature-slug>/`, containing:

- `README.md` — agent map: participating services, one-line role/status each,
  links to their files below. Small, rare edits (a row per participant) —
  the only file more than one agent may ever touch.
- `<service-name>.md` per participating service — written only by that
  service's own agent. Everyone else reads it; nobody else writes it. Put
  questions for another service in your own file, not theirs.

Delete the feature's folder (or fold anything worth keeping into permanent
docs) once it ships — these are working documents, not permanent reference.
