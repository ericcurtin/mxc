# MXC maintainer guide

> **Audience:** MXC maintainers

This guide covers feature acceptance and spec approval. Contributor steps and
spec requirements are in the
[feature authoring guide](docs/development/guides/authoring-a-new-feature.md).
For technical review, use the
[MXC review guidance](.github/skills/mxc-code-review/SKILL.md).

## Accept a feature

- Agree on scope and the contributor's GitHub username in the tracking issue.
- Apply `feature-accepted` only after that agreement. Acceptance permits design
  work; it does not approve the design or promise a release.
- Record scope or contributor changes in the issue. If acceptance is withdrawn,
  remove `feature-accepted` and tell the contributor to pause work.

Approval decisions belong to maintainers. Contributors and agents must not
apply approval labels themselves.

## Approve the specs

Use the contributor guide's
[spec requirements](docs/development/guides/authoring-a-new-feature.md#when-a-spec-is-required)
to determine which documents are needed.

- Review the feature design and any required API proposal in the same
  documentation-only PR. Both need approval before merge.
- After approving the design, ask the proposer to change its status from
  **Proposed** to **Accepted**. Verify that update before merging.
- After merge, apply `design-approved` to the tracking issue. Apply `api-approved`
  only when a public API proposal was approved and merged.
- Add an issue comment linking the merged PR, checked-in specs, and remaining
  implementation work.
- If there are no public API changes, include
  `API review: Not applicable - no public API changes.` in that comment.
  Do not apply `api-approved`.

Labels record decisions; they do not replace review and merge. Implementation
PRs opened before acceptance and any required spec merge may be closed without
implementation review.

## Handle design changes

If an approved design or API changes materially, remove the affected approval
labels. Restore them only after the revised spec is approved and merged.
The contributor must wait for that approval before implementing the affected
changes.

## Complete the feature

Keep the tracking issue open through spec and intermediate implementation PRs.
Close it only when the agreed implementation, functional validation, and
documentation are complete. The final implementation PR may close the issue;
otherwise, close it after confirming that work is finished.
