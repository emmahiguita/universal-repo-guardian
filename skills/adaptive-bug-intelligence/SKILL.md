---
name: adaptive-bug-intelligence
description: Use when recording or ranking verified bug outcomes across audits — confirmed bugs, false positives, fix pass/fail, regression memory, rule promotion/demotion, knowledge versioning in .repo-guardian/knowledge.json.
---

# ADAPTIVE BUG INTELLIGENCE

## Purpose
Improve detection quality over time without unsafe self-modification.

## Learning inputs
- confirmed bugs
- false positives
- fix pass/fail
- regressions
- incident fingerprints
- verified compatibility outcomes

## Learning principles
- evidence-gated
- versioned
- reversible
- repository-local
- explainable

## Never learn from
- an unverified model guess
- a build warning alone
- a single pattern match
- a failed test with unknown cause

## Knowledge fields
fingerprint
category
context
root cause
fix
verification
false-positive count
confirmation count
regression links

## Adaptive ranking
Raise confidence slightly for repeated verified patterns.
Lower confidence for verified false positives.
Never turn confidence into proof.

## Regression memory
If component X previously caused regression Y, future changes to X should recommend Y as a targeted regression check.

## Failed-fix memory
Record failed corrections so they are not repeated without new evidence.

## Rule promotion
EXPERIMENTAL → OBSERVED → RELIABLE
only after multiple independently verified cases.

## Rule demotion
RELIABLE → REVIEW → LOW_CONFIDENCE
when false positives rise.

## Versioning
Every knowledge mutation increments a knowledge version.
Every audit should record repository commit + guardian version + knowledge version.
