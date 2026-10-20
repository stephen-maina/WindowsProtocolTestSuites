---
name: test-debugging
description: Evidence-based triage of Windows Protocol Test Suite failures. Use test/adapter source, driver logs, captures, available SUT logs and exact published specification sections to distinguish protocol defects, product-specific expectations, test bugs and environment limitations without importing unmerged diagnostics.
license: MIT
metadata:
  author: Microsoft
  version: "1.2"
---

# Test-failure debugging skill

## 1. Establish the tested boundary

- Load the relevant protocol skill; classify FileServer scenarios by concepts before searching.
- Record repository, full source commit, build/test command, filter, configuration identity (without
  credentials), SUT/driver versions and topology. Historical results are not current validation.
- Read the actual test, helper/adapter, SDK encoder and suite User Guide. Confirm which request was sent,
  which assertion failed and whether the required prerequisites were present.
- Inspect current configuration and available tooling before enabling diagnostics. Do not assume shared
  collectors, property names, SUT scripts or artifact paths from another branch exist in this checkout.

## 2. Collect available evidence safely

- Read the TRX `ErrorInfo/Message` and stack trace, console output and PTF logs for the failing case.
  Stream large reports rather than loading an entire run into memory.
- Correlate packet evidence and available SUT logs by test identity and timestamps; account for clock
  offsets. Inspect both the request and response before attributing a rejection or timeout.
- Parse actual packet encapsulation, header lengths, offsets and lengths with bounds checks. Do not
  assume fixed absolute offsets, a particular IP version, or that a control message has a data payload.
- Collect SUT logs only through authorized existing access. If access is denied, diagnostics are disabled,
  or captures are absent, state exactly what is missing and continue with the evidence available.
  Do not change firewall/network security controls or clear existing SUT logs to obtain a diagnosis.
- Keep secrets and raw sensitive captures out of commits. Preserve authorized evidence durably with
  source/run provenance and explicit access restrictions where needed.

## 3. Compare source with the specification

Use Microsoft Learn search, then fetch the exact section. Follow the protocol landing page's published
PDF/DOCX link if section text is unavailable; record revision/date, errata, section and requirement level.
If evidence cannot be retrieved, report that limitation rather than inventing normative text.

Separate MUST, SHOULD (including exceptions), MAY and product-behavior notes. Verify negotiated feature,
dialect, platform and test preconditions before deciding applicability. A missing optional feature can
make its feature-specific test inapplicable; it does not justify skipping unrelated baseline requirements.
A Windows control run is comparison evidence, not proof that a failing Windows SUT cannot have a defect.

## 4. Classify only what the evidence supports

| Classification | Required evidence and next action |
|---|---|
| SUT implementation defect | Well-formed applicable request, exact requirement and observed violating response/state. Distinguish SHOULD recommendations from MUST violations; retain supporting source/wire evidence. |
| Product-specific test expectation | Exact product-behavior note or implementation evidence establishes a narrower expectation. Reuse existing suite platform/capability configuration; do not generalize one product's default. |
| Test/SDK defect | Concrete precondition, encoding, ordering or assertion path contradicts the intended requirement. Fix only the evidenced path and validate affected neighboring cases. |
| Environment/configuration limitation | Missing topology, account, share, hardware or other prerequisite is demonstrated. Correct authorized setup or record the case as unavailable according to suite conventions, not a conformance failure. |
| Unsubstantiated attribution | Evidence does not distinguish test, transport, environment or SUT. Record the missing path/reproduction and next collection action; do not present a hypothesis as a proven defect. |
| Coverage gap | Compare the requirement with existing tests, including relevant model-based coverage and the Test Design Specification. A text search alone does not prove absence. |

Never turn a timeout/exception into a pass or weaken an assertion solely to accommodate a SUT.
Do not add a configuration property for every implementation choice; reuse existing constants/settings
and explain any setting that genuinely needs to vary.
When a new setting is justified, validate its allowed values and default behavior, and document the
property, valid values, default and effect in the relevant User Guide.

## 5. Change, validate and report

Reproduce an evidenced in-scope defect before changing it where possible. Run focused regressions and
relevant neighbors, inspect actual failures and record exact commands, per-suite counts and limitations.
Explain non-obvious protocol decisions in code and keep existing annotations accurate.
Update the relevant Test Design Specification/User Guide when behavior changes.

Report: `Test | expected/actual | source path | wire/log evidence | spec revision/section/level |
classification | action | unavailable evidence`.
Do not treat a successful discovery, metadata check or historical SUT run as executed protocol validation.

## Skill regression protocol

[tests/guidance-cases.json](tests/guidance-cases.json) defines bounded synthetic scenarios for these
decisions. Execute the stated fresh-context protocol and preserve raw responses and separately frozen
reviewer expectations. Authored cases and link checks alone do not prove agent behavior.
