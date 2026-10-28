# Ranking study

## Research question

How does asset context change a remediation queue compared with severity alone? A separate, currently unanswered question is whether the changed ordering improves decisions in an operational setting.

## Baseline and candidate policy

Baseline: descending severity, breaking ties by first observation and finding ID.

Candidate: `6 × severity + 12 × exposure + 6 × (importance − 1) + 20 × exploitation`.

Severity is a scanner-supplied number from 0 to 10. It is not independently validated as a CVSS score. Exposure and exploitation are binary fields; importance is an operator-assigned ordinal rating from 1 to 5. Treating that rating as a linear contribution is a simplifying assumption.

The default score ranges from 0 to 116. It is an index, not a percentage or probability. Other weight sets have different ranges. Default deadline bands are 7, 30, and 90 days at scores of 85+, 60+, and below 60. They are illustrative policy decisions, not regulatory deadlines. Deadlines are recomputed from first observation when context changes.

## Reproduction

Run `python evaluate.py`. It creates an in-memory database, imports only scan 01, and prints all rankings. The web comparison uses the current actionable database findings instead, so later imports and decisions can change its output.

On the supplied ten-finding case:

| Policy | Top-five overlap with baseline |
| --- | ---: |
| Default | 60% |
| No exposure weight | 40% |
| Double exploitation weight | 60% |

Severity-only begins with LAB-003 on archive-test. The default starts with LAB-001 on student-portal, then LAB-004 on vpn-gateway. This follows directly from the selected policy weights and invented inputs. It is not an independently discovered security result.

Overlap is the size of the intersection divided by the number of selected findings (five, or all findings if fewer). Movement is baseline rank minus policy rank; positive values mean upward movement. Ties use first observation and ID for reproducibility. IDs depend on import order, so tie ordering is not security evidence.

## What this evaluation cannot establish

The sample has no ground-truth priority labels. A policy and a scenario written to demonstrate that policy are not independent evidence of usefulness. No accuracy, recall, reduced incident rate, or analyst time savings can be inferred. The two sensitivity variants are small interventions, not an exhaustive parameter search. The study does not estimate uncertainty in exposure classification, asset importance, or exploitation data.

## Next experiment to conduct

Before collecting ratings, specify the ranking policies, tie rules, and metrics. Create multiple scenarios with internal critical services, exposed low-value assets, ambiguous exploitation status, and incomplete context. Ask independent reviewers to order a fixed set of remediation tasks without seeing model scores. Record disagreements rather than silently forcing consensus.

Compare rank correlation, top-k agreement, and concrete disagreement cases against reviewer judgments. Repeat after varying weights and input uncertainty. Keep scenario construction, labeling, and evaluation separate where practical. Report the sample size, reviewer background, missing data, and all tested settings. Human judgments are a reference with limitations, not objective attack outcomes.

This protocol is proposed work. No reviewer study has been conducted.
