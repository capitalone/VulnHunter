## Residual Risk

This fix ships as **{COMPLETENESS_TIER}** — the stated attack vector is
{TIER_ONE_LINER}. The following vectors remain open and require follow-up
work:

{RESIDUAL_BULLETS}

Each vector above has an auto-created follow-up issue labelled
`vulnhunter-followup`. See the primary issue #{ISSUE_NUMBER} for the linked
list.

---

<!-- TEMPLATE VARIABLES:
     {COMPLETENESS_TIER}     — MITIGATION | WORKAROUND (this template is
                                only rendered when tier != FULL, per
                                REQ-HON-009)
     {TIER_ONE_LINER}        — "partially blocked; residual exposure remains"
                                (MITIGATION) or
                                "not blocked; a compensating control was
                                applied instead" (WORKAROUND)
     {RESIDUAL_BULLETS}      — one Markdown bullet per entry in
                                result.residual_vectors[], in list order,
                                per residual-risk-rules.md Rule R-6
     {ISSUE_NUMBER}          — the primary finding issue number
-->
