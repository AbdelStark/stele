---
name: rfc-author
description: Write or amend RFCs with the mandatory sections, consistent glossary, explicit error terms, controls and cost formulas; write short development-tier amendments and promotion texts.
---
# RFC author
Read: RFC-0000, RFC-0027 §2, Workflow 02, `agents/templates/rfc.md`, `agents/templates/amendment-short.md`, glossary.

Rules
- Every protocol RFC has the eight mandatory sections; every random challenge has a ledger line with its
  per-round error; every binding has a control id; every cost claim is a formula in cost-model symbols.
- Amendments are append-only; never change Accepted text in place. State the exact replacement text.
- A Draft is direction, not law. Code follows the Accepted text.
- Development-tier amendments are short and say so in their status line; they grant no `standard` admission.
- A number in an RFC cites a ledger. A claim about another system cites its source and its statement.
- Use the glossary's words. Do not put a word in double quotes inside the glossary unless you mean to forbid it:
  the lint reads every quoted word after the forbidden-synonym marker as forbidden.
- Write for a hostile expert who has time and for an agent who has none: short sentences, one idea each, the
  conclusion first.
