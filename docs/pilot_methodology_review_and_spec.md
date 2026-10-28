# Pilot Design Review and Implementation Specification
## Staged-disclosure measurement of Minimum Diagnostic Context (MDC) in real access-control vulnerabilities

**Role:** primary research-methodology agent
**Date:** 28 October 2026
**Inputs:** `fable_prompt.md` (proposed pilot), the two prior reviews, BAC-Bench (Liu et al., arXiv:2610.34290; repo `TianMaXingK/BAC-BENCH`), BAC-BENCH (Duarte et al., ABSENTIA, arXiv:2610.00977; repo `avduarte333/Absentia`), both inspected directly.

---

## 0. Verdict first

**REDESIGN REQUIRED — targeted, not a restart.** The staged-disclosure concept, the MDC variable, matched controls and blinding are sound and remain. Four components of the *proposed instantiation* would produce a biased or uninformative pilot and are replaced below:

1. **Data source.** "BAC-Bench" names two different benchmarks. The one the proposal assumes (Liu et al.) has only **14 Python/Java cases** (BookWyrm 5, Apache InLong 4, XWiki 5), of which 4 BookWyrm cases are the same bug shape, the 5 XWiki cases are not route handlers, and all cases per project sit in one code snapshot. It cannot supply the requested diversity. The second BAC-BENCH (ABSENTIA) supplies 18 Python advisories across 13 repositories and four framework flavours (FastAPI, Flask, Django, DRF), with vulnerable/fixed commits and a human-verified oracle. The pilot must draw from both.
2. **Fixed-version control.** Leaks the answer to any annotator who sees both versions and is not a control for the *diagnosis* question. Replaced by protected-sibling controls in the same vulnerable revision, with a tainted-operation exclusion list.
3. **Stage 2 as "containing file".** Makes MDC a function of file layout (Django puts peers in the same file; Spring puts the decisive callee in another). Redefined as a one-hop semantic closure; file co-location becomes a recorded covariate.
4. **Hypothesis-laden fields.** "Fragmented/incomplete enforcement" and "architectural root cause" as annotator checkboxes bias toward the hypothesis. Replaced by raw per-peer observations from which fragmentation is *computed*, plus a clearly labelled free-text hypothesis field.

The specification in Part III is the redesign. Claude Code can implement it once the researcher settles the decisions in §III.12.

---

# Part I — Independent verification

## I.1 What the two BAC-Benches actually contain

| | **BAC-Bench (Liu et al., repair)** | **BAC-BENCH (Duarte et al., detection)** |
|---|---|---|
| Size | 46 vulns, 6 apps | 30 advisories, 25 repos |
| Languages | PHP 12 (OpenEMR 10, Nextcloud 2), Go 20 (Usememos), **Java 9 (InLong 4, XWiki 5)**, **Python 5 (BookWyrm)** | **Python 18**, TypeScript 9, JavaScript 3 |
| Python frameworks | Django only | FastAPI 6 (open-webui, langflow×3, khoj, aegra), DRF 7 (wger×2, weblate×3, recipes, plane), Django 3 (pretix, wagtail, askbot), Flask 2 (indico, mlflow) |
| Java | Spring Boot (InLong), XWiki platform (scripting API, Velocity templates) | none |
| Revisions | pinned source *versions* per app (BookWyrm v0.4.3 for all 5; InLong 1.6.0-RC0; XWiki 12.10.1/13.1) | per-advisory vulnerable + fixed commit SHAs |
| Artifacts | description (partly Chinese), textual PoC, `official.patch`, `poc.py`, `functional_test.py`, Docker sandbox (Google Drive) | `authz_instances.jsonl`: `affected_routes`, `invariant`, `violation`, `root_files/symbols`, `sink_files/locations`, `match_criteria`, `expected_cwes`; no code copies, no PoC |
| Disclosure years | 2021–2023 (in LLM training data) | July 2025–June 2026 |
| Verification | PoC executed in sandbox | one security researcher validated against advisory + fix |
| Availability (checked today) | public, cloned successfully | public, cloned successfully |

**Liu et al. in-scope cases, inspected:**
- BookWyrm BW-2…BW-5: identical shape — owner/user taken from client-supplied form data instead of `request.user` (group, list, review, shelf creation). BW-1: block relationship not checked on direct message. Fixes local to the view.
- InLong CVE-2023-31064/-31066/-31453/-31454: owner/in-charge check missing at the **service layer** (`*ServiceImpl.java`); -31066 and -31453 also touch controllers; -31453 spans consume + sink services (multi-unit). All four in one snapshot.
- XWiki: CVE-2022-41929 (`User#setDisabledStatus` missing admin-right check in scripting API), CVE-2022-23615 (save with PR right), CVE-2022-23621 (script right reads WAR files), CVE-2021-32620 (disabled user re-activates via validation key), CVE-2021-32731 (Velocity template reveals email — information disclosure, arguably not BAC). These are API-method or template operations, not HTTP route handlers.

**Duarte et al. Python cases, inspected (oracle `violation` field):** the set contains exactly the shapes the pilot wants and the proposal feared BAC-Bench lacked — a route omitted from a central authorization validator map (mlflow), a DRF `detail=False` action that bypasses `has_object_permission` while the sibling detail route is protected (tandoor), an endpoint class missing the `allow_permission` decorator its peers carry (plane), a FastAPI route lacking the ownership dependency its siblings use (langflow-7grx), a helper missing a user filter (langflow-8c4j), a writable `ModelViewSet` where read-only was intended (weblate-mpf5), a guard that is present but broken by an int-vs-string comparison (askbot), a default-allow auth hook (aegra), multi-route file-access families (pretix, open-webui), preview views not mirroring edit permissions (wagtail).

**Neither benchmark contains alternate-channel cases.** Duarte et al. state that every instance localizes to a single handler and none requires chaining routes. Liu et al.'s XWiki cases are the nearest thing (scripting API vs. UI), and they are not HTTP channels. The pilot must therefore record `channel` but **must not expect** to exercise the alternate-channel category; that category needs targeted mining later.

## I.2 Prior work that touches this pilot (beyond the two earlier reviews)

- **ABSENTIA** states the non-locality thesis as its obstacle O2 ("a missing check is a claim about the whole application, not about a line") and builds a route→guard graph, but **does not measure** how much context a diagnosis needs. The measurement gap stands.
- **MOCGuard** (IEEE S&P 2025) detects missing-owner-check vulnerabilities in Java web apps by reading ownership off the database schema; **Li et al.** (IEEE S&P 2026) detect privilege escalation in polyglot microservices via agentic analysis; **SPACE** (ICSE 2016) uses a catalog of access-control patterns; **BACScan** (CCS 2025) is black-box. These further occupy *detection*. None reports per-vulnerability context requirements or enforcement placement.
- The ABSENTIA oracle's `invariant`/`violation`/`sink_locations` fields are usable for adjudication and for a mechanical lower bound on MDC (§III.6), and must be hidden from annotators.

**Scientific-meaning check.** With 10 cases the pilot cannot "identify and characterize an anti-pattern"; it can validate the instrument that would. The honest pilot claim is: *the staged-disclosure protocol yields stable, adjudicable MDC and placement measurements on real cases, with controls, within budget.* At most it produces an existence proof: one or more cases whose diagnosis demonstrably required peer/configuration context, with the evidence trail to show it. That is what the design below is built to deliver.

---

# Part II — Answers to the review questions

**Q1. Are the four stages operationally distinct?** No, as proposed. Stage 2 ("containing file") coincides with Stage 3 for Django/DRF (peers share the views file) and omits the decisive callee for Spring (service in another file). Redefine Stage 2 as the one-hop semantic closure (direct-callee bodies + referenced model/serializer/form/DTO definitions) and record `peers_colocated_in_file` as a covariate. Stage 3 adds peers, guard definitions, routing/config, class hierarchy. Stage 4 is the repository snapshot. With this, the stages are information-typed rather than layout-typed, and comparable across frameworks.

**Q2. What appears at each stage?** See §III.4. Two rules: every stage is a superset of the previous (verified mechanically); nothing added by the fix commit appears at any stage.

**Q3. Are the matched-control rules valid?** Partly. "Semantically similar protected operation in the same vulnerable revision" is valid and should be the only *paired* control. "Another comparable protected operation in the same project" is the fallback. The fixed version is not valid as a paired control (Q4). Additional requirement the proposal lacks: a **tainted-operation exclusion** — a control may not be an operation affected by any other case in either benchmark or by any later security advisory for that repository (InLong 1.6.0 alone has >10 CVEs; langflow and weblate have three instances each).

**Q4. Could the fixed version leak the answer?** Yes, three ways: (i) an annotator who sees both versions diffs them mentally; (ii) the added check is itself a tell ("why would this exist unless needed"), so the control is trivially "not vulnerable" and the vulnerable item becomes decidable by pattern-matching the absence; (iii) fix commits add tests whose names describe the bug. Use the fixed version only at the post-Stage-4 reveal for patch-locus annotation.

**Q5. What additional blinding is necessary?** Beyond the proposal's list: remove `.git`, CHANGELOG/HISTORY/release notes, `SECURITY.md`, `.github/` advisories and issue templates, docs folders, and any file whose path contains the fix commit's added test names; present bundles as plain files with no commit metadata; no internet during annotation; annotators declare prior familiarity with the project and with the specific advisory before each item (item excluded for that annotator if the advisory is recognized); annotators are not told the vulnerable:control ratio; the two members of a pair are separated by ≥5 items in presentation order and the order is logged; descriptions in Liu et al. (partly Chinese) and the ABSENTIA oracle are never shipped to annotators.

**Q6. Enforcement-placement categories?** The list is right in spirit but must be recorded **per enforcement point and per peer**, not once per case, and must distinguish *where the rule is declared* from *where it executes*. Final values in §III.8. "Mixed" is computed, never ticked. "Multi-channel" is not a placement value.

**Q7. Failure-mechanism categories?** Overlapping (e.g., "authentication missing on one path" vs "alternate-channel bypass"; "wrong subject checked" vs "ownership missing"). Replace the flat list with three orthogonal facets — F1 *defect type* (absent / wrong subject / wrong resource-or-scope / present-but-broken), F2 *coverage shape* (single op / one of N peers / one of N paths to same op / whole family), F3 *required property* (authn / function-role / object ownership / tenant-membership / relationship-share / property-level). A "mechanism" is the tuple. Emergent values allowed under `other` with mandatory free text.

**Q8. Which labels remain independent?** MDC, placement (per PEP), channel, F1, F2, F3, patch locus, peer table, oracle-visibility stage, and the *computed* fragmentation indicator. Do not fold these into one taxonomy until the full study has data.

**Q9. Operationalizing "architectural cause" without overclaiming.** Do not ask annotators. Compute `fragmentation_indicator` from observed fields: ≥2 peers exist ∧ ≥1 peer is guarded ∧ the guards on guarded peers are declared per-operation or per-class rather than through one shared PEP covering the family ∧ the vulnerable operation is the unguarded outlier. Report it as a *structural observation*, not a cause. Separately collect one free-text field after the fix reveal, labelled "root-cause hypothesis (speculative)", which is analysed qualitatively and never counted.

**Q10. Recording scattered/incomplete enforcement without biasing annotators.** Annotators fill a neutral **peer table** (for each peer: route, guard present?, guard kind, where declared) and never see the words "scattered", "fragmented", "anti-pattern" or "central". The annotation form and training materials describe the task as "determine whether this operation enforces the access rule it needs, and document how related operations enforce theirs." The hypothesis lives only in the analysis script.

**Q11. Is 10 cases sufficient?** For a methodology pilot, yes; for any claim about prevalence or recurrence, no. 10 vulnerable + 10 controls, two annotators each on all 20 items, a third adjudicator, and a 2-item dry run beforehand. Agreement statistics on 20 items have wide intervals and are diagnostics, not gates (§III.10).

**Q12. How to select the 10?** Priority list in §III.3: 6 Python from ABSENTIA's set (≤1 per repository, ≥3 framework flavours), 1 Django from Liu (BookWyrm), 2 Spring from Liu (InLong), 1 stress case (XWiki non-route API) or its fallback. Selection is by *mechanism diversity and framework coverage*, documented per case; representativeness is explicitly not claimed.

**Q13. Randomize vulnerable and control individually?** Yes: per-annotator random order over all 20 items, constrained so pair-mates are ≥5 positions apart; no blocking by project; order logged for carry-over analysis.

**Q14. Annotation form per stage?** §III.7: decision (vulnerable / not vulnerable / cannot decide), confidence 1–5, evidence pointers (file:line-range, ≥1 when deciding), the property the operation needs (free text), what information would be needed next (free text), time.

**Q15. Evidence annotators must provide?** A location pointer that resolves to a line range in the shown bundle, plus a one-sentence statement of the rule the operation should enforce. A "vulnerable" verdict with no resolvable pointer is scored as "cannot decide".

**Q16. Reasons to reject a pilot case?** §III.3.3: vulnerable operation not identifiable as a single entry point; fix spans >1 commit with intervening unrelated changes; vulnerable revision does not parse/import; no eligible control after taint exclusion; advisory wording required to understand the bug (oracle-dependent); defect lives in a template/view-layer rendering rather than an operation; project has a later public advisory touching the same operation.

**Q17. What to check before scaling?** §III.10/11: bundle generation success rate; stage-collapse rate; time per stage; control false-positive rate at Stages 1–2; proportion of items with MDC ≥ 3 and whether it matches the oracle-visibility lower bound; codebook edits needed; annotator debrief on stage definitions; carry-over effect size.

**Q18. Missed validity threats.**
- *Decision prior:* annotators know every item is "possibly vulnerable"; controls partly address this, but the base rate should be undisclosed and the instructions should include "many items are correctly protected".
- *Oracle-dependence:* some advisories (e.g., khoj's OAuth binding) are hard to judge without the advisory; those cases measure advisory-dependence, not code non-locality — flag `oracle_dependent` during adjudication.
- *Reviewer expertise confound:* MDC depends on who reads; record years of experience and framework familiarity; within-pair design controls part of this.
- *Mechanical lower bound ignored:* if the fix-touched lines first appear at Stage 3, Stage-1 "vulnerable" verdicts are guesses, not diagnoses. Record `oracle_visible_stage` and treat verdicts before it as unsupported unless the evidence pointer explains the diagnosis from shown material.
- *Project-snapshot coupling:* InLong's four cases share one snapshot; a Stage-4 annotator on one item sees the other three vulnerabilities. Use ≤2 InLong items and keep them with different annotators at Stage 4 if possible, or accept and log.
- *Benchmark-construction bias:* both benchmarks favour single-handler, PoC-able bugs; multi-step and alternate-channel cases are absent by construction. State this as a scope limit of the pilot.
- *Contamination for later model baselines:* Liu cases (2021–2023) are in training data; ABSENTIA cases are post-July-2025. If model baselines are added later, stratify by this.

---

# Part III — Recommended final design and Claude Code specification

## III.1 Research goal of the pilot (as to be stated)

Validate a staged-disclosure instrument for measuring the minimum diagnostic context (MDC) of real access-control vulnerabilities in Python and Java web applications, with matched protected controls, and collect per-case enforcement-placement observations, on 10 vulnerable operations drawn from two public benchmarks. No prevalence or anti-pattern claim is made from the pilot.

## III.2 Terminology fixed for the pilot

- **Operation:** one request entry point (route + method + handler) or, for the XWiki stress case, one public API method reachable from scripts.
- **PEP (policy enforcement point):** any code or configuration element that decides or applies an access rule for an operation (decorator, dependency, middleware matcher, security-config rule, base-class check, in-body check, service-layer check, query scope).
- **Peer:** another operation on the same resource type (same route noun segment, same controller/viewset class, or same model class).
- **MDC:** earliest stage at which an annotator's decision is correct (per §III.6) and stays correct through Stage 4.
- **Oracle-visible stage:** earliest stage whose bundle contains the fix-touched lines (mechanical).

## III.3 Case selection

### III.3.1 Sources (both public; both must be pinned by commit)
- `S-LIU`: `https://github.com/TianMaXingK/BAC-BENCH`, directory `benchmark/<app>/<id>/`; source versions per README (BookWyrm v0.4.3; InLong 1.6.0-RC0; XWiki 12.10.1, 13.1 for CVE-2021-32731). Claude Code records the exact tag/commit it checks out.
- `S-ABS`: `https://github.com/avduarte333/Absentia`, file `data/authz_instances.jsonl` (30 records; fields listed in Part I). Use `vulnerable_commit` for checkout; `fixed_commit` only for the post-reveal patch-locus bundle.

### III.3.2 Selected cases (priority order; rationale; fallback)

| # | Case id | Source | Lang / framework | Why selected | Fallback |
|---|---|---|---|---|---|
| 1 | `mlflow-ghsa-46r5-x6jq-v8g6` | S-ABS | Python / Flask | route omitted from a central authorization-validator registry; defect is in `server/auth/__init__.py`, not the handler → expected high MDC | `indico-ghsa-q28v-664f-q6wj` |
| 2 | `tandoor-ghsa-v8x3-w674-55p5` | S-ABS | Python / DRF | `detail=False` action bypasses `has_object_permission`; protected sibling `PUT /api/recipe/{id}/` is the natural control | `weblate-ghsa-3pmh-24wp-xpf4` |
| 3 | `plane-ghsa-qw87-v5w3-6vxx` | S-ABS | Python / DRF | endpoint class lacks the `allow_permission` decorator its peers carry; base class enforces only authentication | `wger-ghsa-g8gc-6c4h-jg86` |
| 4 | `langflow-ghsa-7grx-3xcx-2xv5` | S-ABS | Python / FastAPI | route lacks the ownership-checking dependency used by siblings; also lacks authentication | `langflow-ghsa-8c4j-f57c-35cf` |
| 5 | `weblate-ghsa-mpf5-3vph-q75r` | S-ABS | Python / DRF | writable viewset where read-only intended → "policy at wrong scope" via framework mechanism | `wagtail-ghsa-4qvv-g3vr-m348` |
| 6 | `askbot-devel-ghsa-r2jv-fwfr-4j8c` | S-ABS | Python / Django | guard present but broken (int vs str compare) → tests whether the instrument yields low MDC for a local mistake | `aegra-aegra-ghsa-m98r-6667-4wq7` |
| 7 | `bookwyrm/BW-1` | S-LIU | Python / Django | block relationship not checked on direct-message path; has executable PoC | `bookwyrm/BW-4` |
| 8 | `inlong/cve-2023-31066` | S-LIU | Java / Spring Boot | owner check missing; fix touches controller and service | `inlong/cve-2023-31064` |
| 9 | `inlong/cve-2023-31453` | S-LIU | Java / Spring Boot | service-layer owner check missing across consume and sink services (multi-unit) | `inlong/cve-2023-31454` |
| 10 | `xwiki/cve-2022-41929` | S-LIU | Java / XWiki API | **stress test:** non-route operation (`User#setDisabledStatus`) missing admin-right check; tests whether stage definitions generalize beyond HTTP handlers | `aegra-aegra-ghsa-m98r-6667-4wq7` (FastAPI default-allow) — **researcher decision §III.12(a)** |

Constraints enforced by Claude Code: ≤1 case per S-ABS repository; ≤2 InLong cases; ≥3 distinct Python framework flavours; every selected case passes §III.3.3.

### III.3.3 Inclusion / exclusion / rejection rules (mechanical where possible)

Include when all hold:
- I1. Vulnerable revision checks out and the language's parser (tree-sitter / `ast` / JavaParser) parses the handler file.
- I2. Exactly one *primary* vulnerable operation can be designated from the oracle (`affected_routes`[0] for S-ABS; the operation exercised by `poc.py` for S-LIU). Additional affected routes become peers, flagged `also_affected=true`, never controls.
- I3. Fix is a single commit or a set of commits with no unrelated intervening changes to the touched files.
- I4. At least one eligible control exists (§III.3.4).
- I5. The handler exists in the vulnerable revision (the fix did not create it).

Exclude when any holds:
- E1. Defect is in rendering/templating only (e.g., XWiki CVE-2021-32731).
- E2. Understanding the defect requires external-system semantics not visible in code (OAuth provider behaviour) — mark `oracle_dependent` and exclude from the pilot.
- E3. Project has a later public security advisory touching the same operation (ambiguous ground truth).
- E4. Source bundle for Stage 4 exceeds 2 GB or 50k files after pruning.

### III.3.4 Matched-control rules

- C1. Preferred: a peer operation in the **same vulnerable revision**, same resource noun, same read/write class, that enforces the property the vulnerable operation lacks, and whose enforcement is visible in the same stage types. Use the sibling named or implied by the advisory where one exists (tandoor `PUT /api/recipe/{id}/`; mlflow REST counterpart present in the validator map; plane sibling endpoint with `allow_permission`; langflow sibling using `get_flow`).
- C2. Fallback: a protected operation on a different resource in the same revision with the same enforcement mechanism.
- C3. **Taint exclusion:** the control must not appear in `affected_routes`/`sink_files` of any instance for that repository in either benchmark, must not be touched by the fix diff of any such instance, and must not be touched by any GitHub Security Advisory for that repository published up to the pilot date. Claude Code builds `tainted_operations.csv` per repository from both benchmarks plus the GHSA API and checks every control against it.
- C4. Never use the fixed revision as a paired control.
- C5. Record `control_similarity`: same_class / same_prefix / same_model / other, and `control_guard_kind`.

## III.4 Disclosure stages (final)

Bundles are plain directories of source files (no `.git`, no metadata). Each stage ⊇ previous stage, verified by hash manifest.

**Stage 1 — Operation unit.** The handler/method body; its signature; decorators/annotations attached in the same source span; the route registration line(s) if declared elsewhere (e.g., `urls.py` line, `router.add_api_route`, `@app.route`) **as a single excerpted line with file path**; names and signatures (not bodies) of directly called functions/methods; class name and base-class *names* for class-based views. Nothing else.

**Stage 2 — One-hop semantic closure.** Add: bodies of directly called project functions/methods (one hop; framework/library code excluded); definitions of model/serializer/form/DTO classes referenced in the handler (class body only); the rest of the containing file **with sibling handlers and their decorators masked** (replaced by a stub `# [handler omitted at this stage]` preserving line numbers). Record `peers_colocated_in_file` = whether the masked siblings are peers.

> Rationale: Stage 2 approximates what an inter-procedural, function-plus-dependencies analysis sees (VulEval's dependency setting) without exposing peer comparison. Masking preserves line numbers so evidence pointers stay stable across stages.

**Stage 3 — Peers, guards, configuration.** Add: the containing file unmasked; all peer operations (≤12; rule in §III.2) with their full bodies and decorators; definitions of every guard element encountered (decorator/dependency/permission-class/mixin/base-view bodies; middleware classes listed in settings; Spring Security configuration classes; router-level dependencies; URL conf for the resource); class hierarchy up to the framework boundary; the authorization helper module(s) referenced by any peer.

**Stage 4 — Repository snapshot.** The vulnerable revision with: `.git`, `node_modules`, vendored dependencies, binaries, `CHANGELOG*`, `HISTORY*`, `RELEASE*`, `SECURITY*`, `.github/`, `docs/` removed; test directories **retained** (they are legitimate context) except files added or modified by the fix commit, which do not exist in the vulnerable revision anyway. Time cap applies.

**Post-Stage-4 reveal (separate screen, after all Stage-4 fields are submitted):** the fix diff; then patch-locus fields.

## III.5 Blinding requirements (checklist Claude Code must enforce)

- B1. No advisory/CVE/GHSA identifier, title, text, CWE, PoC, or benchmark id anywhere in bundles or file names; bundles named `item_<random6>`.
- B2. No fix diff, fixed revision, or commit messages before the reveal.
- B3. Removal list of §III.4 Stage 4 applied to all stages.
- B4. Automated scan of every bundle for the strings `CVE-`, `GHSA-`, the fix commit SHA, the advisory URL, and the benchmark case id → hard fail. A soft report listing lines containing `vulnerab`, `exploit`, `IDOR`, `security fix` is produced for the researcher to inspect; these are **not** auto-removed (they may be legitimate code).
- B5. Annotators receive bundles offline; instructions prohibit web access and prior-case lookup; per-item familiarity declaration (project: none/some/contributor; advisory recognized: yes/no); items with `advisory_recognized=yes` are excluded for that annotator.
- B6. Vulnerable:control ratio undisclosed; instructions state that many items are correctly protected.
- B7. Presentation order randomized per annotator with pair-mates ≥5 positions apart; order logged.

## III.6 Scoring rules (analysis script, not annotator-facing)

- Decision at stage *s* is **correct** for a vulnerable item iff `decision=vulnerable` ∧ at least one evidence pointer overlaps the oracle location set (fix-touched line ranges mapped to the vulnerable revision, ±10 lines, or the handler span) ∨ the stated required property matches the oracle invariant (adjudicator judgment, logged).
- Correct for a control iff `decision=not_vulnerable`.
- `cannot_decide` is incorrect for MDC purposes.
- **MDC** = min *s* such that decisions at all stages ≥ *s* are correct; if none, `MDC = 5` ("not decided within protocol").
- **oracle_visible_stage** = min *s* whose bundle contains ≥1 oracle line range (mechanical). A correct vulnerable verdict at *s* < oracle_visible_stage is flagged `pre_oracle_guess` and reviewed by the adjudicator.
- Control false-positive at stage *s* = `decision=vulnerable` on a control.
- Carry-over covariate: whether the pair-mate was presented earlier for that annotator.

## III.7 Annotation schema (exact fields)

**Per annotator (once):** `annotator_id`, `years_security_experience`, `framework_familiarity{django,drf,flask,fastapi,spring,xwiki}` ∈ {none, basic, working, expert}.

**Per item, before Stage 1:** `item_id`, `project_familiarity` ∈ {none, user, contributor}, `advisory_recognized` ∈ {no, maybe, yes}.

**Per item × stage (1–4):**
- `decision` ∈ {vulnerable, not_vulnerable, cannot_decide}
- `confidence` ∈ 1..5
- `evidence_pointers` list of `{path, line_start, line_end}` (≥1 if decision ≠ cannot_decide)
- `required_property` free text, one sentence ("this operation should only be allowed when …")
- `enforcing_element` free text: where (if anywhere) the property is enforced for this operation, as seen so far
- `info_needed_next` free text
- `time_seconds`

**Per item, after Stage 4 (before reveal):**
- `channel` ∈ {http_route, websocket, graphql, rpc_grpc, cli_command, async_consumer, script_api, other(text)}
- `peer_table`: rows `{peer_route_or_symbol, path, line, guard_present ∈ {yes,no,unclear}, guard_kind (text), guard_declared_at ∈ placement enum, also_affected ∈ {yes,no,unknown}}` — up to 12 rows; `peer_count_total` if truncated
- `vuln_op_pep_table`: rows for every PEP on the vulnerable operation's path `{kind, declared_at ∈ placement enum, path, line, decides ∈ {authn, role, ownership, tenant, relationship, property, other}}` (may be empty)
- `shared_pep_covers_family` ∈ {yes, no, unclear} + pointer
- `F1_defect_type` ∈ {check_absent, wrong_subject, wrong_resource_or_scope, present_but_broken, other(text)}
- `F2_coverage_shape` ∈ {single_operation, one_of_n_peers, one_of_n_paths_same_operation, whole_family, other(text)}
- `F3_required_property` ∈ {authentication, function_role, object_ownership, tenant_membership, relationship_share, property_level, other(text)}
- `cwe_guess` (free; for calibration only)

**Per item, after reveal:**
- `patch_locus_layer` ∈ {presentation, control, business, data, cross_cutting_authz} (BAC-Bench Position layers)
- `patch_is_central_chokepoint` ∈ {yes, no}
- `patch_locus_placement` ∈ placement enum
- `fix_changed_my_mechanism_labels` ∈ {no, yes(text)}
- `root_cause_hypothesis` free text, labelled speculative

**Computed (analysis only):** `MDC`, `oracle_visible_stage`, `pre_oracle_guess`, `control_fp_by_stage`, `peers_colocated_in_file`, `fragmentation_indicator` (§II Q9), `placement_mixed` (≥2 distinct `declared_at` values across vuln op + guarded peers), `carry_over_seen_pair_mate_first`.

## III.8 Codebook (pre-defined vs emergent)

**Placement enum (closed for the pilot):** `gateway_or_global_middleware`, `framework_config` (URL conf / security config / router-level dependency / settings), `class_or_base_view` (class decorator, mixin, base class, permission_classes attribute), `per_operation_declared` (handler decorator / per-route dependency / `@PreAuthorize`), `in_body_check` (explicit check in handler body), `service_layer_check`, `data_layer_scope` (ORM filter / queryset / query predicate / row policy), `none_observed`, `other(text)`.

**Channel enum:** closed as in §III.7; `other` with text.

**F1/F2/F3:** closed lists as in §III.7 with `other(text)`; any `other` used ≥2 times across the pilot becomes a candidate category for the full study.

**Open/emergent:** `required_property` phrasing, `root_cause_hypothesis`, `info_needed_next`. These are coded qualitatively after the pilot and feed codebook revision; they are never counted in the pilot.

**Never in the codebook:** "scattered", "fragmented", "anti-pattern", "architectural", "central is better".

## III.9 Pilot procedure

1. Researcher approves §III.12 decisions.
2. Claude Code builds candidate table, taint lists, bundles, manifests, validation report (§III.11).
3. Researcher inspects validation report and the soft-leak report; approves bundles.
4. Dry run: 2 items (one vulnerable, one control, from a *non-selected* case) with both annotators; debrief; fix instructions.
5. Main run: 20 items, both annotators, randomized orders; time cap 45 min per item through Stage 4 (recorded, not enforced by cutting off).
6. Adjudicator resolves disagreements on F1–F3, placement and decision-correctness using the oracle; logs every codebook change.
7. Analysis script produces the §III.10 table.
8. Debrief questionnaire on stage clarity and leakage suspicion.

## III.10 Pilot success criteria (methodology readiness)

All of:
- S1. ≥9/10 vulnerable cases and ≥9/10 controls bundled by the pipeline without case-specific hand edits beyond the documented peer-selection rule.
- S2. Stage monotonicity and leak scans pass for all bundles.
- S3. No annotator reports recognizing an advisory on more than 1 item.
- S4. Median time to complete Stage 4 ≤ 45 min; no item > 90 min.
- S5. Control false-positive rate at Stage 1 ≤ 30% and at Stage 2 ≤ 30% (if higher, the decision task is under-specified).
- S6. For ≥8/10 vulnerable items, human MDC ≥ oracle_visible_stage, or every exception is explained by the evidence pointer (no unexplained `pre_oracle_guess`).
- S7. Raw agreement between annotators ≥ 70% on F1, F2, F3 and on vulnerable-op placement; κ reported with CI but not used as a gate at n=20.
- S8. Adjudication requires ≤ 5 codebook edits, none of which changes a Stage definition.
- S9. Debrief: no stage judged "unclear what belongs here" on ≥3 items.
- S10. At least 3 vulnerable items reach MDC ≥ 3 **and** at least 1 reaches MDC ≤ 2 — the instrument must demonstrably separate cases, otherwise it is not measuring.

## III.11 Pilot failure criteria (redesign before continuing)

Any of:
- F1. >3 cases need ad-hoc manual judgment to build Stage 1–3 bundles.
- F2. Control false-positive rate ≥ 50% at Stage 1 or 2 (annotators are guessing "something is missing").
- F3. Stage 2 and Stage 3 bundles are byte-identical in content (after unmasking) for ≥50% of Python cases → stage definitions collapsed.
- F4. Any confirmed leak (identifier in bundle; annotator reports recognizing ≥2 advisories; fix content visible before reveal).
- F5. MDC distribution is degenerate (all 1 or all 5) across vulnerable items.
- F6. Raw agreement on F1 < 50% after adjudication-round codebook revision.
- F7. Pair carry-over: Stage-1 correctness differs by ≥40 pp between "pair-mate seen first" and "not seen first" → switch to between-annotator pair assignment for the full study.

## III.12 Unresolved decisions requiring researcher approval

- (a) Include the XWiki non-route stress case (#10) or replace with aegra (FastAPI default-allow)?
- (b) Pair assignment: within-annotator (both annotators see all 20 items, separation ≥5) as specified, or between-annotator crossover (each annotator sees one member of each pair; no within-pair κ)?
- (c) Stage 2 definition: one-hop callee bodies + referenced model definitions (specified) vs. verbatim containing file (proposal). Specified version recommended.
- (d) Accept S-ABS cases without executable PoC (oracle = advisory + fix only)? Recommended yes for the pilot.
- (e) Annotator pool: two security-literate annotators external to the project plus one adjudicator; experience thresholds.
- (f) Time cap value (45 min recorded, not enforced) and whether Stage 4 is time-boxed.
- (g) Whether later LLM baselines will run on the same items (affects contamination stratification; S-LIU cases are pre-cutoff).
- (h) Policy for `oracle_dependent` cases discovered during bundling (exclude vs keep flagged).

---

# Part IV — Final Claude Code Implementation Specification

Claude Code implements the *build and validation pipeline* and the *analysis script*. It does not annotate, adjudicate, or select cases beyond this specification.

## IV.1 Repository layout to create

```
mdc-pilot/
  README.md                          # purpose, how to run, what not to do
  config/
    cases_selected.csv               # §IV.4 schema, pre-filled from §III.3.2
    cases_candidates.csv             # all 14 S-LIU in-scope + 18 S-ABS Python, with eligibility fields
    controls.csv                     # §IV.4
    tainted_operations/<repo>.csv    # §III.3.4 C3
    peer_selection_rules.md          # the deterministic rules below, verbatim
    banned_strings.txt               # CVE-, GHSA-, per-case SHAs/URLs/ids (generated)
    stage4_prune_patterns.txt        # §III.4 removal list
  sources/                           # git checkouts at pinned SHAs (not committed)
  scripts/
    00_fetch_benchmarks.py           # clones both benchmark repos; records their commit SHAs
    01_build_candidates.py           # fills cases_candidates.csv; applies I1–I5, E1–E4
    02_build_taint_lists.py          # both benchmarks + GHSA API per repo
    03_resolve_operation.py          # locates handler span, route registration, decorators (tree-sitter py/java)
    04_select_peers.py               # deterministic peer rule; writes peers/<item>.json
    05_build_stages.py               # Stage 1–4 bundles + masks + manifests
    06_validate_bundles.py           # §IV.6 checks; writes validation_report.md
    07_make_annotation_packets.py    # per-annotator randomized order, item ids, forms
    08_score.py                      # §III.6 scoring and §III.10 table from annotation CSVs
  bundles/<item_random6>/stage{1,2,3,4}/...     # generated
  bundles/<item_random6>/reveal/fix.diff        # generated, kept out of annotator packets
  manifests/<item_random6>.json                 # provenance + hashes + oracle (private)
  forms/annotation_form.md ; forms/form_schema.json   # §III.7 fields
  analysis/validation_report.md ; analysis/pilot_summary.md
```

## IV.2 Provenance requirements (per item, in `manifests/<item>.json`)

`benchmark_source` (S-LIU|S-ABS), `benchmark_repo_commit`, `case_id`, `project_repo_url`, `vulnerable_ref` (SHA or tag → resolved SHA), `fixed_ref`, `primary_operation` {path, symbol, line_start, line_end, route, method, channel_guess}, `oracle` {sink locations mapped to vulnerable revision, affected_routes, invariant/violation text or Liu description — **private**}, `peer_rule_applied`, `peers` list, `control_item_id`, `control_operation`, `stage_file_lists` with SHA-256 per file per stage, `stage4_prune_log`, `banned_string_scan` result, `soft_leak_report` path, `build_tool_versions`, `build_timestamp`, `item_random6` ↔ case mapping (**private; never shipped with packets**).

## IV.3 Deterministic rules Claude Code must apply

**Operation resolution (03):** Python — the function/method whose span contains the oracle's first sink line in the handler file; if the sink is outside the handler file (e.g., mlflow), the operation is the handler of `affected_routes[0]` found by route-table parsing (Flask `@app.route`/`add_url_rule`, FastAPI decorators/`add_api_route`, Django `urls.py`/`router.register`, DRF viewset action). Java — the controller method mapped to the route (`@RequestMapping` family) for InLong; the public method named in the oracle for XWiki. Record ambiguity in the manifest and stop for researcher input if >1 candidate.

**Peer selection (04):** peers = union of (i) other handlers in the same class/viewset/blueprint/router module operating on the same model or resource noun; (ii) handlers whose route shares the longest noun segment with the primary route; (iii) for Spring, other controller methods calling the same service class. Rank by (same class, same noun, same method class), cap 12, log the rule hits per peer. Mark `also_affected=true` for peers in the oracle's `affected_routes`.

**Stage 2 one-hop closure (05):** callees resolved by static name resolution within the project (imports followed one level); framework/library calls excluded by package prefix list; model/serializer/form/DTO = classes referenced in the handler whose base class matches framework ORM/serializer bases or whose name is referenced as a type annotation. Masking: replace sibling handler bodies with equal-line-count stub comments.

**Guard element discovery (05, Stage 3):** decorators/dependencies/permission classes/mixins/base views referenced by the primary op or any peer; Django `MIDDLEWARE` entries and their classes; DRF `DEFAULT_PERMISSION_CLASSES`; FastAPI router `dependencies=`; Spring `@Configuration` classes extending/implementing security config, `@PreAuthorize`/`@Secured` usages; XWiki rights-check helpers referenced by peers.

## IV.4 CSV schemas

**`cases_candidates.csv`:** `candidate_id, benchmark_source, case_id, repo_url, language, framework, vulnerable_ref, fixed_ref, primary_route, primary_symbol, oracle_sink_files, I1..I5 (bool), E1..E4 (bool), eligible (bool), exclusion_reason, notes`

**`cases_selected.csv`:** `item_id_vuln, item_id_control, candidate_id, selection_rationale, fallback_candidate_id, framework_flavor, expected_oracle_visible_stage (filled after build), build_status`

**`controls.csv`:** `item_id_control, paired_item_id_vuln, control_route, control_symbol, control_path, control_line_start, control_line_end, control_similarity, control_guard_kind, taint_check_passed (bool), taint_check_sources`

**`tainted_operations/<repo>.csv`:** `source (S-LIU|S-ABS|GHSA), identifier, affected_route_or_symbol, path, line_start, line_end, published_date`

**Annotation input (`annotations/<annotator>.csv`, one row per item×stage):** `annotator_id, item_id, presentation_order, stage, decision, confidence, evidence_pointers (JSON), required_property, enforcing_element, info_needed_next, time_seconds` — plus `annotations/<annotator>_post.csv` with the post-Stage-4 and post-reveal fields of §III.7 (JSON columns for tables).

## IV.5 Validation checks (06) — all must pass or be explicitly waived in the report

- V1. Monotonicity: file set and content of stage *n* ⊆ stage *n+1* (masked stubs in Stage 2 are the only permitted content difference, and only toward unmasking).
- V2. Banned-string scan = 0 hits per bundle.
- V3. Fix-touched content absent: no line of the fix diff's `+` side appears in any stage bundle; no file created by the fix exists.
- V4. Oracle visibility: `oracle_visible_stage` computed and ≤4 for every vulnerable item; error if 5.
- V5. Control taint check passed; control is not in the oracle's affected routes.
- V6. Stage 1 contains exactly one handler body; Stage 2 masks all sibling handlers; Stage 3 contains all listed peers; Stage 4 size within E4.
- V7. Line-number stability: every file present in stages 2–4 has identical line numbering to its first appearance (masking preserves counts).
- V8. Soft-leak report generated (occurrences of `vulnerab|exploit|IDOR|BOLA|security fix|permission bypass`) for researcher review.
- V9. Packet check: annotator packets contain no manifest, oracle, reveal folder, or case-id mapping; item ids are random; orders satisfy the ≥5 separation constraint.
- V10. Parse check: Stage 1 and Stage 2 files parse under the language's parser after masking.

## IV.6 Actions Claude Code must not perform

- Must not annotate items, pre-judge vulnerability, or produce MDC estimates; must not run LLMs as stand-in annotators.
- Must not change Stage definitions, the codebook, or the selected-case list; swaps go through `fallback_candidate_id` only with the researcher's written approval recorded in `cases_selected.csv`.
- Must not include advisory, CWE, PoC, fix content, commit messages, or benchmark identifiers in any annotator-facing artifact.
- Must not use the fixed revision for anything except building `reveal/fix.diff` and the patch-locus bundle.
- Must not select peers or controls by LLM judgment; only the logged deterministic rules; ambiguous cases stop for researcher input.
- Must not execute the applications, run PoCs against external hosts, or contact maintainers.
- Must not publish, upload, or share bundles outside the project directory.
- Must not remove soft-leak lines automatically.

## IV.7 Deliverables Claude Code returns for researcher sign-off before any annotation starts

1. `cases_candidates.csv` with eligibility for all 32 candidates and reasons.
2. `cases_selected.csv` + `controls.csv` with taint checks.
3. `analysis/validation_report.md` (V1–V10 per item, soft-leak excerpts, `oracle_visible_stage` per vulnerable item, bundle sizes, build time).
4. Two blank annotator packets and the adjudicator packet (with manifests).
5. `forms/annotation_form.md` rendering §III.7 exactly, with no hypothesis vocabulary (§III.8).
6. `08_score.py` dry-run output on synthetic annotations demonstrating the §III.10 table.

---

## Appendix — Sources verified in this review

- Liu et al., *Repairing Broken Access Control in Web Applications with LLMs: An Empirical Benchmark Study*, arXiv:2610.34290 (25 Oct 2026); repo `github.com/TianMaXingK/BAC-BENCH` (cloned; case directories counted: bookwyrm 5, inlong 4, xwiki 5, nextcloud 2, openemr 10, usememos 20).
- Duarte et al., *ABSENTIA: Detecting Broken Access Control Vulnerabilities in Web Applications*, arXiv:2610.00977 (Oct 2026); repo `github.com/avduarte333/Absentia`, `data/authz_instances.jsonl` (30 records; 18 Python inspected).
- MOCGuard (IEEE S&P 2025); Li et al., *Detecting Privilege Escalation in Polyglot Microservices via Agentic Program Analysis* (IEEE S&P 2026); SPACE (ICSE 2016); BACScan (CCS 2025) — cited via ABSENTIA's related work.
- Prior reviews in this project: architectural_antipattern_adversarial_review.md; followup_review_nonlocality_enforcement_architecture.md.
