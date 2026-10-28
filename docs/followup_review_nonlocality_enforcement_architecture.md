# Follow-up Review: Diagnostic Non-Locality and Enforcement Architecture in Access-Control CVEs

**Reviewing:** "Follow-up to Adversarial Review — Revised Research Direction, Remaining Literature Questions, and Draft Introduction/Background"
**Date:** 28 October 2026
**Scope:** Only the narrower questions in §9/§14 (A–I). The broad detector/policy-inference landscape (ACMiner, Chucky, MACE, ReACP, Ote, Antaeus, Semgrep, Code2DFD, BAC-Bench) is taken as established from the first review and cited only where it answers a narrow question.

---

## 0. Headline answer

**Is there a publishable empirical gap in measuring diagnostic non-locality and enforcement architecture in real access-control vulnerabilities?**

**Yes, with two conditions.** No study measures, per vulnerability and with human annotators, the *earliest context stage* at which an access-control bug becomes decidable, and no CVE taxonomy records *where enforcement is placed* as a dimension. The closest work measures inter-procedural depth automatically in C/C++ (VulTrigger, VulEval/ReposVul), measures LLM performance under more/less repository context (Antaeus, BAC-Bench), or classifies BAC by exploit shape (BOLA taxonomy, OWASP). The conditions: (1) the study must include non-vulnerable controls so "decidable" is not "confirm what you were told"; (2) the multi-channel family should be a stratum of the sample, not the paper's claim, because it will be small-n.

**Recommendation: GO**, as a measurement/taxonomy study (MSR / ICSME / EMSE scale), with the protocol changes in §G.

---

## A. Diagnostic non-locality

### A1. Has anyone defined or measured the amount of context needed to diagnose a vulnerability?

Not in the form proposed. The nearest measurements are automatic and call-graph-based:

| Work | What it measures | Distance from the proposed study |
|---|---|---|
| **VulTrigger** — Li et al., *On the Effectiveness of Function-Level Vulnerability Detectors for Inter-Procedural Vulnerabilities* (ICSE 2024) | Whether the vulnerability-triggering statement lies outside the patched function; reports inter-procedural vulnerabilities are prevalent with ~2.8 inter-procedural layers on average; function-level detectors degrade on them | Closest *quantitative* precedent. Differences: C/C++, all CWEs, locality = call-graph distance to the triggering statement, computed automatically, no human decidability, no peers/configuration as a context type |
| **VulEval** — Wen et al. (arXiv 2404.15596; TSE 2026 as *From Function to Repository*) | Separates intra- vs inter-procedural detection; 4,196 CVEs, C/C++; shows detection improves when vulnerability-related dependencies are supplied | Benchmark design precedent for "how much context helps"; again C/C++, call-graph context only |
| **ReposVul** — Wang et al. (ICSE 2024 Companion) | 6,134 CVEs, 236 CWEs, C/C++/Java/Python; multi-granularity (line/function/file/repo) with inter-procedural call extraction | Supplies repo-level checkouts and inter-procedural annotations; no access-control-specific locality labels |
| **Antaeus** (arXiv 2607.01138, 2026) | Ablation: removing local augmentation or the repository-level bundle roughly halves recall (15→9 / 12→7 of 28 CVEs); CVE-2020-10701 detectable only with repo context | Model-side evidence that CWE-284 logic bugs are non-local; not a human measurement; C/C++ |
| **BAC-Bench** (arXiv 2610.34290, 2026) | Single-turn LLM restricted to patched files repairs 30–38%; repository navigation lifts best model to 75%; failures attributed to missing non-local context (sibling modules, field contracts) | Repair, not diagnosis; but it is the only access-control-specific context-dependence measurement for web apps |
| **Semgrep IDOR study** (2025, industrial) | Difficulty ladder: (1) no authorization at all; (2) protections in a single function/file; (3) custom RBAC spread across files and layers; (4) ownership logic hidden in ORM models | Informal, practitioner-defined stages that almost coincide with the proposed disclosure levels; no counts per level, no κ |
| **Braz, Çalikli, Bacchelli et al.** — *Why Don't Developers Detect Improper Input Validation* (ICSE 2021); *Less is More* (ICSE 2022) | Online experiments (150 participants) on whether developers spot a vulnerability in a change; security priming ×8 detection probability | Human-experiment methodology precedent; context amount was not the manipulated variable |
| **Program-slicing inspection experiment** (EMSE/PMC 2025; n=236 students, Tomcat) | Whether *reducing* inspected lines helps reviewers find vulnerable lines | Opposite direction (less context), but the "identify the vulnerable lines" success criterion is reusable |

**Conclusion A1:** no prior work defines a per-vulnerability *minimum diagnostic context* with human annotators, and none does so for access control or with peers/configuration as a context category.

### A2. Has staged disclosure been used (function → file → component/config → repository)?

No published security study uses incremental disclosure as the measurement instrument. Program-comprehension and code-review research uses think-aloud and eye-tracking with a fixed artifact. VulEval's three tasks (function → dependency retrieval → repository) are the closest machine analogue.

### A3. Studies of detection performance vs. amount of repository context?

Yes, for models: VulEval, Antaeus (ablations), BAC-Bench (file-restricted vs. navigation), Yildiz et al. (ACL 2025, repository-level benchmarking of LLM agents), Li et al. 2025 (*Everything You Wanted to Know About LLM-based Vulnerability Detection*, context effects). None for humans; none for access control except BAC-Bench (repair).

### A4. Better terminology than "diagnostic non-locality"?

The established neighbour is **inter-procedural vulnerability** (VulTrigger, ReposVul, VulEval), but it means "spans a call edge," which is narrower than what you need (peers and configuration are not callees). Options:

- **Minimum diagnostic context (MDC)** — the smallest disclosure stage at which the vulnerability is decidable. Operational, measurable, neutral. *Recommended as the measured variable.*
- **Diagnostic locality / non-locality** — fine as the property name; define it once via MDC.
- Avoid "architectural" for this property entirely.

---

## B. Enforcement architecture

### B5. Existing taxonomy for placement of authn/authz enforcement?

Several, none designed for vulnerability annotation:

| Source | Categories | Usable? |
|---|---|---|
| **XACML / IETF policy framework** (OASIS 2013; RFC 2753/3198) | PEP, PDP, PAP, PIP; the *reference* vocabulary | Yes — name every enforcement location as a PEP; "central vs. per-handler" becomes "one PEP governing many operations vs. one PEP per operation" |
| **Barabanov & Makrushin**, *Authentication and authorization in microservice-based systems: survey of architecture patterns* (arXiv 2009.02114, 2020) | Edge-level (gateway) authorization; centralized pattern with single PDP; decentralized pattern (per-service PDP); hybrid; explicitly warns against single-point-of-decision and recommends defense in depth | Yes — reuse the pattern names for service-level architectures |
| **SBC/WGRS "Authorization Patterns for Microservices Applications"** | Edge-level, centralized service-level, decentralized service-level; notes decentralized → inconsistent enforcement, centralized → bottleneck | Supporting |
| **Ponce et al.**, *Smells and Refactorings for Microservices Security: A Multivocal Literature Review* (JSS 2022; arXiv 2104.13303) | Lists **"Centralized Authorization" as a security smell** (edge-only authorization with no service-level checks), refactoring = decentralize | Critical: direct published support for "do not assume central is safer" |
| **BAC-Bench Position dimension** | Presentation / Control / Business / Data / Cross-cutting authorization layer, plus "centralized chokepoint" flag | Yes — reuse the five layers for *patch locus*; it is already validated with κ=0.955 against human raters |
| **Santos/Mirakhorli security tactics** | "Authorize Actors", "Authenticate Actors" tactics; CAWE root-cause subtypes | Use as the tactic-level frame |
| **Industry pattern writing** (Richardson microservices.io; Cisco; Cerbos; Gravitee) | gateway / sidecar / embedded-library / centralized-PDP enforcement models | Informal; cite as evidence the vocabulary is practitioner-current |

### B6. Has prior work categorized applications or vulnerabilities as central / per-handler / config-driven / mixed / distributed / multi-channel?

Applications: yes, at the microservice-architecture level (B5). Vulnerabilities: **no** — no CVE study records enforcement placement per vulnerability. BAC-Bench records where the *patch* went, which is the nearest.

### B7. Is "enforcement architecture" established terminology?

Not as a term of art. "Authorization architecture," "access-control architecture," and "policy enforcement architecture" appear in the microservice-security literature and NIST ABAC (SP 800-162) context. "Enforcement architecture" is immediately understandable to both communities and does not collide with anything. Keep it, define it once as *the set and placement of PEPs relative to the operations they govern*.

### B8. Is "enforcement-architecture weakness" acceptable?

Acceptable only as a *conditional* label applied after causal evidence (your §2 already says this). Do not use it as a paper-title term; reviewers will read "weakness" as a CWE/CAWE claim. For the measurement paper, use "enforcement architecture" as a descriptive dimension and report associations, not weaknesses.

**Recommended dimension values (merge yours with B5):**
- *Gateway/edge PEP* (reverse proxy, API gateway, framework middleware applied globally)
- *Framework-config PEP* (Spring Security matchers, Django `urls.py`-level wrappers, FastAPI router-level dependencies)
- *Class/controller-level PEP* (class decorator, mixin, `@PreAuthorize` on class, base-view)
- *Per-operation PEP* (handler decorator / in-body check / per-route dependency)
- *Data-layer PEP* (ORM scoping, query filters, row-level policy)
- *Mixed* (record which combination)
- *Multi-channel* is **not** an enforcement-architecture value; record it on the Channel dimension and let "channel-inconsistent" emerge as a mechanism.

---

## C. Real-CVE taxonomies

### C9. Studies classifying real access-control CVEs by failure mechanism

- **BOLA taxonomy** (arXiv 2605.25865, 2026): six families from 107 HackerOne reports; dimensions = family, action type, authorization direction, sector, identifier format, exploit mechanism. Report-level, no code.
- **Zhong, *A Survey of Prevent and Detect Access Control Vulnerabilities*** (arXiv 2304.10600): vertical / horizontal / context-dependent; root cause = code-logic error vs. misconfiguration; "unprotected endpoints" as a case.
- **Santos et al., tactical vulnerabilities** (ICSA 2017 / journal): CWE-284/862/269 root-cause subtypes under "Authorize Actors" (e.g., missing check before operation; incorrect authorization of external APIs/plugins; not revoking access).
- **BAC-Bench** repair framework (Position / Coverage / Mechanism / Content) applied to official patches; BACFuzz's preliminary CVE characterization (PHP, 2022–2025).
- **OWASP API Top 10**: BOLA / BFLA / BOPLA granularity.
- **Inigo GraphQL CVE analysis** (industry, 2023): 45 GraphQL CVEs, 54.8% authorization bypass; HackerOne Hacktivity 87%.

### C10. Do any include enforcement location as a dimension?

Only BAC-Bench (patch Position) and Zhong's code-vs-config split. None records pre-fix enforcement placement or peer structure.

### C11. Does an existing taxonomy cover the proposed mechanism labels?

Partially:
- "authentication/authorization missing on one path" ≈ CWE-306/862, Santos "missing check before operation", BOLA "absent check" family.
- "wrong resource/subject checked" ≈ CWE-863/639, BOLA "ownership metadata trusted from client".
- "ownership/tenant check missing" ≈ BOLA horizontal families.
- "alternate channel bypasses enforcement" ≈ CWE-288 — **no taxonomy instance found**.
- "direct path bypasses policy layer" ≈ CWE-288/CWE-425 (direct request / forced browsing) — rarely used label.
- "policy applies at wrong scope" — no existing label (closest: Spring/Django misconfig writeups).

### C12. Would the taxonomy add information beyond CWE/BOLA/IDOR taxonomies?

Yes, **only if** each case carries the joint triple (MDC stage × enforcement placement × mechanism). Mechanism alone re-derives CWE; placement alone re-derives microservice pattern surveys; MDC alone re-derives VulTrigger for a new domain. The joint distribution — e.g., "per-operation PEP + one path missing" vs. "framework-config PEP + wrong scope" and how decidable each is — is the new information. State this explicitly as the contribution.

---

## D. Multi-channel enforcement

### D13. Research on authn/authz inconsistency across channels

**No peer-reviewed systematic study found** for HTTP vs WebSocket, REST vs GraphQL, REST vs RPC, API vs CLI, or sync vs async entry points. Evidence base is practitioner-grade:
- Egorov, *What's Wrong with WebSocket APIs?* (DeepSec 2019): auth usually only at handshake, not per-message; authz bypass and IDOR cases from bug bounties.
- WebSocket security reviews (iTDAF 2024) focus on CSWSH/XSS/MITM, not cross-channel policy inconsistency.
- GraphQL: Inigo/Help Net Security CVE analysis (45 CVEs, majority authz bypass); BrightSec/Feeld case study describing per-resolver authorization inconsistency and REST-proxy bypass.
- Microservice vulnerability literature review (arXiv 2408.03960) lists "unenforced access controls" and "access grant misconfigurations" but not channel inconsistency.

### D14. Is alternate-channel bypass a named recurring category?

Named (CWE-288 *Authentication Bypass Using an Alternate Path or Channel*; CWE-425 *Direct Request*), but **not empirically established as recurring in code-level studies**. Nobody has counted it.

### D15. Datasets or CVE studies covering these cases?

None dedicated. Candidates must be mined: NVD/GHSA keyword search ("websocket" + "authentication"/"authorization"; "graphql" + "permission"; "rpc"/"grpc" + "unauthenticated"; "management command"/"CLI" + "privilege"), plus GraphQL CVE lists (Inigo).

### D16. Which CWE labels are used in practice?

Expect CWE-306, CWE-287, CWE-862, CWE-284 far more often than CWE-288; CWE-288 is applied inconsistently by CNAs. Sampling by CWE-288 alone will undercount; sample by keyword and then label channel yourself.

**Assessment:** a *defensible open subproblem*, but small-n in any 60–80-case sample (expect 5–15 cases). Treat it as a stratum with an oversampling rule (e.g., ensure ≥10 multi-channel candidates), report it descriptively, and do not make it the paper's central claim unless the count surprises you.

---

## E. Expected-policy inference

### E17. Systems that infer what an operation *should* require (not just the implemented policy)

| System | Inference mechanism | Explicit policy? |
|---|---|---|
| ACMiner (2019) | Association rules over authorization checks per entry point within a service; outliers = candidates | no |
| Sun et al. 2011; MACE 2014; RoleCast 2011 | Role / security-sensitive-operation inference from code; privilege-escalation detection by comparing paths | no |
| Chucky 2013; Crix/PeX 2019 | Missing checks via comparison with structurally similar functions | no |
| Antaeus (2026) | LLM derives sinks + required safety conditions from local + repo context; comparative validation vs. similar sinks | no |
| Semgrep agentic IDOR (2025) | Frontier LLM reasons about whether an ID-taking endpoint should check ownership | no |
| BAC-Bench (2026) | LLMs reconstruct intended policy from sibling modules and context for *repair*; Content errors remain the dominant failure (18–31%) | no |
| DePLOI / IBAC-DB (2024) | Synthesizes/audits DB access-control from intent abstractions | yes (intent given) |
| ReACP, Ote | Extract implemented policy | no, but expected policy not inferred |

### E18. How do they establish ground truth?

- ACMiner/Crix/PeX: manual confirmation of flagged inconsistencies + developer reports (28 vulns for ACMiner).
- Antaeus/BAC-Bench: known CVEs with patches; a finding counts only if it explains the CVE.
- Semgrep: manual triage of agent findings (15 TP / 93 FP).
- None has negative ground truth for "intentionally public" at scale.

### E19. How do they distinguish intentionally public endpoints?

By majority behaviour of peers (ACMiner, Chucky, Antaeus's comparative validation) or by manual triage. No system models "public by design" explicitly. This is a real gap and the main false-positive source (Semgrep's 78%).

### E20. Do they rely mainly on route names and identifiers?

Antaeus's prioritizer admits to keyword heuristics and name/callee signals; its full pipeline uses structure as well. LLM-agent approaches are unmeasured on this point. Nobody has isolated the lexical contribution for access control.

### E21. Obfuscation / masking studies

General vulnerability detection only:
- *A Systematic Study of Code Obfuscation Against LLM-based Vulnerability Detection* (arXiv 2512.16538): identifier renaming and other transformations shift accuracy; some transformations paradoxically help.
- *When Names Disappear* (arXiv 2510.03178): α-renaming framework to separate name vs. structure channels; releases ClassEval-Obf.
- Hinrichs, Diercks, Scandariato, *Impact of identifier normalization on vulnerability detection techniques* (2025): SAST vs ML vs LLM under normalized identifiers on BigVul.
- Gülay & Yılmaz (EuroS&PW 2025): identifier renaming had minimal impact vs. control-flow obfuscation (GPT-4o-mini).
- Semantics-preserving evasion papers (arXiv 2602.00305).

**None masks route paths, handler names or resource nouns for access-control inference.** A route/identifier-masking ablation would be new.

### E22. Is peer comparison sufficient without an LLM?

Sufficient when (a) ≥3 peers exist, (b) enforcement is expressed in code or resolvable config, and (c) peer grouping is syntactic (same URL prefix, same controller). It is insufficient for (i) grouping semantically equivalent operations across controllers/channels, (ii) singleton operations with no peers, (iii) deciding "public by design." Those three are the only scientifically justified LLM roles; the empirical study should record how many cases fall into each so the later AI decision is evidence-based.

---

## F. Dataset reuse

| Dataset | Access-control cases (expected) | Repo | Vuln. revision | Fix commit | Framework | Vulnerable operation | PoC/tests | AC label | Notes |
|---|---|---|---|---|---|---|---|---|---|
| **BAC-Bench** (2026) | 46 total: BookWyrm (Django, Python) and Apache InLong + XWiki (Java) are in your scope — likely **15–25 in-scope**; OpenEMR/Nextcloud (PHP), Usememos (Go) out of scope | yes | yes (Docker) | yes | 6 apps | yes (PoC text) | yes | yes | Highest quality; but only 6 projects → recurrence claims need other sources |
| **ReposVul** (2024) | 6,134 CVEs across C/C++/Java/Python; Java and Python splits available; CWE-284/862/863/306 share unknown but plausibly **100–300** in Java+Python before framework filtering, perhaps **30–60** in Django/Flask/FastAPI/Spring | yes | yes | yes | no (derive) | function-level | no | CWE only | Must filter by framework by inspecting `requirements.txt`/`pom.xml`; expect ~40% loss to unbuildable/tangled cases |
| **VulEval** | C/C++ only | – | – | – | – | – | – | – | Not usable |
| **BACFuzz** CVE list (2025) | PHP only | – | – | – | – | – | – | – | Out of scope |
| **BOLA HackerOne taxonomy** (2026) | 107 reports, mostly closed-source targets | mostly no | no | no | no | described | no | yes | Useful for mechanism codebook, not for code annotation |
| **Vul4J** | 79 Java vulns, 51 projects; few access-control | yes | yes | yes | partial | yes | tests | CWE | Maybe 3–6 cases |
| **CVE-Bench** (2025, web app exploit benchmark) | 40 critical web CVEs, several auth/authz | yes | yes (Docker) | yes | mixed | yes | exploit | partial | Maybe 5–10 in scope |
| **NVD + GHSA keyword mining** (BAC-Bench's recipe) | Unbounded; GHSA "pypi"/"maven" ecosystems with fix commits | yes | derive | yes | derive | derive | no | CWE + text | Needed to reach framework diversity and the multi-channel stratum |
| **Antaeus 28 CVEs** | C/C++ | – | – | – | – | – | – | – | Not usable |

### F26. Most efficient path to ≥60 usable cases

1. Take all in-scope BAC-Bench cases (~20) — ready-made PoCs make them ideal pilot and calibration material.
2. Filter ReposVul Java+Python by CWE-284/285/287/288/306/639/862/863 and by framework markers → expect 30–60 candidates, ~25–35 survivors.
3. GHSA/NVD keyword mining (your §5 term list + "websocket", "graphql", "management command", "rpc") restricted to pypi/maven ecosystems with a linked commit → fill to 100–150 candidates, oversampling multi-channel and Flask/FastAPI (under-represented elsewhere).
4. Add CVE-Bench and Vul4J stragglers.

Realistic yield: 60–80 usable cases from ~140 candidates without building a new collection pipeline. Do **not** draw more than ~25% of the sample from any single project (BAC-Bench concentration risk).

---

## G. Evaluation of the staged-disclosure experiment

### Problems with the current design

1. **No negative controls.** With only known-vulnerable cases, "vulnerable: yes" is always right; annotators will converge on "yes" early and MDC will be underestimated. Every case needs a matched control: the same handler from the *fixed* revision, and/or a protected sibling handler, shown under the same staging, randomized and unlabeled. Measure MDC as the earliest stage with a correct *discriminating* decision (vulnerable vs. control).
2. **Leakage.** Annotators must be blinded to CVE ID, advisory text, fix diff, commit message, test names, and any security-fix comments. Strip or neutralize these in the shown artifacts; keep ordinary comments (they are legitimate context). Prefer annotators who have not worked on the project; record prior familiarity.
3. **Stage definitions need operational rules:**
   - *Stage 1 — Handler:* the function body plus its signature, decorators attached in the same source span, and direct-callee *signatures* (not bodies). Decorators are part of the handler; hiding them would be artificial.
   - *Stage 2 — File:* full containing file, plus imports resolved to names only.
   - *Stage 3 — Peers + guards + config:* all handlers in the same router/controller/blueprint and all handlers matching the same resource noun elsewhere; middleware/dependency/decorator definitions; framework security config (`settings.py` middleware list, `urls.py`, Spring Security config classes, FastAPI router dependencies); class hierarchy of class-based views.
   - *Stage 4 — Repository:* unrestricted, time-capped.
   Pre-generate each stage's bundle per case so both annotators see identical material.
4. **Vulnerable-only vs vulnerable+fixed.** Show vulnerable revision only during staging; reveal the fix only after Stage 4 labelling, then record patch locus and whether the fix changed the annotator's mechanism label (disagreement here is itself a finding about fix-vs-root-cause).
5. **Decision fields per stage:** decision (vulnerable / not / unsure), confidence (1–5), evidence pointer (file:line), *what information they would need next* (free text — this is cheap and tells you which stage boundaries are wrong).
6. **Annotators:** two security-literate annotators per case is the minimum; use three on a 20% calibration subset. Record time per stage (cap 15 min at Stage 4).
7. **Agreement metrics:** Cohen's κ for binary/nominal fields with two raters; Krippendorff's α if a third rater or missing cells; weighted κ for the ordinal MDC stage; report percent agreement alongside. Target κ ≥ 0.6 on mechanism and MDC; recalibrate after a 10-case pilot.
8. **Sample size.** With n=60, a 30% proportion has a 95% CI of roughly ±11.5 pp, so 15% and 30% are barely distinguishable. Prefer **n=80 vulnerable + 80 controls**; keep 60 as the floor. Power the mechanism-recurrence claim by requiring ≥8 instances in ≥3 projects and ≥2 frameworks.
9. **Thresholds.** Keep ≥30% (continue) / <15% (kill) for "MDC ≥ Stage 3," but compute them on controls-adjusted decisions. Add: control false-positive rate at Stage 1 must be reported; if annotators flag >30% of controls as vulnerable at Stage 1, the task is under-specified.
10. **Name-shortcut check (cheap).** For a 20-case subset, run Stage 1–3 a second time with route paths and handler/resource identifiers α-renamed (preserving structure, decorators, and config). The drop in Stage-1/2 decidability is your first evidence on the lexical-shortcut question (E20/E21) and costs no model.

### Revised protocol (compact)

- **Units:** 80 (CVE, vulnerable operation) + 80 matched controls; stratified by framework; ≥10 multi-channel candidates.
- **Blinding:** no CVE/advisory/fix/commit text; neutralized security comments; project-unfamiliar annotators.
- **Stages:** as operationalized above, bundles pre-generated.
- **Per-stage fields:** decision, confidence, evidence pointer, information needed next, time.
- **Post-Stage-4 fields:** mechanism; enforcement architecture (B8 values); channel; peer count and whether peers are consistently protected; "public by design" plausibility; patch locus (BAC-Bench five layers + centralized flag) after fix reveal; architectural-cause judgment + evidence.
- **Reliability:** κ / weighted κ / α as above; pilot 10; calibration 20%.
- **Outputs:** MDC distribution (vulnerable vs control); joint table MDC × placement × mechanism; recurrence table by project/framework; renamed-subset delta; codebook; released corpus.

---

## H. Review of the draft Introduction and Background

### Issues found
- "Previous research has already developed techniques for finding missing authorization checks, learning access-control policies, and comparing similar program paths" — accurate; add one sentence that those techniques presuppose the non-local evidence is available, which is exactly what has not been measured.
- "If a meaningful fraction … this would provide evidence that function-level vulnerability analysis misses an important class" — slight overclaim: function-level *tools* missing them is already shown for C/C++ (VulTrigger). Rephrase to "for access-control vulnerabilities in web applications."
- "We call this property diagnostic non-locality" — fine, but define via MDC and relate to "inter-procedural" so reviewers map it.
- Background §12.4 lists "Multi-channel" as an enforcement architecture; it is a channel property (B8).
- Background §12.3 complete-mediation example is good; cite Saltzer–Schroeder once.
- No mention of controls; the Introduction should foreshadow that decidability is measured against non-vulnerable counterparts, otherwise reviewers will raise it immediately.
- Jargon check: "PEP", "mediation", "handler" need one-line definitions on first use; otherwise the text is readable by a non-specialist.

### Revised Introduction (plain, no new novelty claims)

Many software vulnerabilities can be recognized from a small piece of code. An SQL query assembled from user input, or a call that executes untrusted text, is visible inside one function.

Access-control vulnerabilities are often different. A request handler can look reasonable on its own. The problem appears only in relation to other parts of the application: similar operations require a login while this one does not; most operations on a resource check who owns it while one path does not; HTTP requests pass through an authentication layer while a WebSocket path reaches the same functionality without it. In these cases there is no suspicious line of code. There is a mismatch between related parts of the application.

Researchers have built tools that look for exactly such mismatches: detectors for missing authorization checks, techniques that recover the access-control policy an application implements, and methods that compare similar code paths and flag the odd one out. These tools assume that the evidence lives outside the vulnerable function and that it can be found. What has not been measured, for access-control vulnerabilities in real web applications, is how often that assumption holds: how much of the application a reviewer must see before the vulnerability can be recognized at all, and how the application's security checks were organized when it happened.

This study measures that. We take real access-control vulnerabilities from Python and Java web applications and show them to reviewers in stages: first the affected handler, then its file, then related operations together with the application's security configuration, and finally the wider repository. For each vulnerability we record the earliest stage at which a reviewer can tell it apart from a non-vulnerable counterpart. We then record how enforcement was organized — whether checks sat in a shared gateway or middleware, in framework configuration, on a controller class, inside each handler, or in the data layer — and what kind of failure occurred.

The aim is not to show that one way of organizing checks is correct. Repeated or distributed checks are often deliberate. The aim is to report which arrangements appear in real vulnerabilities, which failures occur within them, and how much context their diagnosis requires. The annotated cases are released so that later work on repository-aware analysis can be evaluated against them.

### Revised Background (plain)

**Authentication and authorization.** Authentication answers "who is making this request?"; authorization answers "is this requester allowed to do this?". Web frameworks let developers place these checks in many locations: a reverse proxy or API gateway in front of the application; middleware that runs for every request; framework configuration that maps URL patterns to required roles; annotations or decorators on a controller class or on an individual handler; dependencies injected per route; or filters applied to database queries. In access-control terminology each such location is a *policy enforcement point*. An application may rely on one shared enforcement point or on many. Several enforcement points are not a defect in themselves; what matters is whether every path to a sensitive operation passes through one that applies the right rule.

**Local and non-local problems.** Some vulnerabilities are visible inside one function — an unsafe query string, for instance. Others depend on relationships between parts of the application. If endpoints A and B check authorization before calling a service and endpoint C calls the same service without a check, C may contain nothing suspicious on its own; the problem is visible only by comparison. We call the amount of surrounding material a reviewer needs before such a problem becomes recognizable the *minimum diagnostic context*, and we say a vulnerability is *diagnostically non-local* when that context extends beyond the affected function. The related notion of an *inter-procedural vulnerability* describes one whose cause spans a function call; non-locality is broader, because the needed context may be a sibling endpoint or a configuration file rather than a callee.

**Complete mediation.** A long-standing design principle says that every access to a protected resource should be checked. A system violates it when one path — a second protocol, a direct call to a backend, an administrative command — reaches protected functionality without the check applied on other paths. The application then has authentication or authorization, but not consistently.

**Enforcement architecture.** We use this term for the set of enforcement points in an application and how they relate to the operations they protect. In the study we distinguish enforcement at the gateway or global middleware, in framework configuration, at the controller or class level, per operation, at the data layer, and combinations of these. Separately we record the *channel* through which the vulnerable operation was reached (HTTP route, WebSocket, GraphQL, RPC, command line, message handler), because the same functionality is often exposed through more than one.

**Peer operations.** Applications usually expose related operations on the same resource — read, update, delete a document. When most of them enforce a rule and one does not, the difference may be a vulnerability, but it may also be intentional: some operations are public by design. Deciding which requires knowing what the operation does, what it touches, who is meant to perform it, and how comparable operations are protected. This study records those facts for each case; it does not attempt to automate the judgment.

---

## I. Final decision

### I1. Focused literature synthesis
Context dependence of vulnerabilities has been measured automatically (call-graph depth, C/C++) and for models (ablations, repair benchmarks), never with humans and never for access control in web frameworks with peers/configuration as context. Enforcement placement has taxonomies at the architecture-pattern level and at the patch level, never as a per-vulnerability annotation. Mechanism taxonomies exist at exploit level (BOLA, OWASP) and tactic level (CAWE). Multi-channel inconsistency is named in CWE and discussed by practitioners but uncounted. Expected-policy inference exists (peer-majority and LLM) with no negative ground truth and no lexical-shortcut analysis for access control.

### I2. Answers to Questions 1–26 — see sections A–F above (Q1–4: A; Q5–8: B; Q9–12: C; Q13–16: D; Q17–22: E; Q23–26: F).

### I3. Recommended terminology
- Measured variable: **minimum diagnostic context (MDC)**; property: **diagnostic (non-)locality**; relate to *inter-procedural*.
- Dimension: **enforcement architecture** = placement of **policy enforcement points** (XACML vocabulary); values per B8.
- Avoid "architectural anti-pattern" and "enforcement-architecture weakness" in the measurement paper; reserve the latter for a causal follow-up.
- Channel is its own dimension; "multi-channel" is not an architecture value.

### I4. Closest prior work to MDC measurement
VulTrigger (ICSE 2024) > VulEval/ReposVul > Antaeus ablations > BAC-Bench context conditions > Semgrep's IDOR difficulty ladder > Braz et al. human experiments.

### I5. Closest prior work to enforcement-architecture taxonomy
Barabanov & Makrushin 2020 and the SBC authorization-pattern paper (edge / centralized / decentralized); Ponce et al. 2022 ("Centralized Authorization" as a smell); BAC-Bench Position layers; XACML PEP/PDP.

### I6. Multi-channel gap
Real and unoccupied academically; evidence is practitioner-only; CWE-288 under-used. Keep as an oversampled stratum, report descriptively, claim only what the count supports.

### I7. Dataset recommendation
BAC-Bench in-scope cases (~20) + ReposVul Java/Python filtered (~25–35) + GHSA/NVD keyword mining (~20–30) + CVE-Bench/Vul4J stragglers → 60–80 usable from ~140 candidates; cap any single project at 25%.

### I8. Revised staged-disclosure protocol — §G.

### I9. Revised Introduction — §H.

### I10. Revised Background — §H.

### I11. Final RQ1 and RQ2
- **RQ1 (locality).** For real access-control vulnerabilities in Python and Java web applications, what is the minimum diagnostic context — handler, file, peers and configuration, or repository — at which reviewers can distinguish the vulnerable operation from a non-vulnerable counterpart, and how does this change when route and identifier names are masked?
- **RQ2 (enforcement architecture and mechanism).** How was policy enforcement placed in the applications where these vulnerabilities occurred, which failure mechanisms recur across projects and frameworks, and how do placement, mechanism and minimum diagnostic context co-occur?

### I12. Go / Reframe / Stop
**GO** — as a measurement and taxonomy study, with: negative controls, blinding, operationalized stages, n≈80+80, the renamed-subset check, channel as a separate dimension, and multi-channel as a stratum. Do not add a detector RQ. Venue target: MSR / ICSME / SANER / EMSE; ICSA if the enforcement-architecture framing dominates.

---

## Appendix — Sources consulted in this pass

- Li et al., *On the Effectiveness of Function-Level Vulnerability Detectors for Inter-Procedural Vulnerabilities* (VulTrigger), ICSE 2024
- Wen et al., *VulEval: Towards Repository-Level Evaluation of Software Vulnerability Detection*, arXiv:2404.15596; *From Function to Repository*, TSE 2026. https://arxiv.org/abs/2404.15596
- Wang et al., *ReposVul: A Repository-Level High-Quality Vulnerability Dataset*, ICSE 2024 Companion. https://github.com/Eshe0922/ReposVul
- Armillotta et al., *Antaeus*, arXiv:2607.01138 (2026)
- Liu et al., *Repairing Broken Access Control in Web Applications with LLMs* (BAC-Bench), arXiv:2610.34290 (2026)
- Semgrep, *Can LLMs Detect IDORs?* (2025). https://semgrep.dev/blog/2025/can-llms-detect-idors-understanding-the-boundaries-of-ai-reasoning/
- Braz, Çalikli, Bacchelli et al., *Less is More: Supporting Developers in Vulnerability Detection during Code Review*, ICSE 2022, arXiv:2202.04586; *Why Don't Developers Detect Improper Input Validation?*, ICSE 2021
- *On the effects of program slicing for vulnerability detection during code inspection*, EMSE 2025 (PMC11972194)
- Barabanov & Makrushin, *Authentication and authorization in microservice-based systems: survey of architecture patterns*, arXiv:2009.02114
- *Authorization Patterns for Microservices Applications*, SBC WGRS (sol.sbc.org.br)
- Ponce et al., *Smells and Refactorings for Microservices Security: A Multivocal Literature Review*, JSS 2022, arXiv:2104.13303
- *Distributed Authorization in IoT and Edge Cybersecurity: A Standards-Informed Analytical Framework and Taxonomy* (2026, PMC13709304) — PDP/PEP placement vocabulary
- Santos et al., *An Empirical Study of Tactical Vulnerabilities*; CAWE (ICSAW 2017)
- *Broken Object Level Authorization in the Wild*, arXiv:2605.25865 (2026)
- Zhong, *A Survey of Prevent and Detect Access Control Vulnerabilities*, arXiv:2304.10600
- *Microservice Vulnerability Analysis: A Literature Review with Empirical Insights*, arXiv:2408.03960
- Egorov, *What's Wrong with WebSocket APIs?*, DeepSec 2019
- Inigo / Help Net Security GraphQL CVE analysis (2023); BrightSec GraphQL security; Feeld case study (STEELCON 2025)
- *A Systematic Study of Code Obfuscation Against LLM-based Vulnerability Detection*, arXiv:2512.16538
- Le et al., *When Names Disappear: Revealing What LLMs Actually Understand About Code*, arXiv:2510.03178
- Hinrichs, Diercks, Scandariato, *Impact of identifier normalization on vulnerability detection techniques*, 2025 (TUHH)
- Gülay & Yılmaz, *Mitigating information leakage in LLMs: evaluating the impact of code obfuscation on vulnerability detection*, EuroS&PW 2025
- *Semantics-/Syntax-Preserving Evasion of LLM Vulnerability Detectors*, arXiv:2602.00305
- *Vulnerability Detection with Interprocedural Context in Multiple Languages* (ReposVul-based), arXiv:2604.08417
- OASIS XACML 3.0 (2013); NIST SP 800-162 (ABAC); Saltzer & Schroeder (1975) complete mediation
- Datasets referenced from prior knowledge (counts to verify): Vul4J (79 Java vulns, 51 projects); CVE-Bench (40 web CVEs)
