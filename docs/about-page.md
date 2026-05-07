# Fira — about page design doc

> Working doc for the about / landing page. The chapter copy in this file is
> v1 — written before any visual design work, intended to be iterated on.
> Sister docs: [spec.md](spec.md) is the working product spec;
> [old/brief_description.md](old/brief_description.md) and
> [old/fira_design_doc.md](old/fira_design_doc.md) are the long-form vision.

---

## 1. Thesis

**Completeness without complexity, via smart design.**

Prior art forces a false choice:

- **Notion-shaped tools** — complete but cluttered. Every detail held; unusable for fast work.
- **Apple Notes-shaped tools** — simple but partial. Fast, but half the picture is missing.
- **Akiflow / Motion / Reclaim** — claim to bridge by integrating with the other apps. Now you're maintaining three.
- **Result**: the user holds the truth in their head, because no tool holds all of it.

Fira's claim: completeness AND simplicity, achieved through smart design rather than feature accumulation. One model holds plan, calendar, time spent, captured ideas, personal life, teammates' weeks — same data, multiple views. The simplicity isn't from leaving things out; it's from putting things in the right shape.

This is the academically defensible contribution and the marketing anchor. It should sit at the top of the page (hook) and be named again at the bottom (closing). The middle chapters demonstrate it without naming it.

## 2. Audience

Two readers, one page:

- **Marketing visitor** — 8 seconds to decide whether to keep scrolling. Wants the *what* (a screenshot that says everything) and a felt pain that matches their week.
- **Defense reader** — wants the *why*. The thesis, the prior-art critique, the specific design moves that resolve the tension.

The page serves both via subtext: marketing-shaped on the surface (visible copy, screenshots, animations); defense-shaped underneath (the thesis is real, the competitor critique is specific, every feature anchors a design decision). Defense substrate that doesn't fit the surface lives in the thesis paper, not on the page (see §9).

## 3. Design values

Three values anchor every design decision in Fira; they should also anchor every line on the about page.

- **Realness** — the plan and the log are the same model. Personal life and work life are on one axis. Tasks are N sessions, not atomic blocks. No separate Toggl, no separate calendar.
- **Relevance** — Now / Later / Someday / Done sections do triage by ambience. What matters bubbles up; nothing disappears.
- **Flow** — adjustment must be cheap and tactile. Drag-resize, shift-tab to promote a subtask into a task, lane-split for overlap, drop-to-delete. Fast, gestural, no friction.

Fira is optimized for **adjustment over placement**. Plans drift, scope grows, meetings land — the app's primary motion is the adjustment, not the initial plan.

## 4. Voice & tone

Editorial, declarative, slightly sardonic. Match the user's own subtitle voice:

> *"I'll do it tomorrow." — tomorrow.*
> *A task in-progress for weeks is a signal.*
> *Stop scheduling "deep work." Schedule the work.*

Confident understatement, not promotional energy. Linear's marketing voice is a useful reference point; Notion's earlier pages too. Specifically avoid:

- "Boost your productivity" / "supercharge" / "delight" / "powerful"
- "Unlock" anything
- Vague feature-marketing ("AI-powered," "intelligent," "seamless")
- Bullet lists of features without an anchor narrative

Show, don't tell. Name specific gestures (`shift-tab`), specific competitors (Notion, Akiflow), specific tags (`?`, `v1`, `auth`). Concrete beats abstract.

## 5. Page structure

Eight sections (seven chapters + CTA). Side-rail scroll-spy is the working pattern on desktop; mobile pattern is an open question (see §10).

| # | title | what it proves |
|---|-------|----------------|
| 1 | Hook | The thesis. Pain → positioning → answer. |
| 2 | A task isn't a block | The time-block thesis. One task, many sessions. |
| 3 | Capture, so you don't lose it | Capture without friction. Sections do triage. |
| 4 | See only what matters now | Cognitive overload. Filters, sections, tags. |
| 5 | Time you can actually see | Overlays. Personal + partner + team on one axis. |
| 6 | Adjust, don't redo | The primary motion. Drag, resize, shift-tab. |
| 7 | Reality talks back | Feedback loop. Plan vs done as the same data. |
| 8 | Try it | Playground CTA + closing reveal of the thesis. |

The progression is intentional: introduce the model (1-2), capture into it (3), navigate it (4), bring reality into it (5), move it (6), learn from it (7), try it (8).

## 6. Chapter copy (v1)

### 1 — Hook

**Subtitle:** *Stop holding your plan in your head.*

**H1:** Everything in one place. Without becoming everything.

Most people run their work across three apps and a memory. Tasks in Jira. Calendar in Google. Time tracking in Toggl. Personal life — wherever. Plans you make on Monday don't survive Wednesday because the tools don't talk to each other, reality doesn't talk back, and the only place the truth lives is your head.

The tools that try to fix this overcorrect. Notion holds every detail and becomes a graveyard of nested pages. Apple Notes stays fast but loses half the picture. Akiflow and Motion integrate with the other apps you're already drowning in.

Fira holds the whole picture through one model. Tasks accrue work sessions across the week as time blocks on a calendar. The inbox and the calendar are the same data, two views. Personal time and teammates' weeks overlay the same grid. The simplicity isn't from leaving things out — it's from putting things in the right shape.

*Visual: hero — inbox + calendar side by side; one task captured, dragged onto Tuesday, resized.*

---

### 2 — A task isn't a block

**Subtitle:** *One task, many sessions. Like real work.*

**H1:** The thing every other tool gets wrong.

Akiflow, Motion, Reclaim — they all schedule a task as one calendar block. Start, end, done. That's not how work happens. You write a feature across Tuesday morning, Wednesday after lunch, and an hour Friday before standup. The task is one thing; the sessions are many.

In Fira a task accrues N blocks across the week. Time spent is the sum of completed blocks. **Time left** — the gap between estimate and reality — is on every task, all the time. No separate Toggl, no mental math, no surprise on Friday when you realize you didn't track this week.

**Callout:** *Stop scheduling "deep work." Schedule the work.*

*Animation: a competitor's single 2h block fractures into four smaller blocks scattered across the week, task title persistent.*

---

### 3 — Capture, so you don't lose it

**Subtitle:** *Idea? Capture. Bug? Log. Think later.*

**H1:** The cost of friction is forgotten things.

When capture takes eight fields, ideas land in Apple Notes, Slack DMs, four different docs. They re-emerge weeks later as a gut punch.

Fira's inbox is one document per project, sectioned **Now / Later / Someday / Done**. Type and it lands. No required project, no estimate, no modal stack. Things don't disappear — they sit one section away. Triage is dragging Later → Now when Now needs more. The structure is the prioritization.

**Callout:** *"I'll do it tomorrow." — tomorrow.*

*Animation: rapid quick-adds landing in Later; one drags up to Now.*

---

### 4 — See only what matters now

**Subtitle:** *Filter the noise.*

**H1:** A productive week isn't the one with the longest list.

It's the one where you keep finding the next right thing without re-reading the whole list. Fira filters by default and on demand.

- **Sections** push noise out of sight without losing it. Later sits below Now; you don't see it until you scroll.
- **Project switcher** scopes the inbox to one project. **Person switcher** picks whose week the calendar shows.
- **Tag filters** carve scope further. Tags are bounds you invent: `?` for unsure, `v1` for committed scope, `auth` for a component. Filter by `v1` and the inbox condenses to scope-to-ship, with planned and remaining hours summed at the top.

The page in front of you is the page you need. Everything else is one click away.

**Callout:** *Out of sight isn't out of mind when it's one tab away.*

*Animation: full project → filter by `v1` → inbox condenses → "11.5h left" totals at the top.*

---

### 5 — Time you can actually see

**Subtitle:** *Plan what actually fits.*

**H1:** One axis. All of it.

You have one Friday. The boss's deadline and your kid's recital live on it together. Fira renders your personal calendar, your partner's calendar, and your teammates' weeks as overlays on the same grid. You can't drop a focus block on top of dinner because dinner is already there.

A standup is just scrubbing a date — who finished what, what's planned, what slipped. There's no separate team view to sync; the data was already shared.

**Callout:** *Meetings aren't the only thing that takes time.*

*Animation: clean work week → personal overlay fades in → partner overlay → user drags a work block around dinner.*

---

### 6 — Adjust, don't redo

**Subtitle:** *Plans drift. Adjust.*

**H1:** This is where most tools die.

A meeting lands. A task grew. A subtask turned out to be its own task. The plan was right yesterday; today it isn't. Fira makes the adjustment cheap.

- Drag a block to a different day. Resize from the edge. Drop it to delete.
- Overlapping blocks split into lanes — you see contention instead of silently double-booking.
- A subtask that escapes its scope **shift-tabs into its own task**. Work that grew gets its own row, its own estimate, its own blocks.
- Drag a task between Now / Later / Someday and the calendar follows.

Adjustment is the primary motion of the app, not a recovery move.

**Callout:** *Scope hides until the deadline shows up.*

*Animation: a meeting drops onto Wednesday → surrounding blocks slide. A subtask shift-tabs into its own row. A 1h block resizes to 2h.*

---

### 7 — Reality talks back

**Subtitle:** *Your plan needs feedback from reality.*

**H1:** Plans are hypotheses. The week is the test.

Each task shows planned, spent, and left, totaled live from its blocks. A task with five completed sessions against an estimate of two isn't a failure — it's information. A task in progress for weeks is a signal. The last 20% really is another 80%, and you'll see it accumulating before the deadline does.

For a retro or a defense, scrub the inbox by date: who finished what, where blocks landed vs. where they were planned. History isn't a separate report — it's the same data played back.

**Callout:** *A task in-progress for weeks is a signal.*

*Animation: estimate bar growing past planned line; ticked blocks accumulating; one task with many completed sessions highlighted.*

---

### 8 — Try it

**H1:** Try it as Maya.

One click drops you into a fully populated workspace. No signup, no backend, no waiting. Drag a block. Capture a task. Shift-tab a subtask. Filter by a tag.

Most tools make you pick: complete or simple. Fira holds the whole picture without making you carry it. See for yourself.

*CTA → playground mode.*

## 7. Subtitles bank

Reserve variations from the working list — useful as callouts, alt subtitles, social posts, OG tags. Use sparingly so the same line doesn't repeat across the page.

```
Make plans real.
Looks familiar. Works differently.
Stop handling everything in your head, write things down.
Idea? Capture. Bug? Log. Think later.
Plan together. Adjust together.
Plan what actually fits.
Plans drift. Adjust.
Built for how work actually happens.
"I'll do it tomorrow." — tomorrow.
A task in-progress for weeks is a signal.
Your plan needs feedback from reality.
Meetings aren't the only thing that takes time.
Stop scheduling "deep work." Schedule the work.
The last 20% is another 80%.
Scope hides until the deadline shows up.
One task, many sessions. Like real work.
```

## 8. What this page does NOT do

Discipline matters more than ambition here.

- **No "bounds" framing outside chapter 4.** It was an early experiment; it diluted when used everywhere. Tags are the one place where "a bound you invent" earns its keep, because tags genuinely are user-defined scopes.
- **No feature-list chapters.** Every chapter has one anchor (one feature, one gesture, one screenshot). The exception is chapter 6, where the multi-gesture list is the point — adjustment as a primitive motion, not one specific gesture.
- **No more than 8 sections.** Side-rail scroll-spy starts feeling like a tax past 8. Cuts available if needed: chapter 4 could fold into chapter 3 (sections-and-filters together); chapter 5 could fold into chapter 6 (overlays-as-something-to-adjust-around).
- **No SaaS-marketese.** See §4.
- **No naming "completeness without complexity" in the middle chapters.** State it once at the top, demonstrate it through 2-7, name it again at the bottom. Repetition kills the reveal.
- **No defense-paper material on the surface.** See §9.

## 9. Defense substrate (paper, not page)

These appeared in the user's notes for the page. They belong in the thesis paper, not on the marketing surface — they're meta-design philosophy that a marketing visitor won't decode in 8 seconds, but a defense reader will care about deeply.

- **Abstraction as design** — Fira reduces UI surface area the way good code reduces interface surface (the "arm vs bones / muscles / veins" frame). One unit (the time block) substitutes for what other tools split into estimates + calendar + tracking.
- **Cognitive complexity reduction as a design discipline** — feature-rich vs usable is a false dichotomy when the design enforces relevance.
- **Productivity-app market analysis** — taxonomy of competitors, mapping each to the failure mode it commits.
- **Time-block-as-unit literature review** — prior art around time-blocking, what's been tried, what hasn't.
- **Multi-tenant team-allocation theory** — many-to-many user-task allocation across overlapping projects.
- **Local-first / sync architecture justification** — see [spec.md §2](spec.md) for the implementation; the *why* (offline resilience, single source of truth, intent-shaped ops) belongs in the paper.

The about page should *not* try to argue these. It should be findable from the about page (footer link to a `/thesis` companion, maybe) but not visible on the marketing surface.

## 10. Open questions

Decisions deferred so far:

- **Mobile pattern.** Side-rail scroll-spy doesn't translate. Top progress strip? Horizontal-snap carousel? Decide before building so it's not a retrofit.
- **Animation production.** Real screencaps from the live app, hand-authored Lottie / Rive, or CSS-only? Five great animations carry the page; five mediocre ones sink it. Budget reality first, then chapter count.
- **Where does the page live.** New route in `web/src` (same SPA, share the design system) or a separate static site (more SEO/SSR-friendly, decoupled iteration)? Both have valid cases.
- **Should middle chapters thread the completeness/simplicity claim explicitly.** Currently subtext. If subtext feels too quiet during user testing, sharpen one sentence per chapter to name the through-line.
- **Cut to 6 chapters?** 8 is the upper bound. If usage data or attention budgets suggest shorter, the cut candidates are listed in §8.
- **Tone calibration.** Drier (closer to Linear) or punchier (closer to the user's own subtitle voice)? Test on a few readers before committing.

## 11. Status

- [x] Anchor / thesis
- [x] Audience definition
- [x] Voice & tone principles
- [x] Page structure (8 sections)
- [x] Chapter copy v1
- [ ] Visual design
- [ ] Animations
- [ ] Mobile layout
- [ ] Tested with readers (defense advisor + 2-3 marketing visitors)
- [ ] Implemented
