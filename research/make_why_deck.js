const pptxgen = require("pptxgenjs");

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.3 x 7.5

// Palette — diagnostic / forensic, not generic blue
const SLATE = "2B2D42";
const PAPER = "EDF2F4";
const MUTED = "8D99AE";
const ALERT = "D62828";
const WHITE = "FFFFFF";
const INK = "1A1B26";

const H_FONT = "Cambria";
const B_FONT = "Calibri";

// ---------------------------------------------------------------
// SLIDE 1 — the design space
// ---------------------------------------------------------------
const s1 = pres.addSlide();
s1.background = { color: WHITE };

s1.addText("Why This Method, Not the Alternatives", {
  x: 0.6, y: 0.42, w: 12.1, h: 0.7,
  fontFace: H_FONT, fontSize: 36, bold: true, color: SLATE, margin: 0,
});
s1.addText("Four ways to answer: is my guardrail policy actually any good?", {
  x: 0.6, y: 1.12, w: 12.1, h: 0.35,
  fontFace: B_FONT, fontSize: 15, color: MUTED, italic: true, margin: 0,
});

const options = [
  {
    n: "A",
    title: "Runtime attack corpus",
    what: "Fire attacks, measure defence rate",
    verdict: "REJECTED",
    why: "A 100% defence rate cannot distinguish eight working layers from two.",
    chosen: false,
  },
  {
    n: "B",
    title: "LLM-as-judge on the policy",
    what: "Ask a model to review the rules",
    verdict: "REJECTED",
    why: "Non-deterministic and unauditable — the exact property policy-as-code exists to escape.",
    chosen: false,
  },
  {
    n: "C",
    title: "Formal verification (SMT)",
    what: "Prove reachability over modelled semantics",
    verdict: "DEFERRED",
    why: "Sound, but a research programme in itself. Named as future work, not a competitor.",
    chosen: false,
  },
  {
    n: "D",
    title: "Static + dynamic lint",
    what: "Analyse the artefacts already on disk",
    verdict: "ADOPTED",
    why: "Detects what runtime cannot, at zero marginal cost.",
    chosen: true,
  },
];

let y = 1.72;
options.forEach((opt) => {
  const rowH = 1.26;

  if (opt.chosen) {
    s1.addShape(pres.ShapeType.roundRect, {
      x: 0.55, y: y - 0.1, w: 12.2, h: rowH,
      fill: { color: PAPER }, line: { color: ALERT, width: 1.75 },
      rectRadius: 0.08,
    });
  }

  s1.addShape(pres.ShapeType.ellipse, {
    x: 0.78, y: y + 0.14, w: 0.62, h: 0.62,
    fill: { color: opt.chosen ? ALERT : SLATE }, line: { color: opt.chosen ? ALERT : SLATE, width: 1 },
  });
  s1.addText(opt.n, {
    x: 0.78, y: y + 0.14, w: 0.62, h: 0.62,
    fontFace: H_FONT, fontSize: 20, bold: true, color: WHITE,
    align: "center", valign: "middle", margin: 0,
  });

  s1.addText(opt.title, {
    x: 1.62, y: y + 0.1, w: 4.0, h: 0.34,
    fontFace: H_FONT, fontSize: 18, bold: true, color: opt.chosen ? ALERT : SLATE, margin: 0,
  });
  s1.addText(opt.what, {
    x: 1.62, y: y + 0.46, w: 4.0, h: 0.32,
    fontFace: B_FONT, fontSize: 13, color: MUTED, margin: 0,
  });

  s1.addText(opt.verdict, {
    x: 5.75, y: y + 0.2, w: 1.3, h: 0.4,
    fontFace: B_FONT, fontSize: 12, bold: true,
    color: opt.chosen ? ALERT : MUTED,
    align: "center", valign: "middle", charSpacing: 1.2, margin: 0,
  });

  s1.addText(opt.why, {
    x: 7.2, y: y + 0.12, w: 5.35, h: 0.76,
    fontFace: B_FONT, fontSize: 13.5, color: INK, valign: "middle", margin: 0,
  });

  y += rowH + 0.13;
});

// ---------------------------------------------------------------
// SLIDE 2 — framework comparison
// ---------------------------------------------------------------
const s2 = pres.addSlide();
s2.background = { color: WHITE };

s2.addText("Every Tool Analyses a Different Artefact", {
  x: 0.6, y: 0.42, w: 12.1, h: 0.7,
  fontFace: H_FONT, fontSize: 36, bold: true, color: SLATE, margin: 0,
});
s2.addText("Comparison against the closest existing systems", {
  x: 0.6, y: 1.12, w: 12.1, h: 0.35,
  fontFace: B_FONT, fontSize: 15, color: MUTED, italic: true, margin: 0,
});

const hdr = (t) => ({
  text: t,
  options: { fontFace: B_FONT, fontSize: 13, bold: true, color: WHITE, fill: { color: SLATE }, valign: "middle" },
});
const cell = (t, opts = {}) => ({
  text: t,
  options: Object.assign(
    { fontFace: B_FONT, fontSize: 13, color: INK, valign: "middle" },
    opts
  ),
});

const rows = [
  [hdr("System"), hdr("Artefact analysed"), hdr("Pre-deployment"), hdr("Detects inert rules")],
  [cell("AgentSpec  2025"), cell("Runtime constraints"), cell("No", { color: MUTED }), cell("No", { color: MUTED })],
  [cell("Progent  2025"), cell("Privilege policy"), cell("No", { color: MUTED }), cell("No", { color: MUTED })],
  [cell("LlamaFirewall  2025"), cell("Runtime layers"), cell("No", { color: MUTED }), cell("No", { color: MUTED })],
  [cell("Agentproof  2026"), cell("Workflow graph"), cell("Yes"), cell("Topology only", { color: MUTED })],
  [cell("λA  2026"), cell("Composition config"), cell("Yes"), cell("Config only", { color: MUTED })],
  [cell("Margrave  2005"), cell("XACML policy"), cell("Yes"), cell("Yes — single-pass model", { color: MUTED })],
  [
    cell("detguard lint", { bold: true, color: ALERT, fill: { color: PAPER } }),
    cell("Guardrail ruleset", { bold: true, fill: { color: PAPER } }),
    cell("Yes", { bold: true, fill: { color: PAPER } }),
    cell("Yes — incl. cross-hook", { bold: true, color: ALERT, fill: { color: PAPER } }),
  ],
];

s2.addTable(rows, {
  x: 0.6, y: 1.68, w: 12.1,
  colW: [2.7, 3.4, 2.4, 3.6],
  rowH: 0.52,
  border: { type: "solid", color: "D8DEE4", pt: 1 },
  align: "left",
  margin: 0.08,
});

s2.addText(
  "Static analysis reached agents in 2026 — but each tool inspects a different object. None inspects the policy ruleset.",
  {
    x: 0.6, y: 6.4, w: 12.1, h: 0.5,
    fontFace: B_FONT, fontSize: 15, bold: true, color: SLATE,
    valign: "middle", margin: 0,
  }
);

// ---------------------------------------------------------------
// SLIDE 3 — why it holds up (dark)
// ---------------------------------------------------------------
const s3 = pres.addSlide();
s3.background = { color: SLATE };

s3.addText("Why This Method Holds Up", {
  x: 0.6, y: 0.5, w: 12.1, h: 0.7,
  fontFace: H_FONT, fontSize: 36, bold: true, color: WHITE, margin: 0,
});

const reasons = [
  {
    n: "01",
    head: "Zero marginal cost",
    body: "Reuses policy.yaml and results.json already produced by any normal run. No LLM call, no network, no re-execution — cheap enough to run on every commit.",
  },
  {
    n: "02",
    head: "Detects what runtime cannot",
    body: "A rule that never fires is invisible to any accuracy metric by construction. No corpus, however large, surfaces it. Only artefact analysis can.",
  },
  {
    n: "03",
    head: "Honest scope",
    body: "A lint, not a verifier. Soundness is traded for deployability, and the sound alternative is cited as future work rather than claimed as delivered.",
  },
];

let cx = 0.6;
reasons.forEach((r) => {
  const w = 3.7;
  s3.addText(r.n, {
    x: cx, y: 1.62, w: w, h: 0.62,
    fontFace: H_FONT, fontSize: 40, bold: true, color: ALERT, margin: 0,
  });
  s3.addText(r.head, {
    x: cx, y: 2.34, w: w, h: 0.72,
    fontFace: H_FONT, fontSize: 21, bold: true, color: WHITE, margin: 0,
  });
  s3.addText(r.body, {
    x: cx, y: 3.12, w: w, h: 2.0,
    fontFace: B_FONT, fontSize: 14, color: PAPER, lineSpacingMultiple: 1.25, margin: 0,
  });
  cx += w + 0.5;
});

s3.addShape(pres.ShapeType.roundRect, {
  x: 0.6, y: 5.62, w: 12.1, h: 1.16,
  fill: { color: INK }, line: { color: ALERT, width: 1.5 }, rectRadius: 0.08,
});
s3.addText(
  "The alternative to this method is not a better method. It is not checking at all.",
  {
    x: 0.8, y: 5.62, w: 11.7, h: 1.16,
    fontFace: H_FONT, fontSize: 23, bold: true, color: WHITE,
    align: "center", valign: "middle", margin: 0,
  }
);

pres.writeFile({ fileName: "why-this-methodology.pptx" }).then((f) => {
  console.log("wrote", f);
});
