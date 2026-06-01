const C = {
  bg: "#FBFAF5",
  ink: "#1F2933",
  muted: "#5E6B75",
  faint: "#D8D2C4",
  panel: "#FFFFFF",
  teal: "#0F766E",
  tealLight: "#DDEFEA",
  blue: "#2563EB",
  blueLight: "#E4ECFF",
  amber: "#B7791F",
  amberLight: "#F6E8C8",
  rose: "#B42318",
  roseLight: "#F6D8D4",
  slate: "#334155",
  slateLight: "#E8ECEF",
  green: "#3F7D47",
  greenLight: "#E4F1DE",
};

const W = 1280;
const H = 720;
const M = 72;

function bg(slide) {
  slide.background.fill = C.bg;
}

function addText(ctx, slide, text, x, y, w, h, opts = {}) {
  const shape = ctx.addText(slide, {
    text,
    x,
    y,
    w,
    h,
    fontSize: opts.size ?? 24,
    color: opts.color ?? C.ink,
    bold: opts.bold ?? false,
    typeface: opts.face ?? (opts.title ? ctx.fonts.title : ctx.fonts.body),
    align: opts.align ?? "left",
    valign: opts.valign ?? "top",
    fill: opts.fill ?? "#00000000",
    line: opts.line ?? ctx.line("#00000000", 0),
    insets: opts.insets ?? { left: 0, right: 0, top: 0, bottom: 0 },
    name: opts.name,
  });
  if (shape.text) {
    if (opts.lineSpacing) shape.text.lineSpacing = opts.lineSpacing;
    if (opts.wrap) shape.text.wrap = opts.wrap;
  }
  return shape;
}

function title(ctx, slide, kicker, headline, subhead, slideNo) {
  const longHeadline = headline.length > 70;
  const headlineHeight = longHeadline ? 132 : 112;
  const headlineSize = headline.length > 95 ? 34 : headline.length > 58 ? 38 : 42;
  addText(ctx, slide, kicker.toUpperCase(), M, 44, 760, 24, {
    size: 12,
    color: C.teal,
    bold: true,
  });
  addText(ctx, slide, headline, M, 76, 820, headlineHeight, {
    size: headlineSize,
    color: C.ink,
    bold: true,
    title: true,
  });
  if (subhead) {
    addText(ctx, slide, subhead, M, 76 + headlineHeight + 10, 760, 52, {
      size: 20,
      color: C.muted,
    });
  }
  addText(ctx, slide, String(slideNo).padStart(2, "0"), W - 104, 46, 40, 20, {
    size: 11,
    color: C.muted,
    align: "right",
  });
  line(ctx, slide, M, 660, W - 2 * M, 1, C.faint);
  addText(ctx, slide, "FEN identity model | team briefing", M, 674, 460, 18, {
    size: 10,
    color: C.muted,
  });
}

function line(ctx, slide, x, y, w, h = 1, color = C.faint) {
  return ctx.addShape(slide, {
    x,
    y,
    w,
    h,
    geometry: "rect",
    fill: color,
    line: ctx.line(color, 0),
  });
}

function box(ctx, slide, x, y, w, h, opts = {}) {
  const shape = ctx.addShape(slide, {
    x,
    y,
    w,
    h,
    geometry: opts.geometry ?? "rect",
    fill: opts.fill ?? C.panel,
    line: ctx.line(opts.stroke ?? C.faint, opts.strokeWidth ?? 1),
    name: opts.name,
  });
  return shape;
}

function labelBox(ctx, slide, x, y, w, h, label, body, opts = {}) {
  box(ctx, slide, x, y, w, h, {
    fill: opts.fill ?? C.panel,
    stroke: opts.stroke ?? C.faint,
    strokeWidth: opts.strokeWidth ?? 1,
  });
  if (opts.accent) line(ctx, slide, x, y, w, 5, opts.accent);
  addText(ctx, slide, label, x + 18, y + 18, w - 36, 28, {
    size: opts.labelSize ?? 17,
    color: opts.labelColor ?? C.ink,
    bold: true,
  });
  addText(ctx, slide, body, x + 18, y + 52, w - 36, h - 66, {
    size: opts.bodySize ?? 14,
    color: opts.bodyColor ?? C.muted,
  });
}

function dot(ctx, slide, cx, cy, r, fill, stroke = fill) {
  box(ctx, slide, cx - r, cy - r, r * 2, r * 2, {
    geometry: "ellipse",
    fill,
    stroke,
    strokeWidth: 1,
  });
}

function chip(ctx, slide, x, y, w, text, fill, color = C.ink) {
  box(ctx, slide, x, y, w, 28, { fill, stroke: fill });
  addText(ctx, slide, text, x + 10, y + 7, w - 20, 16, {
    size: 11,
    color,
    bold: true,
    align: "center",
  });
}

function flowNode(ctx, slide, x, y, w, h, label, body, fill, accent) {
  labelBox(ctx, slide, x, y, w, h, label, body, {
    fill,
    stroke: accent,
    accent,
    labelSize: label.length > 16 ? 14 : 17,
    bodySize: 13,
  });
}

function connector(ctx, slide, x1, y1, x2, y2, color = C.faint) {
  if (Math.abs(y2 - y1) < 2) {
    line(ctx, slide, Math.min(x1, x2), y1, Math.abs(x2 - x1), 2, color);
  } else if (Math.abs(x2 - x1) < 2) {
    line(ctx, slide, x1, Math.min(y1, y2), 2, Math.abs(y2 - y1), color);
  } else {
    const midX = (x1 + x2) / 2;
    line(ctx, slide, Math.min(x1, midX), y1, Math.abs(midX - x1), 2, color);
    line(ctx, slide, midX, Math.min(y1, y2), 2, Math.abs(y2 - y1), color);
    line(ctx, slide, Math.min(midX, x2), y2, Math.abs(x2 - midX), 2, color);
  }
}

function miniArrow(ctx, slide, x, y, color = C.faint) {
  line(ctx, slide, x, y, 36, 2, color);
  addText(ctx, slide, ">", x + 32, y - 9, 14, 18, { size: 14, color, bold: true });
}

export async function renderSlide(presentation, ctx, n) {
  const slide = presentation.slides.add();
  bg(slide);
  switch (n) {
    case 1:
      return slide01(slide, ctx);
    case 2:
      return slide02(slide, ctx);
    case 3:
      return slide03(slide, ctx);
    case 4:
      return slide04(slide, ctx);
    case 5:
      return slide05(slide, ctx);
    case 6:
      return slide06(slide, ctx);
    case 7:
      return slide07(slide, ctx);
    case 8:
      return slide08(slide, ctx);
    case 9:
      return slide09(slide, ctx);
    case 10:
      return slide10(slide, ctx);
    case 11:
      return slide11(slide, ctx);
    case 12:
      return slide12(slide, ctx);
    case 13:
      return slide13(slide, ctx);
    case 14:
      return slide14(slide, ctx);
    default:
      throw new Error(`Unknown slide ${n}`);
  }
}

function slide01(slide, ctx) {
  addText(ctx, slide, "Identity as Evidence", M, 92, 650, 72, {
    size: 50,
    color: C.ink,
    bold: true,
    title: true,
  });
  addText(
    ctx,
    slide,
    "A Rust-based FEN framework for biological continuity, institutional linkage, and auditable trust",
    M,
    176,
    680,
    86,
    { size: 24, color: C.muted },
  );
  addText(ctx, slide, "Team briefing", M, 305, 260, 26, {
    size: 15,
    color: C.teal,
    bold: true,
  });
  addText(ctx, slide, "Programmer | UX researcher/designer | cancer lab scientist", M, 334, 520, 28, {
    size: 15,
    color: C.muted,
  });

  const x = 790;
  const ys = [108, 258, 408];
  const items = [
    ["Initial binding", "First bind account, person, device, evidence, and records.", C.blueLight, C.blue],
    ["Continuity", "Later prove the current actor is continuous with that subject.", C.tealLight, C.teal],
    ["Policy decision", "Materialize only what the caller and purpose are allowed to rely on.", C.amberLight, C.amber],
  ];
  items.forEach(([label, body, fill, accent], i) => {
    labelBox(ctx, slide, x, ys[i], 360, 110, label, body, { fill, stroke: accent, accent });
    if (i < 2) miniArrow(ctx, slide, x + 160, ys[i] + 126, C.faint);
  });
  line(ctx, slide, M, 660, W - 2 * M, 1, C.faint);
  addText(ctx, slide, "Source: FEN Identity Model and current Rust implementation", M, 674, 600, 18, {
    size: 10,
    color: C.muted,
  });
  return slide;
}

function slide02(slide, ctx) {
  title(ctx, slide, "Problem frame", "Identity is not one question.", "Ordinary login collapses several risks that FEN needs to keep separate.", 2);
  const y = 300;
  const cards = [
    ["Account control", "Who controls this app account or session?", C.blueLight, C.blue],
    ["Biological continuity", "Is the acting person continuous with the enrolled subject?", C.tealLight, C.teal],
    ["Institutional linkage", "Which provider, payer, or portal records are linked?", C.greenLight, C.green],
    ["Authority", "What may this person do for self or another subject?", C.amberLight, C.amber],
  ];
  cards.forEach(([label, body, fill, accent], i) => {
    const x = M + i * 284;
    labelBox(ctx, slide, x, y, 246, 150, label, body, {
      fill,
      stroke: accent,
      accent,
      labelSize: 16,
      bodySize: 15,
    });
  });
  addText(ctx, slide, "Deck thesis", M, 516, 190, 26, { size: 14, color: C.teal, bold: true });
  addText(ctx, slide, "The answer to the identity problem is never a primitive field. It is an auditable interpretation of evidence over time.", 300, 512, 740, 56, { size: 22, color: C.ink, bold: true });
  return slide;
}

function slide03(slide, ctx) {
  title(ctx, slide, "Core model", "FEN treats identity as a high-assurance region of the fact graph.", "The same abstractions carry onboarding, recovery, access, delegation, and disputes.", 3);
  const x = 84;
  const y = 290;
  const nodes = [
    ["SubjectId", "Durable anchor for the biologically continuous subject.", C.slateLight, C.slate],
    ["Fact", "Time-indexed evidence, event, assertion, or decision.", C.tealLight, C.teal],
    ["ProblemEpisode", "Fallible workflow context, such as onboarding or recovery.", C.blueLight, C.blue],
    ["EpisodeMembership", "Authored claim that a fact matters to an episode.", C.amberLight, C.amber],
    ["Narrative / projection", "Current interpretation, rebuilt from active facts.", C.greenLight, C.green],
  ];
  nodes.forEach(([label, body, fill, accent], i) => {
    const nx = x + i * 228;
    flowNode(ctx, slide, nx, y, 190, 126, label, body, fill, accent);
    if (i < nodes.length - 1) miniArrow(ctx, slide, nx + 194, y + 64, C.faint);
  });
  addText(ctx, slide, "Important boundary", 112, 502, 220, 24, {
    size: 14,
    color: C.rose,
    bold: true,
  });
  addText(ctx, slide, "The projection is useful for the product experience, but it is not the source of truth. The graph is.", 112, 532, 780, 56, {
    size: 21,
    color: C.ink,
    bold: true,
  });
  return slide;
}

function slide04(slide, ctx) {
  title(ctx, slide, "Initial binding", "Onboarding establishes the reference that continuity later protects.", "Section 10 describes onboarding as a sequence of facts grouped into an identity-verification episode.", 4);
  const steps = [
    ["Create SubjectId", "SubjectCreated"],
    ["Bind account/device", "DeviceBindingEstablished"],
    ["Enroll biometric reference", "BiometricEnrollmentReferenceAdded"],
    ["Collect witnesses", "Government ID + selfie liveness"],
    ["Link records", "Provider and payer links"],
    ["Summarize current state", "Narrative / projection"],
  ];
  const y = 290;
  steps.forEach(([label, body], i) => {
    const x = 82 + i * 190;
    dot(ctx, slide, x + 58, y, 21, i === 2 ? C.teal : C.panel, i === 2 ? C.teal : C.faint);
    addText(ctx, slide, String(i + 1), x + 49, y - 10, 18, 20, {
      size: 13,
      color: i === 2 ? "#FFFFFF" : C.ink,
      bold: true,
      align: "center",
    });
    if (i < steps.length - 1) line(ctx, slide, x + 82, y, 112, 2, C.faint);
    addText(ctx, slide, label, x, y + 46, 136, 40, { size: 15, color: C.ink, bold: true, align: "center" });
    addText(ctx, slide, body, x - 6, y + 94, 148, 44, { size: 12, color: C.muted, align: "center" });
  });
  labelBox(ctx, slide, 146, 506, 430, 106, "What this does", "Binds account, device, witnesses, enrollment reference, and institutional records to one subject.", {
    fill: C.blueLight,
    stroke: C.blue,
    accent: C.blue,
    bodySize: 12,
  });
  labelBox(ctx, slide, 704, 506, 430, 106, "What this does not do", "Does not declare identity as one immutable value or put raw biometric material inside FEN facts.", {
    fill: C.roseLight,
    stroke: C.rose,
    accent: C.rose,
    bodySize: 12,
  });
  return slide;
}

function slide05(slide, ctx) {
  title(ctx, slide, "Two distinct jobs", "Initial binding and continuity answer different questions.", "This distinction should be explicit in the team discussion.", 5);
  labelBox(ctx, slide, 96, 285, 500, 242, "Initial establishment", "Question: should this account, person, device, biometric reference, and institutional evidence be treated as bound?\n\nOutput: an onboarding episode with identity witnesses, device binding, enrollment reference, provider/payer links, and narrative.", {
    fill: C.blueLight,
    stroke: C.blue,
    accent: C.blue,
    labelSize: 24,
    bodySize: 18,
  });
  labelBox(ctx, slide, 684, 285, 500, 242, "Biological continuity", "Question: does this live presentation match this subject's enrollment reference now?\n\nOutput: a signed continuity assertion that FEN verifies and records as a BiometricContinuityCheck fact.", {
    fill: C.tealLight,
    stroke: C.teal,
    accent: C.teal,
    labelSize: 24,
    bodySize: 18,
  });
  addText(ctx, slide, "Onboarding establishes the reference. Continuity protects reliance on it over time.", 164, 568, 950, 58, {
    size: 25,
    color: C.ink,
    bold: true,
    align: "center",
  });
  return slide;
}

function slide06(slide, ctx) {
  title(ctx, slide, "Continuity substrate", "Section 21 is a three-trust-domain architecture.", "The vault verifies continuity, not identity. FEN decides what that continuity means.", 6);
  const lanes = [
    ["Client device", "Capture + attestation\nApp Attest, frames\nEcho FEN nonce", C.blueLight, C.blue],
    ["Continuity vault", "Liveness / PAD\n1:1 match vs this subject\nSign assertion", C.tealLight, C.teal],
    ["FEN graph", "Verify signature + nonce\nWrite continuity fact\nMap assurance to decision", C.amberLight, C.amber],
  ];
  lanes.forEach(([label, body, fill, accent], i) => {
    const x = 100 + i * 390;
    labelBox(ctx, slide, x, 326, 300, 190, label, body, {
      fill,
      stroke: accent,
      accent,
      labelSize: 22,
      bodySize: 18,
    });
    if (i < 2) miniArrow(ctx, slide, x + 320, 392, C.slate);
  });
  line(ctx, slide, 270, 294, 740, 2, C.rose);
  addText(ctx, slide, "Phase boundary: ownership moves left over time; signed assertion stays stable.", 250, 260, 780, 24, {
    size: 18,
    color: C.rose,
    bold: true,
    align: "center",
  });
  addText(ctx, slide, "Phase 1: vendor vault     Phase 2: in-house capture/store     Phase 3: enclave matching + multimodal governance", 184, 556, 912, 24, {
    size: 15,
    color: C.muted,
    align: "center",
  });
  return slide;
}

function slide07(slide, ctx) {
  title(ctx, slide, "Freshness", "The nonce is the anti-replay and anti-injection hinge.", "FEN issues a challenge that must be bound into the capture and returned in the signed assertion.", 7);
  const x0 = 118;
  const y0 = 326;
  const items = [
    ["1", "FEN issues nonce", C.amberLight, C.amber],
    ["2", "Client captures now", C.blueLight, C.blue],
    ["3", "Vault signs result", C.tealLight, C.teal],
    ["4", "FEN checks freshness", C.amberLight, C.amber],
  ];
  items.forEach(([num, label, fill, accent], i) => {
    const x = x0 + i * 276;
    dot(ctx, slide, x, y0, 28, fill, accent);
    addText(ctx, slide, num, x - 10, y0 - 13, 20, 26, { size: 18, color: accent, bold: true, align: "center" });
    addText(ctx, slide, label, x - 88, y0 + 48, 176, 38, { size: 18, color: C.ink, bold: true, align: "center" });
    if (i < items.length - 1) line(ctx, slide, x + 34, y0, 206, 2, C.faint);
  });
  labelBox(ctx, slide, 170, 488, 280, 108, "Blocks replay", "A prior valid assertion cannot be submitted again; its nonce is stale.", {
    fill: C.roseLight,
    stroke: C.rose,
    accent: C.rose,
    bodySize: 12,
  });
  labelBox(ctx, slide, 500, 488, 280, 108, "Blocks pre-recording", "The response must include a value that did not exist moments ago.", {
    fill: C.roseLight,
    stroke: C.rose,
    accent: C.rose,
    bodySize: 12,
  });
  labelBox(ctx, slide, 830, 488, 280, 108, "Supports UX clarity", "High-risk actions can explain why a fresh live check is needed now.", {
    fill: C.greenLight,
    stroke: C.green,
    accent: C.green,
    bodySize: 12,
  });
  return slide;
}

function slide08(slide, ctx) {
  title(ctx, slide, "Data minimization", "FEN stores continuity evidence, not biometric material.", "The template is read by the matcher and never crosses into the FEN graph.", 8);
  addText(ctx, slide, "FEN stores", 140, 282, 340, 30, { size: 26, color: C.teal, bold: true });
  addText(ctx, slide, "FEN refuses to store", 720, 282, 360, 30, { size: 26, color: C.rose, bold: true });
  const yes = ["enrollment reference", "signed result", "modality", "assurance level", "policy / audit context"];
  const no = ["raw face frames", "biometric templates", "embeddings", "liveness media", "cross-subject watchlists"];
  yes.forEach((t, i) => {
    chip(ctx, slide, 140, 334 + i * 46, 310, t, C.tealLight, C.teal);
  });
  no.forEach((t, i) => {
    chip(ctx, slide, 720, 334 + i * 46, 330, t, C.roseLight, C.rose);
  });
  line(ctx, slide, 616, 300, 2, 260, C.faint);
  addText(ctx, slide, "The privacy claim depends on a 1:1 subject check, isolated references, and no gallery search.", 188, 590, 906, 50, {
    size: 22,
    color: C.ink,
    bold: true,
    align: "center",
  });
  return slide;
}

function slide09(slide, ctx) {
  title(ctx, slide, "Adapter boundary", "External systems produce evidence; FEN owns identity semantics.", "This is the portability argument applied to authentication, devices, continuity, providers, and payers.", 9);
  const sources = [
    ["OIDC / Keycloak", "account session"],
    ["App Attest", "app-bound device"],
    ["Continuity vault", "signed assertion"],
    ["Provider / payer", "institutional link"],
  ];
  sources.forEach(([label, body], i) => {
    const y = 262 + i * 80;
    const fill = i % 2 ? C.tealLight : C.blueLight;
    const accent = i % 2 ? C.teal : C.blue;
    box(ctx, slide, 96, y, 280, 64, { fill, stroke: accent });
    addText(ctx, slide, label, 114, y + 17, 244, 20, {
      size: 15,
      color: C.ink,
      bold: true,
    });
    addText(ctx, slide, body, 114, y + 42, 244, 16, {
      size: 10,
      color: C.muted,
    });
    connector(ctx, slide, 376, y + 32, 510, y + 32, C.faint);
  });
  labelBox(ctx, slide, 510, 288, 240, 246, "Verifier / translator", "Validate evidence at the edge.\nTranslate only verified claims into typed FEN facts.", {
    fill: C.slateLight,
    stroke: C.slate,
    accent: C.slate,
    labelSize: 20,
    bodySize: 17,
  });
  connector(ctx, slide, 750, 411, 850, 411, C.faint);
  labelBox(ctx, slide, 850, 284, 330, 226, "FEN fact graph", "CredentialAssertion\nDeviceBindingEstablished\nBiometricContinuityCheck\nIdentityWitnessRecorded\nClinicalIdentityLinkEstablished\nAccessDecision", {
    fill: C.greenLight,
    stroke: C.green,
    accent: C.green,
    labelSize: 20,
    bodySize: 17,
  });
  return slide;
}

function slide10(slide, ctx) {
  title(ctx, slide, "Materialization", "A SQL read is not the same as reconstructing meaning.", "Sensitive facts stay encrypted until Rust policy, key access, decryption, and replay allow a derived view.", 10);
  const y = 330;
  const nodes = [
    ["Encrypted envelopes", "append order\nmetadata\nciphertext", C.slateLight, C.slate],
    ["Rust policy", "caller\npurpose\noperation", C.amberLight, C.amber],
    ["Key + decrypt", "associated data\nkey state\nauthentication", C.blueLight, C.blue],
    ["Replay facts", "typed graph\nprojection\naudit", C.tealLight, C.teal],
  ];
  nodes.forEach(([label, body, fill, accent], i) => {
    const x = 108 + i * 285;
    labelBox(ctx, slide, x, y, 220, 142, label, body, {
      fill,
      stroke: accent,
      accent,
      labelSize: 19,
      bodySize: 16,
    });
    if (i < nodes.length - 1) miniArrow(ctx, slide, x + 230, y + 72, C.faint);
  });
  addText(ctx, slide, "Rust owns semantic interpretation. Storage preserves append-only encrypted envelopes.", 166, 540, 948, 58, {
    size: 23,
    color: C.ink,
    bold: true,
    align: "center",
  });
  return slide;
}

function slide11(slide, ctx) {
  title(ctx, slide, "Failure handling", "A failed check is still evidence.", "The model avoids bare denial by turning failures, disputes, and corrections into facts and episodes.", 11);
  const examples = [
    ["Failed liveness", "BiometricContinuityCheck: Failed", "manual review or lockout"],
    ["Stale nonce", "continuity rejection reason", "retry with fresh challenge"],
    ["Contested provider link", "ClinicalIdentityLinkContested", "exclude from high-risk reliance"],
    ["Lost device", "DeviceBindingRevoked", "recovery episode"],
  ];
  examples.forEach(([event, fact, next], i) => {
    const y = 276 + i * 78;
    addText(ctx, slide, event, 112, y + 8, 230, 28, { size: 18, color: C.ink, bold: true });
    miniArrow(ctx, slide, 350, y + 22, C.faint);
    addText(ctx, slide, fact, 420, y + 8, 330, 28, { size: 17, color: C.teal, bold: true });
    miniArrow(ctx, slide, 762, y + 22, C.faint);
    addText(ctx, slide, next, 830, y + 8, 320, 28, { size: 17, color: C.muted });
    line(ctx, slide, 112, y + 58, 1038, 1, C.faint);
  });
  addText(ctx, slide, "This is a UX design advantage: errors become explainable states, not mysterious dead ends.", 166, 606, 948, 28, {
    size: 21,
    color: C.ink,
    bold: true,
    align: "center",
  });
  return slide;
}

function slide12(slide, ctx) {
  title(ctx, slide, "Product implications", "The model gives UX a vocabulary for trust transitions.", "Each user flow can show what evidence is required, what confidence changed, and what happens next.", 12);
  const flows = [
    ["Onboarding", "bind subject, device, witnesses, records"],
    ["Step-up export", "fresh continuity + risk + access decision"],
    ["Recovery", "replace device without erasing history"],
    ["Delegation", "actor authority over target subject"],
    ["Dispute", "contested link remains auditable"],
  ];
  flows.forEach(([label, body], i) => {
    const x = 92 + (i % 3) * 370;
    const y = i < 3 ? 284 : 458;
    labelBox(ctx, slide, x, y, 300, 112, label, body, {
      fill: i === 1 ? C.amberLight : i === 4 ? C.roseLight : C.panel,
      stroke: i === 1 ? C.amber : i === 4 ? C.rose : C.faint,
      accent: i === 1 ? C.amber : i === 4 ? C.rose : C.teal,
      labelSize: 18,
      bodySize: 15,
    });
  });
  addText(ctx, slide, "Design target: users should understand why the system asks for more evidence, not just that it blocked them.", 178, 602, 924, 48, {
    size: 20,
    color: C.ink,
    bold: true,
    align: "center",
  });
  return slide;
}

function slide13(slide, ctx) {
  title(ctx, slide, "Rust proof", "The current framework already exercises the architectural boundary.", "The codebase has enough working slices to make this a concrete MVP path rather than a theory deck.", 13);
  labelBox(ctx, slide, 96, 280, 500, 270, "Already built and tested", "Typed FEN facts and identity primitives\nWorkflow slices for onboarding, recovery, delegation, access, disputes\nOIDC / Keycloak evidence boundary\nApp Attest-shaped device evidence guard\nEncrypted persistence and PostgreSQL replay\nPolicy-gated materialized projections", {
    fill: C.greenLight,
    stroke: C.green,
    accent: C.green,
    labelSize: 24,
    bodySize: 17,
  });
  labelBox(ctx, slide, 684, 280, 500, 270, "Next MVP proof", "Real Apple App Attest adapter\nProduction key management / wrapping\nOperational PostgreSQL deployment\nDurable policy artifact lifecycle\nMinimal iPhone path against production HTTP runtime\nHardening: audit, replay, failure taxonomy, observability", {
    fill: C.amberLight,
    stroke: C.amber,
    accent: C.amber,
    labelSize: 24,
    bodySize: 17,
  });
  return slide;
}

function slide14(slide, ctx) {
  title(ctx, slide, "Team discussion", "The next decision is not whether the model is elegant. It is which risks we must prove first.", "Use the deck to converge on MVP proof, UX language, and governance boundaries.", 14);
  const questions = [
    ["Highest-risk identity mistake", "Which wrong binding or wrong authority scenario would harm users or data integrity most?"],
    ["Explainability standard", "What must the user, support team, scientist, or auditor be able to understand after a failure?"],
    ["Evidence threshold", "Which actions require fresh continuity, and which can rely on ordinary account/device evidence?"],
    ["Governance path", "Where should thresholds, assurance mappings, consent, and retention live as durable policy?"],
  ];
  questions.forEach(([label, body], i) => {
    const x = 112 + (i % 2) * 548;
    const y = 288 + Math.floor(i / 2) * 150;
    labelBox(ctx, slide, x, y, 448, 108, label, body, {
      fill: C.panel,
      stroke: C.faint,
      accent: [C.rose, C.teal, C.blue, C.amber][i],
      labelSize: 18,
      bodySize: 14,
    });
  });
  addText(ctx, slide, "Suggested close: pick one end-to-end demo path and one failure path to prove.", 214, 612, 852, 28, {
    size: 22,
    color: C.ink,
    bold: true,
    align: "center",
  });
  return slide;
}
