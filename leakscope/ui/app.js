const form = document.querySelector("#triage-form");
const input = document.querySelector("#alert-text");
const count = document.querySelector("#char-count");
const button = document.querySelector("#triage-button");
const emptyState = document.querySelector("#empty-state");
const resultContent = document.querySelector("#result-content");
const errorMessage = document.querySelector("#error-message");

const descriptions = {
  L4: "Critical signal. Follow your organisation's approved incident process.",
  L3: "High-priority signal. Assign an owner for prompt investigation.",
  L2: "Moderate signal. Queue for analyst review.",
  L1: "Low-priority signal. Retain according to local policy.",
  L0: "Suppressed by deterministic policy. Audit suppressions routinely.",
  REVIEW: "Evidence is not enough to decide safely. An analyst must review this item.",
};

input.addEventListener("input", () => {
  count.textContent = `${input.value.length.toLocaleString()} characters`;
});

function addProvenance(provenance) {
  const list = document.querySelector("#provenance-list");
  list.replaceChildren();
  for (const [key, value] of Object.entries(provenance)) {
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = key;
    detail.textContent = String(value);
    list.append(term, detail);
  }
}

function renderResult(result) {
  const level = result.level;
  const badge = document.querySelector("#level-badge");
  badge.textContent = level;
  badge.className = `level-badge level-${level}`;
  document.querySelector("#level-description").textContent = descriptions[level] ?? descriptions.REVIEW;
  document.querySelector("#result-state").textContent = "DECISION READY";

  const reasons = document.querySelector("#reasons");
  reasons.replaceChildren();
  for (const reason of result.reasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    reasons.append(item);
  }

  const evidenceList = document.querySelector("#evidence-list");
  evidenceList.replaceChildren();
  for (const evidence of result.evidence) {
    const chip = document.createElement("span");
    chip.className = "evidence-chip";
    chip.textContent = `${evidence.kind}${evidence.is_test_value ? " · test value" : ""}`;
    evidenceList.append(chip);
  }
  document.querySelector("#evidence-count").textContent = result.facts.evidence_truncated
    ? `${result.evidence.length}+`
    : String(result.evidence.length);
  document.querySelector("#no-evidence").hidden = result.evidence.length > 0;
  document.querySelector("#masked-preview").textContent = result.masked_text;
  addProvenance(result.provenance);
  errorMessage.hidden = true;
  emptyState.hidden = true;
  resultContent.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!input.value.trim()) return;
  button.disabled = true;
  button.textContent = "Analyzing…";
  errorMessage.hidden = true;
  try {
    const response = await fetch("/v1/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: input.value, source: document.querySelector("#source").value }),
    });
    if (!response.ok) throw new Error("Triage request failed. Check the input and local API status.");
    renderResult(await response.json());
  } catch (error) {
    errorMessage.textContent = error instanceof Error ? error.message : "Triage request failed.";
    errorMessage.hidden = false;
  } finally {
    button.disabled = false;
    button.innerHTML = '<span aria-hidden="true">↗</span> Run triage';
  }
});