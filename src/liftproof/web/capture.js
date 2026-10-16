// Liftproof recorder: runs in every page and frame of the recording browser.
// Captures what the engineer does, with several locator candidates per element
// (spec 5: test id, role and name, label, text, then css). Values typed into
// sensitive fields go to the recorder process only, which swaps them for a token.
(() => {
  if (window.__liftproofCapture) return;
  window.__liftproofCapture = true;

  const ROLE_BY_TAG = {
    A: "link", BUTTON: "button", SELECT: "combobox", TEXTAREA: "textbox",
    H1: "heading", H2: "heading", H3: "heading", H4: "heading", H5: "heading", H6: "heading",
  };
  const INPUT_ROLES = {
    button: "button", submit: "button", reset: "button", checkbox: "checkbox", radio: "radio",
    email: "textbox", text: "textbox", search: "searchbox", tel: "textbox", url: "textbox",
    password: "textbox", number: "spinbutton", "": "textbox",
  };
  const clean = (s) => (s || "").replace(/\s+/g, " ").trim();

  function role(el) {
    const explicit = el.getAttribute("role");
    if (explicit) return explicit;
    if (el.tagName === "INPUT") return INPUT_ROLES[(el.type || "").toLowerCase()] || null;
    if (el.tagName === "A" && !el.hasAttribute("href")) return null;
    return ROLE_BY_TAG[el.tagName] || null;
  }

  function labelText(el) {
    if (el.labels && el.labels.length) return clean(el.labels[0].innerText);
    const by = el.getAttribute("aria-labelledby");
    if (by) {
      const t = by.split(/\s+/).map((id) => document.getElementById(id))
        .filter(Boolean).map((n) => n.innerText).join(" ");
      if (clean(t)) return clean(t);
    }
    return clean(el.getAttribute("aria-label"));
  }

  function accessibleName(el) {
    const l = labelText(el);
    if (l) return l;
    if (el.tagName === "INPUT") {
      const t = (el.type || "").toLowerCase();
      if (["button", "submit", "reset"].includes(t)) return clean(el.value) || clean(el.title);
      return clean(el.getAttribute("placeholder")) || clean(el.title);
    }
    return clean(el.innerText).slice(0, 80) || clean(el.title);
  }

  function cssPath(el) {
    const parts = [];
    for (let n = el; n && n.nodeType === 1 && n !== document.body; n = n.parentElement) {
      if (n.id) { parts.unshift("#" + CSS.escape(n.id)); break; }
      let part = n.tagName.toLowerCase();
      const name = n.getAttribute("name");
      if (name) part += `[name="${name.replace(/"/g, '\\"')}"]`;
      else {
        const same = Array.from(n.parentElement ? n.parentElement.children : [])
          .filter((c) => c.tagName === n.tagName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(n) + 1})`;
      }
      parts.unshift(part);
    }
    return parts.join(" > ");
  }

  function candidates(el) {
    const out = [];
    const tid = el.getAttribute("data-testid") || el.getAttribute("data-test-id");
    if (tid) out.push({ kind: "testid", value: tid });
    const r = role(el);
    const name = accessibleName(el);
    if (r && name) out.push({ kind: "role", role: r, name });
    const lbl = labelText(el);
    if (lbl && ["INPUT", "SELECT", "TEXTAREA"].includes(el.tagName)) {
      out.push({ kind: "label", value: lbl });
    }
    const text = clean(el.innerText);
    if (text && text.length <= 80 && !["INPUT", "SELECT", "TEXTAREA"].includes(el.tagName)) {
      out.push({ kind: "text", value: text });
    }
    out.push({ kind: "css", value: cssPath(el) });
    return out;
  }

  function target(el) {
    // a click on the text inside a button belongs to the button
    return el.closest("button, a, [role=button], [role=link], input, select, textarea, label, " +
      "[data-testid]") || el;
  }

  function send(ev) {
    ev.t = Date.now();
    ev.page_url = location.href;
    try { window.__liftproofRecord(JSON.stringify(ev)); } catch (e) { /* page closing */ }
  }

  // Same rule as browser.REGION_JS at replay: the region a step touched is the
  // nearest form, dialog, table, section, article or main around the element.
  function markRegion(el) {
    const r = el.closest("form, dialog, [role=dialog], [role=form], table, section, " +
      "article, main");
    document.querySelectorAll("[data-liftproof-region]").forEach(
      (n) => n.removeAttribute("data-liftproof-region"));
    if (r) r.setAttribute("data-liftproof-region", "1");
  }

  function describe(el) {
    markRegion(el);
    return { candidates: candidates(el), description: `${el.tagName.toLowerCase()} ` +
      `"${accessibleName(el)}"` };
  }

  document.addEventListener("click", (e) => {
    const el = target(e.target);
    if (["INPUT", "SELECT", "TEXTAREA"].includes(el.tagName)) {
      const t = (el.type || "").toLowerCase();
      if (!["button", "submit", "reset", "checkbox", "radio"].includes(t)) return;
      if (t === "checkbox" || t === "radio") return; // captured on change
    }
    if (el.tagName === "LABEL") return; // the change on its control is the step
    send({ action: "click", locator: describe(el) });
  }, true);

  document.addEventListener("change", (e) => {
    const el = e.target;
    if (el.tagName === "SELECT") {
      send({ action: "select", locator: describe(el), value: el.value });
    } else if (el.tagName === "INPUT" && ["checkbox", "radio"].includes(el.type)) {
      send({ action: el.checked ? "check" : "uncheck", locator: describe(el) });
    }
  }, true);

  // Text is recorded as it is typed ("input"), not on blur ("change"), so the step and
  // the snapshot after it line up; the recorder merges keystrokes into one fill step.
  document.addEventListener("input", (e) => {
    const el = e.target;
    if (el.tagName === "INPUT" && ["checkbox", "radio", "file"].includes(el.type)) return;
    if (["INPUT", "TEXTAREA"].includes(el.tagName)) {
      const sensitive = el.type === "password" || el.hasAttribute("data-liftproof-sensitive") ||
        /pass|secret|token|otp|pin/i.test(el.name || "");
      // A sensitive value goes to the recorder process only, which swaps it for a
      // token and scrubs it from every captured request; it is never written anywhere.
      send({ action: "fill", locator: describe(el), value: el.value, sensitive,
             field: accessibleName(el) || el.name || "" });
    }
  }, true);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target && e.target.tagName === "INPUT") {
      send({ action: "press", locator: describe(e.target), value: "Enter" });
    }
  }, true);

  // Back and Forward in the browser window. The Navigation API marks a traversal the browser
  // started (toolbar, Alt+Left, mouse back button) userInitiated; a page's own history.back()
  // is not, and the click that ran it is already a step. The recorder counts how far it went
  // in the browser's history, which has the entries frames added too; delta, the page's own
  // count, is null when the destination is on another origin.
  if (window === window.top && window.navigation) {
    navigation.addEventListener("navigate", (e) => {
      if (e.navigationType !== "traverse" || !e.userInitiated) return;
      const to = e.destination.index;
      const from = navigation.currentEntry ? navigation.currentEntry.index : -1;
      send({ action: "traverse", delta: to >= 0 && from >= 0 ? to - from : null });
    });
  }
})();
