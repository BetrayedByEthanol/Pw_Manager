let selectorMode = false;
let selectorRole = "generic";
let selectorLabel = "page element";
let previousCursor = "";
let hoveredElement = null;

const VAULTY_SHADOW_HOST_ID = "vaulty-shadow-host";
const VAULTY_CURSOR_STYLE_ID = "vaulty-selector-cursor-style";

let selectorUi = {
  host: null,
  shadow: null,
  highlight: null,
  badge: null,
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "START_SELECTOR") {
    startSelectorMode(message);
    sendResponse({ ok: true });
    return;
  }

  if (message?.type === "VAULTY_TEST_FILL") {
    const result = testFill(message.payload || {});
    sendResponse(result);
    return;
  }

  if (message?.type === "VAULTY_FILL_BY_SELECTORS") {
    const result = fillBySelectors(message.payload || {});
    sendResponse(result);
    return;
  }

  if (message?.type === "VAULTY_VALIDATE_MAPPING") {
  const result = validateMapping(message.payload || {});
  sendResponse(result);
  return;
}
});

function startSelectorMode(message) {
  if (selectorMode) {
    stopSelectorMode();
  }

  selectorMode = true;
  selectorRole = message.role || "generic";
  selectorLabel = message.label || "page element";
  hoveredElement = null;

  previousCursor = document.body.style.cursor;
  document.body.style.cursor = "crosshair";

  createSelectorUi();
  installCursorStyle();

  document.addEventListener("click", handleSelectorClick, true);
  document.addEventListener("keydown", handleSelectorKeydown, true);
  document.addEventListener("mousemove", handleSelectorMouseMove, true);
  window.addEventListener("scroll", refreshHighlight, true);
  window.addEventListener("resize", refreshHighlight, true);

  console.log(`Vaulty selector active: click a ${selectorLabel}`);
}

function stopSelectorMode() {
  selectorMode = false;
  hoveredElement = null;

  document.body.style.cursor = previousCursor || "";

  document.removeEventListener("click", handleSelectorClick, true);
  document.removeEventListener("keydown", handleSelectorKeydown, true);
  document.removeEventListener("mousemove", handleSelectorMouseMove, true);
  window.removeEventListener("scroll", refreshHighlight, true);
  window.removeEventListener("resize", refreshHighlight, true);

  removeSelectorUi();
  removeCursorStyle();
}

function handleSelectorMouseMove(event) {
  if (!selectorMode) {
    return;
  }

  const target = event.target;

  if (!target || isVaultyUiElement(target)) {
    return;
  }

  hoveredElement = target;
  updateSelectorUi(target);
}

function handleSelectorClick(event) {
  if (!selectorMode) {
    return;
  }

  const element = event.target;

  if (!element || isVaultyUiElement(element)) {
    return;
  }

  event.preventDefault();
  event.stopPropagation();

  const info = getElementInfo(element);

  stopSelectorMode();

  chrome.runtime.sendMessage({
    type: "ELEMENT_SELECTED",
    element: info,
  });

  console.log("Vaulty selected element:", info);
}

function handleSelectorKeydown(event) {
  if (!selectorMode) {
    return;
  }

  if (event.key === "Escape") {
    event.preventDefault();
    event.stopPropagation();

    stopSelectorMode();
    console.log("Vaulty selector cancelled");
  }
}

function createSelectorUi() {
  removeSelectorUi();

  const host = document.createElement("div");
  host.id = VAULTY_SHADOW_HOST_ID;

  host.style.position = "fixed";
  host.style.inset = "0";
  host.style.zIndex = "2147483647";
  host.style.pointerEvents = "none";

  const shadow = host.attachShadow({ mode: "open" });

  const style = document.createElement("style");
  style.textContent = `
    :host {
      all: initial;
      pointer-events: none;
      position: fixed;
      inset: 0;
      z-index: 2147483647;
    }

    .highlight {
      position: fixed;
      display: none;
      pointer-events: none;
      border: 2px solid #7c5cff;
      border-radius: 6px;
      box-shadow: 0 0 0 3px rgba(124, 92, 255, 0.22);
      background: rgba(124, 92, 255, 0.08);
      transition: top 80ms, left 80ms, width 80ms, height 80ms;
      box-sizing: border-box;
    }

    .badge {
      position: fixed;
      top: 12px;
      left: 12px;
      pointer-events: none;
      padding: 8px 10px;
      border-radius: 999px;
      background: #111318;
      color: #f4f5f7;
      border: 1px solid #2b303b;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
      font: 12px system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0.01em;
      max-width: min(680px, calc(100vw - 24px));
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      box-sizing: border-box;
    }
  `;

  const highlight = document.createElement("div");
  highlight.className = "highlight";

  const badge = document.createElement("div");
  badge.className = "badge";
  badge.textContent = `Vaulty: select ${selectorLabel} · Esc cancels`;

  shadow.appendChild(style);
  shadow.appendChild(highlight);
  shadow.appendChild(badge);

  document.documentElement.appendChild(host);

  selectorUi = {
    host,
    shadow,
    highlight,
    badge,
  };
}

function removeSelectorUi() {
  document.getElementById(VAULTY_SHADOW_HOST_ID)?.remove();

  selectorUi = {
    host: null,
    shadow: null,
    highlight: null,
    badge: null,
  };
}

function installCursorStyle() {
  removeCursorStyle();

  const style = document.createElement("style");
  style.id = VAULTY_CURSOR_STYLE_ID;
  style.textContent = `
    html.vaulty-selector-active,
    html.vaulty-selector-active * {
      cursor: crosshair !important;
    }
  `;

  document.documentElement.classList.add("vaulty-selector-active");
  document.documentElement.appendChild(style);
}

function removeCursorStyle() {
  document.documentElement.classList.remove("vaulty-selector-active");
  document.getElementById(VAULTY_CURSOR_STYLE_ID)?.remove();
}

function updateSelectorUi(element) {
  const { highlight, badge } = selectorUi;

  if (!highlight || !badge || !element || element.nodeType !== Node.ELEMENT_NODE) {
    return;
  }

  const rect = element.getBoundingClientRect();

  if (rect.width <= 0 || rect.height <= 0) {
    highlight.style.display = "none";
    return;
  }

  highlight.style.display = "block";
  highlight.style.top = `${Math.max(0, rect.top)}px`;
  highlight.style.left = `${Math.max(0, rect.left)}px`;
  highlight.style.width = `${rect.width}px`;
  highlight.style.height = `${rect.height}px`;

  const label = describeElement(element);
  badge.textContent = `Vaulty: select ${selectorLabel} · ${label} · Esc cancels`;
}

function refreshHighlight() {
  if (!selectorMode || !hoveredElement) {
    return;
  }

  updateSelectorUi(hoveredElement);
}

function isVaultyUiElement(element) {
  return Boolean(element.closest?.(`#${VAULTY_SHADOW_HOST_ID}`));
}

function describeElement(element) {
  const tag = element.tagName?.toLowerCase() || "element";
  const id = element.id ? `#${element.id}` : "";
  const name = element.getAttribute("name");
  const type = element.getAttribute("type");

  if (type) {
    return `${tag}[type="${type}"]${id}`;
  }

  if (name) {
    return `${tag}[name="${name}"]${id}`;
  }

  return `${tag}${id}`;
}

function getElementInfo(element) {
  return {
    role: selectorRole,
    label: selectorLabel,

    tag: element.tagName?.toLowerCase() || "",
    type: element.getAttribute("type") || "",
    name: element.getAttribute("name") || "",
    id: element.id || "",
    className: typeof element.className === "string" ? element.className : "",
    placeholder: element.getAttribute("placeholder") || "",
    autocomplete: element.getAttribute("autocomplete") || "",
    ariaLabel: element.getAttribute("aria-label") || "",
    htmlRole: element.getAttribute("role") || "",

    text: getCleanText(element),
    selector: buildCssSelector(element),

    url: window.location.href,
    origin: window.location.origin,
    selectedAt: Date.now(),
  };
}

function getCleanText(element) {
  const text = element.innerText || element.textContent || "";
  return text.trim().replace(/\s+/g, " ").slice(0, 120);
}

function buildCssSelector(element) {
  if (!element || element.nodeType !== Node.ELEMENT_NODE) {
    return "";
  }

  if (element.id) {
    return `#${cssEscape(element.id)}`;
  }

  const parts = [];
  let current = element;

  while (
    current &&
    current.nodeType === Node.ELEMENT_NODE &&
    current !== document.body
  ) {
    let part = current.tagName.toLowerCase();

    if (current.className && typeof current.className === "string") {
      const classes = current.className
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 3)
        .map((className) => `.${cssEscape(className)}`)
        .join("");

      part += classes;
    }

    const parent = current.parentElement;

    if (parent) {
      const siblings = Array.from(parent.children).filter(
        (child) => child.tagName === current.tagName
      );

      if (siblings.length > 1) {
        const index = siblings.indexOf(current) + 1;
        part += `:nth-of-type(${index})`;
      }
    }

    parts.unshift(part);

    if (parts.length >= 5) {
      break;
    }

    current = current.parentElement;
  }

  return parts.join(" > ");
}

function fillBySelectors(payload) {
  const mapping = payload.mapping || {};

  const usernameSelector =
    payload.usernameSelector ||
    mapping.username?.selector ||
    "";

  const passwordSelector =
    payload.passwordSelector ||
    mapping.password?.selector ||
    "";

  const username = payload.username ?? "demo@example.com";
  const password = payload.password ?? "demo-password";

  const usernameField = usernameSelector
    ? safeQuerySelector(usernameSelector)
    : null;

  const passwordField = passwordSelector
    ? safeQuerySelector(passwordSelector)
    : null;

  let usernameFilled = false;
  let passwordFilled = false;

  if (usernameField) {
    usernameFilled = setElementValue(usernameField, username);
  }

  if (passwordField) {
    passwordFilled = setElementValue(passwordField, password);
  }

  return {
    ok: usernameFilled || passwordFilled,
    mode: "selectors",
    usernameSelector,
    passwordSelector,
    usernameFound: Boolean(usernameField),
    passwordFound: Boolean(passwordField),
    usernameFilled,
    passwordFilled,
  };
}

function testFill(payload) {
  const username = payload.username || "demo@example.com";
  const password = payload.password || "demo-password";

  const usernameField =
    document.querySelector('input[type="email"]') ||
    document.querySelector('input[name*="user" i]') ||
    document.querySelector('input[name*="email" i]') ||
    document.querySelector('input[autocomplete="username"]');

  const passwordField =
    document.querySelector('input[type="password"]') ||
    document.querySelector('input[autocomplete="current-password"]');

  let usernameFilled = false;
  let passwordFilled = false;

  if (usernameField) {
    usernameFilled = setElementValue(usernameField, username);
  }

  if (passwordField) {
    passwordFilled = setElementValue(passwordField, password);
  }

  return {
    ok: usernameFilled || passwordFilled,
    mode: "heuristic",
    usernameFound: Boolean(usernameField),
    passwordFound: Boolean(passwordField),
    usernameFilled,
    passwordFilled,
  };
}

function validateMapping(payload) {
  const mapping = payload.mapping || {};

  const fieldsToCheck = {
    username: mapping.username || mapping.login?.username || null,
    password: mapping.password || mapping.login?.password || null,

    // Future registration support
    email: mapping.registration?.email || null,
    passwordConfirm: mapping.registration?.passwordConfirm || null,
    submit: mapping.registration?.submit || null,
  };

  const fields = {};

  for (const [role, field] of Object.entries(fieldsToCheck)) {
    if (!field) {
      continue;
    }

    fields[role] = validateStoredField(role, field);
  }

  const values = Object.values(fields);

  const summary = {
    total: values.length,
    found: values.filter((field) => field.found).length,
    missing: values.filter((field) => !field.found).length,
    fillable: values.filter((field) => field.fillable).length,
  };

  return {
    ok: true,
    mode: "validate",
    origin: window.location.origin,
    url: window.location.href,
    fields,
    summary,
  };
}

function validateStoredField(role, field) {
  const selector = field?.selector || "";

  if (!selector) {
    return {
      role,
      selector,
      found: false,
      fillable: false,
      reason: "no-selector",
    };
  }

  const element = safeQuerySelector(selector);

  if (!element) {
    return {
      role,
      selector,
      found: false,
      fillable: false,
      reason: "missing",
    };
  }

  return {
    role,
    selector,
    found: true,
    fillable: isFillableElement(element),
    tag: element.tagName?.toLowerCase() || "",
    type: element.getAttribute("type") || "",
    name: element.getAttribute("name") || "",
    id: element.id || "",
    visible: isVisibleElement(element),
    reason: "found",
  };
}

function isFillableElement(element) {
  if (!element) {
    return false;
  }

  if (element.isContentEditable) {
    return true;
  }

  const tag = element.tagName?.toLowerCase();

  if (tag === "textarea" || tag === "select") {
    return true;
  }

  if (tag !== "input") {
    return false;
  }

  const type = (element.getAttribute("type") || "text").toLowerCase();

  const fillableInputTypes = new Set([
    "text",
    "email",
    "password",
    "search",
    "tel",
    "url",
    "number",
  ]);

  return fillableInputTypes.has(type);
}

function isVisibleElement(element) {
  const rect = element.getBoundingClientRect();
  const style = window.getComputedStyle(element);

  return (
    rect.width > 0 &&
    rect.height > 0 &&
    style.visibility !== "hidden" &&
    style.display !== "none" &&
    Number(style.opacity) !== 0
  );
}

function safeQuerySelector(selector) {
  try {
    return document.querySelector(selector);
  } catch (error) {
    console.warn("Vaulty: invalid selector", selector, error);
    return null;
  }
}

function setElementValue(element, value) {
  if (!element) {
    return false;
  }

  if (element.isContentEditable) {
    element.focus();
    element.textContent = value;
    dispatchInputEvents(element);
    return true;
  }

  const tag = element.tagName?.toLowerCase();

  if (tag !== "input" && tag !== "textarea" && tag !== "select") {
    console.warn("Vaulty: selected element is not fillable", element);
    return false;
  }

  element.focus();
  setNativeValue(element, value);
  dispatchInputEvents(element);

  return true;
}

function setNativeValue(element, value) {
  const prototype = Object.getPrototypeOf(element);
  const descriptor = Object.getOwnPropertyDescriptor(prototype, "value");

  if (descriptor?.set) {
    descriptor.set.call(element, value);
  } else {
    element.value = value;
  }
}

function dispatchInputEvents(element) {
  element.dispatchEvent(new Event("input", { bubbles: true }));
  element.dispatchEvent(new Event("change", { bubbles: true }));
}

function cssEscape(value) {
  if (window.CSS?.escape) {
    return CSS.escape(value);
  }

  return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
}
