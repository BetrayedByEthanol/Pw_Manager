let selectorMode = false;
let selectorRole = "generic";
let selectorLabel = "page element";
let selectorScope = "login";
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

  if (message?.type === "VAULTY_SCAN_PAGE_SECURITY") {
    const result = scanPageSecurity(message.payload || {});
    sendResponse(result);
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

  if (message?.type === "VAULTY_SCAN_LOGIN_FIELDS") {
    const result = scanLoginFields(message.payload || {});
    sendResponse(result);
    return;
  }

  if (message?.type === "VAULTY_FILL_REGISTRATION_PASSWORD") {
    const result = fillRegistrationPassword(message.payload || {});
    sendResponse(result);
    return;
  }

  if (message?.type === "VAULTY_READ_CREDENTIAL_FIELDS") {
    const result = readCredentialFields(message.payload || {});
    sendResponse(result);
    return;
  }

  sendResponse({
    ok: false,
    reason: "unknown-message-type",
  });
});

function scanPageSecurity(payload) {
  const originError = getOriginLockError(payload);

  if (originError) {
    return originError;
  }

  const iframes = detectIframes();
  const oauthProviders = detectOAuthProviders();
  const forms = detectLoginForms();

  return {
    ok: true,
    mode: "page-security-scan",
    origin: window.location.origin,
    url: window.location.href,

    iframes,
    oauthProviders,
    forms,

    summary: {
      iframeCount: iframes.length,
      visibleIframeCount: iframes.filter((frame) => frame.visible).length,
      crossOriginIframeCount: iframes.filter((frame) => frame.likelyCrossOrigin).length,
      oauthProviderCount: oauthProviders.length,
      passwordFieldCount: forms.passwordFieldCount,
      possibleUsernameFieldCount: forms.possibleUsernameFieldCount,
    },
  };
}

function resolveStoredField(role, field) {
  const attempts = buildSelectorFallbacks(role, field);

  for (const attempt of attempts) {
    const element = safeQuerySelector(attempt.selector);

    if (!element) {
      continue;
    }

    const validation = validateElementForFill(role, field, element);

    if (!validation.ok) {
      continue;
    }

    return {
      element,
      resolved: true,
      resolvedBy: attempt.method,
      resolvedSelector: attempt.selector,
      attemptedSelectors: attempts.map((item) => item.selector),
    };
  }

  return {
    element: null,
    resolved: false,
    resolvedBy: "",
    resolvedSelector: "",
    attemptedSelectors: attempts.map((item) => item.selector),
  };
}

function buildSelectorFallbacks(role, field) {
  const attempts = [];
  const seen = new Set();

  function add(method, selector) {
    if (!selector || typeof selector !== "string") {
      return;
    }

    const trimmed = selector.trim();

    if (!trimmed || seen.has(trimmed)) {
      return;
    }

    seen.add(trimmed);
    attempts.push({ method, selector: trimmed });
  }

  add("stored-selector", field?.selector);

  if (field?.id) {
    add("id", `#${cssEscape(field.id)}`);
  }

  if (field?.name) {
    add("name", `[name="${cssEscapeAttribute(field.name)}"]`);
  }

  if (field?.autocomplete) {
    add("autocomplete", `[autocomplete="${cssEscapeAttribute(field.autocomplete)}"]`);
  }

  if (field?.placeholder) {
    add("placeholder", `[placeholder="${cssEscapeAttribute(field.placeholder)}"]`);
  }

  for (const selector of getRoleHeuristicSelectors(role)) {
    add("role-heuristic", selector);
  }

  return attempts;
}

function getRoleHeuristicSelectors(role) {
  if (role === "password" || role === "passwordConfirm") {
    return [
      'input[type="password"]',
      'input[autocomplete="current-password"]',
      'input[autocomplete="new-password"]',
    ];
  }

  if (role === "email") {
    return [
      'input[type="email"]',
      'input[autocomplete="email"]',
      'input[name*="email" i]',
      'input[id*="email" i]',
      'input[placeholder*="email" i]',
    ];
  }

  if (role === "username") {
    return [
      'input[autocomplete="username"]',
      'input[type="email"]',
      'input[name*="email" i]',
      'input[id*="email" i]',
      'input[name*="user" i]',
      'input[id*="user" i]',
      'input[name*="login" i]',
      'input[id*="login" i]',
      'input[type="text"]',
    ];
  }

  return [];
}

function cssEscapeAttribute(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function startSelectorMode(message) {
  if (selectorMode) {
    stopSelectorMode();
  }

  selectorMode = true;
  selectorRole = message.role || "generic";
  selectorLabel = message.label || "page element";
  selectorScope = message.scope || "login";
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
    scope: selectorScope,
    role: selectorRole,
    label: selectorLabel,

    tag: element.tagName?.toLowerCase() || "",
    type: getNormalizedElementType(element),
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

function getNearbyText(element) {
  const parts = [];

  if (element.labels) {
    for (const label of Array.from(element.labels)) {
      parts.push(label.innerText || label.textContent || "");
    }
  }

  const parent = element.parentElement;

  if (parent) {
    parts.push(parent.innerText || parent.textContent || "");
  }

  const previous = element.previousElementSibling;
  const next = element.nextElementSibling;

  if (previous) {
    parts.push(previous.innerText || previous.textContent || "");
  }

  if (next) {
    parts.push(next.innerText || next.textContent || "");
  }

  return parts
    .join(" ")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, 160);
}

function fillBySelectors(payload) {
  const originError = getOriginLockError(payload);

  if (originError) {
    console.warn("Vaulty: blocked fill due to origin lock", originError);
    return originError;
  }

  const mapping = payload.mapping || {};

  const usernameField =
    mapping.username ||
    mapping.login?.username ||
    null;

  const passwordField =
    mapping.password ||
    mapping.login?.password ||
    null;

  const username = payload.username;
  const password = payload.password;

  const usernameResult = usernameField
    ? fillMappedField("username", usernameField, username)
    : {
        ok: false,
        filled: false,
        role: "username",
        reason: "no-username-mapping",
      };

  const passwordResult = passwordField
    ? fillMappedField("password", passwordField, password)
    : {
        ok: false,
        filled: false,
        role: "password",
        reason: "no-password-mapping",
      };

  return {
    ok: usernameResult.filled || passwordResult.filled,
    mode: "selectors",

    usernameFound: usernameResult.reason !== "missing",
    passwordFound: passwordResult.reason !== "missing",

    usernameFilled: usernameResult.filled,
    passwordFilled: passwordResult.filled,

    fields: {
      username: usernameResult,
      password: passwordResult,
    },
  };
}

function testFill(payload) {
  const username = payload.username
  const password = payload.password;

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
  const originError = getOriginLockError(payload);

  if (originError) {
    return originError;
  }

  const mapping = payload.mapping || {};

  const fieldsToCheck = {
    loginUsername: {
      role: "username",
      field: mapping.login?.username || mapping.username || null,
    },
    loginPassword: {
      role: "password",
      field: mapping.login?.password || mapping.password || null,
    },

    registrationEmail: {
      role: "email",
      field: mapping.registration?.email || null,
    },
    registrationUsername: {
      role: "username",
      field: mapping.registration?.username || null,
    },
    registrationPassword: {
      role: "password",
      field: mapping.registration?.password || null,
    },
    registrationPasswordConfirm: {
      role: "passwordConfirm",
      field: mapping.registration?.passwordConfirm || null,
    },
    registrationSubmit: {
      role: "submit",
      field: mapping.registration?.submit || null,
    },
  };

  const fields = {};

  for (const [key, config] of Object.entries(fieldsToCheck)) {
    if (!config.field) {
      continue;
    }

    fields[key] = validateStoredField(config.role, config.field);
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
    iframeWarnings: detectIframes(),
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
      visible: false,
      enabled: false,
      readOnly: false,
      hiddenInput: false,
      interactable: false,
      roleSafe: false,
      stable: false,
      drift: {
        stable: false,
        mismatchCount: 0,
        mismatches: [],
      },
      reason: "no-selector",
    };
  }

  const resolution = resolveStoredField(role, field);
  const element = resolution.element;

  if (!element) {
    return {
      role,
      selector,
      found: false,
      resolved: false,
      resolvedBy: "",
      resolvedSelector: "",
      attemptedSelectors: resolution.attemptedSelectors,

      fillable: false,
      visible: false,
      enabled: false,
      readOnly: false,
      hiddenInput: false,
      interactable: false,
      roleSafe: false,
      stable: false,
      drift: {
        stable: false,
        mismatchCount: 0,
        mismatches: [],
      },
      reason: "missing",
    };
  }

  const visible = isVisibleElement(element);
  const enabled = isEnabledElement(element);
  const readOnly = isReadOnlyElement(element);
  const hiddenInput = isHiddenInput(element);
  const fillable = isFillableElement(element);
  const roleSafe = isSafeElementForRole(role, element);
  const drift = compareStoredFieldToLiveElement(field, element);

  const interactable =
    role === "submit"
      ? isClickableElement(element)
      : isInteractableElement(element);


  return {
    role,
    selector,

    found: true,
    fillable,
    visible,
    enabled,
    readOnly,
    hiddenInput,
    interactable,
    roleSafe,

    stable: drift.stable,
    drift,

    resolved: true,
    resolvedBy: resolution.resolvedBy,
    resolvedSelector: resolution.resolvedSelector,
    attemptedSelectors: resolution.attemptedSelectors,

    tag: element.tagName?.toLowerCase() || "",
    type: getNormalizedElementType(element),
    name: element.getAttribute("name") || "",
    id: element.id || "",
    autocomplete: element.getAttribute("autocomplete") || "",
    placeholder: element.getAttribute("placeholder") || "",

    reason: getValidationReason({
      interactable,
      roleSafe,
      drift,
    }),
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

  if (!isInteractableElement(element)) {
    console.warn("Vaulty: blocked fill because element is not interactable", {
      tag: element.tagName?.toLowerCase() || "",
      type: element.getAttribute("type") || "",
      name: element.getAttribute("name") || "",
      id: element.id || "",
      visible: isVisibleElement(element),
      enabled: isEnabledElement(element),
      readOnly: isReadOnlyElement(element),
      hiddenInput: isHiddenInput(element),
      fillable: isFillableElement(element),
    });


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

function isEnabledElement(element) {
  if (!element) {
    return false;
  }

  if (element.disabled) {
    return false;
  }

  if (element.getAttribute("aria-disabled") === "true") {
    return false;
  }

  return true;
}

function isReadOnlyElement(element) {
  return Boolean(element.readOnly || element.getAttribute("readonly") !== null);
}

function isHiddenInput(element) {
  const tag = element.tagName?.toLowerCase();
  const type = (element.getAttribute("type") || "").toLowerCase();

  return tag === "input" && type === "hidden";
}

function isInteractableElement(element) {
  return (
    isFillableElement(element) &&
    isVisibleElement(element) &&
    isEnabledElement(element) &&
    !isReadOnlyElement(element) &&
    !isHiddenInput(element)
  );
}

function compareStoredFieldToLiveElement(field, element) {
  const mismatches = [];

  const checks = [
    ["tag", element.tagName?.toLowerCase() || ""],
    ["type", getNormalizedElementType(element)],
    ["name", element.getAttribute("name") || ""],
    ["id", element.id || ""],
    ["autocomplete", element.getAttribute("autocomplete") || ""],
    ["placeholder", element.getAttribute("placeholder") || ""],
  ];

  for (const [key, liveValue] of checks) {
    const storedValue = field?.[key] || "";

    // Only compare attributes we actually captured originally.
    if (!storedValue) {
      continue;
    }

    if (String(storedValue) !== String(liveValue || "")) {
      mismatches.push({
        key,
        stored: String(storedValue),
        live: String(liveValue || ""),
      });
    }
  }

  return {
    stable: mismatches.length === 0,
    mismatchCount: mismatches.length,
    mismatches,
  };
}

function detectIframes() {
  const iframes = Array.from(document.querySelectorAll("iframe"));

  return iframes.map((iframe, index) => {
    const src = iframe.getAttribute("src") || "";
    const rect = iframe.getBoundingClientRect();

    let sameOriginAccessible = false;

    try {
      sameOriginAccessible = Boolean(iframe.contentDocument);
    } catch {
      sameOriginAccessible = false;
    }

    const frameOrigin = src ? safeOriginFromPage(src) : "";
    const likelyCrossOrigin =
      Boolean(frameOrigin) && frameOrigin !== window.location.origin;

    return {
      index,
      src,
      origin: frameOrigin,
      visible: isVisibleElement(iframe),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      sameOriginAccessible,
      likelyCrossOrigin,
    };
  });
}

function safeOrigin(url) {
  try {
    return new URL(url, window.location.href).origin;
  } catch {
    return "";
  }
}

function getOriginLockError(payload) {
  const expectedOrigin = payload?.origin || "";
  const actualOrigin = window.location.origin;

  if (!expectedOrigin) {
    return {
      ok: false,
      reason: "missing-origin",
      actualOrigin,
    };
  }

  if (expectedOrigin !== actualOrigin) {
    return {
      ok: false,
      reason: "origin-mismatch",
      expectedOrigin,
      actualOrigin,
      url: window.location.href,
    };
  }

  return null;
}

function isSafeElementForRole(role, element) {
  if (!element) {
    return false;
  }

  const tag = element.tagName?.toLowerCase() || "";
  const type = (element.getAttribute("type") || "text").toLowerCase();
  const htmlRole = element.getAttribute("role") || "";

  if (role === "submit") {
    return (
      tag === "button" ||
      tag === "a" ||
      htmlRole === "button" ||
      (tag === "input" && (type === "submit" || type === "button"))
    );
  }

  if (role === "password") {
    return tag === "input" && type === "password";
  }

  if (role === "passwordConfirm") {
    return tag === "input" && type === "password";
  }

  if (role === "username" || role === "email") {
    return (
      isFillableElement(element) &&
      type !== "password" &&
      type !== "hidden"
    );
  }

  return isFillableElement(element);
}

function scanLoginFields(payload) {
  const originError = getOriginLockError(payload);

  if (originError) {
    return originError;
  }

  const candidates = getFillableInputCandidates();

  const usernameCandidates = candidates
    .map((candidate) => scoreUsernameCandidate(candidate))
    .filter((candidate) => candidate.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  const passwordCandidates = candidates
    .map((candidate) => scorePasswordCandidate(candidate))
    .filter((candidate) => candidate.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  const bestUsername = usernameCandidates[0] || null;
  const bestPassword = passwordCandidates[0] || null;

  const confidence = calculateLoginScanConfidence(bestUsername, bestPassword);

  return {
    ok: true,
    mode: "login-field-scan",
    origin: window.location.origin,
    url: window.location.href,

    usernameCandidates,
    passwordCandidates,

    best: {
      username: bestUsername,
      password: bestPassword,
    },

    confidence,
    hasLikelyLoginForm: Boolean(bestPassword && confidence >= 0.45),
  };
}

function getFillableInputCandidates() {
  const elements = Array.from(
    document.querySelectorAll("input, textarea, [contenteditable='true']")
  );

  return elements
    .filter((element) => isInteractableElement(element))
    .map((element, index) => toFieldCandidate(element, index));
}

function toFieldCandidate(element, index) {
  const tag = element.tagName?.toLowerCase() || "";
  const type = (element.getAttribute("type") || "text").toLowerCase();
  const name = element.getAttribute("name") || "";
  const id = element.id || "";
  const autocomplete = element.getAttribute("autocomplete") || "";
  const placeholder = element.getAttribute("placeholder") || "";
  const ariaLabel = element.getAttribute("aria-label") || "";
  const htmlRole = element.getAttribute("role") || "";
  const text = getNearbyText(element);
  const selector = buildCssSelector(element);
  const rect = element.getBoundingClientRect();

  return {
    index,
    selector,
    tag,
    type,
    name,
    id,
    autocomplete,
    placeholder,
    ariaLabel,
    htmlRole,
    text,
    visible: isVisibleElement(element),
    enabled: isEnabledElement(element),
    fillable: isFillableElement(element),
    interactable: isInteractableElement(element),
    width: Math.round(rect.width),
    height: Math.round(rect.height),
  };
}

function validateElementForFill(role, field, element) {
  if (!element) {
    return {
      ok: false,
      role,
      reason: "missing",
    };
  }

  const visible = isVisibleElement(element);
  const enabled = isEnabledElement(element);
  const readOnly = isReadOnlyElement(element);
  const hiddenInput = isHiddenInput(element);
  const fillable = isFillableElement(element);
  const interactable = isInteractableElement(element);
  const roleSafe = isSafeElementForRole(role, element);

  return {
    ok: interactable && roleSafe,
    role,
    reason: interactable && roleSafe ? "ready" : "unsafe-target",

    visible,
    enabled,
    readOnly,
    hiddenInput,
    fillable,
    interactable,
    roleSafe,

    tag: element.tagName?.toLowerCase() || "",
    type: element.getAttribute("type") || "",
    name: element.getAttribute("name") || "",
    id: element.id || "",
    selector: field?.selector || "",
  };
}

function fillMappedField(role, field, value) {
  const selector = field?.selector || "";

  if (!selector) {
    return {
      ok: false,
      filled: false,
      role,
      reason: "missing-selector",
    };
  }

  const resolution = resolveStoredField(role, field);
  const element = resolution.element;
  const validation = validateElementForFill(role, field, element);

  if (!validation.ok) {
    console.warn("Vaulty: blocked unsafe fill target", {
      ...validation,
      resolvedBy: resolution.resolvedBy,
      resolvedSelector: resolution.resolvedSelector,
    });

    return {
      ...validation,
      resolved: resolution.resolved,
      resolvedBy: resolution.resolvedBy,
      resolvedSelector: resolution.resolvedSelector,
      attemptedSelectors: resolution.attemptedSelectors,
      filled: false,
    };
  }

  const filled = setElementValue(element, value);

  return {
    ...validation,
    resolved: resolution.resolved,
    resolvedBy: resolution.resolvedBy,
    resolvedSelector: resolution.resolvedSelector,
    attemptedSelectors: resolution.attemptedSelectors,
    ok: filled,
    filled,
    reason: filled ? "filled" : "fill-failed",
  };
}

function getValidationReason({ interactable, roleSafe, drift }) {
  if (!interactable) {
    return "not-interactable";
  }

  if (!roleSafe) {
    return "unsafe-role-target";
  }

  if (!drift?.stable) {
    return "field-drift";
  }

  return "ready";
}

function detectOAuthProviders() {
  const providers = [
    {
      id: "google",
      label: "Google",
      patterns: [
        "accounts.google.com",
        "continue with google",
        "sign in with google",
        "login with google",
      ],
    },
    {
      id: "github",
      label: "GitHub",
      patterns: [
        "github.com/login",
        "continue with github",
        "sign in with github",
        "login with github",
      ],
    },
    {
      id: "microsoft",
      label: "Microsoft",
      patterns: [
        "login.microsoftonline.com",
        "live.com",
        "continue with microsoft",
        "sign in with microsoft",
        "login with microsoft",
      ],
    },
    {
      id: "apple",
      label: "Apple",
      patterns: [
        "appleid.apple.com",
        "continue with apple",
        "sign in with apple",
        "login with apple",
      ],
    },
    {
      id: "facebook",
      label: "Facebook",
      patterns: [
        "facebook.com",
        "continue with facebook",
        "sign in with facebook",
        "login with facebook",
      ],
    },
  ];

  const pageText = getPageTextForSecurityScan();
  const linksAndButtons = getLinkButtonHints();

  const haystack = [
    window.location.href,
    pageText,
    linksAndButtons.join(" "),
  ]
    .join(" ")
    .toLowerCase();

  const found = [];

  for (const provider of providers) {
    const matchedPattern = provider.patterns.find((pattern) =>
      haystack.includes(pattern.toLowerCase())
    );

    if (matchedPattern) {
      found.push({
        id: provider.id,
        label: provider.label,
        matchedPattern,
      });
    }
  }

  return found;
}

function getPageTextForSecurityScan() {
  const text = document.body?.innerText || "";
  return text.trim().replace(/\s+/g, " ").slice(0, 5000);
}

function getLinkButtonHints() {
  const elements = Array.from(
    document.querySelectorAll("a, button, [role='button'], input[type='button'], input[type='submit']")
  );

  return elements.slice(0, 200).map((element) => {
    const href = element.getAttribute("href") || "";
    const aria = element.getAttribute("aria-label") || "";
    const title = element.getAttribute("title") || "";
    const value = element.getAttribute("value") || "";
    const text = element.innerText || element.textContent || "";

    return [href, aria, title, value, text]
      .join(" ")
      .trim()
      .replace(/\s+/g, " ")
      .slice(0, 300);
  });
}

function detectLoginForms() {
  const inputs = Array.from(document.querySelectorAll("input, textarea"));

  const passwordFields = inputs.filter((input) => {
    const type = (input.getAttribute("type") || "").toLowerCase();
    return type === "password";
  });

  const possibleUsernameFields = inputs.filter((input) => {
    const type = (input.getAttribute("type") || "text").toLowerCase();
    const name = (input.getAttribute("name") || "").toLowerCase();
    const id = (input.id || "").toLowerCase();
    const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
    const placeholder = (input.getAttribute("placeholder") || "").toLowerCase();

    if (type === "password" || type === "hidden") {
      return false;
    }

    const combined = `${type} ${name} ${id} ${autocomplete} ${placeholder}`;

    return (
      type === "email" ||
      combined.includes("email") ||
      combined.includes("user") ||
      combined.includes("login") ||
      combined.includes("account") ||
      autocomplete === "username"
    );
  });

  return {
    passwordFieldCount: passwordFields.length,
    possibleUsernameFieldCount: possibleUsernameFields.length,
    hasLikelyLoginForm: passwordFields.length > 0,
  };
}

function safeOriginFromPage(url) {
  try {
    return new URL(url, window.location.href).origin;
  } catch {
    return "";
  }
}

function scoreUsernameCandidate(candidate) {
  let score = 0;
  const reasons = [];

  const haystack = candidateHaystack(candidate);

  if (candidate.type === "email") {
    score += 35;
    reasons.push("type=email");
  }

  if (candidate.autocomplete === "username") {
    score += 40;
    reasons.push("autocomplete=username");
  }

  if (candidate.autocomplete === "email") {
    score += 35;
    reasons.push("autocomplete=email");
  }

  if (containsAny(haystack, ["email", "e-mail", "mail"])) {
    score += 30;
    reasons.push("email keyword");
  }

  if (containsAny(haystack, ["user", "username", "login", "account"])) {
    score += 24;
    reasons.push("username keyword");
  }

  if (candidate.type === "text") {
    score += 8;
    reasons.push("type=text");
  }

  if (candidate.type === "password" || candidate.type === "hidden") {
    score -= 100;
    reasons.push("bad type for username");
  }

  if (!candidate.interactable) {
    score -= 100;
    reasons.push("not interactable");
  }

  return {
    ...candidate,
    role: "username",
    score: clampScore(score),
    confidence: scoreToConfidence(score),
    reasons,
  };
}

function scorePasswordCandidate(candidate) {
  let score = 0;
  const reasons = [];

  const haystack = candidateHaystack(candidate);

  if (candidate.type === "password") {
    score += 70;
    reasons.push("type=password");
  }

  if (candidate.autocomplete === "current-password") {
    score += 25;
    reasons.push("autocomplete=current-password");
  }

  if (candidate.autocomplete === "new-password") {
    score += 12;
    reasons.push("autocomplete=new-password");
  }

  if (containsAny(haystack, ["password", "passwort", "passcode"])) {
    score += 20;
    reasons.push("password keyword");
  }

  if (candidate.type !== "password") {
    score -= 80;
    reasons.push("not password type");
  }

  if (!candidate.interactable) {
    score -= 100;
    reasons.push("not interactable");
  }

  return {
    ...candidate,
    role: "password",
    score: clampScore(score),
    confidence: scoreToConfidence(score),
    reasons,
  };
}

function candidateHaystack(candidate) {
  return [
    candidate.type,
    candidate.name,
    candidate.id,
    candidate.autocomplete,
    candidate.placeholder,
    candidate.ariaLabel,
    candidate.htmlRole,
    candidate.text,
  ]
    .join(" ")
    .toLowerCase();
}

function containsAny(value, needles) {
  return needles.some((needle) => value.includes(needle));
}

function clampScore(score) {
  return Math.max(0, Math.min(100, score));
}

function scoreToConfidence(score) {
  return Math.max(0, Math.min(1, score / 100));
}

function calculateLoginScanConfidence(username, password) {
  if (!password) {
    return 0;
  }

  const passwordConfidence = password.confidence || 0;
  const usernameConfidence = username?.confidence || 0;

  if (!username) {
    return Math.min(0.7, passwordConfidence);
  }

  return Math.min(1, passwordConfidence * 0.6 + usernameConfidence * 0.4);
}

function getNormalizedElementType(element) {
  const tag = element.tagName?.toLowerCase() || "";

  if (tag !== "input") {
    return element.getAttribute("type") || "";
  }

  return (element.getAttribute("type") || "text").toLowerCase();
}

function readCredentialFields(payload) {
  const originError = getOriginLockError(payload);

  if (originError) {
    return originError;
  }

  const mapping = payload.mapping || {};
  const registration = mapping.registration || {};
  const login = mapping.login || {};

  const emailResult = readMappedFieldValue("email", registration.email || null);
  const registrationUsernameResult = readMappedFieldValue(
    "username",
    registration.username || null
  );
  const loginUsernameResult = readMappedFieldValue("username", login.username || null);
  const registrationPasswordResult = readMappedFieldValue(
    "password",
    registration.password || null
  );
  const registrationPasswordConfirmResult = readMappedFieldValue(
    "passwordConfirm",
    registration.passwordConfirm || null
  );
  const loginPasswordResult = readMappedFieldValue("password", login.password || null);

  const email = emailResult.value || "";
  const username =
    registrationUsernameResult.value ||
    loginUsernameResult.value ||
    email ||
    "";
  const password =
    registrationPasswordResult.value ||
    loginPasswordResult.value ||
    "";
  const passwordConfirm = registrationPasswordConfirmResult.value || "";
  const passwordConfirmMapped = Boolean(registration.passwordConfirm);
  const passwordsMatch = !passwordConfirmMapped || (Boolean(password) && password === passwordConfirm);

  return {
    ok: true,
    mode: "read-credential-fields",
    origin: window.location.origin,
    url: window.location.href,

    credential: {
      origin: window.location.origin,
      url: window.location.href,
      email,
      username,
      password,
    },

    summary: {
      hasEmail: Boolean(email),
      hasUsername: Boolean(username),
      hasPassword: Boolean(password),
      hasPasswordConfirm: Boolean(passwordConfirm),
      passwordConfirmMapped,
      passwordsMatch,
      source: {
        email: emailResult.source,
        username: registrationUsernameResult.value
          ? "registration.username"
          : loginUsernameResult.value
            ? "login.username"
            : email
              ? "registration.email"
              : "",
        password: registrationPasswordResult.value
          ? "registration.password"
          : loginPasswordResult.value
            ? "login.password"
            : "",
        passwordConfirm: registrationPasswordConfirmResult.source,
      },
    },

    // No field values are included here. The actual password appears only in credential.password
    // so the later native-host relay can receive it without leaking it into debug metadata.
    fields: {
      email: redactReadResult(emailResult),
      registrationUsername: redactReadResult(registrationUsernameResult),
      loginUsername: redactReadResult(loginUsernameResult),
      registrationPassword: redactReadResult(registrationPasswordResult),
      registrationPasswordConfirm: redactReadResult(registrationPasswordConfirmResult),
      loginPassword: redactReadResult(loginPasswordResult),
    },
  };
}

function readMappedFieldValue(role, field) {
  if (!field) {
    return {
      ok: false,
      found: false,
      hasValue: false,
      value: "",
      source: "",
      reason: "not-mapped",
    };
  }

  const resolution = resolveStoredField(role, field);
  const element = resolution.element;

  if (!element) {
    return {
      ok: false,
      found: false,
      hasValue: false,
      value: "",
      source: field.scope ? `${field.scope}.${role}` : role,
      resolvedBy: resolution.resolvedBy,
      attemptedSelectors: resolution.attemptedSelectors,
      reason: "missing",
    };
  }

  const validation = validateElementForCredentialRead(role, field, element);

  if (!validation.ok) {
    return {
      ...validation,
      found: true,
      hasValue: false,
      value: "",
      source: field.scope ? `${field.scope}.${role}` : role,
      resolvedBy: resolution.resolvedBy,
      resolvedSelector: resolution.resolvedSelector,
      reason: validation.reason,
    };
  }

  const value = getElementCredentialValue(element).trim();

  return {
    ok: true,
    found: true,
    hasValue: Boolean(value),
    value,
    source: field.scope ? `${field.scope}.${role}` : role,
    resolvedBy: resolution.resolvedBy,
    resolvedSelector: resolution.resolvedSelector,
    reason: value ? "read" : "empty",
  };
}

function validateElementForCredentialRead(role, field, element) {
  const visible = isVisibleElement(element);
  const enabled = isEnabledElement(element);
  const hiddenInput = isHiddenInput(element);
  const fillable = isFillableElement(element);
  const roleSafe = isSafeElementForRole(role, element);

  const ok = visible && enabled && !hiddenInput && fillable && roleSafe;

  return {
    ok,
    role,
    visible,
    enabled,
    hiddenInput,
    fillable,
    roleSafe,
    reason: ok ? "ready" : "unsafe-read-target",
    selector: field?.selector || "",
  };
}

function getElementCredentialValue(element) {
  if (!element) {
    return "";
  }

  if (element.isContentEditable) {
    return element.textContent || "";
  }

  if ("value" in element) {
    return String(element.value || "");
  }

  return "";
}

function redactReadResult(result) {
  return {
    ok: Boolean(result?.ok),
    found: Boolean(result?.found),
    hasValue: Boolean(result?.hasValue),
    source: result?.source || "",
    resolvedBy: result?.resolvedBy || "",
    reason: result?.reason || "",
  };
}

function fillRegistrationPassword(payload) {
  const originError = getOriginLockError(payload);

  if (originError) {
    console.warn("Vaulty: blocked registration password fill due to origin lock", originError);
    return originError;
  }

  const mapping = payload.mapping || {};
  const registration = mapping.registration || {};
  const password = payload.password || "";

  if (!password) {
    return {
      ok: false,
      reason: "missing-password",
    };
  }

  const passwordField = registration.password || null;
  const confirmField = registration.passwordConfirm || null;

  const passwordResult = passwordField
    ? fillMappedField("password", passwordField, password)
    : {
        ok: false,
        filled: false,
        role: "password",
        reason: "no-registration-password-mapping",
      };

  const confirmResult = confirmField
    ? fillMappedField("passwordConfirm", confirmField, password)
    : {
        ok: false,
        filled: false,
        role: "passwordConfirm",
        reason: "no-registration-confirm-password-mapping",
      };

  return {
    ok: passwordResult.filled || confirmResult.filled,
    mode: "registration-password-fill",

    passwordFilled: passwordResult.filled,
    passwordConfirmFilled: confirmResult.filled,

    fields: {
      password: passwordResult,
      passwordConfirm: confirmResult,
    },
  };
}
