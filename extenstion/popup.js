let latestLoginScan = null;

const STORAGE_KEYS = {
  lastSelected: "vaulty.lastSelectedElement",
  selectionIntent: "vaulty.selectionIntent",
  siteMappings: "vaulty.siteMappings",
};

const SELECTOR_BUTTONS = [
  {
    id: "select",
    role: "generic",
    label: "page element",
  },
  {
    id: "select-username",
    role: "username",
    label: "username field",
  },
  {
    id: "select-password",
    role: "password",
    label: "password field",
  },
];

document.addEventListener("DOMContentLoaded", async () => {
  ensureSiteMappingUi();

  wireSelectorButtons();
  wireTestFillButton();
  wireClearMappingButton();
  wireUseDetectedLoginFieldsButton();

  await renderPopupState();
});

function ensureSiteMappingUi() {
  if (document.getElementById("site-mapping-card")) {
    return;
  }

  const footer = document.querySelector(".footer");

  const card = document.createElement("section");
  card.id = "site-mapping-card";
  card.className = "card";

  card.innerHTML = `
    <div class="card-title">Current site mapping</div>

    <div id="site-origin" class="empty">
      No active site.
    </div>

    <div id="page-security-warning" class="empty" hidden style="margin-top: 8px; color: #ffcc66;">
    </div>

    <div id="login-scan-result" class="empty" hidden style="margin-top: 8px;">
    </div>

    <button id="use-detected-login-fields" class="secondary full" type="button" hidden>
      Use detected login fields
    </button>

    <div id="site-mapping-empty" class="empty" style="margin-top: 8px;">
      No username/password fields stored for this site yet.
    </div>

    <div id="site-mapping-details" class="field-list" hidden style="margin-top: 8px;">
      <div class="field-row">
        <span class="field-label">Username</span>
        <span id="mapping-username" class="field-value">—</span>
      </div>

      <div class="field-row">
        <span class="field-label">Password</span>
        <span id="mapping-password" class="field-value">—</span>
      </div>

      <div class="field-row">
        <span class="field-label">Updated</span>
        <span id="mapping-updated" class="field-value">—</span>
      </div>

      <button id="clear-mapping" class="secondary full" type="button">
        Clear site mapping
      </button>
    </div>
  `;

  if (footer) {
    footer.before(card);
  } else {
    document.querySelector(".app")?.appendChild(card);
  }
}

function wireSelectorButtons() {
  for (const config of SELECTOR_BUTTONS) {
    const button = document.getElementById(config.id);

    if (!button) {
      console.warn(`Vaulty popup: missing button #${config.id}`);
      continue;
    }

    button.addEventListener("click", async () => {
      await startSelector(config.role, config.label, button);
    });
  }
}

function wireTestFillButton() {
  const button = document.getElementById("test-fill");

  if (!button) {
    console.warn("Vaulty popup: missing button #test-fill");
    return;
  }

  button.addEventListener("click", async () => {
    const tab = await getActiveTab();

    if (!tab?.id || !isSelectablePage(tab.url)) {
      flashButton(button, "Unavailable");
      return;
    }

    const origin = safeOrigin(tab.url);

    if (!origin) {
      flashButton(button, "No site");
      return;
    }

    const mappingResponse = await sendMessageToBackground({
      type: "GET_SITE_MAPPING",
      origin,
    });

    const mapping = mappingResponse?.mapping || null;

    if (!mapping?.username?.selector && !mapping?.password?.selector) {
      flashButton(button, "Map fields first");
      return;
    }

  const fillResponse = await sendMessageToTab(tab.id, {
    type: "VAULTY_FILL_BY_SELECTORS",
    payload: {
      origin,
      mapping,
      username: "demo@example.com",
      password: "demo-password",
    },
  });

    if (fillResponse?.ok) {
      flashButton(button, "Filled");
      console.log("Vaulty popup: fill result", fillResponse);
    } else if (fillResponse) {
      flashButton(button, "Fields missing");
      console.warn("Vaulty popup: fill failed", fillResponse);
    } else {
      flashButton(button, "No content script");
    }
  });
}

function wireClearMappingButton() {
  const button = document.getElementById("clear-mapping");

  if (!button) {
    return;
  }

  button.addEventListener("click", async () => {
    const tab = await getActiveTab();
    const origin = safeOrigin(tab?.url);

    if (!origin) {
      flashButton(button, "No site");
      return;
    }

    const response = await sendMessageToBackground({
      type: "CLEAR_SITE_MAPPING",
      origin,
    });

    if (response?.ok) {
      flashButton(button, "Cleared");
      await renderPopupState();
    } else {
      flashButton(button, "Failed");
    }
  });
}

function wireUseDetectedLoginFieldsButton() {
  const button = document.getElementById("use-detected-login-fields");

  if (!button) {
    return;
  }

  button.addEventListener("click", async () => {
    const tab = await getActiveTab();
    const origin = safeOrigin(tab?.url);

    if (!tab?.id || !origin || !isSelectablePage(tab.url)) {
      flashButton(button, "Unavailable");
      return;
    }

    let scan = latestLoginScan;

    if (!scan?.ok || !scan.best?.password) {
      scan = await sendMessageToTab(tab.id, {
        type: "VAULTY_SCAN_LOGIN_FIELDS",
        payload: { origin },
      });
    }

    if (!scan?.ok || !scan.best?.password) {
      flashButton(button, "No login found");
      return;
    }

    const response = await sendMessageToBackground({
      type: "SAVE_DETECTED_LOGIN_MAPPING",
      origin,
      url: tab.url,
      username: scan.best.username || null,
      password: scan.best.password || null,
    });

    if (response?.ok) {
      flashButton(button, "Saved");
      await renderPopupState();
    } else {
      console.warn("Vaulty popup: failed to save detected mapping", response);
      flashButton(button, "Save failed");
    }
  });
}

async function renderPopupState() {
  await renderPageSecurityWarning();
  await renderLoginScanResult();
  await renderLastSelectedElement();
  await renderCurrentSiteMapping();
}

async function startSelector(role, label, button) {
  const tab = await getActiveTab();

  if (!tab?.id || !isSelectablePage(tab.url)) {
    flashButton(button, "Unavailable");
    return;
  }

  const intent = {
    role,
    label,
    tabId: tab.id,
    url: tab.url,
    origin: safeOrigin(tab.url),
    startedAt: Date.now(),
  };

  await storageSet({
    [STORAGE_KEYS.selectionIntent]: intent,
  });

  const response = await sendMessageToTab(tab.id, {
    type: "START_SELECTOR",
    role,
    label,
  });

  if (response?.ok) {
    flashButton(button, "Click page");
    window.close();
  } else {
    flashButton(button, "No content script");
  }
}

async function renderLastSelectedElement() {
  const result = await storageGet(STORAGE_KEYS.lastSelected);
  const selected = result?.[STORAGE_KEYS.lastSelected];

  const empty = document.getElementById("selected-empty");
  const details = document.getElementById("selected-details");

  if (!empty || !details) {
    return;
  }

  if (!selected) {
    empty.hidden = false;
    details.hidden = true;
    return;
  }

  empty.hidden = true;
  details.hidden = false;

  setText("selected-tag", selected.tag || "—");
  setText("selected-type", selected.type || selected.role || "—");
  setText("selected-id", selected.id || "—");
  setText("selected-class", selected.className || "—");
  setText(
    "selected-text",
    selected.text || selected.placeholder || selected.name || selected.selector || "—"
  );
}

async function renderCurrentSiteMapping() {
  const tab = await getActiveTab();
  const origin = safeOrigin(tab?.url);

  const siteOrigin = document.getElementById("site-origin");
  const empty = document.getElementById("site-mapping-empty");
  const details = document.getElementById("site-mapping-details");

  if (!siteOrigin || !empty || !details) {
    return;
  }

  if (!origin || !isSelectablePage(tab?.url)) {
    siteOrigin.textContent = "This page cannot be mapped.";
    empty.hidden = false;
    details.hidden = true;
    return;
  }

  siteOrigin.textContent = origin;

  const response = await sendMessageToBackground({
    type: "GET_SITE_MAPPING",
    origin,
  });

  const mapping = response?.mapping || null;

  if (!mapping || (!mapping.username && !mapping.password)) {
    empty.hidden = false;
    details.hidden = true;
    return;
  }

  const validation = await validateCurrentMapping(tab.id, origin, mapping);
  
  if (validation?.fields) {
    for (const [role, result] of Object.entries(validation.fields)) {
      if (result?.drift && !result.drift.stable) {
        console.warn(`Vaulty: ${role} field drift detected`, result.drift);
      }
    }
  }
  
  empty.hidden = true;
  details.hidden = false;

  setText(
    "mapping-username",
    formatStoredField(mapping.username, validation?.fields?.username)
  );

  setText(
    "mapping-password",
    formatStoredField(mapping.password, validation?.fields?.password)
  );

  setText("mapping-updated", formatTimestamp(mapping.updatedAt));
}

async function validateCurrentMapping(tabId, origin, mapping) {
  if (!tabId || !origin || !mapping) {
    return null;
  }

  const response = await sendMessageToTab(tabId, {
    type: "VAULTY_VALIDATE_MAPPING",
    payload: {
      origin,
      mapping,
    },
  });

  if (!response?.ok) {
    return null;
  }

  return response;
}

function formatStoredField(field, validation = null) {
  if (!field) {
    return "—";
  }

  let base = "stored";

  if (field.selector) {
    base = field.selector;
  } else if (field.id) {
    base = `#${field.id}`;
  } else if (field.name) {
    base = `[name="${field.name}"]`;
  } else if (field.tag) {
    base = field.tag;
  }

  if (!validation) {
    return `${base} · ?`;
  }

  if (!validation.found) {
    return `${base} ❌ missing`;
  }

  if (!validation.visible) {
    return `${base} ⚠️ hidden`;
  }

  if (!validation.enabled) {
    return `${base} ⚠️ disabled`;
  }

  if (validation.readOnly) {
    return `${base} ⚠️ readonly`;
  }

  if (validation.hiddenInput) {
    return `${base} ⚠️ hidden input`;
  }

  if (!validation.fillable) {
    return `${base} ⚠️ not fillable`;
  }

  if (!validation.roleSafe) {
    return `${base} ⛔ unsafe target`;
  }

  if (validation.drift && !validation.drift.stable) {
    return `${base} ⚠️ changed`;
  }

  if (
    validation.resolvedBy &&
    validation.resolvedBy !== "stored-selector"
  ) {
    return `${base} ✅ via ${validation.resolvedBy}`;
  }

  if (validation.interactable) {
    return `${base} ✅ ready`;
  }

  return `${base} ⚠️ not ready`;
}


function formatTimestamp(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleString();
}

function setText(id, value) {
  const element = document.getElementById(id);

  if (!element) {
    return;
  }

  element.textContent = String(value || "—");
  element.title = String(value || "");
}

async function getActiveTab() {
  const tabs = await chromePromise(chrome.tabs.query, chrome.tabs, {
    active: true,
    currentWindow: true,
  });

  return tabs?.[0] || null;
}

async function sendMessageToTab(tabId, message) {
  try {
    return await chromePromise(
      chrome.tabs.sendMessage,
      chrome.tabs,
      tabId,
      message
    );
  } catch (error) {
    console.warn("Vaulty popup: failed to message tab", error);
    return null;
  }
}

async function sendMessageToBackground(message) {
  try {
    return await chromePromise(
      chrome.runtime.sendMessage,
      chrome.runtime,
      message
    );
  } catch (error) {
    console.warn("Vaulty popup: failed to message background", error);
    return null;
  }
}

function isSelectablePage(url) {
  if (!url) {
    return false;
  }

  return (
    url.startsWith("http://") ||
    url.startsWith("https://") ||
    url.startsWith("file://")
  );
}

function safeOrigin(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

function flashButton(button, temporaryText) {
  const originalText = button.textContent;

  button.textContent = temporaryText;
  button.disabled = true;

  setTimeout(() => {
    button.textContent = originalText;
    button.disabled = false;
  }, 900);
}

function storageGet(keys) {
  return chromePromise(chrome.storage.local.get, chrome.storage.local, keys);
}

function storageSet(value) {
  return chromePromise(chrome.storage.local.set, chrome.storage.local, value);
}

function chromePromise(fn, thisArg, ...args) {
  return new Promise((resolve, reject) => {
    fn.call(thisArg, ...args, (result) => {
      const error = chrome.runtime.lastError;

      if (error) {
        reject(error);
        return;
      }

      resolve(result);
    });
  });
}

async function renderPageSecurityWarning() {
  const warning = document.getElementById("page-security-warning");

  if (!warning) {
    return;
  }

  warning.hidden = true;
  warning.textContent = "";

  const tab = await getActiveTab();
  const origin = safeOrigin(tab?.url);

  if (!tab?.id || !origin || !isSelectablePage(tab.url)) {
    return;
  }

  const scan = await sendMessageToTab(tab.id, {
    type: "VAULTY_SCAN_PAGE_SECURITY",
    payload: {
      origin,
    },
  });

  if (!scan?.ok) {
    return;
  }

  const messages = [];

  const crossOriginIframeCount = scan.summary?.crossOriginIframeCount || 0;
  const visibleIframeCount = scan.summary?.visibleIframeCount || 0;
  const oauthProviderCount = scan.summary?.oauthProviderCount || 0;

  if (crossOriginIframeCount > 0) {
    messages.push(
      `${crossOriginIframeCount} cross-origin iframe(s) detected. OAuth/provider login may happen on another origin.`
    );
  } else if (visibleIframeCount > 0) {
    messages.push(
      `${visibleIframeCount} iframe(s) detected. Fields inside frames may need later iframe support.`
    );
  }

  if (oauthProviderCount > 0) {
    const providerLabels = scan.oauthProviders
      .map((provider) => provider.label)
      .join(", ");

    messages.push(`OAuth/provider login detected: ${providerLabels}.`);
  }

  if (messages.length === 0) {
    warning.hidden = true;
    warning.textContent = "";
    return;
  }

  warning.hidden = false;
  warning.textContent = `⚠️ ${messages.join(" ")}`;
}

async function renderLoginScanResult() {
  const resultElement = document.getElementById("login-scan-result");
  const useButton = document.getElementById("use-detected-login-fields");

  latestLoginScan = null;

  if (useButton) {
    useButton.hidden = true;
  }

  if (!resultElement) {
    return;
  }

  resultElement.hidden = true;
  resultElement.textContent = "";

  const tab = await getActiveTab();
  const origin = safeOrigin(tab?.url);

  if (!tab?.id || !origin || !isSelectablePage(tab.url)) {
    return;
  }

  const scan = await sendMessageToTab(tab.id, {
    type: "VAULTY_SCAN_LOGIN_FIELDS",
    payload: {
      origin,
    },
  });

  if (!scan?.ok || !scan.hasLikelyLoginForm) {
    return;
  }

  latestLoginScan = scan;

  const username = scan.best?.username;
  const password = scan.best?.password;

  const parts = [];

  if (username) {
    parts.push(`username: ${username.selector}`);
  }

  if (password) {
    parts.push(`password: ${password.selector}`);
  }

  resultElement.hidden = false;
  resultElement.textContent =
    `Detected login fields (${Math.round(scan.confidence * 100)}%): ` +
    parts.join(" · ");

  if (useButton && password) {
    useButton.hidden = false;
  }
}
