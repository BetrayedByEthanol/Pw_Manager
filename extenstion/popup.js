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

async function renderPopupState() {
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

  const validation = await validateCurrentMapping(tab.id, mapping);

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

async function validateCurrentMapping(tabId, mapping) {
  if (!tabId || !mapping) {
    return null;
  }

  const response = await sendMessageToTab(tabId, {
    type: "VAULTY_VALIDATE_MAPPING",
    payload: {
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

  if (validation.found && validation.fillable && validation.visible) {
    return `${base} ✅`;
  }

  if (validation.found && validation.fillable && !validation.visible) {
    return `${base} ⚠️ hidden`;
  }

  if (validation.found && !validation.fillable) {
    return `${base} ⚠️ not fillable`;
  }

  return `${base} ❌ missing`;
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
