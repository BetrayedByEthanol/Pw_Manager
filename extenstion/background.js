const STORAGE_KEYS = {
  lastSelected: "vaulty.lastSelectedElement",
  siteMappings: "vaulty.siteMappings",
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "ELEMENT_SELECTED") {
    handleElementSelected(message, sender, sendResponse);
    return true;
  }

  if (message?.type === "GET_SITE_MAPPING") {
    handleGetSiteMapping(message, sendResponse);
    return true;
  }

  if (message?.type === "CLEAR_SITE_MAPPING") {
    handleClearSiteMapping(message, sendResponse);
    return true;
  }
});

function handleElementSelected(message, sender, sendResponse) {
  const element = message.element || {};

  const selected = {
    ...element,
    tabId: sender.tab?.id || null,
    tabUrl: sender.tab?.url || element.url || null,
    origin: element.origin || safeOrigin(sender.tab?.url),
    storedAt: Date.now(),
  };

  chrome.storage.local.get([STORAGE_KEYS.siteMappings], (result) => {
    const error = chrome.runtime.lastError;

    if (error) {
      console.warn("Vaulty background: failed to read mappings", error);
      sendResponse({ ok: false, error: error.message });
      return;
    }

    const mappings = result[STORAGE_KEYS.siteMappings] || {};
    const origin = selected.origin;

    if (origin && shouldStoreAsSiteField(selected.role)) {
      mappings[origin] = {
        ...(mappings[origin] || {}),
        [selected.role]: toStoredField(selected),
        updatedAt: Date.now(),
      };
    }

    chrome.storage.local.set(
      {
        [STORAGE_KEYS.lastSelected]: selected,
        [STORAGE_KEYS.siteMappings]: mappings,
      },
      () => {
        const writeError = chrome.runtime.lastError;

        if (writeError) {
          console.warn("Vaulty background: failed to store selected element", writeError);
          sendResponse({ ok: false, error: writeError.message });
          return;
        }

        console.log("Vaulty background: stored selected element", selected);

        if (origin && shouldStoreAsSiteField(selected.role)) {
          console.log("Vaulty background: updated site mapping", {
            origin,
            role: selected.role,
            selector: selected.selector,
          });
        }

        sendResponse({
          ok: true,
          selected,
          mappingUpdated: origin && shouldStoreAsSiteField(selected.role),
        });
      }
    );
  });
}

function handleGetSiteMapping(message, sendResponse) {
  const origin = message.origin || safeOrigin(message.url);

  if (!origin) {
    sendResponse({
      ok: false,
      error: "Missing origin",
    });
    return;
  }

  chrome.storage.local.get([STORAGE_KEYS.siteMappings], (result) => {
    const error = chrome.runtime.lastError;

    if (error) {
      console.warn("Vaulty background: failed to read site mapping", error);
      sendResponse({ ok: false, error: error.message });
      return;
    }

    const mappings = result[STORAGE_KEYS.siteMappings] || {};

    sendResponse({
      ok: true,
      origin,
      mapping: mappings[origin] || null,
    });
  });
}

function handleClearSiteMapping(message, sendResponse) {
  const origin = message.origin || safeOrigin(message.url);

  if (!origin) {
    sendResponse({
      ok: false,
      error: "Missing origin",
    });
    return;
  }

  chrome.storage.local.get([STORAGE_KEYS.siteMappings], (result) => {
    const error = chrome.runtime.lastError;

    if (error) {
      console.warn("Vaulty background: failed to read mappings", error);
      sendResponse({ ok: false, error: error.message });
      return;
    }

    const mappings = result[STORAGE_KEYS.siteMappings] || {};
    delete mappings[origin];

    chrome.storage.local.set(
      {
        [STORAGE_KEYS.siteMappings]: mappings,
      },
      () => {
        const writeError = chrome.runtime.lastError;

        if (writeError) {
          console.warn("Vaulty background: failed to clear mapping", writeError);
          sendResponse({ ok: false, error: writeError.message });
          return;
        }

        sendResponse({
          ok: true,
          origin,
        });
      }
    );
  });
}

function shouldStoreAsSiteField(role) {
  return role === "username" || role === "password";
}

function toStoredField(selected) {
  return {
    role: selected.role || "",
    label: selected.label || "",

    selector: selected.selector || "",
    tag: selected.tag || "",
    type: selected.type || "",
    name: selected.name || "",
    id: selected.id || "",
    className: selected.className || "",
    placeholder: selected.placeholder || "",
    autocomplete: selected.autocomplete || "",
    ariaLabel: selected.ariaLabel || "",
    htmlRole: selected.htmlRole || "",
    text: selected.text || "",

    url: selected.url || "",
    origin: selected.origin || "",
    selectedAt: selected.selectedAt || Date.now(),
    storedAt: selected.storedAt || Date.now(),
  };
}

function safeOrigin(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}
