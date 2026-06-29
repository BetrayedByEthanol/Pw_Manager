const STORAGE_SCHEMA_VERSION = 1;

const STORAGE_KEYS = {
  schemaVersion: "vaulty.schemaVersion",
  lastSelected: "vaulty.lastSelectedElement",
  siteMappings: "vaulty.siteMappings",
};

const ALLOWED_ROLES = new Set([
  "generic",
  "username",
  "password",
  "email",
  "passwordConfirm",
  "submit",
]);

const MAPPABLE_ROLES = new Set([
  "username",
  "password",
  "email",
  "passwordConfirm",
  "submit",
]);

const MAX_SELECTOR_LENGTH = 1000;
const MAX_STRING_LENGTH = 500;
const MAX_TEXT_LENGTH = 120;
const MAX_ORIGIN_LENGTH = 300;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message?.type) {
    case "ELEMENT_SELECTED":
      handleElementSelected(message, sender, sendResponse);
      return true;

    case "GET_SITE_MAPPING":
      handleGetSiteMapping(message, sendResponse);
      return true;

    case "CLEAR_SITE_MAPPING":
      handleClearSiteMapping(message, sendResponse);
      return true;

    case "SAVE_DETECTED_LOGIN_MAPPING":
      handleSaveDetectedLoginMapping(message, sendResponse);
      return true;

    default:
      sendResponse({
        ok: false,
        error: "unknown-message-type",
      });
      return false;
  }
});

function handleElementSelected(message, sender, sendResponse) {
  const rawElement = message.element || {};
  const selected = sanitizeSelectedElement({
    ...rawElement,
    tabId: sender.tab?.id || null,
    tabUrl: sender.tab?.url || rawElement.url || null,
    origin: rawElement.origin || safeOrigin(sender.tab?.url),
    storedAt: Date.now(),
  });

  if (!selected) {
    sendResponse({
      ok: false,
      error: "invalid-selected-element",
    });
    return;
  }

  chrome.storage.local.get([STORAGE_KEYS.siteMappings], (result) => {
    const readError = chrome.runtime.lastError;

    if (readError) {
      console.warn("Vaulty background: failed to read mappings", readError);
      sendResponse({ ok: false, error: readError.message });
      return;
    }

    const mappings = sanitizeAllMappings(result[STORAGE_KEYS.siteMappings] || {});
    const origin = selected.origin;

    let mappingUpdated = false;

    if (origin && shouldStoreAsSiteField(selected.role)) {
      const storedField = sanitizeStoredField(toStoredField(selected));

      if (!storedField) {
        sendResponse({
          ok: false,
          error: "invalid-stored-field",
        });
        return;
      }

      mappings[origin] = sanitizeSiteMapping({
        ...(mappings[origin] || {}),
        [selected.role]: storedField,
        updatedAt: Date.now(),
      });

      mappingUpdated = true;
    }

    chrome.storage.local.set(
      {
        [STORAGE_KEYS.schemaVersion]: STORAGE_SCHEMA_VERSION,
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

        sendResponse({
          ok: true,
          selected,
          mappingUpdated,
        });
      }
    );
  });
}

function handleGetSiteMapping(message, sendResponse) {
  const origin = sanitizeOrigin(message.origin || safeOrigin(message.url));

  if (!origin) {
    sendResponse({
      ok: false,
      error: "invalid-origin",
    });
    return;
  }

  chrome.storage.local.get(
    [STORAGE_KEYS.schemaVersion, STORAGE_KEYS.siteMappings],
    (result) => {
      const readError = chrome.runtime.lastError;

      if (readError) {
        console.warn("Vaulty background: failed to read site mapping", readError);
        sendResponse({ ok: false, error: readError.message });
        return;
      }

      const mappings = sanitizeAllMappings(result[STORAGE_KEYS.siteMappings] || {});
      const mapping = mappings[origin] || null;

      // Opportunistically rewrite sanitized mappings.
      chrome.storage.local.set(
        {
          [STORAGE_KEYS.schemaVersion]: STORAGE_SCHEMA_VERSION,
          [STORAGE_KEYS.siteMappings]: mappings,
        },
        () => {
          const writeError = chrome.runtime.lastError;

          if (writeError) {
            console.warn("Vaulty background: failed to rewrite sanitized mappings", writeError);
          }

          sendResponse({
            ok: true,
            schemaVersion: STORAGE_SCHEMA_VERSION,
            origin,
            mapping,
          });
        }
      );
    }
  );
}

function handleClearSiteMapping(message, sendResponse) {
  const origin = sanitizeOrigin(message.origin || safeOrigin(message.url));

  if (!origin) {
    sendResponse({
      ok: false,
      error: "invalid-origin",
    });
    return;
  }

  chrome.storage.local.get([STORAGE_KEYS.siteMappings], (result) => {
    const readError = chrome.runtime.lastError;

    if (readError) {
      console.warn("Vaulty background: failed to read mappings", readError);
      sendResponse({ ok: false, error: readError.message });
      return;
    }

    const mappings = sanitizeAllMappings(result[STORAGE_KEYS.siteMappings] || {});
    delete mappings[origin];

    chrome.storage.local.set(
      {
        [STORAGE_KEYS.schemaVersion]: STORAGE_SCHEMA_VERSION,
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

function handleSaveDetectedLoginMapping(message, sendResponse) {
  const origin = sanitizeOrigin(message.origin);
  const url = sanitizeUrl(message.url);

  if (!origin) {
    sendResponse({
      ok: false,
      error: "invalid-origin",
    });
    return;
  }

  const usernameField = message.username
    ? sanitizeStoredField(candidateToStoredField("username", message.username, origin, url))
    : null;

  const passwordField = message.password
    ? sanitizeStoredField(candidateToStoredField("password", message.password, origin, url))
    : null;

  if (!usernameField && !passwordField) {
    sendResponse({
      ok: false,
      error: "no-valid-detected-fields",
    });
    return;
  }

  chrome.storage.local.get([STORAGE_KEYS.siteMappings], (result) => {
    const readError = chrome.runtime.lastError;

    if (readError) {
      console.warn("Vaulty background: failed to read mappings", readError);
      sendResponse({ ok: false, error: readError.message });
      return;
    }

    const mappings = sanitizeAllMappings(result[STORAGE_KEYS.siteMappings] || {});
    const existing = mappings[origin] || {};

    const updated = {
      ...existing,
      updatedAt: Date.now(),
    };

    if (usernameField) {
      updated.username = usernameField;
    }

    if (passwordField) {
      updated.password = passwordField;
    }

    const cleanUpdated = sanitizeSiteMapping(updated);

    if (!cleanUpdated) {
      sendResponse({
        ok: false,
        error: "invalid-updated-mapping",
      });
      return;
    }

    mappings[origin] = cleanUpdated;

    chrome.storage.local.set(
      {
        [STORAGE_KEYS.schemaVersion]: STORAGE_SCHEMA_VERSION,
        [STORAGE_KEYS.siteMappings]: mappings,
      },
      () => {
        const writeError = chrome.runtime.lastError;

        if (writeError) {
          console.warn("Vaulty background: failed to save detected mapping", writeError);
          sendResponse({ ok: false, error: writeError.message });
          return;
        }

        sendResponse({
          ok: true,
          origin,
          mapping: cleanUpdated,
        });
      }
    );
  });
}

function shouldStoreAsSiteField(role) {
  return MAPPABLE_ROLES.has(role);
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

function candidateToStoredField(role, candidate, origin, url) {
  return {
    role,
    label: role === "username" ? "detected username field" : "detected password field",

    selector: candidate.selector || "",
    tag: candidate.tag || "",
    type: candidate.type || "",
    name: candidate.name || "",
    id: candidate.id || "",
    className: candidate.className || "",
    placeholder: candidate.placeholder || "",
    autocomplete: candidate.autocomplete || "",
    ariaLabel: candidate.ariaLabel || "",
    htmlRole: candidate.htmlRole || "",
    text: candidate.text || "",

    url,
    origin,

    selectedAt: Date.now(),
    storedAt: Date.now(),
  };
}

/**
 * Storage validators / sanitizers
 */

function sanitizeAllMappings(rawMappings) {
  if (!isPlainObject(rawMappings)) {
    return {};
  }

  const clean = {};

  for (const [rawOrigin, rawMapping] of Object.entries(rawMappings)) {
    const origin = sanitizeOrigin(rawOrigin);

    if (!origin) {
      continue;
    }

    const mapping = sanitizeSiteMapping(rawMapping);

    if (!mapping) {
      continue;
    }

    clean[origin] = mapping;
  }

  return clean;
}

function sanitizeSiteMapping(rawMapping) {
  if (!isPlainObject(rawMapping)) {
    return null;
  }

  const clean = {};

  for (const role of MAPPABLE_ROLES) {
    const field = sanitizeStoredField(rawMapping[role]);

    if (field) {
      clean[role] = field;
    }
  }

  const hasFields = Object.keys(clean).length > 0;

  if (!hasFields) {
    return null;
  }

  clean.updatedAt = sanitizeTimestamp(rawMapping.updatedAt) || Date.now();

  return clean;
}

function sanitizeSelectedElement(rawElement) {
  if (!isPlainObject(rawElement)) {
    return null;
  }

  const role = sanitizeRole(rawElement.role);

  if (!role) {
    return null;
  }

  const origin = sanitizeOrigin(rawElement.origin || safeOrigin(rawElement.url));

  if (!origin) {
    return null;
  }

  return {
    role,
    label: sanitizeString(rawElement.label, MAX_STRING_LENGTH),

    tag: sanitizeString(rawElement.tag, 80).toLowerCase(),
    type: sanitizeString(rawElement.type, 80).toLowerCase(),
    name: sanitizeString(rawElement.name, MAX_STRING_LENGTH),
    id: sanitizeString(rawElement.id, MAX_STRING_LENGTH),
    className: sanitizeString(rawElement.className, MAX_STRING_LENGTH),
    placeholder: sanitizeString(rawElement.placeholder, MAX_STRING_LENGTH),
    autocomplete: sanitizeString(rawElement.autocomplete, MAX_STRING_LENGTH),
    ariaLabel: sanitizeString(rawElement.ariaLabel, MAX_STRING_LENGTH),
    htmlRole: sanitizeString(rawElement.htmlRole, MAX_STRING_LENGTH),

    text: sanitizeString(rawElement.text, MAX_TEXT_LENGTH),
    selector: sanitizeSelector(rawElement.selector),

    url: sanitizeUrl(rawElement.url),
    origin,

    tabId: Number.isInteger(rawElement.tabId) ? rawElement.tabId : null,
    tabUrl: sanitizeUrl(rawElement.tabUrl),

    selectedAt: sanitizeTimestamp(rawElement.selectedAt) || Date.now(),
    storedAt: sanitizeTimestamp(rawElement.storedAt) || Date.now(),
  };
}

function sanitizeStoredField(rawField) {
  if (!isPlainObject(rawField)) {
    return null;
  }

  const role = sanitizeRole(rawField.role);

  if (!role || !MAPPABLE_ROLES.has(role)) {
    return null;
  }

  const selector = sanitizeSelector(rawField.selector);

  // A mapped field without a selector is useless for the current implementation.
  if (!selector) {
    return null;
  }

  const origin = sanitizeOrigin(rawField.origin || safeOrigin(rawField.url));

  if (!origin) {
    return null;
  }

  return {
    role,
    label: sanitizeString(rawField.label, MAX_STRING_LENGTH),

    selector,
    tag: sanitizeString(rawField.tag, 80).toLowerCase(),
    type: sanitizeString(rawField.type, 80).toLowerCase(),
    name: sanitizeString(rawField.name, MAX_STRING_LENGTH),
    id: sanitizeString(rawField.id, MAX_STRING_LENGTH),
    className: sanitizeString(rawField.className, MAX_STRING_LENGTH),
    placeholder: sanitizeString(rawField.placeholder, MAX_STRING_LENGTH),
    autocomplete: sanitizeString(rawField.autocomplete, MAX_STRING_LENGTH),
    ariaLabel: sanitizeString(rawField.ariaLabel, MAX_STRING_LENGTH),
    htmlRole: sanitizeString(rawField.htmlRole, MAX_STRING_LENGTH),
    text: sanitizeString(rawField.text, MAX_TEXT_LENGTH),

    url: sanitizeUrl(rawField.url),
    origin,

    selectedAt: sanitizeTimestamp(rawField.selectedAt) || Date.now(),
    storedAt: sanitizeTimestamp(rawField.storedAt) || Date.now(),
  };
}

function sanitizeRole(role) {
  const value = sanitizeString(role, 80);

  if (!ALLOWED_ROLES.has(value)) {
    return "";
  }

  return value;
}

function sanitizeOrigin(origin) {
  const value = sanitizeString(origin, MAX_ORIGIN_LENGTH);

  if (!value) {
    return "";
  }

  try {
    const url = new URL(value);

    // For real credentials, keep this http/https only.
    // If you need file:// test pages, add "file:" here intentionally.
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return "";
    }

    return url.origin;
  } catch {
    return "";
  }
}

function sanitizeUrl(url) {
  const value = sanitizeString(url, 2000);

  if (!value) {
    return "";
  }

  try {
    const parsed = new URL(value);

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:" &&
      parsed.protocol !== "file:"
    ) {
      return "";
    }

    return parsed.href;
  } catch {
    return "";
  }
}

function sanitizeSelector(selector) {
  const value = sanitizeString(selector, MAX_SELECTOR_LENGTH);

  if (!value) {
    return "";
  }

  // Avoid absurd selector payloads. Selectors are not executed as JS, but they
  // still influence where values are written.
  if (value.includes("\0")) {
    return "";
  }

  return value;
}

function sanitizeString(value, maxLength) {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim().slice(0, maxLength);
}

function sanitizeTimestamp(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return 0;
  }

  if (value <= 0) {
    return 0;
  }

  return value;
}

function safeOrigin(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}