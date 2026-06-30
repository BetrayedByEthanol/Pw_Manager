const STORAGE_SCHEMA_VERSION = 1;

const STORAGE_KEYS = {
  schemaVersion: "vaulty.schemaVersion",
  siteMappings: "vaulty.siteMappings",
  lastSelected: "vaulty.lastSelectedElement",
  devCredentials: "vaulty.devCredentials",
};

const ALLOWED_ROLES = new Set([
  "username",
  "password",
  "email",
  "passwordConfirm",
  "submit",
]);

const FIELD_DISPLAY_ORDER = [
  "username",
  "password",
  "email",
  "passwordConfirm",
  "submit",
];

const MAX_SELECTOR_LENGTH = 1000;
const MAX_STRING_LENGTH = 500;
const MAX_TEXT_LENGTH = 120;
const MAX_ORIGIN_LENGTH = 300;

let currentState = {
  schemaVersion: STORAGE_SCHEMA_VERSION,
  siteMappings: {},
  lastSelected: null,
  devCredentials: {},
};

document.addEventListener("DOMContentLoaded", async () => {
  wireActions();
  await loadAndRender();
});

function wireActions() {
  document.getElementById("refresh")?.addEventListener("click", loadAndRender);
  document.getElementById("export-json")?.addEventListener("click", exportJsonFile);
  document.getElementById("copy-json")?.addEventListener("click", copyJsonToClipboard);
  document.getElementById("import-file")?.addEventListener("change", importJsonFile);
  document.getElementById("clear-mappings")?.addEventListener("click", clearMappings);
  document.getElementById("clear-all")?.addEventListener("click", clearAllVaultyData);
}

async function loadAndRender() {
  const result = await storageGet([
    STORAGE_KEYS.schemaVersion,
    STORAGE_KEYS.siteMappings,
    STORAGE_KEYS.lastSelected,
    STORAGE_KEYS.devCredentials,
  ]);

  currentState = {
    schemaVersion: normalizeSchemaVersion(result[STORAGE_KEYS.schemaVersion]),
    siteMappings: sanitizeAllMappings(result[STORAGE_KEYS.siteMappings] || {}),
    lastSelected: sanitizeLastSelected(result[STORAGE_KEYS.lastSelected]),
    devCredentials: sanitizeDevCredentials(result[STORAGE_KEYS.devCredentials] || {}),
  };

  await storageSet({
    [STORAGE_KEYS.schemaVersion]: STORAGE_SCHEMA_VERSION,
    [STORAGE_KEYS.siteMappings]: currentState.siteMappings,
    [STORAGE_KEYS.devCredentials]: currentState.devCredentials,
  });

  renderAll();
  setStatus("Loaded Vaulty extension data.", "success");
}

function renderAll() {
  renderHeader();
  renderSummary();
  renderMappings();
  renderRawJson();
}

function renderHeader() {
  setText("schema-version", String(currentState.schemaVersion || STORAGE_SCHEMA_VERSION));
}

function renderSummary() {
  const origins = Object.keys(currentState.siteMappings);
  const fieldCount = countMappedFields(currentState.siteMappings);
  const devCredentialCount = countDevCredentials(currentState.devCredentials);

  setText("summary-origins", String(origins.length));
  setText("summary-fields", String(fieldCount));
  setText("summary-dev-credentials", String(devCredentialCount));

  const lastSelected = currentState.lastSelected;

  if (lastSelected?.role && lastSelected?.origin) {
    setText("summary-last-selected", `${lastSelected.role} @ ${lastSelected.origin}`);
  } else {
    setText("summary-last-selected", "—");
  }
}

function renderMappings() {
  const list = document.getElementById("mapping-list");
  const count = document.getElementById("mapping-count");

  if (!list) {
    return;
  }

  const origins = Object.keys(currentState.siteMappings).sort();

  if (count) {
    count.textContent = `${origins.length} mapping${origins.length === 1 ? "" : "s"}`;
  }

  list.replaceChildren();

  if (origins.length === 0) {
    const empty = document.createElement("div");
    empty.className = "mapping-empty";
    empty.textContent = "No mappings stored yet.";
    list.appendChild(empty);
    return;
  }

  for (const origin of origins) {
    const mapping = currentState.siteMappings[origin];
    list.appendChild(createMappingItem(origin, mapping));
  }
}

function createMappingItem(origin, mapping) {
  const item = document.createElement("article");
  item.className = "mapping-item";

  const head = document.createElement("div");
  head.className = "mapping-head";

  const titleWrap = document.createElement("div");

  const originEl = document.createElement("div");
  originEl.className = "origin";
  originEl.textContent = origin;
  originEl.title = origin;

  const meta = document.createElement("div");
  meta.className = "mapping-meta";
  meta.textContent = `Updated: ${formatTimestamp(mapping.updatedAt)} · Fields: ${countFieldsInMapping(mapping)}`;

  titleWrap.appendChild(originEl);
  titleWrap.appendChild(meta);

  const actions = document.createElement("div");
  actions.className = "mapping-actions";

  const copyButton = document.createElement("button");
  copyButton.className = "small secondary";
  copyButton.type = "button";
  copyButton.textContent = "Copy";
  copyButton.addEventListener("click", async () => {
    await navigator.clipboard.writeText(JSON.stringify({ [origin]: mapping }, null, 2));
    setStatus(`Copied mapping for ${origin}.`, "success");
  });

  const deleteButton = document.createElement("button");
  deleteButton.className = "small danger";
  deleteButton.type = "button";
  deleteButton.textContent = "Delete";
  deleteButton.addEventListener("click", async () => {
    await deleteMapping(origin);
  });

  actions.appendChild(copyButton);
  actions.appendChild(deleteButton);

  head.appendChild(titleWrap);
  head.appendChild(actions);

  const fields = document.createElement("div");
  fields.className = "fields";

    if (mapping.login?.username || mapping.login?.password) {
    fields.appendChild(createSectionLabel("Login"));

    if (mapping.login.username) {
        fields.appendChild(createFieldRow("username", mapping.login.username));
    }

    if (mapping.login.password) {
        fields.appendChild(createFieldRow("password", mapping.login.password));
    }
    }

    if (mapping.registration && Object.keys(mapping.registration).length > 0) {
    fields.appendChild(createSectionLabel("Registration"));

    for (const role of FIELD_DISPLAY_ORDER) {
        if (!mapping.registration[role]) {
        continue;
        }

        fields.appendChild(createFieldRow(role, mapping.registration[role]));
    }
}

  item.appendChild(head);
  item.appendChild(fields);

  return item;
}

function createSectionLabel(text) {
  const row = document.createElement("div");
  row.className = "field-row";

  const label = document.createElement("div");
  label.className = "field-label";
  label.textContent = text;

  const value = document.createElement("div");
  value.className = "field-value";
  value.textContent = "—";

  row.appendChild(label);
  row.appendChild(value);

  return row;
}

function createFieldRow(role, field) {
  const row = document.createElement("div");
  row.className = "field-row";

  const label = document.createElement("div");
  label.className = "field-label";
  label.textContent = role;

  const value = document.createElement("div");
  value.className = "field-value";

  const summary = field.selector || field.id || field.name || field.tag || "stored";
  value.textContent = summary;
  value.title = buildFieldTitle(field);

  row.appendChild(label);
  row.appendChild(value);

  return row;
}

function buildFieldTitle(field) {
  return [
    `selector: ${field.selector || "—"}`,
    `tag: ${field.tag || "—"}`,
    `type: ${field.type || "—"}`,
    `id: ${field.id || "—"}`,
    `name: ${field.name || "—"}`,
    `autocomplete: ${field.autocomplete || "—"}`,
    `placeholder: ${field.placeholder || "—"}`,
  ].join("\n");
}

function renderRawJson() {
  const box = document.getElementById("raw-json");

  if (!box) {
    return;
  }

  box.value = JSON.stringify(buildExportPayload(), null, 2);
}

function buildExportPayload() {
  return {
    schemaVersion: currentState.schemaVersion || STORAGE_SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    siteMappings: currentState.siteMappings,
    devCredentials: currentState.devCredentials,
  };
}

async function exportJsonFile() {
  const payload = buildExportPayload();
  const json = JSON.stringify(payload, null, 2);

  const blob = new Blob([json], {
    type: "application/json",
  });

  const url = URL.createObjectURL(blob);
  const filename = `vaulty-mappings-${new Date().toISOString().slice(0, 10)}.json`;

  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();

  URL.revokeObjectURL(url);

  setStatus(`Exported ${filename}.`, "success");
}

async function copyJsonToClipboard() {
  const json = JSON.stringify(buildExportPayload(), null, 2);
  await navigator.clipboard.writeText(json);
  setStatus("Copied export JSON to clipboard.", "success");
}

async function importJsonFile(event) {
  const file = event.target.files?.[0];

  if (!file) {
    return;
  }

  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    const imported = parseImportPayload(parsed);

    if (!imported.ok) {
      setStatus(imported.error || "Invalid import file.", "error");
      return;
    }

    const confirmImport = confirm(
      `Import ${Object.keys(imported.siteMappings).length} mapping origin(s)? Existing origins with the same name will be overwritten.`
    );

    if (!confirmImport) {
      setStatus("Import cancelled.", "warning");
      return;
    }

    const mergedMappings = {
      ...currentState.siteMappings,
      ...imported.siteMappings,
    };

    const mergedDevCredentials = {
      ...currentState.devCredentials,
      ...imported.devCredentials,
    };

    await storageSet({
      [STORAGE_KEYS.schemaVersion]: STORAGE_SCHEMA_VERSION,
      [STORAGE_KEYS.siteMappings]: sanitizeAllMappings(mergedMappings),
      [STORAGE_KEYS.devCredentials]: sanitizeDevCredentials(mergedDevCredentials),
    });

    await loadAndRender();
    setStatus("Import complete.", "success");
  } catch (error) {
    console.error("Vaulty options: import failed", error);
    setStatus("Import failed. File must be valid Vaulty JSON.", "error");
  } finally {
    event.target.value = "";
  }
}

function parseImportPayload(parsed) {
  if (!isPlainObject(parsed)) {
    return {
      ok: false,
      error: "Import file must contain a JSON object.",
    };
  }

  const rawMappings =
    parsed.siteMappings ||
    parsed.mappings ||
    parsed["vaulty.siteMappings"] ||
    {};

  const rawDevCredentials =
    parsed.devCredentials ||
    parsed["vaulty.devCredentials"] ||
    {};

  const siteMappings = sanitizeAllMappings(rawMappings);
  const devCredentials = sanitizeDevCredentials(rawDevCredentials);

  if (Object.keys(siteMappings).length === 0 && Object.keys(devCredentials).length === 0) {
    return {
      ok: false,
      error: "No valid Vaulty mappings or dev credentials found.",
    };
  }

  return {
    ok: true,
    siteMappings,
    devCredentials,
  };
}

async function deleteMapping(origin) {
  const confirmed = confirm(`Delete mapping for ${origin}?`);

  if (!confirmed) {
    return;
  }

  const nextMappings = {
    ...currentState.siteMappings,
  };

  delete nextMappings[origin];

  await storageSet({
    [STORAGE_KEYS.schemaVersion]: STORAGE_SCHEMA_VERSION,
    [STORAGE_KEYS.siteMappings]: sanitizeAllMappings(nextMappings),
  });

  await loadAndRender();
  setStatus(`Deleted mapping for ${origin}.`, "success");
}

async function clearMappings() {
  const confirmed = confirm("Clear all Vaulty site mappings?");

  if (!confirmed) {
    return;
  }

  await storageSet({
    [STORAGE_KEYS.schemaVersion]: STORAGE_SCHEMA_VERSION,
    [STORAGE_KEYS.siteMappings]: {},
  });

  await loadAndRender();
  setStatus("Cleared all site mappings.", "success");
}

async function clearAllVaultyData() {
  const confirmed = confirm(
    "Clear all Vaulty extension-local data? This removes mappings, last selected element, and dev credentials."
  );

  if (!confirmed) {
    return;
  }

  await chromePromise(chrome.storage.local.remove, chrome.storage.local, [
    STORAGE_KEYS.schemaVersion,
    STORAGE_KEYS.siteMappings,
    STORAGE_KEYS.lastSelected,
    STORAGE_KEYS.devCredentials,
  ]);

  currentState = {
    schemaVersion: STORAGE_SCHEMA_VERSION,
    siteMappings: {},
    lastSelected: null,
    devCredentials: {},
  };

  renderAll();
  setStatus("Cleared all Vaulty extension-local data.", "success");
}

/**
 * Validation / sanitization
 */

function normalizeSchemaVersion(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return STORAGE_SCHEMA_VERSION;
  }

  return value;
}

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
  rawMapping = migrateSiteMapping(rawMapping);

  if (!isPlainObject(rawMapping)) {
    return null;
  }

  const clean = {
    login: {},
    registration: {},
    preferences: {},
  };

  const loginUsername = sanitizeStoredField(rawMapping.login?.username, "username");
  const loginPassword = sanitizeStoredField(rawMapping.login?.password, "password");

  if (loginUsername) {
    clean.login.username = loginUsername;
  }

  if (loginPassword) {
    clean.login.password = loginPassword;
  }

  for (const role of FIELD_DISPLAY_ORDER) {
    const field = sanitizeStoredField(rawMapping.registration?.[role], role);

    if (field) {
      clean.registration[role] = field;
    }
  }

  const hasLoginFields = Object.keys(clean.login).length > 0;
  const hasRegistrationFields = Object.keys(clean.registration).length > 0;

  if (!hasLoginFields && !hasRegistrationFields) {
    return null;
  }

  clean.updatedAt = sanitizeTimestamp(rawMapping.updatedAt) || Date.now();

  return clean;
}

function migrateSiteMapping(rawMapping) {
  if (!isPlainObject(rawMapping)) {
    return null;
  }

  if (isPlainObject(rawMapping.login) || isPlainObject(rawMapping.registration)) {
    return rawMapping;
  }

  return {
    login: {
      username: rawMapping.username || undefined,
      password: rawMapping.password || undefined,
    },
    registration: {
      email: rawMapping.email || undefined,
      passwordConfirm: rawMapping.passwordConfirm || undefined,
      submit: rawMapping.submit || undefined,
    },
    preferences: rawMapping.preferences || {},
    updatedAt: rawMapping.updatedAt || Date.now(),
  };
}

function sanitizeStoredField(rawField, fallbackRole = "") {
  if (!isPlainObject(rawField)) {
    return null;
  }

  const role = sanitizeRole(rawField.role || fallbackRole);

  if (!role) {
    return null;
  }

  const selector = sanitizeSelector(rawField.selector);

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

function sanitizeLastSelected(rawElement) {
  if (!isPlainObject(rawElement)) {
    return null;
  }

  return {
    role: sanitizeString(rawElement.role, 80),
    label: sanitizeString(rawElement.label, MAX_STRING_LENGTH),
    selector: sanitizeSelector(rawElement.selector),
    tag: sanitizeString(rawElement.tag, 80).toLowerCase(),
    type: sanitizeString(rawElement.type, 80).toLowerCase(),
    name: sanitizeString(rawElement.name, MAX_STRING_LENGTH),
    id: sanitizeString(rawElement.id, MAX_STRING_LENGTH),
    origin: sanitizeOrigin(rawElement.origin || safeOrigin(rawElement.url)),
    url: sanitizeUrl(rawElement.url),
    selectedAt: sanitizeTimestamp(rawElement.selectedAt) || 0,
    storedAt: sanitizeTimestamp(rawElement.storedAt) || 0,
  };
}

function sanitizeDevCredentials(rawCredentials) {
  if (!isPlainObject(rawCredentials)) {
    return {};
  }

  const clean = {};

  for (const [rawOrigin, rawList] of Object.entries(rawCredentials)) {
    const origin = sanitizeOrigin(rawOrigin);

    if (!origin || !Array.isArray(rawList)) {
      continue;
    }

    clean[origin] = rawList
      .filter(isPlainObject)
      .slice(0, 20)
      .map((entry) => ({
        id: sanitizeString(entry.id, 120),
        label: sanitizeString(entry.label, MAX_STRING_LENGTH),
        email: sanitizeString(entry.email, MAX_STRING_LENGTH),
        username: sanitizeString(entry.username, MAX_STRING_LENGTH),

        // Extension-only dev data. Do not store real passwords here.
        password: sanitizeString(entry.password, MAX_STRING_LENGTH),

        createdAt: sanitizeTimestamp(entry.createdAt) || Date.now(),
        updatedAt: sanitizeTimestamp(entry.updatedAt) || 0,
      }))
      .filter((entry) => entry.id || entry.email || entry.username || entry.password);

    if (clean[origin].length === 0) {
      delete clean[origin];
    }
  }

  return clean;
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

  if (!value || value.includes("\0")) {
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
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
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
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Utilities
 */

function countMappedFields(mappings) {
  return Object.values(mappings).reduce((sum, mapping) => {
    return sum + countFieldsInMapping(mapping);
  }, 0);
}

function countFieldsInMapping(mapping) {
  const loginCount =
    Number(Boolean(mapping?.login?.username)) +
    Number(Boolean(mapping?.login?.password));

  const registrationCount = FIELD_DISPLAY_ORDER.filter((role) =>
    Boolean(mapping?.registration?.[role])
  ).length;

  return loginCount + registrationCount;
}

function countDevCredentials(devCredentials) {
  return Object.values(devCredentials).reduce((sum, list) => {
    return sum + (Array.isArray(list) ? list.length : 0);
  }, 0);
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

  if (element) {
    element.textContent = value;
  }
}

function setStatus(message, type = "") {
  const element = document.getElementById("action-status");

  if (!element) {
    return;
  }

  element.className = `status ${type}`.trim();
  element.textContent = message || "";

  if (message) {
    setTimeout(() => {
      if (element.textContent === message) {
        element.textContent = "";
        element.className = "status";
      }
    }, 3500);
  }
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