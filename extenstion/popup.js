let latestLoginScan = null;
let latestGeneratedPasswordMeta = null;
let pendingCredentialSaveConfirmation = null;

const GENERATED_PASSWORD_META_MAX_AGE_MS = 10 * 60 * 1000;
const CREDENTIAL_SAVE_CONFIRMATION_MAX_AGE_MS = 2 * 60 * 1000;
const DEFAULT_PREPARE_CREDENTIAL_BUTTON_TEXT = "Prepare login for Vaulty";
const CONFIRM_SAVE_CREDENTIAL_BUTTON_TEXT = "Confirm save to Vaulty";
const CONFIRM_OVERWRITE_CREDENTIAL_BUTTON_TEXT = "Confirm overwrite in Vaulty";

const STORAGE_KEYS = {
  lastSelected: "vaulty.lastSelectedElement",
  selectionIntent: "vaulty.selectionIntent",
  siteMappings: "vaulty.siteMappings",
};

const SELECTOR_BUTTONS = [
  {
    id: "select",
    scope: "generic",
    role: "generic",
    label: "page element",
  },

  // Login mapping
  {
    id: "select-username",
    scope: "login",
    role: "username",
    label: "login username field",
  },
  {
    id: "select-password",
    scope: "login",
    role: "password",
    label: "login password field",
  },

  // Registration mapping
  {
    id: "select-registration-email",
    scope: "registration",
    role: "email",
    label: "registration email field",
  },
  {
    id: "select-registration-username",
    scope: "registration",
    role: "username",
    label: "registration username field",
  },
  {
    id: "select-registration-password",
    scope: "registration",
    role: "password",
    label: "registration password field",
  },
  {
    id: "select-registration-password-confirm",
    scope: "registration",
    role: "passwordConfirm",
    label: "registration confirm password field",
  },
  {
    id: "select-registration-submit",
    scope: "registration",
    role: "submit",
    label: "registration submit button",
  },
];

document.addEventListener("DOMContentLoaded", async () => {
  wireSelectorButtons();
  wireTestFillButton();
  wireClearMappingButton();
  wireUseDetectedLoginFieldsButton();
  wirePasswordHelperButtons();
  wireMockSaveCredentialButton();

  await renderPopupState();
});


function wireSelectorButtons() {
  for (const config of SELECTOR_BUTTONS) {
    const button = document.getElementById(config.id);

    if (!button) {
      console.warn(`Vaulty popup: missing button #${config.id}`);
      continue;
    }

    button.addEventListener("click", async () => {
      await startSelector(config, button);
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

    const hasLoginMapping =
      Boolean(mapping?.login?.username?.selector) ||
      Boolean(mapping?.login?.password?.selector) ||
      Boolean(mapping?.username?.selector) ||
      Boolean(mapping?.password?.selector);

    if (!hasLoginMapping) {
      flashButton(button, "Map fields first");
      return;
    }

    let retrieveResponse;

    try {
      retrieveResponse = await vaultyRetrieveCredential({
        origin,
        purpose: "login_fill",
      });
    } catch (error) {
      console.warn("Vaulty popup: native credential retrieve failed", error);
      flashButton(button, "Vaulty failed");
      return;
    }

    const credential = retrieveResponse?.credential || {};

    if (!credential.username && !credential.password) {
      flashButton(button, "No credential");
      return;
    }

    const fillResponse = await sendMessageToTab(tab.id, {
      type: "VAULTY_FILL_BY_SELECTORS",
      payload: {
        origin,
        mapping,
        username: credential.username || "",
        password: credential.password || "",
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
      clearCredentialSaveConfirmation(document.getElementById("mock-save-credential"));
      flashButton(button, "Cleared");
      await renderPopupState();
    } else {
      flashButton(button, "Failed");
    }
  });
}
function wirePasswordHelperButtons() {
  const button = document.getElementById("fill-generated-password");

  if (!button) {
    console.warn("Vaulty popup: missing button #fill-generated-password");
    return;
  }

  button.addEventListener("click", fillFreshGeneratedPasswordFields);
}



function rememberGeneratedPasswordMeta(generation, origin) {
  if (!generation?.generatedRequestId) {
    latestGeneratedPasswordMeta = null;
    return;
  }

  latestGeneratedPasswordMeta = {
    generatedRequestId: generation.generatedRequestId,
    generatedAt: generation.generatedAt || Date.now(),
    origin: origin || generation.origin || "",
    source: "vaulty-native-generator",
  };
}

function getActiveGeneratedPasswordMeta(origin) {
  if (!latestGeneratedPasswordMeta) {
    return null;
  }

  if (latestGeneratedPasswordMeta.origin && latestGeneratedPasswordMeta.origin !== origin) {
    return null;
  }

  const ageMs = Date.now() - latestGeneratedPasswordMeta.generatedAt;

  if (ageMs < 0 || ageMs > GENERATED_PASSWORD_META_MAX_AGE_MS) {
    latestGeneratedPasswordMeta = null;
    return null;
  }

  return latestGeneratedPasswordMeta;
}

function wireMockSaveCredentialButton() {
  const button = document.getElementById("mock-save-credential");
  const cancelButton = document.getElementById("cancel-credential-confirmation");
  const status = document.getElementById("mock-save-credential-status");

  if (!button) {
    console.warn("Vaulty popup: missing button #mock-save-credential");
    return;
  }

  button.addEventListener("click", prepareCredentialForVaulty);

  cancelButton?.addEventListener("click", () => {
    clearCredentialSaveConfirmation(button);
    setCredentialStatus(status, "Pending Vaulty save cancelled.", "neutral");
    flashButton(cancelButton, "Cancelled");
  });
}

async function prepareCredentialForVaulty() {
  const button = document.getElementById("mock-save-credential");
  const status = document.getElementById("mock-save-credential-status");
  const tab = await getActiveTab();

  if (!tab?.id || !isSelectablePage(tab.url)) {
    clearCredentialSaveConfirmation(button);
    setCredentialStatus(status, "Unavailable on this page.", "error");
    flashButton(button, "Unavailable");
    return;
  }

  const origin = safeOrigin(tab.url);

  if (!origin) {
    clearCredentialSaveConfirmation(button);
    setCredentialStatus(status, "No valid site origin.", "error");
    flashButton(button, "No site");
    return;
  }

  const mappingResponse = await sendMessageToBackground({
    type: "GET_SITE_MAPPING",
    origin,
  });

  const mapping = mappingResponse?.mapping || null;

  if (!mapping) {
    clearCredentialSaveConfirmation(button);
    setCredentialStatus(status, "Map credential fields first.", "warning");
    flashButton(button, "Map first");
    return;
  }

  const readResponse = await sendMessageToTab(tab.id, {
    type: "VAULTY_READ_CREDENTIAL_FIELDS",
    payload: {
      origin,
      mapping,
    },
  });

  if (!readResponse?.ok) {
    clearCredentialSaveConfirmation(button);
    setCredentialStatus(status, formatCredentialReadError(readResponse), "error");
    flashButton(button, "Read failed");
    return;
  }

  const validation = validateCredentialReadiness(readResponse);

  if (!validation.ok) {
    clearCredentialSaveConfirmation(button);
    setCredentialStatus(status, validation.message, "warning");
    flashButton(button, validation.buttonLabel);
    return;
  }

  const credential = validation.credential;
  const summary = readResponse.summary || {};
  const fingerprint = buildCredentialConfirmationFingerprint(credential, summary);
  const confirmation = getActiveCredentialSaveConfirmation(origin);

  if (!confirmation || confirmation.fingerprint !== fingerprint) {
    rememberCredentialSaveConfirmation(credential, summary, fingerprint, "save");

    const sourceLabel = getCredentialSourceLabelForOrigin(credential.origin);
    const identityLabel = formatCredentialIdentityLabel(credential);

    setCredentialButtonMode("save");
    setCredentialStatus(
      status,
      `Ready to save ${identityLabel} · password present · ${sourceLabel}. Click again to confirm, or cancel.`,
      "pending"
    );
    flashButton(button, "Confirm");
    return;
  }

  const allowOverwrite = confirmation.mode === "overwrite";
  const relayRequest = buildVaultySaveRequest(credential, summary, {
    allowOverwrite,
  });

  let saveResponse;

  try {
    saveResponse = await vaultySaveCredential(relayRequest);
  } catch (error) {
    clearCredentialSaveConfirmation(button);
    setCredentialStatus(status, `Vaulty native save failed: ${error.message}`, "error");
    flashButton(button, "Save failed");
    return;
  }

  if (saveResponse?.reason === "duplicate-credential") {
    rememberCredentialSaveConfirmation(credential, summary, fingerprint, "overwrite");
    setCredentialButtonMode("overwrite");
    setCredentialStatus(
      status,
      `A credential already exists for ${formatCredentialIdentityLabel(credential)} on this origin. Click again to confirm overwrite, or cancel.`,
      "warning"
    );
    flashButton(button, "Duplicate");
    return;
  }

  if (!saveResponse?.ok) {
    clearCredentialSaveConfirmation(button);
    setCredentialStatus(status, "Vaulty save failed.", "error");
    flashButton(button, "Save failed");
    return;
  }

  const sourceLabel = relayRequest.source.generatedRequestId
    ? "generated request attached"
    : "current page fields";
  const actionLabel = saveResponse.action === "updated" ? "Updated" : "Saved";

  clearCredentialSaveConfirmation(button);
  setCredentialStatus(
    status,
    `${actionLabel} for ${credential.email || credential.username} · password present · ${sourceLabel} · not stored in extension.`,
    "success"
  );
  flashButton(button, saveResponse.action === "updated" ? "Updated" : "Saved");
}

function rememberCredentialSaveConfirmation(credential, summary, fingerprint, mode = "save") {
  pendingCredentialSaveConfirmation = {
    origin: credential.origin || "",
    identityLabel: formatCredentialIdentityLabel(credential),
    fingerprint,
    mode,
    createdAt: Date.now(),
    hasPassword: true,
    passwordConfirmMapped: Boolean(summary?.passwordConfirmMapped),
  };
}

function getActiveCredentialSaveConfirmation(origin) {
  if (!pendingCredentialSaveConfirmation) {
    return null;
  }

  if (pendingCredentialSaveConfirmation.origin !== origin) {
    pendingCredentialSaveConfirmation = null;
    return null;
  }

  const ageMs = Date.now() - pendingCredentialSaveConfirmation.createdAt;

  if (ageMs < 0 || ageMs > CREDENTIAL_SAVE_CONFIRMATION_MAX_AGE_MS) {
    pendingCredentialSaveConfirmation = null;
    return null;
  }

  return pendingCredentialSaveConfirmation;
}

function clearCredentialSaveConfirmation(button = null) {
  pendingCredentialSaveConfirmation = null;
  setCredentialButtonMode("default", button);
}

function setCredentialButtonMode(mode = "default", button = null) {
  const saveButton = button || document.getElementById("mock-save-credential");
  const cancelButton = document.getElementById("cancel-credential-confirmation");

  if (saveButton) {
    saveButton.classList.toggle("pending-confirmation", mode !== "default");

    if (mode === "overwrite") {
      saveButton.textContent = CONFIRM_OVERWRITE_CREDENTIAL_BUTTON_TEXT;
    } else if (mode === "save") {
      saveButton.textContent = CONFIRM_SAVE_CREDENTIAL_BUTTON_TEXT;
    } else {
      saveButton.textContent = DEFAULT_PREPARE_CREDENTIAL_BUTTON_TEXT;
    }
  }

  if (cancelButton) {
    cancelButton.hidden = mode === "default";
  }
}

function buildCredentialConfirmationFingerprint(credential, summary) {
  return [
    credential.origin || "",
    credential.email || "",
    credential.username || "",
    summary?.passwordConfirmMapped ? "confirm-mapped" : "confirm-not-mapped",
    summary?.passwordsMatch === false ? "confirm-mismatch" : "confirm-ok",
  ].join("|");
}

function formatCredentialIdentityLabel(credential) {
  return credential.email || credential.username || "this login";
}

function getCredentialSourceLabelForOrigin(origin) {
  return getActiveGeneratedPasswordMeta(origin)
    ? "generated request attached"
    : "current page fields";
}

function validateCredentialReadiness(readResponse) {
  const credential = readResponse?.credential || {};
  const summary = readResponse?.summary || {};
  const fields = readResponse?.fields || {};

  const email = String(credential.email || "").trim();
  const username = String(credential.username || "").trim();
  const password = String(credential.password || "");

  if (!email && !username) {
    return {
      ok: false,
      message: "Missing email or username. Fill a mapped registration email/username field first.",
      buttonLabel: "Missing ID",
    };
  }

  if (!password) {
    const passwordWasMapped = Boolean(
      fields.registrationPassword?.source || fields.loginPassword?.source
    );

    return {
      ok: false,
      message: passwordWasMapped
        ? "Mapped password field is empty or unreadable. Fill it before preparing the login."
        : "Map and fill a password field before preparing the login.",
      buttonLabel: "Missing PW",
    };
  }

  if (summary.passwordConfirmMapped && !summary.hasPasswordConfirm) {
    return {
      ok: false,
      message: "Confirm-password field is mapped but empty or unreadable.",
      buttonLabel: "Confirm empty",
    };
  }

  if (summary.passwordConfirmMapped && summary.passwordsMatch === false) {
    return {
      ok: false,
      message: "Password and confirm-password fields do not match. Save blocked.",
      buttonLabel: "Mismatch",
    };
  }

  return {
    ok: true,
    credential: {
      ...credential,
      email,
      username,
      password,
    },
  };
}

function buildVaultySaveRequest(credential, summary, options = {}) {
  const generatedMeta = getActiveGeneratedPasswordMeta(credential.origin);

  return {
    type: "SAVE_CREDENTIAL",
    origin: credential.origin,
    url: credential.url,
    allowOverwrite: Boolean(options.allowOverwrite),

    credential: {
      email: credential.email || "",
      username: credential.username || "",
      password: credential.password || "",
    },

    source: {
      flow: "registration",
      passwordSource: generatedMeta ? "generated-then-read-from-page" : "read-from-page",
      generatedRequestId: generatedMeta?.generatedRequestId || "",
      generatedAt: generatedMeta?.generatedAt || null,
      collectedAt: Date.now(),
      fieldSources: summary?.source || {},
    },
  };
}



function setCredentialStatus(element, text, tone = "neutral") {
  if (!element) {
    return;
  }

  element.textContent = text || "—";
  element.classList.remove("neutral", "success", "warning", "error", "pending");
  element.classList.add(tone || "neutral");
}

function formatCredentialReadError(response) {
  if (!response) {
    return "No content script response.";
  }

  if (response.reason === "origin-mismatch") {
    return "Origin mismatch. Refresh the page and try again.";
  }

  if (response.reason === "missing-origin") {
    return "Missing origin lock.";
  }

  return "Could not read mapped credential fields.";
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

async function startSelector(config, button) {
  const tab = await getActiveTab();

  if (!tab?.id || !isSelectablePage(tab.url)) {
    flashButton(button, "Unavailable");
    return;
  }

  const scope = config.scope || "login";
  const role = config.role || "generic";
  const label = config.label || "page element";

  const intent = {
    scope,
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
    scope,
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

  const hasLoginMapping =
    Boolean(mapping?.login?.username) ||
    Boolean(mapping?.login?.password);

  const hasRegistrationMapping =
    Boolean(mapping?.registration?.email) ||
    Boolean(mapping?.registration?.username) ||
    Boolean(mapping?.registration?.password) ||
    Boolean(mapping?.registration?.passwordConfirm) ||
    Boolean(mapping?.registration?.submit);

  if (!mapping || (!hasLoginMapping && !hasRegistrationMapping)) {
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
    formatStoredField(mapping.login?.username, validation?.fields?.loginUsername)
  );

  setText(
    "mapping-password",
    formatStoredField(mapping.login?.password, validation?.fields?.loginPassword)
  );

  setText("mapping-updated", formatTimestamp(mapping.updatedAt));

  setText(
  "mapping-registration-email",
  formatStoredField(
    mapping.registration?.email,
    validation?.fields?.registrationEmail
  )
);

setText(
  "mapping-registration-username",
  formatStoredField(
    mapping.registration?.username,
    validation?.fields?.registrationUsername
  )
);

setText(
  "mapping-registration-password",
  formatStoredField(
    mapping.registration?.password,
    validation?.fields?.registrationPassword
  )
);

setText(
  "mapping-registration-password-confirm",
  formatStoredField(
    mapping.registration?.passwordConfirm,
    validation?.fields?.registrationPasswordConfirm
  )
);

setText(
  "mapping-registration-submit",
  formatStoredField(
    mapping.registration?.submit,
    validation?.fields?.registrationSubmit
  )
);
}

async function validateCurrentMapping(tabId, origin, mapping) {
  if (!tabId || !origin || !mapping) {
    return null;
  }

  const response = await sendMessageToTab(tabId, {
    type: "VAULTY_VALIDATE_MAPPING",
    payload: {
      origin,
      mapping
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
async function fillFreshGeneratedPasswordFields() {
  const button = document.getElementById("fill-generated-password");
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

  const hasRegistrationPassword =
    Boolean(mapping?.registration?.password?.selector) ||
    Boolean(mapping?.registration?.passwordConfirm?.selector);

  if (!hasRegistrationPassword) {
    flashButton(button, "Map password first");
    return;
  }

  let generation;

  try {
    generation = await vaultyGeneratePassword({
      length: 24,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
    });
  } catch (error) {
    console.warn("Vaulty popup: native password generation failed", error);
    flashButton(button, "Vaulty failed");
    return;
  }

  if (!generation?.ok || !generation.password) {
    flashButton(button, "Generate failed");
    return;
  }

  const fillResponse = await sendMessageToTab(tab.id, {
    type: "VAULTY_FILL_REGISTRATION_PASSWORD",
    payload: {
      origin,
      mapping,
      password: generation.password,
      generatedRequestId: generation.generatedRequestId,
    },
  });

  if (fillResponse?.ok) {
    rememberGeneratedPasswordMeta(generation, origin);
    clearCredentialSaveConfirmation(document.getElementById("mock-save-credential"));
    setCredentialStatus(
      document.getElementById("mock-save-credential-status"),
      "Generated password filled. Prepare login when the registration fields are final.",
      "success"
    );
    flashButton(button, "Filled");
  } else if (fillResponse) {
    latestGeneratedPasswordMeta = null;
    flashButton(button, "Fill failed");
    console.warn("Vaulty popup: generated password fill failed", {
      reason: fillResponse.reason,
      fields: fillResponse.fields,
    });
  } else {
    flashButton(button, "No content script");
  }
}
