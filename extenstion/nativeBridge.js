const VAULTY_NATIVE_HOST = "com.vaulty.native_host";

function getRuntimeApi() {
  return globalThis.browser?.runtime ?? globalThis.chrome?.runtime;
}

async function getActiveTabOrigin() {
  const tabs = await chromePromise(chrome.tabs.query, chrome.tabs, {
    active: true,
    currentWindow: true,
  });

  const url = tabs?.[0]?.url;

  if (!url) {
    throw new Error("No active tab URL available.");
  }

  const origin = safeOrigin(url);

  if (!origin) {
    throw new Error("No valid active tab origin.");
  }

  return origin;
}

async function sendVaultyNativeMessage(message, { timeoutMs = 5000 } = {}) {
  const runtime = getRuntimeApi();

  if (!runtime?.sendNativeMessage) {
    throw new Error("Native messaging API is not available.");
  }

  const response = await Promise.race([
    new Promise((resolve, reject) => {
      runtime.sendNativeMessage(VAULTY_NATIVE_HOST, message, (reply) => {
        const err = runtime.lastError;

        if (err) {
          reject(new Error(err.message));
          return;
        }

        resolve(reply);
      });
    }),
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Vaulty native host timed out.")), timeoutMs);
    }),
  ]);

  if (!response || typeof response !== "object") {
    throw new Error("Invalid Vaulty native host response.");
  }

  if (response.requestId !== message.requestId) {
    throw new Error("Vaulty native host response requestId mismatch.");
  }

  if (response.ok === false) {
    throw new Error(response.error?.message ?? "Vaulty native host request failed.");
  }

  return response;
}

async function vaultyGeneratePassword(policy = {}) {
  return sendVaultyNativeMessage({
    type: "GENERATE_PASSWORD",
    requestId: crypto.randomUUID(),
    origin: await getActiveTabOrigin(),
    policy,
  });
}

async function vaultyRetrieveCredential(options = {}) {
  return sendVaultyNativeMessage({
    type: "RETRIEVE_CREDENTIAL",
    requestId: crypto.randomUUID(),
    origin: options.origin || await getActiveTabOrigin(),
    purpose: options.purpose || "login_fill",
  });
}

async function vaultySaveCredential(request) {
  return sendVaultyNativeMessage({
    ...request,
    type: "SAVE_CREDENTIAL",
    requestId: crypto.randomUUID(),
    origin: request.origin || await getActiveTabOrigin(),
  });
}
