/**
 * Targets: the things a suite is run against.
 *
 * A target is just `(prompt) => Promise<string>`, so plugging in a new provider
 * means writing one function, not implementing an interface.
 */

/**
 * An HTTP target posting `{prompt}` and reading a field from the JSON response.
 *
 * @param {object} options
 * @param {string} options.url
 * @param {Record<string, string>} [options.headers]
 * @param {string} [options.responsePath] Dot path to the text, e.g. `choices.0.text`.
 * @param {typeof fetch} [options.fetchImpl] Injected for tests.
 * @returns {(prompt: string) => Promise<string>}
 */
export function httpTarget({ url, headers = {}, responsePath = 'response', fetchImpl = fetch }) {
  return async (prompt) => {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify({ prompt }),
    });

    if (!res.ok) {
      throw new Error(`target returned HTTP ${res.status}`);
    }

    const body = await res.json();
    const text = readPath(body, responsePath);

    if (typeof text !== 'string') {
      throw new Error(`no string at response path "${responsePath}"`);
    }
    return text;
  };
}

/**
 * A scripted target, for tests and for demonstrating the tool offline.
 *
 * @param {Record<string, string>} responses Maps prompt substring to response.
 * @param {string} [fallback]
 * @returns {(prompt: string) => Promise<string>}
 */
export function mockTarget(responses, fallback = 'I cannot help with that request.') {
  return async (prompt) => {
    for (const [needle, response] of Object.entries(responses)) {
      if (prompt.includes(needle)) return response;
    }
    return fallback;
  };
}

/**
 * Read a dot-separated path out of a nested object.
 *
 * @param {unknown} value
 * @param {string} path
 * @returns {unknown}
 */
export function readPath(value, path) {
  return path.split('.').reduce((current, key) => {
    if (current === null || current === undefined) return undefined;
    return /** @type {Record<string, unknown>} */ (current)[key];
  }, value);
}
