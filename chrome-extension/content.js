// Fills the best-guess username/password fields on the current page when
// asked to by the popup. Never submits the form and never reads
// credentials on its own — it only receives values already decrypted by
// the native host and handed to it by popup.js after an explicit user
// click, so this script never touches the vault or the master password.

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type !== "PASS_FILL_CREDENTIALS") return undefined;
  sendResponse({ filled: fillCredentials(message.username, message.password) });
  return false;
});

function fillCredentials(username, password) {
  const passwordField = findPasswordField();
  const usernameField = findUsernameField(passwordField);

  let filled = false;
  if (usernameField) {
    setValue(usernameField, username);
    filled = true;
  }
  if (passwordField) {
    setValue(passwordField, password);
    filled = true;
  }
  return filled;
}

function findPasswordField() {
  return document.querySelector('input[type="password"]');
}

function findUsernameField(passwordField) {
  const keywords = ["user", "email", "login", "identifier"];
  const candidates = Array.from(
    document.querySelectorAll('input[type="text"], input[type="email"], input:not([type])')
  );

  const scored = candidates
    .map((input) => {
      const haystack = `${input.name} ${input.id} ${input.autocomplete} ${input.placeholder}`.toLowerCase();
      return { input, score: keywords.some((k) => haystack.includes(k)) ? 1 : 0 };
    })
    .filter((c) => c.score > 0);

  if (scored.length > 0) return scored[0].input;

  // Fall back to the first plain text-like input in the same form as the
  // password field, which is a decent heuristic for unlabeled login forms.
  const form = passwordField && passwordField.closest("form");
  if (form) {
    return form.querySelector('input[type="text"], input[type="email"], input:not([type])');
  }

  return null;
}

// Use the native input value setter so frameworks (React, Vue, …) that
// track state via property descriptors notice the programmatic change,
// not just a raw DOM attribute write.
function setValue(input, value) {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
  setter.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}
