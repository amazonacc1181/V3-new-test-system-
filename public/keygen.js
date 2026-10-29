(() => {
  const keyField = document.getElementById("key");
  const status = document.getElementById("status");
  document.getElementById("generate").addEventListener("click", () => {
    try {
      if (!window.crypto || typeof window.crypto.getRandomValues !== "function") {
        throw new Error("Secure random generator unavailable");
      }
      const bytes = new Uint8Array(32);
      window.crypto.getRandomValues(bytes);
      keyField.value = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
      status.textContent = "Key generated locally. Save it securely; do not send it in chat.";
    } catch (err) {
      status.textContent = "Could not generate in this browser. Try opening this page directly in Safari and reload.";
    }
  });
  document.getElementById("copy").addEventListener("click", async () => {
    if (!keyField.value) {
      status.textContent = "Generate a key first.";
      return;
    }
    try {
      await navigator.clipboard.writeText(keyField.value);
      status.textContent = "Copied. Paste it directly into Render; do not share it in chat.";
    } catch (err) {
      keyField.focus();
      keyField.select();
      status.textContent = "Key selected. Touch and hold the selected text, then tap Copy.";
    }
  });
})();