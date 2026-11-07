// Copy only after a tap. With JavaScript off, the original text stays usable.
for (const snippet of document.querySelectorAll('[data-copy-label]')) {
  const tools = document.createElement('div');
  tools.className = 'copy-tools';
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'copy-button';
  button.textContent = 'Copy';
  button.setAttribute('aria-label', `Copy ${snippet.dataset.copyLabel}`);
  const status = document.createElement('span');
  status.className = 'copy-status';
  status.setAttribute('role', 'status');
  tools.append(button, status);
  snippet.before(tools);

  let reset;
  button.addEventListener('click', async () => {
    clearTimeout(reset);
    button.disabled = true;
    status.textContent = '';
    try {
      await navigator.clipboard.writeText(snippet.textContent);
      button.textContent = 'Copied';
      button.setAttribute('aria-label', `Copied ${snippet.dataset.copyLabel}`);
      status.textContent = 'Copied to clipboard.';
    } catch {
      // A denied or unavailable clipboard is not a successful copy.
      const selection = window.getSelection();
      if (selection) {
        const range = document.createRange();
        range.selectNodeContents(snippet);
        selection.removeAllRanges();
        selection.addRange(range);
        status.textContent = 'Text selected. Use your device’s Copy command.';
      } else {
        status.textContent = 'Select the text below and use your device’s Copy command.';
      }
      button.textContent = 'Select text';
      button.setAttribute('aria-label', `Select text: ${snippet.dataset.copyLabel}`);
    } finally {
      button.disabled = false;
      reset = setTimeout(() => {
        button.textContent = 'Copy';
        button.setAttribute('aria-label', `Copy ${snippet.dataset.copyLabel}`);
        status.textContent = '';
      }, 6000);
    }
  });
}
