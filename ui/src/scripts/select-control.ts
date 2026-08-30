function closeSelects(except?: BarkSelectElement) {
  document.querySelectorAll<BarkSelectElement>('bark-select[open]').forEach((control) => {
    if (control !== except) control.close();
  });
}

class BarkSelectElement extends HTMLElement {
  private select?: HTMLSelectElement;
  private trigger?: HTMLButtonElement;
  private menu?: HTMLDivElement;
  private initialized = false;

  connectedCallback() {
    this.upgrade();
  }

  upgrade() {
    const select = this.querySelector<HTMLSelectElement>(':scope > select');
    if (!select) return;
    this.select = select;
    if (!this.initialized) {
      this.initialized = true;
      select.classList.add('custom-select-native');
      select.tabIndex = -1;
      select.setAttribute('aria-hidden', 'true');
      this.trigger = document.createElement('button');
      this.trigger.type = 'button';
      this.trigger.className = 'custom-select-trigger';
      this.trigger.setAttribute('aria-haspopup', 'listbox');
      this.trigger.setAttribute('aria-expanded', 'false');
      this.trigger.setAttribute('aria-label', (select.getAttribute('aria-label') || select.name || select.id || 'Select').replaceAll('_', ' '));
      this.trigger.innerHTML = '<span></span><svg aria-hidden="true"><use href="#i-chevron"></use></svg>';
      this.menu = document.createElement('div');
      this.menu.className = 'custom-select-menu';
      this.menu.setAttribute('role', 'listbox');
      this.insertBefore(this.trigger, select);
      this.appendChild(this.menu);
      this.trigger.addEventListener('click', (event) => {
        event.stopPropagation();
        const opening = !this.hasAttribute('open');
        closeSelects(this);
        if (opening) this.open(); else this.close();
      });
      this.addEventListener('keydown', (event) => this.handleKeydown(event));
      select.addEventListener('change', () => this.refresh());
      select.form?.addEventListener('reset', () => queueMicrotask(() => this.refresh()));
    }
    this.refresh();
  }

  open() {
    if (this.select?.disabled) return;
    this.setAttribute('open', '');
    this.trigger?.setAttribute('aria-expanded', 'true');
    this.menu?.querySelector<HTMLButtonElement>('.selected:not(:disabled)')?.focus();
  }

  close() {
    this.removeAttribute('open');
    this.trigger?.setAttribute('aria-expanded', 'false');
  }

  private refresh() {
    if (!this.select || !this.trigger || !this.menu) return;
    const selected = this.select.selectedOptions[0];
    const label = this.trigger.querySelector('span');
    if (label) label.textContent = selected?.textContent || 'Select';
    this.trigger.disabled = this.select.disabled;
    const options = [...this.select.options].map((option) => {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'custom-select-option';
      item.textContent = option.textContent;
      item.disabled = option.disabled;
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', String(option.selected));
      if (option.selected) item.classList.add('selected');
      item.addEventListener('click', () => {
        if (!this.select) return;
        this.select.value = option.value;
        this.select.dispatchEvent(new Event('change', { bubbles: true }));
        this.close();
        this.trigger?.focus();
      });
      return item;
    });
    this.menu.replaceChildren(...options);
  }

  private handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      this.close();
      this.trigger?.focus();
      return;
    }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key) || !this.menu) return;
    event.preventDefault();
    if (!this.hasAttribute('open')) this.open();
    const options = [...this.menu.querySelectorAll<HTMLButtonElement>('.custom-select-option:not(:disabled)')];
    if (!options.length) return;
    const current = Math.max(0, options.indexOf(document.activeElement as HTMLButtonElement));
    const index = event.key === 'Home'
      ? 0
      : event.key === 'End'
        ? options.length - 1
        : event.key === 'ArrowDown'
          ? Math.min(options.length - 1, current + 1)
          : Math.max(0, current - 1);
    options[index].focus();
  }
}

customElements.define('bark-select', BarkSelectElement);

function enhanceSelects(root: ParentNode) {
  root.querySelectorAll<HTMLSelectElement>('select').forEach((select) => {
    const existing = select.closest<BarkSelectElement>('bark-select');
    if (existing) {
      existing.upgrade();
      return;
    }
    const control = document.createElement('bark-select') as BarkSelectElement;
    select.parentNode?.insertBefore(control, select);
    control.appendChild(select);
    control.upgrade();
  });
}

enhanceSelects(document);
document.addEventListener('click', () => closeSelects());
new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    if (mutation.target instanceof HTMLSelectElement) {
      mutation.target.closest<BarkSelectElement>('bark-select')?.upgrade();
    } else if (mutation.target instanceof HTMLOptionElement) {
      mutation.target.closest<HTMLSelectElement>('select')?.closest<BarkSelectElement>('bark-select')?.upgrade();
    }
    mutation.addedNodes.forEach((node) => {
      if (node instanceof HTMLSelectElement) enhanceSelects(node.parentNode || document);
      else if (node instanceof Element) enhanceSelects(node);
    });
  }
}).observe(document.body, { attributes: true, attributeFilter: ['disabled', 'selected'], childList: true, subtree: true });
