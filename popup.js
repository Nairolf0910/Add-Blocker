// ============================================
// Redirect Guard – Popup Logic
// ============================================

(function () {
  'use strict';

  // --- DOM References ---
  const toggleEnabled = document.getElementById('toggle-enabled');
  const statsToday = document.getElementById('stats-today');
  const statsTotal = document.getElementById('stats-total');
  const sensitivitySlider = document.getElementById('sensitivity-slider');
  const sliderLabels = document.querySelectorAll('.slider-label');
  const whitelistList = document.getElementById('whitelist-list');
  const whitelistEmpty = document.getElementById('whitelist-empty');
  const whitelistCount = document.getElementById('whitelist-count');
  const whitelistInput = document.getElementById('whitelist-input');
  const whitelistAddBtn = document.getElementById('whitelist-add-btn');

  // Sensitivity value mapping
  const SENSITIVITY_MAP = ['low', 'medium', 'high'];
  const SENSITIVITY_INDEX = { low: 0, medium: 1, high: 2 };

  // Default settings
  const DEFAULTS = {
    enabled: true,
    sensitivity: 'medium',
    whitelist: [],
    statsToday: 0,
    statsTotal: 0,
    statsDate: new Date().toISOString().slice(0, 10),
  };

  // --- Storage Helpers ---

  /**
   * Read all settings from chrome.storage.local, filling in defaults.
   * @returns {Promise<object>}
   */
  function loadSettings() {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(DEFAULTS, (data) => resolve(data));
      } else {
        // Fallback for local testing outside of extension context
        const data = {};
        for (const key of Object.keys(DEFAULTS)) {
          try {
            const stored = localStorage.getItem('rg_' + key);
            data[key] = stored !== null ? JSON.parse(stored) : DEFAULTS[key];
          } catch {
            data[key] = DEFAULTS[key];
          }
        }
        resolve(data);
      }
    });
  }

  /**
   * Save a partial settings object.
   * @param {object} obj
   * @returns {Promise<void>}
   */
  function saveSettings(obj) {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set(obj, () => resolve());
      } else {
        for (const [key, value] of Object.entries(obj)) {
          localStorage.setItem('rg_' + key, JSON.stringify(value));
        }
        resolve();
      }
    });
  }

  /**
   * Send a message to the background script.
   */
  function sendMessage(msg) {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage(msg);
    }
  }

  // --- UI Rendering ---

  /**
   * Apply all settings to the UI.
   */
  function applySettingsToUI(settings) {
    // Toggle
    toggleEnabled.checked = settings.enabled;
    document.body.classList.toggle('extension-disabled', !settings.enabled);

    // Stats – check if the day rolled over
    const today = new Date().toISOString().slice(0, 10);
    if (settings.statsDate !== today) {
      settings.statsToday = 0;
      settings.statsDate = today;
      saveSettings({ statsToday: 0, statsDate: today });
    }
    animateNumber(statsToday, settings.statsToday);
    animateNumber(statsTotal, settings.statsTotal);

    // Sensitivity
    const idx = SENSITIVITY_INDEX[settings.sensitivity] ?? 1;
    sensitivitySlider.value = idx;
    updateSliderLabels(idx);

    // Whitelist
    renderWhitelist(settings.whitelist);
  }

  /**
   * Simple animated number counter.
   */
  function animateNumber(el, target) {
    const current = parseInt(el.textContent, 10) || 0;
    if (current === target) {
      el.textContent = target;
      return;
    }
    const diff = target - current;
    const steps = Math.min(Math.abs(diff), 20);
    const stepTime = Math.max(15, 300 / steps);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      const progress = step / steps;
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      el.textContent = Math.round(current + diff * eased);
      if (step >= steps) {
        el.textContent = target;
        clearInterval(interval);
      }
    }, stepTime);
  }

  /**
   * Update active state on slider labels.
   */
  function updateSliderLabels(activeIndex) {
    sliderLabels.forEach((label) => {
      const val = parseInt(label.dataset.value, 10);
      label.classList.toggle('active', val === activeIndex);
    });
  }

  /**
   * Render the whitelist domain list.
   */
  function renderWhitelist(whitelist) {
    // Remove old items (keep the empty placeholder)
    whitelistList.querySelectorAll('.whitelist-item').forEach((el) => el.remove());

    whitelistCount.textContent = whitelist.length;

    if (whitelist.length === 0) {
      whitelistEmpty.style.display = 'flex';
      return;
    }

    whitelistEmpty.style.display = 'none';

    whitelist.forEach((domain) => {
      const item = document.createElement('div');
      item.className = 'whitelist-item';
      item.innerHTML = `
        <span class="domain-dot"></span>
        <span class="domain-name" title="${escapeHtml(domain)}">${escapeHtml(domain)}</span>
        <button class="delete-btn" title="Entfernen" data-domain="${escapeHtml(domain)}">✕</button>
      `;
      whitelistList.appendChild(item);
    });
  }

  /**
   * Escape HTML entities.
   */
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  /**
   * Basic domain format validation.
   * Accepts: example.com, sub.example.com, example.co.uk, etc.
   */
  function isValidDomain(str) {
    if (!str || str.length > 253) return false;
    // Strip optional protocol and path
    let domain = str.trim().toLowerCase();
    domain = domain.replace(/^(https?:\/\/)/, '');
    domain = domain.replace(/\/.*$/, '');
    domain = domain.replace(/:\d+$/, '');
    // Basic domain regex
    return /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain);
  }

  /**
   * Normalize domain input.
   */
  function normalizeDomain(str) {
    let domain = str.trim().toLowerCase();
    domain = domain.replace(/^(https?:\/\/)/, '');
    domain = domain.replace(/\/.*$/, '');
    domain = domain.replace(/:\d+$/, '');
    return domain;
  }

  // --- Event Handlers ---

  // Toggle
  toggleEnabled.addEventListener('change', async () => {
    const enabled = toggleEnabled.checked;
    document.body.classList.toggle('extension-disabled', !enabled);
    await saveSettings({ enabled });
    sendMessage({ type: 'toggleEnabled', enabled });
  });

  // Sensitivity slider
  sensitivitySlider.addEventListener('input', async () => {
    const idx = parseInt(sensitivitySlider.value, 10);
    updateSliderLabels(idx);
    const sensitivity = SENSITIVITY_MAP[idx] || 'medium';
    await saveSettings({ sensitivity });
    sendMessage({ type: 'sensitivityChanged', sensitivity });
  });

  // Whitelist delete
  whitelistList.addEventListener('click', async (e) => {
    const deleteBtn = e.target.closest('.delete-btn');
    if (!deleteBtn) return;

    const domain = deleteBtn.dataset.domain;
    const item = deleteBtn.closest('.whitelist-item');

    // Animate out
    if (item) {
      item.style.animation = 'slideOut 0.25s cubic-bezier(0.4, 0, 0.2, 1) forwards';
      await new Promise((r) => setTimeout(r, 230));
    }

    const settings = await loadSettings();
    const newWhitelist = settings.whitelist.filter((d) => d !== domain);
    await saveSettings({ whitelist: newWhitelist });
    renderWhitelist(newWhitelist);
    sendMessage({ type: 'whitelistChanged', whitelist: newWhitelist });
  });

  // Add domain
  async function addDomain() {
    const raw = whitelistInput.value;
    const domain = normalizeDomain(raw);

    if (!isValidDomain(domain)) {
      whitelistInput.classList.add('input-error');
      setTimeout(() => whitelistInput.classList.remove('input-error'), 500);
      whitelistInput.focus();
      return;
    }

    const settings = await loadSettings();

    // Check duplicates
    if (settings.whitelist.includes(domain)) {
      whitelistInput.classList.add('input-error');
      setTimeout(() => whitelistInput.classList.remove('input-error'), 500);
      whitelistInput.value = '';
      whitelistInput.focus();
      return;
    }

    const newWhitelist = [...settings.whitelist, domain];
    await saveSettings({ whitelist: newWhitelist });
    renderWhitelist(newWhitelist);
    whitelistInput.value = '';
    whitelistInput.focus();
    sendMessage({ type: 'whitelistChanged', whitelist: newWhitelist });
  }

  whitelistAddBtn.addEventListener('click', addDomain);

  whitelistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addDomain();
    }
  });

  // Remove error state on input
  whitelistInput.addEventListener('input', () => {
    whitelistInput.classList.remove('input-error');
  });

  // --- Real-time Storage Listener ---
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;

      if (changes.enabled !== undefined) {
        toggleEnabled.checked = changes.enabled.newValue;
        document.body.classList.toggle('extension-disabled', !changes.enabled.newValue);
      }

      if (changes.sensitivity !== undefined) {
        const idx = SENSITIVITY_INDEX[changes.sensitivity.newValue] ?? 1;
        sensitivitySlider.value = idx;
        updateSliderLabels(idx);
      }

      if (changes.whitelist !== undefined) {
        renderWhitelist(changes.whitelist.newValue || []);
      }

      if (changes.statsToday !== undefined) {
        animateNumber(statsToday, changes.statsToday.newValue || 0);
      }

      if (changes.statsTotal !== undefined) {
        animateNumber(statsTotal, changes.statsTotal.newValue || 0);
      }
    });
  }

  // --- Initialize ---
  loadSettings().then(applySettingsToUI);
})();
