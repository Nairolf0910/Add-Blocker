/**
 * Redirect Guard – Blocked Page Logic
 * 
 * Handles URL parameter parsing, button actions,
 * and communication with the background script.
 */

(function () {
  'use strict';

  // ── Helpers ──────────────────────────────────────────────

  /**
   * Parse URL search parameters from the current page URL.
   * @returns {{ url: string, source: string, reason: string, tabId: number|null }}
   */
  function getParams() {
    const params = new URLSearchParams(window.location.search);
    const tabIdRaw = params.get('tabId');
    return {
      url: params.get('url') || '',
      source: params.get('source') || '',
      reason: params.get('reason') || '',
      tabId: tabIdRaw ? parseInt(tabIdRaw, 10) : null,
    };
  }

  /**
   * Try to extract the hostname (domain) from a URL string.
   * @param {string} urlStr
   * @returns {string}
   */
  function extractDomain(urlStr) {
    try {
      return new URL(urlStr).hostname;
    } catch {
      // Fallback: try adding protocol
      try {
        return new URL('https://' + urlStr).hostname;
      } catch {
        return urlStr;
      }
    }
  }

  /**
   * Truncate a URL for display if it exceeds maxLen characters.
   * @param {string} url 
   * @param {number} maxLen 
   * @returns {string}
   */
  function truncateUrl(url, maxLen = 200) {
    if (url.length <= maxLen) return url;
    return url.substring(0, maxLen) + '…';
  }

  /**
   * Send a message to the Chrome/Edge extension background script.
   * Returns a Promise that resolves with the response.
   * @param {object} message 
   * @returns {Promise<any>}
   */
  function sendMessage(message) {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) {
            console.warn('Redirect Guard: Message error:', chrome.runtime.lastError.message);
            reject(chrome.runtime.lastError);
          } else {
            resolve(response);
          }
        });
      } else {
        console.warn('Redirect Guard: chrome.runtime not available. Running outside extension context.');
        resolve(null);
      }
    });
  }

  // ── Toast Notification System ────────────────────────────

  const TOAST_ICONS = {
    success: `<svg viewBox="0 0 20 20" fill="currentColor" class="toast__icon"><path fill-rule="evenodd" d="M16.704 4.153a.75.75 0 01.143 1.052l-8 10.5a.75.75 0 01-1.127.075l-4.5-4.5a.75.75 0 011.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 011.05-.143z" clip-rule="evenodd"/></svg>`,
    info: `<svg viewBox="0 0 20 20" fill="currentColor" class="toast__icon"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clip-rule="evenodd"/></svg>`,
  };

  /**
   * Show a toast notification.
   * @param {string} message - The message to display.
   * @param {'success'|'info'} type - The toast type.
   * @param {number} duration - Auto-dismiss duration in ms.
   */
  function showToast(message, type = 'success', duration = 3500) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.innerHTML = `${TOAST_ICONS[type] || ''}<span>${message}</span>`;
    container.appendChild(toast);

    // Auto-dismiss
    setTimeout(() => {
      toast.style.animation = 'toastSlideOut 0.3s ease-in forwards';
      toast.addEventListener('animationend', () => toast.remove(), { once: true });
    }, duration);
  }

  // ── Page Initialization ──────────────────────────────────

  function init() {
    const { url, source, reason, tabId } = getParams();

    // Populate the page
    const blockedUrlEl = document.getElementById('blockedUrl');
    const sourceUrlEl = document.getElementById('sourceUrl');
    const reasonEl = document.getElementById('reason');

    if (blockedUrlEl) {
      blockedUrlEl.textContent = url ? truncateUrl(url) : 'Unbekannte URL';
      blockedUrlEl.title = url; // Full URL on hover
    }

    if (sourceUrlEl) {
      sourceUrlEl.textContent = source ? truncateUrl(source) : 'Unbekannte Herkunft';
      sourceUrlEl.title = source;
    }

    if (reasonEl) {
      reasonEl.textContent = reason || 'Verdächtige Weiterleitung erkannt';
    }

    // ── Button: Zurück zur Seite ───────────────────────────
    const btnGoBack = document.getElementById('btnGoBack');
    if (btnGoBack) {
      btnGoBack.addEventListener('click', () => {
        if (window.history.length > 1) {
          window.history.back();
        } else if (source) {
          window.location.href = source;
        } else {
          // Fallback: close or go to new tab page
          window.location.href = 'about:newtab';
        }
      });
    }

    // ── Button: Trotzdem öffnen (Allow Once) ───────────────
    const btnProceed = document.getElementById('btnProceed');
    if (btnProceed) {
      btnProceed.addEventListener('click', async () => {
        if (!url) {
          showToast('Keine URL zum Öffnen vorhanden.', 'info');
          return;
        }

        try {
          // Resolve tabId: prefer URL param, then try chrome.tabs
          let resolvedTabId = tabId;
          if (resolvedTabId === null && typeof chrome !== 'undefined' && chrome.tabs) {
            try {
              const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
              if (tab) resolvedTabId = tab.id;
            } catch {
              // Ignore if tabs API not available
            }
          }

          await sendMessage({
            action: 'allowOnce',
            url: url,
            tabId: resolvedTabId,
          });
        } catch (err) {
          console.warn('Redirect Guard: Could not send allowOnce message:', err);
        }

        // Navigate regardless of message success
        window.location.href = url;
      });
    }

    // ── Button: Domain erlauben (Whitelist) ─────────────────
    const btnWhitelist = document.getElementById('btnWhitelist');
    if (btnWhitelist) {
      btnWhitelist.addEventListener('click', async () => {
        if (!url) {
          showToast('Keine URL vorhanden.', 'info');
          return;
        }

        const domain = extractDomain(url);

        try {
          await sendMessage({
            action: 'whitelistDomain',
            domain: domain,
          });

          showToast(`Domain „${domain}" wurde zur Whitelist hinzugefügt.`, 'success');
        } catch (err) {
          console.warn('Redirect Guard: Could not send whitelistDomain message:', err);
          showToast(`Domain „${domain}" wird erlaubt.`, 'info');
        }

        // Navigate after a short delay so the user sees the toast
        setTimeout(() => {
          window.location.href = url;
        }, 1200);
      });
    }
  }

  // ── Boot ─────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
