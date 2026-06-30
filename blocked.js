/**
 * Redirect Guard – Blocked Page Logic v1.2.0
 *
 * Diese Seite erscheint NUR wenn der Tab nicht geschlossen werden konnte
 * (einziger Tab im Fenster). Normalerweise wird der Tab sofort geschlossen.
 */

(function () {
  'use strict';

  function getParams() {
    const params = new URLSearchParams(window.location.search);
    const tabIdRaw = params.get('tabId');
    return {
      url:    params.get('url')    || '',
      source: params.get('source') || '',
      reason: params.get('reason') || '',
      tabId:  tabIdRaw ? parseInt(tabIdRaw, 10) : null,
    };
  }

  function extractDomain(urlStr) {
    try { return new URL(urlStr).hostname; }
    catch {
      try { return new URL('https://' + urlStr).hostname; }
      catch { return urlStr; }
    }
  }

  function truncateUrl(url, maxLen = 200) {
    return url.length <= maxLen ? url : url.substring(0, maxLen) + '…';
  }

  function sendMessage(message) {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
          else resolve(response);
        });
      } else {
        resolve(null);
      }
    });
  }

  // ─── Toast ───────────────────────────────────────────────────

  const TOAST_ICONS = {
    success: `<svg viewBox="0 0 20 20" fill="currentColor" class="toast__icon"><path fill-rule="evenodd" d="M16.704 4.153a.75.75 0 01.143 1.052l-8 10.5a.75.75 0 01-1.127.075l-4.5-4.5a.75.75 0 011.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 011.05-.143z" clip-rule="evenodd"/></svg>`,
    info:    `<svg viewBox="0 0 20 20" fill="currentColor" class="toast__icon"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clip-rule="evenodd"/></svg>`,
  };

  function showToast(message, type = 'success', duration = 3500) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.innerHTML = `${TOAST_ICONS[type] || ''}<span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.animation = 'toastSlideOut 0.3s ease-in forwards';
      toast.addEventListener('animationend', () => toast.remove(), { once: true });
    }, duration);
  }

  // ─── Info-Banner: Erkläre warum diese Seite zu sehen ist ────────

  function showInfoBanner() {
    const banner = document.getElementById('singleTabBanner');
    if (banner) banner.style.display = 'flex';
  }

  // ─── Init ───────────────────────────────────────────────────

  function init() {
    const { url, source, reason, tabId } = getParams();

    // Banner anzeigen (da wir hier sind = einziger Tab)
    showInfoBanner();

    const blockedUrlEl = document.getElementById('blockedUrl');
    const sourceUrlEl  = document.getElementById('sourceUrl');
    const reasonEl     = document.getElementById('reason');

    if (blockedUrlEl) { blockedUrlEl.textContent = url ? truncateUrl(url) : 'Unbekannte URL'; blockedUrlEl.title = url; }
    if (sourceUrlEl)  { sourceUrlEl.textContent  = source ? truncateUrl(source) : 'Unbekannte Herkunft'; sourceUrlEl.title = source; }
    if (reasonEl)     { reasonEl.textContent = reason || 'Verdächtige Weiterleitung erkannt'; }

    // Button: Zurück
    const btnGoBack = document.getElementById('btnGoBack');
    if (btnGoBack) {
      btnGoBack.addEventListener('click', () => {
        if (window.history.length > 1) window.history.back();
        else if (source) window.location.href = source;
        else window.location.href = 'about:newtab';
      });
    }

    // Button: Trotzdem öffnen
    const btnProceed = document.getElementById('btnProceed');
    if (btnProceed) {
      btnProceed.addEventListener('click', async () => {
        if (!url) { showToast('Keine URL zum Öffnen.', 'info'); return; }
        try {
          let resolvedTabId = tabId;
          if (resolvedTabId === null && chrome.tabs) {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab) resolvedTabId = tab.id;
          }
          await sendMessage({ action: 'allowOnce', url, tabId: resolvedTabId });
        } catch {}
        window.location.href = url;
      });
    }

    // Button: Domain zur Whitelist
    const btnWhitelist = document.getElementById('btnWhitelist');
    if (btnWhitelist) {
      btnWhitelist.addEventListener('click', async () => {
        if (!url) { showToast('Keine URL vorhanden.', 'info'); return; }
        const domain = extractDomain(url);
        try {
          await sendMessage({ action: 'whitelistDomain', domain });
          showToast(`Domain „${domain}“ zur Whitelist hinzugefügt.`, 'success');
        } catch {
          showToast(`Domain „${domain}“ wird erlaubt.`, 'info');
        }
        setTimeout(() => { window.location.href = url; }, 1200);
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
