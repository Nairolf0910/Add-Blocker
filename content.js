/**
 * Redirect Guard – Content Script v1.1.0
 * Wird in jede Webseite injiziert und blockiert JavaScript-basierte Redirects,
 * unerwünschte Popups und Meta-Refresh-Tags.
 *
 * NEU in v1.1.0:
 * - location.href / location.assign / location.replace via Object.defineProperty abgefangen
 * - history.pushState / replaceState Domain-Wechsel-Schutz
 * - Verbesserte Edge-Kompatibilität
 */

(function () {
  'use strict';

  if (window.__redirectGuardActive) return;
  window.__redirectGuardActive = true;

  let extensionEnabled = true;
  let sensitivity = 'medium';

  // ─── Einstellungen laden ──────────────────────────────────────────

  function loadSettings() {
    try {
      chrome.runtime.sendMessage({ action: 'getSettings' }, (response) => {
        if (chrome.runtime.lastError) return;
        if (response) {
          extensionEnabled = response.enabled !== false;
          sensitivity = response.sensitivity || 'medium';
        }
      });
    } catch {
      // Extension context ungültig
    }
  }

  loadSettings();

  try {
    chrome.storage.onChanged.addListener((changes) => {
      if (changes.enabled) extensionEnabled = changes.enabled.newValue;
      if (changes.sensitivity) sensitivity = changes.sensitivity.newValue;
    });
  } catch {
    // Extension context ungültig
  }

  // ─── Hilfsfunktionen ─────────────────────────────────────────────

  function extractDomain(url) {
    try {
      return new URL(url).hostname.replace(/^www\./, '');
    } catch {
      return null;
    }
  }

  function getCurrentDomain() {
    return extractDomain(window.location.href);
  }

  function extractRootDomain(d) {
    if (!d) return null;
    const parts = d.split('.');
    return parts.length <= 2 ? d : parts.slice(-2).join('.');
  }

  function isDifferentDomain(url) {
    const targetDomain = extractDomain(url);
    const currentDomain = getCurrentDomain();
    if (!targetDomain || !currentDomain) return false;
    return extractRootDomain(targetDomain) !== extractRootDomain(currentDomain);
  }

  function notifyBackground(url, reason) {
    try {
      chrome.runtime.sendMessage({
        action: 'blockRedirect',
        url: url,
        reason: reason,
      });
    } catch {
      // Extension context ungültig
    }
  }

  async function checkWithBackground(url) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ action: 'checkUrl', url }, (response) => {
          if (chrome.runtime.lastError) {
            resolve({ suspicious: false });
            return;
          }
          resolve(response || { suspicious: false });
        });
      } catch {
        resolve({ suspicious: false });
      }
    });
  }

  // ─── 1. window.open() überschreiben ──────────────────────────────

  const originalWindowOpen = window.open;

  window.open = function (url, target, features) {
    if (!extensionEnabled) {
      return originalWindowOpen.call(window, url, target, features);
    }

    if (!url || url === '' || url === 'about:blank') {
      return originalWindowOpen.call(window, url, target, features);
    }

    let absoluteUrl;
    try {
      absoluteUrl = new URL(url, window.location.href).href;
    } catch {
      return originalWindowOpen.call(window, url, target, features);
    }

    if (isDifferentDomain(absoluteUrl)) {
      checkWithBackground(absoluteUrl).then((result) => {
        if (result.suspicious) {
          notifyBackground(absoluteUrl, 'window.open() Popup blockiert');
        } else {
          originalWindowOpen.call(window, absoluteUrl, target, features);
        }
      });

      if (sensitivity !== 'low') {
        console.log('[Redirect Guard] 🛡️ Popup blockiert:', absoluteUrl);
        return null;
      }
    }

    return originalWindowOpen.call(window, url, target, features);
  };

  // ─── 2. location.href / assign / replace abfangen (NEU) ──────────
  // Überschreibt window.location-Methoden via Object.defineProperty
  // um JS-Redirects auf Seitenebene zu fangen bevor sie ausgeführt werden.

  try {
    const originalAssign = location.assign.bind(location);
    const originalReplace = location.replace.bind(location);

    // location.assign() überschreiben
    Object.defineProperty(window.location, 'assign', {
      writable: true,
      configurable: true,
      value: function (url) {
        if (!extensionEnabled) return originalAssign(url);
        let absoluteUrl;
        try {
          absoluteUrl = new URL(url, window.location.href).href;
        } catch {
          return originalAssign(url);
        }
        if (isDifferentDomain(absoluteUrl) && sensitivity !== 'low') {
          checkWithBackground(absoluteUrl).then((result) => {
            if (result.suspicious) {
              notifyBackground(absoluteUrl, 'location.assign() Weiterleitung blockiert');
            } else {
              originalAssign(absoluteUrl);
            }
          });
          return;
        }
        return originalAssign(url);
      }
    });

    // location.replace() überschreiben
    Object.defineProperty(window.location, 'replace', {
      writable: true,
      configurable: true,
      value: function (url) {
        if (!extensionEnabled) return originalReplace(url);
        let absoluteUrl;
        try {
          absoluteUrl = new URL(url, window.location.href).href;
        } catch {
          return originalReplace(url);
        }
        if (isDifferentDomain(absoluteUrl) && sensitivity !== 'low') {
          checkWithBackground(absoluteUrl).then((result) => {
            if (result.suspicious) {
              notifyBackground(absoluteUrl, 'location.replace() Weiterleitung blockiert');
            } else {
              originalReplace(absoluteUrl);
            }
          });
          return;
        }
        return originalReplace(url);
      }
    });
  } catch (e) {
    // location-Überschreibung nicht möglich (z.B. bei cross-origin iframes)
    console.warn('[Redirect Guard] location-Proxy nicht verfügbar:', e.message);
  }

  // ─── 3. history.pushState / replaceState schützen (NEU) ──────────
  // Verhindert Domain-Wechsel über die History API

  try {
    const originalPushState = history.pushState.bind(history);
    const originalReplaceState = history.replaceState.bind(history);

    history.pushState = function (state, title, url) {
      if (!extensionEnabled || !url) return originalPushState(state, title, url);
      try {
        const absoluteUrl = new URL(url, window.location.href).href;
        if (isDifferentDomain(absoluteUrl) && sensitivity !== 'low') {
          console.log('[Redirect Guard] 🛡️ history.pushState Domain-Wechsel blockiert:', absoluteUrl);
          notifyBackground(absoluteUrl, 'history.pushState Domain-Wechsel blockiert');
          return;
        }
      } catch {
        // Ungültige URL ignorieren
      }
      return originalPushState(state, title, url);
    };

    history.replaceState = function (state, title, url) {
      if (!extensionEnabled || !url) return originalReplaceState(state, title, url);
      try {
        const absoluteUrl = new URL(url, window.location.href).href;
        if (isDifferentDomain(absoluteUrl) && sensitivity !== 'low') {
          console.log('[Redirect Guard] 🛡️ history.replaceState Domain-Wechsel blockiert:', absoluteUrl);
          notifyBackground(absoluteUrl, 'history.replaceState Domain-Wechsel blockiert');
          return;
        }
      } catch {
        // Ungültige URL ignorieren
      }
      return originalReplaceState(state, title, url);
    };
  } catch (e) {
    console.warn('[Redirect Guard] history-Proxy nicht verfügbar:', e.message);
  }

  // ─── 4. Meta-Refresh-Tags entfernen ──────────────────────────────

  function removeMetaRefresh() {
    if (!extensionEnabled) return;

    const metaTags = document.querySelectorAll('meta[http-equiv="refresh"]');
    metaTags.forEach((meta) => {
      const content = meta.getAttribute('content') || '';
      const urlMatch = content.match(/url\s*=\s*['"]?([^'";\s]+)/i);
      if (urlMatch && urlMatch[1]) {
        try {
          const targetUrl = new URL(urlMatch[1], window.location.href).href;
          if (isDifferentDomain(targetUrl)) {
            console.log('[Redirect Guard] 🛡️ Meta-Refresh blockiert:', targetUrl);
            meta.remove();
            notifyBackground(targetUrl, 'Meta-Refresh Weiterleitung blockiert');
          }
        } catch {
          // Ungültige URL ignorieren
        }
      }
    });
  }

  // ─── 5. Klick-Hijacking erkennen ─────────────────────────────────

  document.addEventListener('click', function (event) {
    if (!extensionEnabled) return;

    let target = event.target;
    while (target && target.tagName !== 'A') {
      target = target.parentElement;
    }

    if (!target || !target.href) return;

    const href = target.href;

    if (isDifferentDomain(href)) {
      if (sensitivity === 'high') {
        checkWithBackground(href).then((result) => {
          if (result.suspicious) {
            event.preventDefault();
            event.stopPropagation();
            notifyBackground(href, 'Verdächtiger externer Link');
          }
        });
      }
    }
  }, true);

  // ─── 6. Inline Event-Handler blockieren ──────────────────────────

  function scanForInlineRedirects() {
    if (!extensionEnabled || sensitivity === 'low') return;

    const elements = document.querySelectorAll('[onclick]');
    elements.forEach((el) => {
      const onclick = el.getAttribute('onclick') || '';
      const redirectPatterns = [
        /window\.location\s*[=.]/i,
        /document\.location\s*[=.]/i,
        /location\.href\s*=/i,
        /location\.replace\s*\(/i,
        /location\.assign\s*\(/i,
        /window\.open\s*\(/i,
        /window\.navigate\s*\(/i,
      ];

      if (redirectPatterns.some(p => p.test(onclick))) {
        const urlMatch = onclick.match(/['"]((https?:\/\/)[^'"]+)['"]/);
        if (urlMatch && urlMatch[1] && isDifferentDomain(urlMatch[1])) {
          console.log('[Redirect Guard] 🛡️ Inline-Redirect blockiert in:', el.tagName);
          el.removeAttribute('onclick');
          el.style.cursor = 'pointer';
          el.addEventListener('click', (e) => {
            e.preventDefault();
            notifyBackground(urlMatch[1], 'Inline JavaScript-Weiterleitung blockiert');
          });
        }
      }
    });
  }

  // ─── 7. Dynamisch eingefügte Elemente überwachen ─────────────────

  const observer = new MutationObserver((mutations) => {
    if (!extensionEnabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;

        // Meta-Refresh Tags
        if (node.tagName === 'META' &&
            node.getAttribute('http-equiv')?.toLowerCase() === 'refresh') {
          const content = node.getAttribute('content') || '';
          const urlMatch = content.match(/url\s*=\s*['"]?([^'";\s]+)/i);
          if (urlMatch && urlMatch[1]) {
            try {
              const targetUrl = new URL(urlMatch[1], window.location.href).href;
              if (isDifferentDomain(targetUrl)) {
                console.log('[Redirect Guard] 🛡️ Dynamisches Meta-Refresh blockiert');
                node.remove();
                notifyBackground(targetUrl, 'Dynamisch eingefügtes Meta-Refresh blockiert');
              }
            } catch {
              // ignorieren
            }
          }
        }

        // Versteckte Iframes
        if (node.tagName === 'IFRAME') {
          const src = node.getAttribute('src') || '';
          if (src && isDifferentDomain(src)) {
            const style = window.getComputedStyle(node);
            if (node.width === '0' || node.height === '0' ||
                style.display === 'none' || style.visibility === 'hidden' ||
                parseInt(style.width) <= 1 || parseInt(style.height) <= 1) {
              console.log('[Redirect Guard] 🛡️ Verstecktes Iframe entfernt:', src);
              node.remove();
            }
          }
        }
      }
    }
  });

  // ─── Initialisierung ─────────────────────────────────────────────

  function init() {
    removeMetaRefresh();
    scanForInlineRedirects();
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.addEventListener('load', () => {
    removeMetaRefresh();
    scanForInlineRedirects();
  });

  console.log('[Redirect Guard] 🛡️ v1.1.0 Content Script aktiv auf:', window.location.hostname);
})();
