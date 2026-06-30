/**
 * Redirect Guard – Content Script
 * Wird in jede Webseite injiziert und blockiert JavaScript-basierte Redirects,
 * unerwünschte Popups und Meta-Refresh-Tags.
 */

(function () {
  'use strict';

  // Verhindere doppelte Ausführung
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

  // Auf Einstellungsänderungen reagieren
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

  function isDifferentDomain(url) {
    const targetDomain = extractDomain(url);
    const currentDomain = getCurrentDomain();
    if (!targetDomain || !currentDomain) return false;

    const extractRoot = (d) => {
      const parts = d.split('.');
      return parts.length <= 2 ? d : parts.slice(-2).join('.');
    };

    return extractRoot(targetDomain) !== extractRoot(currentDomain);
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

    // Leere URLs oder gleiche Domain erlauben
    if (!url || url === '' || url === 'about:blank') {
      return originalWindowOpen.call(window, url, target, features);
    }

    // Absolute URL erstellen
    let absoluteUrl;
    try {
      absoluteUrl = new URL(url, window.location.href).href;
    } catch {
      return originalWindowOpen.call(window, url, target, features);
    }

    if (isDifferentDomain(absoluteUrl)) {
      // Prüfe mit dem Background Script
      checkWithBackground(absoluteUrl).then((result) => {
        if (result.suspicious) {
          notifyBackground(absoluteUrl, 'window.open() Popup blockiert');
        } else {
          originalWindowOpen.call(window, absoluteUrl, target, features);
        }
      });

      // Blockiere sofort das synchrone Öffnen bei mittlerer/hoher Empfindlichkeit
      if (sensitivity !== 'low') {
        console.log('[Redirect Guard] 🛡️ Popup blockiert:', absoluteUrl);
        return null;
      }
    }

    return originalWindowOpen.call(window, url, target, features);
  };

  // ─── 2. Meta-Refresh-Tags entfernen ──────────────────────────────

  function removeMetaRefresh() {
    if (!extensionEnabled) return;

    const metaTags = document.querySelectorAll('meta[http-equiv="refresh"]');
    metaTags.forEach((meta) => {
      const content = meta.getAttribute('content') || '';
      // Prüfe ob es eine Weiterleitung zu einer anderen Domain ist
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

  // ─── 3. Klick-Hijacking erkennen ─────────────────────────────────

  // Überwache Klicks auf der gesamten Seite
  document.addEventListener('click', function (event) {
    if (!extensionEnabled) return;

    // Finde das nächste <a>-Element in der Klick-Kette
    let target = event.target;
    while (target && target.tagName !== 'A') {
      target = target.parentElement;
    }

    if (!target || !target.href) return;

    const href = target.href;

    // Prüfe auf verdächtige Links die auf andere Domains zeigen
    if (isDifferentDomain(href)) {
      // Bei hoher Empfindlichkeit: alle externen Links prüfen
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
  }, true); // Capture-Phase für frühzeitige Erkennung

  // ─── 4. Inline Event-Handler blockieren ──────────────────────────

  // Erkennt onclick-Handler die Weiterleitungen auslösen
  function scanForInlineRedirects() {
    if (!extensionEnabled || sensitivity === 'low') return;

    const elements = document.querySelectorAll('[onclick]');
    elements.forEach((el) => {
      const onclick = el.getAttribute('onclick') || '';
      // Suche nach Weiterleitungs-Mustern
      const redirectPatterns = [
        /window\.location\s*[=.]/i,
        /document\.location\s*[=.]/i,
        /location\.href\s*=/i,
        /location\.replace\s*\(/i,
        /window\.open\s*\(/i,
        /window\.navigate\s*\(/i,
      ];

      if (redirectPatterns.some(p => p.test(onclick))) {
        // Extrahiere URL aus dem Handler
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

  // ─── 5. Dynamisch eingefügte Scripts überwachen ──────────────────

  const observer = new MutationObserver((mutations) => {
    if (!extensionEnabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;

        // Meta-Refresh Tags die dynamisch eingefügt werden
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

        // Iframes mit verdächtigen URLs
        if (node.tagName === 'IFRAME') {
          const src = node.getAttribute('src') || '';
          if (src && isDifferentDomain(src)) {
            // Versteckte Iframes sind oft Scam
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
    // Meta-Refresh bei DOMContentLoaded prüfen
    removeMetaRefresh();

    // Inline-Redirects scannen
    scanForInlineRedirects();

    // DOM-Änderungen überwachen
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  // Starte sofort wenn möglich, sonst warte auf DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Auch nach vollständigem Laden nochmal prüfen (für spät geladene Elemente)
  window.addEventListener('load', () => {
    removeMetaRefresh();
    scanForInlineRedirects();
  });

  console.log('[Redirect Guard] 🛡️ Content Script aktiv auf:', window.location.hostname);
})();
