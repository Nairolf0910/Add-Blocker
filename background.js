/**
 * Redirect Guard – Background Service Worker
 * Erkennt und blockiert verdächtige Weiterleitungen in Chrome & Edge.
 * Version: 1.1.0
 */

// ─── State ────────────────────────────────────────────────────────────
const tabState = new Map();       // tabId → { navigations: [], lastUrl, lastDomain }
const tempAllowList = new Map();  // tabId → Set<url> (einmalige Erlaubnisse)

const REDIRECT_CHAIN_THRESHOLD_MS = 3000;
const REDIRECT_CHAIN_MAX = 2;

// Bekannte Scam/Ad-URL-Muster (erweitert)
const SUSPICIOUS_PATTERNS = [
  /\.top\//i,
  /\.xyz\//i,
  /\.click\//i,
  /\.buzz\//i,
  /\.gdn\//i,
  /\.loan\//i,
  /\.win\//i,
  /\.bid\//i,
  /\.stream\//i,
  /\.review\//i,
  /\.trade\//i,
  /\.accountant\//i,
  /\/afu\./i,
  /\/click\?/i,
  /\/redirect\?/i,
  /\/go\?/i,
  /\/out\?/i,
  /\/track(ing)?\//i,
  /\/redir(ect)?\//i,
  /\/cpa\//i,
  /\/aff(iliate)?\//i,
  /\?.*utm_.*&.*redirect/i,
  /popunder/i,
  /popads/i,
  /trafficjunky/i,
  /exoclick/i,
  /juicyads/i,
  /adserv/i,
  /clickadu/i,
  /propellerads/i,
  /popcash/i,
  /admaven/i,
  /adsterra/i,
  /hilltopads/i,
  /richpush/i,
  /push\.house/i,
  /pushground/i,
  /megapush/i,
  /datingadv/i,
  /bodelen\.com/i,
  /adf\.ly/i,
  /bc\.vc/i,
  /shorte\.st/i,
  /sh\.st/i,
  /linkbucks/i,
  /ouo\.io/i,
  /exe\.io/i,
  /fc\.lc/i,
  /za\.gl/i,
  /cut-urls\.com/i,
  /earnow\.online/i,
  /traffboost/i,
  /adfly/i,
  /linkvertise/i,
  /rekonise/i,
  /socialwolvez/i,
  /loot-link/i,
  /direct-link/i,
  /cuty\.io/i,
  /shrinkme\.io/i,
  /gplinks/i,
  /techysuccess/i,
  /mtweb\.co/i,
];

// Domains die immer erlaubt sind
const BUILTIN_WHITELIST = [
  'google.com', 'google.de', 'googleapis.com', 'google.co.uk',
  'microsoft.com', 'live.com', 'microsoftonline.com', 'office.com',
  'windows.com', 'bing.com', 'msn.com', 'outlook.com',
  'github.com', 'githubusercontent.com', 'githubassets.com',
  'youtube.com', 'youtu.be',
  'facebook.com', 'instagram.com', 'whatsapp.com',
  'twitter.com', 'x.com',
  'amazon.com', 'amazon.de', 'amazon.co.uk',
  'paypal.com',
  'apple.com', 'icloud.com',
  'cloudflare.com',
  'reddit.com',
  'wikipedia.org',
  'stackoverflow.com',
  'mozilla.org',
  'w3.org',
  'netflix.com',
  'spotify.com',
  'twitch.tv',
  'discord.com',
  'linkedin.com',
  'ebay.de', 'ebay.com',
  'zalando.de',
  'otto.de',
];

// ─── Hilfsfunktionen ──────────────────────────────────────────────────

function extractDomain(url) {
  try {
    const u = new URL(url);
    return u.hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
}

function extractRootDomain(domain) {
  if (!domain) return null;
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;
  return parts.slice(-2).join('.');
}

function isInternalUrl(url) {
  return url.startsWith('chrome://') ||
         url.startsWith('chrome-extension://') ||
         url.startsWith('edge://') ||
         url.startsWith('extension://') ||
         url.startsWith('about:') ||
         url.startsWith('data:') ||
         url.startsWith('blob:') ||
         url.startsWith('javascript:') ||
         url.startsWith('moz-extension://') ||
         url.startsWith('ms-browser-extension://');
}

async function getSettings() {
  const defaults = {
    enabled: true,
    sensitivity: 'medium',
    whitelist: [],
    statsToday: 0,
    statsTotal: 0,
    statsDate: new Date().toISOString().split('T')[0],
  };
  try {
    const data = await chrome.storage.local.get(defaults);
    const today = new Date().toISOString().split('T')[0];
    if (data.statsDate !== today) {
      data.statsToday = 0;
      data.statsDate = today;
      await chrome.storage.local.set({ statsToday: 0, statsDate: today });
    }
    return data;
  } catch {
    return defaults;
  }
}

async function incrementStats() {
  const settings = await getSettings();
  await chrome.storage.local.set({
    statsToday: (settings.statsToday || 0) + 1,
    statsTotal: (settings.statsTotal || 0) + 1,
  });
}

async function isDomainWhitelisted(domain) {
  if (!domain) return false;
  const rootDomain = extractRootDomain(domain);
  if (BUILTIN_WHITELIST.some(d => domain.endsWith(d) || rootDomain === d)) {
    return true;
  }
  const settings = await getSettings();
  return settings.whitelist.some(d => domain.endsWith(d) || rootDomain === d);
}

function matchesSuspiciousPattern(url) {
  return SUSPICIOUS_PATTERNS.some(pattern => pattern.test(url));
}

function getTabState(tabId) {
  if (!tabState.has(tabId)) {
    tabState.set(tabId, {
      navigations: [],
      lastUrl: null,
      lastDomain: null,
      userInitiated: false,
    });
  }
  return tabState.get(tabId);
}

// ─── Sensitivity-basierte Prüfung ────────────────────────────────────

async function isRedirectSuspicious(tabId, url, sourceUrl) {
  const settings = await getSettings();
  if (!settings.enabled) return { suspicious: false };

  const domain = extractDomain(url);
  const sourceDomain = extractDomain(sourceUrl);

  if (!domain || !sourceDomain) return { suspicious: false };

  if (domain === sourceDomain || extractRootDomain(domain) === extractRootDomain(sourceDomain)) {
    return { suspicious: false };
  }

  if (await isDomainWhitelisted(domain)) {
    return { suspicious: false };
  }

  if (tempAllowList.has(tabId) && tempAllowList.get(tabId).has(url)) {
    tempAllowList.get(tabId).delete(url);
    return { suspicious: false };
  }

  const state = getTabState(tabId);
  const now = Date.now();

  state.navigations.push({ url, domain, timestamp: now });
  state.navigations = state.navigations.filter(n => now - n.timestamp < REDIRECT_CHAIN_THRESHOLD_MS);

  const sensitivity = settings.sensitivity || 'medium';
  let reasons = [];

  // 1. Bekannte Scam-Muster
  if (matchesSuspiciousPattern(url)) {
    reasons.push('URL enthält bekannte Werbe-/Scam-Muster');
  }

  // 2. Redirect-Kette
  const recentDomainChanges = state.navigations
    .filter(n => n.domain !== sourceDomain)
    .length;

  if (recentDomainChanges >= REDIRECT_CHAIN_MAX) {
    reasons.push(`${recentDomainChanges} Weiterleitungen in ${REDIRECT_CHAIN_THRESHOLD_MS / 1000}s erkannt`);
  }

  // 3. Sensitivity-spezifische Prüfungen
  if (sensitivity === 'high') {
    if (reasons.length === 0) {
      reasons.push('Domain-Wechsel erkannt (Hohe Empfindlichkeit)');
    }
  } else if (sensitivity === 'medium') {
    const suspiciousTLDs = ['.top', '.xyz', '.click', '.buzz', '.gdn', '.loan', '.win', '.bid', '.stream', '.review', '.trade'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
      reasons.push('Verdächtige Domain-Endung');
    }
  }

  return {
    suspicious: reasons.length > 0,
    reasons: reasons,
  };
}

// ─── Navigation Events ───────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (isInternalUrl(details.url)) return;

  const settings = await getSettings();
  if (!settings.enabled) return;

  const state = getTabState(details.tabId);

  if (state.lastUrl && state.lastUrl !== details.url) {
    const result = await isRedirectSuspicious(details.tabId, details.url, state.lastUrl);

    if (result.suspicious) {
      const blockedPageUrl = chrome.runtime.getURL('blocked.html') +
        '?url=' + encodeURIComponent(details.url) +
        '&source=' + encodeURIComponent(state.lastUrl) +
        '&reason=' + encodeURIComponent(result.reasons.join('; ')) +
        '&tabId=' + details.tabId;

      try {
        await chrome.tabs.update(details.tabId, { url: blockedPageUrl });
        await incrementStats();
        await updateBadge();
      } catch (e) {
        console.error('[Redirect Guard] Fehler beim Blockieren:', e);
      }
      return;
    }
  }

  state.lastUrl = details.url;
  state.lastDomain = extractDomain(details.url);
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (isInternalUrl(details.url)) return;

  const state = getTabState(details.tabId);

  if (details.transitionQualifiers &&
      details.transitionQualifiers.includes('server_redirect')) {

    const settings = await getSettings();
    if (!settings.enabled) return;

    if (state.lastUrl) {
      const result = await isRedirectSuspicious(details.tabId, details.url, state.lastUrl);

      if (result.suspicious) {
        const blockedPageUrl = chrome.runtime.getURL('blocked.html') +
          '?url=' + encodeURIComponent(details.url) +
          '&source=' + encodeURIComponent(state.lastUrl) +
          '&reason=' + encodeURIComponent(result.reasons.join('; ')) +
          '&tabId=' + details.tabId;

        try {
          await chrome.tabs.update(details.tabId, { url: blockedPageUrl });
          await incrementStats();
          await updateBadge();
        } catch (e) {
          console.error('[Redirect Guard] Fehler beim Blockieren:', e);
        }
        return;
      }
    }
  }

  state.lastUrl = details.url;
  state.lastDomain = extractDomain(details.url);
});

// ─── Neue Tabs/Popups blockieren ─────────────────────────────────────

chrome.webNavigation.onCreatedNavigationTarget.addListener(async (details) => {
  const settings = await getSettings();
  if (!settings.enabled) return;

  const sourceDomain = extractDomain(details.sourceTabId ?
    (getTabState(details.sourceTabId).lastUrl || '') : '');
  const targetDomain = extractDomain(details.url);

  if (!targetDomain || isInternalUrl(details.url)) return;

  if (sourceDomain && sourceDomain !== targetDomain) {
    if (await isDomainWhitelisted(targetDomain)) return;

    if (matchesSuspiciousPattern(details.url)) {
      const blockedPageUrl = chrome.runtime.getURL('blocked.html') +
        '?url=' + encodeURIComponent(details.url) +
        '&source=' + encodeURIComponent('Neuer Tab von ' + sourceDomain) +
        '&reason=' + encodeURIComponent('Verdächtiger neuer Tab/Popup erkannt') +
        '&tabId=' + details.tabId;

      try {
        await chrome.tabs.update(details.tabId, { url: blockedPageUrl });
        await incrementStats();
        await updateBadge();
      } catch (e) {
        console.error('[Redirect Guard] Fehler beim Blockieren:', e);
      }
    }
  }
});

// ─── Tab-Cleanup ─────────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
  tempAllowList.delete(tabId);
});

// ─── Badge aktualisieren ─────────────────────────────────────────────

async function updateBadge() {
  const settings = await getSettings();

  if (!settings.enabled) {
    chrome.action.setBadgeText({ text: 'OFF' });
    chrome.action.setBadgeBackgroundColor({ color: '#6b7280' });
    return;
  }

  const count = settings.statsToday || 0;
  if (count > 0) {
    chrome.action.setBadgeText({ text: count.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#8b5cf6' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}

// ─── Nachrichten von Content Script & Blocked Page ───────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse);
  return true;
});

async function handleMessage(message, sender) {
  switch (message.action) {
    case 'allowOnce': {
      const tabId = message.tabId || sender.tab?.id;
      if (tabId && message.url) {
        if (!tempAllowList.has(tabId)) {
          tempAllowList.set(tabId, new Set());
        }
        tempAllowList.get(tabId).add(message.url);
        const state = getTabState(tabId);
        state.navigations = [];
      }
      return { success: true };
    }

    case 'whitelistDomain': {
      const settings = await getSettings();
      const whitelist = settings.whitelist || [];
      if (message.domain && !whitelist.includes(message.domain)) {
        whitelist.push(message.domain);
        await chrome.storage.local.set({ whitelist });
      }
      return { success: true, whitelist };
    }

    case 'removeDomain': {
      const settings = await getSettings();
      const whitelist = (settings.whitelist || []).filter(d => d !== message.domain);
      await chrome.storage.local.set({ whitelist });
      return { success: true, whitelist };
    }

    case 'getSettings': {
      return await getSettings();
    }

    case 'updateSettings': {
      if (message.settings) {
        await chrome.storage.local.set(message.settings);
        await updateBadge();
      }
      return { success: true };
    }

    case 'checkUrl': {
      const tabId = sender.tab?.id;
      if (!tabId || !message.url) return { suspicious: false };
      const sourceUrl = sender.tab?.url || '';
      const result = await isRedirectSuspicious(tabId, message.url, sourceUrl);
      return result;
    }

    case 'blockRedirect': {
      const tabId = sender.tab?.id;
      if (!tabId) return { success: false };

      const blockedPageUrl = chrome.runtime.getURL('blocked.html') +
        '?url=' + encodeURIComponent(message.url) +
        '&source=' + encodeURIComponent(sender.tab?.url || 'Unbekannt') +
        '&reason=' + encodeURIComponent(message.reason || 'JavaScript-Weiterleitung erkannt') +
        '&tabId=' + tabId;

      try {
        await chrome.tabs.update(tabId, { url: blockedPageUrl });
        await incrementStats();
        await updateBadge();
      } catch (e) {
        console.error('[Redirect Guard] Fehler:', e);
      }
      return { success: true };
    }

    default:
      return { error: 'Unbekannte Aktion' };
  }
}

// ─── Initialisierung ─────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(null);
  const defaults = {
    enabled: true,
    sensitivity: 'medium',
    whitelist: [],
    statsToday: 0,
    statsTotal: 0,
    statsDate: new Date().toISOString().split('T')[0],
  };

  const toSet = {};
  for (const [key, value] of Object.entries(defaults)) {
    if (!(key in existing)) {
      toSet[key] = value;
    }
  }

  if (Object.keys(toSet).length > 0) {
    await chrome.storage.local.set(toSet);
  }

  await updateBadge();
  console.log('[Redirect Guard] v1.1.0 installiert und aktiv! 🛡️');
});

updateBadge();
