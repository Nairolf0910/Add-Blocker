# 🛡️ Redirect Guard

> **Blocks unwanted redirects to scam, ad, and malware pages — automatically.**
> Suspicious tabs are closed instantly. You stay in control.

![Version](https://img.shields.io/badge/version-1.2.0-01696f?style=flat-square)
![Manifest](https://img.shields.io/badge/Manifest-V3-0c4e54?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-cedcd8?style=flat-square)
![Browser](https://img.shields.io/badge/Chrome%20%26%20Edge-compatible-01696f?style=flat-square)

---

## ✨ What it does

Redirect Guard watches every navigation in your browser. The moment it detects a suspicious redirect — like a link that suddenly sends you to an ad network, a scam domain, or a click-farm — it **immediately closes the tab**. No warning page, no delay. If it’s the only open tab, it shows a clean info page instead.

**Protects against:**
- 🚫 Scam & phishing redirect chains
- 🚫 Adware domains (popunder networks, click farms)
- 🚫 JavaScript-based redirects (`location.assign`, `location.replace`)
- 🚫 History API hijacking (`pushState` / `replaceState`)
- 🚫 Server-side redirects to suspicious TLDs (`.top`, `.xyz`, `.click` …)
- 🚫 Unwanted popup tabs opened by ad scripts

---

## 🚀 Installation

### From Chrome Web Store *(coming soon)*
Search for **“Redirect Guard”** in the [Chrome Web Store](https://chrome.google.com/webstore).

### Manual (Developer Mode)

1. Download or clone this repository
2. Open Chrome/Edge and navigate to `chrome://extensions/`
3. Enable **Developer Mode** (top right)
4. Click **“Load unpacked”** and select the project folder
5. The shield icon 🛡️ appears in your toolbar — you’re protected!

---

## 🎮 How to use

| Action | How |
|---|---|
| Enable / Disable | Click the shield icon → toggle the switch |
| Set sensitivity | Low / Medium / High in the popup |
| Allow a domain | Click “Allow domain permanently” on the blocked page |
| View stats | Popup shows today’s and total blocked count |
| Test it | Open `test.html` from the project folder |

---

## ⚙️ Sensitivity Levels

| Level | What gets blocked |
|---|---|
| **Low** | Only known scam patterns & suspicious redirect chains |
| **Medium** *(default)* | + Bad TLDs (`.top`, `.xyz`, `.click` …) |
| **High** | + Any cross-domain redirect not on the whitelist |

---

## 🔒 Privacy

**Zero data collection.** Everything runs locally on your device.

- No analytics, no tracking, no external servers
- Settings stored only in `chrome.storage.local`
- Full source code available for inspection
- [Privacy Policy](privacy.html)

---

## 📁 Project Structure

```
redirect-guard/
├── manifest.json        # Extension config (Manifest V3)
├── background.js        # Service worker: redirect detection & tab management
├── content.js           # Page-level JS redirect interception
├── popup.html/js        # Toolbar popup UI
├── blocked.html/js      # Shown when tab cannot be closed (single tab)
├── privacy.html         # Privacy policy
├── test.html            # Test page to verify the extension works
├── icons/               # icon16.png, icon48.png, icon128.png
└── styles/              # popup.css, blocked.css
```

---

## 🛠️ Development

```bash
# Clone
git clone https://github.com/Nairolf0910/Add-Blocker.git
cd Add-Blocker

# Load in Chrome
# chrome://extensions/ → Developer Mode → Load unpacked

# After any code change:
# chrome://extensions/ → 🔄 Reload button
```

---

## 📄 License

MIT License — free to use, modify and distribute.

---

<p align="center">
  Made with ❤️ to keep the web safe
</p>
