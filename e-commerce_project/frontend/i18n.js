/* ======================================================
   Production i18n Engine (v2.0)
   - Auto-detects legacy settings
   - Prevents structural DOM damage
   - Supports text, attributes, and directionality
   ====================================================== */

(() => {
    const DEFAULT_LANG = 'en';
    const RTL_LANGS = ['ar', 'he', 'fa', 'ur'];
    const STORAGE_KEY = 'keyvault_language'; // Matches your legacy system
  
    // RAM Cache to prevent re-fetching
    const translationsCache = {};
  
    /* ---------- 1. Language State Management ---------- */
  
    function getCurrentLang() {
      // Priority: URL Param > LocalStorage > Browser Lang > Default
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.has('lang')) return urlParams.get('lang');
  
      return localStorage.getItem(STORAGE_KEY) || 
             localStorage.getItem('lang') || 
             navigator.language.split('-')[0] || 
             DEFAULT_LANG;
    }
  
    function setLanguage(lang) {
      localStorage.setItem(STORAGE_KEY, lang);
      // Optional: Update URL without reload (for SPA feel)
      // const url = new URL(window.location);
      // url.searchParams.set('lang', lang);
      // window.history.pushState({}, '', url);
      
      // Reload to apply fresh state
      window.location.reload();
    }
  
    function getCurrentPage() {
      // Defaults to 'index' if no data-i18n-page attribute is found on body
      return document.body?.dataset?.i18nPage || 'index';
    }
  
    /* ---------- 2. Data Loading ---------- */
  
    async function loadJSON(lang, page) {
      const cacheKey = `${lang}/${page}`;
      if (translationsCache[cacheKey]) return translationsCache[cacheKey];
  
      // Path assumption: /en/index.json, /fr/index.json
      // Adjust this line if your JSON files are elsewhere
      const path = `/${lang}/${page}.json`;
  
      try {
        const res = await fetch(path);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        translationsCache[cacheKey] = data;
        return data;
      } catch (err) {
        console.warn(`[i18n] Failed to load translations for: ${path}`, err);
        return null;
      }
    }
  
    /* ---------- 3. DOM Manipulation (The Safe Way) ---------- */
  
    function applyDirection(lang) {
      const isRTL = RTL_LANGS.includes(lang);
      document.documentElement.dir = isRTL ? 'rtl' : 'ltr';
      document.documentElement.lang = lang;
    }
  
    function applyTranslations(dict) {
      if (!dict) return;
  
      // A. Text Content
      document.querySelectorAll('[data-i18n]').forEach(el => {
        // CRITICAL SAFETY CHECK: Never wipe structural tags
        if (['HTML', 'HEAD', 'BODY', 'SCRIPT', 'STYLE'].includes(el.tagName)) {
            console.warn(`[i18n] Safety Block: Ignored data-i18n on <${el.tagName}>`);
            return;
        }
  
        const key = el.dataset.i18n;
        if (dict[key]) {
            // Use innerHTML only if you trust your JSON sources, otherwise textContent
            el.innerHTML = dict[key];
        }
      });
  
      // B. Placeholders (Inputs)
      document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.dataset.i18nPlaceholder;
        if (dict[key]) el.placeholder = dict[key];
      });
  
      // C. Titles (Tooltips)
      document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.dataset.i18nTitle;
        if (dict[key]) el.title = dict[key];
      });
  
      // D. Aria Labels (Accessibility)
      document.querySelectorAll('[data-i18n-aria]').forEach(el => {
        const key = el.dataset.i18nAria;
        if (dict[key]) el.setAttribute('aria-label', dict[key]);
      });
      
      // Dispatch event for other scripts (like Swiper/GSAP) to react
      window.dispatchEvent(new CustomEvent('i18n-loaded', { detail: { lang: getCurrentLang() } }));
    }
  
    /* ---------- 4. Initialization ---------- */
  
    async function init() {
      const lang = getCurrentLang();
      const page = getCurrentPage();
  
      // 1. Set Direction immediately (prevents layout flash)
      applyDirection(lang);
  
      // 2. Load Language + Fallback (English) in parallel
      const [langData, fallbackData] = await Promise.all([
        loadJSON(lang, page),
        lang !== DEFAULT_LANG ? loadJSON(DEFAULT_LANG, page) : null
      ]);
  
      // 3. Merge: Fallback -> Target Language
      const finalDict = { ...fallbackData, ...langData };
  
      // 4. Paint the page
      applyTranslations(finalDict);
      
      console.log(`[i18n] Initialized: ${lang} (${page})`);
    }
  
    /* ---------- 5. Public API ---------- */
    window.i18n = {
      init,
      setLanguage,
      getLanguage: getCurrentLang
    };
  
    // Auto-init when DOM is ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  
  })();