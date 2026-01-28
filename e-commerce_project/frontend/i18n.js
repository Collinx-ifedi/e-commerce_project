/* ======================================================
   Production i18n Engine
   Supports page-scoped JSON + RTL + fallback
   ====================================================== */

(() => {
  const DEFAULT_LANG = 'en';
  const RTL_LANGS = ['ar'];

  /* ---------- Language & Page Detection ---------- */

  function getCurrentLang() {
    return localStorage.getItem('lang') || DEFAULT_LANG;
  }

  function setCurrentLang(lang) {
    localStorage.setItem('lang', lang);
  }

  function getCurrentPage() {
    return document.body?.dataset?.i18nPage || 'index';
  }

  /* ---------- Direction Handling (RTL/LTR) ---------- */

  function applyDirection(lang) {
    const isRTL = RTL_LANGS.includes(lang);
    document.documentElement.dir = isRTL ? 'rtl' : 'ltr';
    document.documentElement.lang = lang;
  }

  /* ---------- JSON Loader ---------- */

  async function loadJSON(lang, page) {
    const path = `/locales/${lang}/${page}.json`;

    try {
      const res = await fetch(path, { cache: 'no-cache' });
      if (!res.ok) throw new Error(`Missing ${path}`);
      return await res.json();
    } catch (err) {
      console.warn(`[i18n] Failed to load ${path}`);
      return null;
    }
  }

  /* ---------- Apply Translations ---------- */

  function applyTranslations(dict) {
    // Text content
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.dataset.i18n;
      if (dict[key] !== undefined) {
        el.textContent = dict[key];
      }
    });

    // Placeholder
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.dataset.i18nPlaceholder;
      if (dict[key] !== undefined) {
        el.placeholder = dict[key];
      }
    });

    // Title attribute
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.dataset.i18nTitle;
      if (dict[key] !== undefined) {
        el.title = dict[key];
      }
    });

    // Aria-label
    document.querySelectorAll('[data-i18n-aria]').forEach(el => {
      const key = el.dataset.i18nAria;
      if (dict[key] !== undefined) {
        el.setAttribute('aria-label', dict[key]);
      }
    });
  }

  /* ---------- Init Engine ---------- */

  async function initI18n() {
    const lang = getCurrentLang();
    const page = getCurrentPage();

    applyDirection(lang);

    const [langDict, enDict] = await Promise.all([
      loadJSON(lang, page),
      lang === DEFAULT_LANG ? null : loadJSON(DEFAULT_LANG, page)
    ]);

    if (!langDict && !enDict) {
      console.error('[i18n] No translation files could be loaded.');
      return;
    }

    // Merge fallback → language overrides English
    const merged = {
      ...(enDict || {}),
      ...(langDict || {})
    };

    applyTranslations(merged);
  }

  /* ---------- Public API ---------- */

  window.i18n = {
    init: initI18n,
    setLanguage(lang) {
      setCurrentLang(lang);
      initI18n();
    },
    getLanguage: getCurrentLang
  };

  /* ---------- Auto Init ---------- */

  document.addEventListener('DOMContentLoaded', initI18n);
})();