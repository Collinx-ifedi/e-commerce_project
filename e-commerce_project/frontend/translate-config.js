(function () {
  const DEFAULT_LANG = 'en';

  function getBrowserLang() {
    return navigator.language?.split('-')[0] || DEFAULT_LANG;
  }

  function getStoredLang() {
    return localStorage.getItem('preferredLang');
  }

  function setStoredLang(lang) {
    localStorage.setItem('preferredLang', lang);
  }

  function applyGoogleTranslate(lang) {
    if (!lang || lang === DEFAULT_LANG) return;

    document.cookie = `googtrans=/en/${lang};path=/`;
    document.cookie = `googtrans=/en/${lang};domain=${location.hostname};path=/`;
  }

  window.changeLanguage = function (lang) {
    setStoredLang(lang);
    applyGoogleTranslate(lang);
    location.reload();
  };

  window.googleTranslateElementInit = function () {
    new google.translate.TranslateElement(
      {
        pageLanguage: DEFAULT_LANG,
        autoDisplay: false
      },
      'google_translate_element'
    );

    const lang = getStoredLang() || getBrowserLang();
    if (lang !== DEFAULT_LANG) {
      setTimeout(() => applyGoogleTranslate(lang), 500);
    }
  };
})();