/**
 * Modern Multi-Language Support for KeyVault
 * Centralizes Google Translate integration with custom UI
 */

// Language configuration
const LANGUAGES = {
  en: { name: 'English', flag: '🇺🇸', code: 'en' },
  es: { name: 'Spanish', flag: '🇪🇸', code: 'es' },
  fr: { name: 'French', flag: '🇫🇷', code: 'fr' },
  ar: { name: 'العربية', flag: '🇸🇦', code: 'ar' },
  'zh-CN': { name: '简体中文', flag: '🇨🇳', code: 'zh-CN' },
  ru: { name: 'Русский', flag: '🇷🇺', code: 'ru' }
};

const LANGUAGE_STORAGE_KEY = 'keyvault_language';

// Declare the google variable
const google = window.google;

/**
 * Initialize Google Translate (called by Google API callback)
 */
function googleTranslateElementInit() {
  new google.translate.TranslateElement(
    {
      pageLanguage: 'en',
      includedLanguages: Object.keys(LANGUAGES).join(','),
      layout: google.translate.TranslateElement.InlineLayout.SIMPLE
    },
    'googleTranslate'
  );
}

/**
 * Setup custom language switcher
 */
function setupLanguageSwitcher() {
  // Hide default Google Translate UI
  hideDefaultGoogleUI();

  // Get or create language switcher container
  const googleTranslateContainer = document.getElementById('googleTranslate');
  if (!googleTranslateContainer) return;

  // Clear default content
  googleTranslateContainer.innerHTML = '';

  // Create custom language switcher
  const switcherHTML = `
    <div class="language-switcher-wrapper">
      <button class="language-switcher-btn" id="languageSwitcherBtn" aria-label="Select language">
        <span class="language-flag" id="currentLanguageFlag">🌐</span>
        <span class="language-code" id="currentLanguageCode">EN</span>
        <i class="fas fa-chevron-down language-chevron"></i>
      </button>
      <div class="language-dropdown" id="languageDropdown">
        ${Object.entries(LANGUAGES)
          .map(([code, lang]) => `
          <button class="language-option" data-language="${code}" onclick="switchLanguage('${code}', event)">
            <span class="language-option-flag">${lang.flag}</span>
            <span class="language-option-name">${lang.name}</span>
          </button>
        `)
          .join('')}
      </div>
    </div>
  `;

  googleTranslateContainer.innerHTML = switcherHTML;

  // Add event listeners
  const switcher = document.getElementById('languageSwitcherBtn');
  const dropdown = document.getElementById('languageDropdown');

  if (switcher && dropdown) {
    // Toggle dropdown
    switcher.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('active');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.language-switcher-wrapper')) {
        dropdown.classList.remove('active');
      }
    });

    // Close dropdown when selecting language
    dropdown.querySelectorAll('.language-option').forEach((btn) => {
      btn.addEventListener('click', () => {
        dropdown.classList.remove('active');
      });
    });
  }

  // Load saved language
  loadSavedLanguage();

  // Add styles for language switcher
  addLanguageSwitcherStyles();
}

/**
 * Switch to a different language
 */
function switchLanguage(langCode, event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }

  // Save language preference
  localStorage.setItem(LANGUAGE_STORAGE_KEY, langCode);

  // Update UI
  updateLanguageSwitcherUI(langCode);

  // Handle RTL for Arabic
  if (langCode === 'ar') {
    document.documentElement.dir = 'rtl';
    document.documentElement.lang = 'ar';
    document.body.style.textAlign = 'right';
  } else {
    document.documentElement.dir = 'ltr';
    document.documentElement.lang = langCode;
    document.body.style.textAlign = '';
  }

  // Trigger Google Translate
  triggerGoogleTranslate(langCode);
}

/**
 * Update language switcher UI
 */
function updateLanguageSwitcherUI(langCode) {
  const language = LANGUAGES[langCode];
  if (!language) return;

  const flagEl = document.getElementById('currentLanguageFlag');
  const codeEl = document.getElementById('currentLanguageCode');

  if (flagEl) flagEl.textContent = language.flag;
  if (codeEl) codeEl.textContent = langCode.toUpperCase();

  // Update active state
  document.querySelectorAll('.language-option').forEach((option) => {
    option.classList.remove('active');
    if (option.dataset.language === langCode) {
      option.classList.add('active');
    }
  });
}

/**
 * Trigger Google Translate for specific language
 */
function triggerGoogleTranslate(langCode) {
  const element = document.querySelector('.goog-te-combo');
  if (element) {
    element.value = langCode;
    element.dispatchEvent(new Event('change'));
  }
}

/**
 * Load saved language preference
 */
function loadSavedLanguage() {
  const savedLang = localStorage.getItem(LANGUAGE_STORAGE_KEY);
  if (savedLang && LANGUAGES[savedLang]) {
    switchLanguage(savedLang);
  }
}

/**
 * Hide default Google Translate UI elements
 */
function hideDefaultGoogleUI() {
  const style = document.createElement('style');
  style.textContent = `
    /* Hide Google Translate default UI */
    .goog-te-banner-frame,
    .goog-te-balloon-frame,
    .goog-logo-link,
    .goog-te-gadget,
    .goog-te-gadget-simple {
      display: none !important;
    }
    
    /* Override body top margin added by Google */
    body {
      top: 0 !important;
      overflow-x: hidden !important;
      max-width: 100% !important;
    }
    
    html {
      max-width: 100% !important;
      overflow-x: hidden !important;
    }
    
    /* Fix flexbox overflow on mobile */
    * {
      min-width: 0;
    }
    
    /* Mobile-first padding fixes */
    @media (max-width: 639px) {
      .hero-content {
        padding: 0 16px !important;
      }
      
      .navbar {
        padding: 0 16px !important;
      }
    }
    
    /* Constrain horizontal scroll sections */
    .hero-swiper,
    .trending-scroll,
    .swiper {
      max-width: 100% !important;
      overflow-x: hidden !important;
    }
  `;
  document.head.appendChild(style);
}

/**
 * Add styles for custom language switcher
 */
function addLanguageSwitcherStyles() {
  const style = document.createElement('style');
  style.textContent = `
    /* Language Switcher Styles */
    .language-switcher-wrapper {
      position: relative;
      display: inline-block;
    }
    
    .language-switcher-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 12px;
      background: transparent;
      border: none;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      color: #1E293B;
      transition: all 0.2s ease;
      border-radius: 8px;
      min-width: 0;
    }
    
    .language-switcher-btn:hover {
      background: #F1F5F9;
      color: #2563EB;
    }
    
    .language-flag {
      font-size: 16px;
      display: inline-block;
    }
    
    .language-code {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      white-space: nowrap;
    }
    
    .language-chevron {
      font-size: 12px;
      transition: transform 0.2s ease;
    }
    
    .language-switcher-btn:hover .language-chevron {
      color: #2563EB;
    }
    
    .language-dropdown {
      position: absolute;
      top: 100%;
      right: 0;
      background: white;
      border-radius: 12px;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15);
      min-width: 200px;
      max-width: calc(100vw - 20px);
      display: none;
      z-index: 1000;
      margin-top: 8px;
      overflow: hidden;
      animation: slideDown 0.2s ease;
    }
    
    .language-dropdown.active {
      display: block;
    }
    
    @keyframes slideDown {
      from {
        opacity: 0;
        transform: translateY(-8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    .language-option {
      width: 100%;
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      background: white;
      border: none;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      color: #1E293B;
      transition: all 0.2s ease;
      text-align: left;
      min-width: 0;
    }
    
    .language-option:hover {
      background: #F8FAFC;
    }
    
    .language-option.active {
      background: #EFF6FF;
      color: #2563EB;
    }
    
    .language-option-flag {
      font-size: 18px;
      min-width: 24px;
      display: inline-block;
    }
    
    .language-option-name {
      white-space: nowrap;
      flex: 1;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    
    /* Dark mode support */
    html.dark .language-switcher-btn {
      color: #E2E8F0;
    }
    
    html.dark .language-switcher-btn:hover {
      background: #334155;
      color: #60A5FA;
    }
    
    html.dark .language-dropdown {
      background: #1E293B;
    }
    
    html.dark .language-option {
      background: #1E293B;
      color: #E2E8F0;
    }
    
    html.dark .language-option:hover {
      background: #334155;
    }
    
    html.dark .language-option.active {
      background: #1E40AF;
      color: #93C5FD;
    }
    
    /* Mobile responsive */
    @media (max-width: 640px) {
      .language-switcher-btn {
        padding: 8px 8px;
        font-size: 12px;
      }
      
      .language-code {
        display: none;
      }
      
      .language-dropdown {
        right: auto;
        left: 50%;
        transform: translateX(-50%);
        min-width: 180px;
      }
      
      .language-option {
        padding: 10px 12px;
        font-size: 13px;
      }
    }
  `;
  document.head.appendChild(style);
}

/**
 * Auto-initialize when DOM is ready
 */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupLanguageSwitcher);
} else {
  setupLanguageSwitcher();
}
