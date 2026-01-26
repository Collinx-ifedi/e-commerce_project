// =========================================================
// LANGUAGE SWITCHER CONFIGURATION
// =========================================================

/**
 * Initialize language preference from localStorage
 * Persists user's language choice across the site
 */
function initLanguagePreference() {
    const savedLanguage = localStorage.getItem('preferredLanguage');
    
    if (savedLanguage && savedLanguage !== 'en') {
        // If a language is saved, apply it using Google Translate
        selectLanguage(savedLanguage);
    }
}

/**
 * Select and persist a language choice
 * @param {string} languageCode - The language code (e.g., 'es', 'fr')
 */
function selectLanguage(languageCode) {
    localStorage.setItem('preferredLanguage', languageCode);
    
    if (languageCode === 'en') {
        // Reload page to reset to English
        document.documentElement.lang = 'en';
        location.reload();
    } else {
        // Use Google Translate to switch language
        window.google.translate.TranslateElement.prototype.switchLanguage(languageCode);
    }
}

/**
 * Google Translate initialization callback
 */
function googleTranslateElementInit() {
    window.google.translate.TranslateElement({
        pageLanguage: 'en',
        includedLanguages: 'en,es,fr,de,it,pt,ru,ja,zh-CN,ar,hi',
        layout: window.google.translate.TranslateElement.InlineLayout.SIMPLE,
        autoDisplay: false
    }, 'googleTranslate');
    
    // Hide the Google Translate footer/branding
    setTimeout(() => {
        const googleTranslateElement = document.querySelector('.goog-te-banner-frame');
        if (googleTranslateElement) {
            googleTranslateElement.style.display = 'none';
        }
    }, 100);
    
    // Apply saved language preference on page load
    const savedLanguage = localStorage.getItem('preferredLanguage');
    if (savedLanguage && savedLanguage !== 'en') {
        setTimeout(() => {
            window.google.translate.TranslateElement.prototype.switchLanguage(savedLanguage);
        }, 500);
    }
}

/**
 * Setup language selector buttons for mobile/desktop
 * Call this function in your page's init code
 */
function setupLanguageSelector() {
    const languages = [
        { code: 'en', name: 'English', flag: '🇺🇸' },
        { code: 'es', name: 'Español', flag: '🇪🇸' },
        { code: 'fr', name: 'Français', flag: '🇫🇷' },
        { code: 'de', name: 'Deutsch', flag: '🇩🇪' },
        { code: 'it', name: 'Italiano', flag: '🇮🇹' },
        { code: 'pt', name: 'Português', flag: '🇵🇹' },
        { code: 'ru', name: 'Русский', flag: '🇷🇺' },
        { code: 'ja', name: '日本語', flag: '🇯🇵' },
        { code: 'zh-CN', name: '中文', flag: '🇨🇳' },
        { code: 'ar', name: 'العربية', flag: '🇸🇦' },
        { code: 'hi', name: 'हिंदी', flag: '🇮🇳' }
    ];
    
    const savedLanguage = localStorage.getItem('preferredLanguage') || 'en';
    
    // Setup mobile language button if it exists
    const mobileLangBtn = document.querySelector('.mobile-lang-btn');
    if (mobileLangBtn) {
        const savedLangName = languages.find(l => l.code === savedLanguage)?.name || 'English';
        mobileLangBtn.innerHTML = `<span>${savedLangName}</span><i class="fas fa-chevron-down"></i>`;
        
        const dropdown = document.querySelector('.mobile-lang-dropdown');
        if (dropdown) {
            languages.forEach(lang => {
                const btn = document.createElement('button');
                btn.textContent = `${lang.flag} ${lang.name}`;
                btn.onclick = (e) => {
                    e.preventDefault();
                    selectLanguage(lang.code);
                };
                if (lang.code === savedLanguage) {
                    btn.classList.add('active');
                }
                dropdown.appendChild(btn);
            });
            
            // Toggle dropdown
            mobileLangBtn.addEventListener('click', () => {
                dropdown.classList.toggle('active');
            });
        }
    }
}

// Initialize language preference on page load
document.addEventListener('DOMContentLoaded', initLanguagePreference);

// Declare google variable
window.google = window.google || {};
window.google.translate = window.google.translate || {};
window.google.translate.TranslateElement = window.google.translate.TranslateElement || function() {};
window.google.translate.TranslateElement.prototype.switchLanguage = window.google.translate.TranslateElement.prototype.switchLanguage || function(languageCode) {};
