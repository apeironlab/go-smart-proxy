import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from './locales/en.json'

export type LanguageCode =
  | 'bg' | 'hr' | 'cs' | 'da' | 'nl' | 'en' | 'et' | 'fi' | 'fr' | 'de'
  | 'el' | 'hu' | 'ga' | 'it' | 'lv' | 'lt' | 'mt' | 'pl' | 'pt' | 'ro'
  | 'sk' | 'sl' | 'es' | 'sv'

export const languages: { code: LanguageCode; label: string }[] = [
  { code: 'en', label: 'English' },
  { code: 'it', label: 'Italiano' },
  { code: 'fr', label: 'Français' },
  { code: 'de', label: 'Deutsch' },
  { code: 'es', label: 'Español' },
  { code: 'pt', label: 'Português' },
  { code: 'bg', label: 'Български' },
  { code: 'hr', label: 'Hrvatski' },
  { code: 'cs', label: 'Čeština' },
  { code: 'da', label: 'Dansk' },
  { code: 'nl', label: 'Nederlands' },
  { code: 'et', label: 'Eesti' },
  { code: 'fi', label: 'Suomi' },
  { code: 'el', label: 'Ελληνικά' },
  { code: 'hu', label: 'Magyar' },
  { code: 'ga', label: 'Gaeilge' },
  { code: 'lv', label: 'Latviešu' },
  { code: 'lt', label: 'Lietuvių' },
  { code: 'mt', label: 'Malti' },
  { code: 'pl', label: 'Polski' },
  { code: 'ro', label: 'Română' },
  { code: 'sk', label: 'Slovenčina' },
  { code: 'sl', label: 'Slovenščina' },
  { code: 'sv', label: 'Svenska' },
]

const supported = languages.map((l) => l.code)
const storageKey = 'gsp.language'

export function detectLanguage(): LanguageCode {
  const stored = localStorage.getItem(storageKey)
  if (stored && supported.includes(stored as LanguageCode)) return stored as LanguageCode
  const candidates = navigator.languages?.length ? navigator.languages : [navigator.language]
  for (const candidate of candidates) {
    const base = candidate.toLowerCase().split('-')[0] as LanguageCode
    if (supported.includes(base)) return base
  }
  return 'en'
}

export async function loadLanguage(code: LanguageCode): Promise<void> {
  if (code === 'en' || i18n.hasResourceBundle(code, 'translation')) return
  const module = await import(`./locales/${code}.json`)
  i18n.addResourceBundle(code, 'translation', module.default ?? module, true, true)
}

i18n
  .use(initReactI18next)
  .init({
    resources: { en: { translation: en } },
    lng: 'en',
    fallbackLng: 'en',
    supportedLngs: supported,
    keySeparator: false,
    nsSeparator: false,
    interpolation: { escapeValue: false },
    returnNull: false,
  })

const initial = detectLanguage()
if (initial !== 'en') {
  void loadLanguage(initial).then(() => {
    void i18n.changeLanguage(initial)
  })
}

i18n.on('languageChanged', (lng) => {
  localStorage.setItem(storageKey, lng)
  document.documentElement.lang = lng
  if (lng !== 'en' && !i18n.hasResourceBundle(lng, 'translation')) {
    void loadLanguage(lng as LanguageCode).then(() => {
      void i18n.changeLanguage(lng)
    })
  }
})

document.documentElement.lang = i18n.language

export default i18n
