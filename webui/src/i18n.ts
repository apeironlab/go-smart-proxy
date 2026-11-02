import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

import bg from './locales/bg.json'
import cs from './locales/cs.json'
import da from './locales/da.json'
import de from './locales/de.json'
import el from './locales/el.json'
import en from './locales/en.json'
import es from './locales/es.json'
import et from './locales/et.json'
import fi from './locales/fi.json'
import fr from './locales/fr.json'
import ga from './locales/ga.json'
import hr from './locales/hr.json'
import hu from './locales/hu.json'
import it from './locales/it.json'
import lt from './locales/lt.json'
import lv from './locales/lv.json'
import mt from './locales/mt.json'
import nl from './locales/nl.json'
import pl from './locales/pl.json'
import pt from './locales/pt.json'
import ro from './locales/ro.json'
import sk from './locales/sk.json'
import sl from './locales/sl.json'
import sv from './locales/sv.json'

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

const resources = {
  bg: { translation: bg },
  hr: { translation: hr },
  cs: { translation: cs },
  da: { translation: da },
  nl: { translation: nl },
  en: { translation: en },
  et: { translation: et },
  fi: { translation: fi },
  fr: { translation: fr },
  de: { translation: de },
  el: { translation: el },
  hu: { translation: hu },
  ga: { translation: ga },
  it: { translation: it },
  lv: { translation: lv },
  lt: { translation: lt },
  mt: { translation: mt },
  pl: { translation: pl },
  pt: { translation: pt },
  ro: { translation: ro },
  sk: { translation: sk },
  sl: { translation: sl },
  es: { translation: es },
  sv: { translation: sv },
}

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

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: detectLanguage(),
    fallbackLng: 'en',
    supportedLngs: supported,
    keySeparator: false,
    nsSeparator: false,
    interpolation: { escapeValue: false },
    returnNull: false,
  })

i18n.on('languageChanged', (lng) => {
  localStorage.setItem(storageKey, lng)
  document.documentElement.lang = lng
})

document.documentElement.lang = i18n.language

export default i18n
