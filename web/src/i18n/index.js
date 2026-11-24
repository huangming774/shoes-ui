import { createI18n } from 'vue-i18n';
import zh from './zh';
import en from './en';

const savedLocale = localStorage.getItem('shoes_panel_lang') || 'zh';

export const i18n = createI18n({
  legacy: false,
  locale: savedLocale,
  fallbackLocale: 'en',
  messages: { zh, en },
});

export function setLocale(lang) {
  i18n.global.locale.value = lang;
  localStorage.setItem('shoes_panel_lang', lang);
}
