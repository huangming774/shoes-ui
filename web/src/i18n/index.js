import { createI18n } from 'vue-i18n';
import zhCN from 'ant-design-vue/es/locale/zh_CN';
import zhTW from 'ant-design-vue/es/locale/zh_TW';
import enUS from 'ant-design-vue/es/locale/en_US';
import ruRU from 'ant-design-vue/es/locale/ru_RU';
import faIR from 'ant-design-vue/es/locale/fa_IR';
import jaJP from 'ant-design-vue/es/locale/ja_JP';
import koKR from 'ant-design-vue/es/locale/ko_KR';
import viVN from 'ant-design-vue/es/locale/vi_VN';
import trTR from 'ant-design-vue/es/locale/tr_TR';
import esES from 'ant-design-vue/es/locale/es_ES';

import zh from './zh';
import zhTwMsg from './zh-TW';
import en from './en';
import ru from './ru';
import fa from './fa';
import ja from './ja';
import ko from './ko';
import vi from './vi';
import tr from './tr';
import es from './es';

export const SUPPORTED_LOCALES = [
  { code: 'zh', label: '简体中文', short: '简中', antd: zhCN, dir: 'ltr' },
  { code: 'zh-TW', label: '繁體中文', short: '繁中', antd: zhTW, dir: 'ltr' },
  { code: 'en', label: 'English', short: 'EN', antd: enUS, dir: 'ltr' },
  { code: 'ru', label: 'Русский', short: 'RU', antd: ruRU, dir: 'ltr' },
  { code: 'fa', label: 'فارسی', short: 'FA', antd: faIR, dir: 'rtl' },
  { code: 'ja', label: '日本語', short: 'JA', antd: jaJP, dir: 'ltr' },
  { code: 'ko', label: '한국어', short: 'KO', antd: koKR, dir: 'ltr' },
  { code: 'vi', label: 'Tiếng Việt', short: 'VI', antd: viVN, dir: 'ltr' },
  { code: 'tr', label: 'Türkçe', short: 'TR', antd: trTR, dir: 'ltr' },
  { code: 'es', label: 'Español', short: 'ES', antd: esES, dir: 'ltr' },
];

const LOCALE_MAP = Object.fromEntries(SUPPORTED_LOCALES.map((item) => [item.code, item]));

function detectInitialLocale() {
  const saved = typeof localStorage !== 'undefined' ? localStorage.getItem('shoes_panel_lang') : null;
  if (saved && LOCALE_MAP[saved]) return saved;

  const nav = typeof navigator !== 'undefined' ? (navigator.language || '').toLowerCase() : '';
  if (nav.startsWith('zh-tw') || nav.startsWith('zh-hk') || nav.startsWith('zh-mo') || nav.includes('hant')) {
    return 'zh-TW';
  }
  if (nav.startsWith('zh')) return 'zh';
  if (nav.startsWith('ru')) return 'ru';
  if (nav.startsWith('fa')) return 'fa';
  if (nav.startsWith('ja')) return 'ja';
  if (nav.startsWith('ko')) return 'ko';
  if (nav.startsWith('vi')) return 'vi';
  if (nav.startsWith('tr')) return 'tr';
  if (nav.startsWith('es')) return 'es';
  if (nav.startsWith('en')) return 'en';
  return 'zh';
}

function applyDocumentLocale(code) {
  if (typeof document === 'undefined') return;
  const meta = LOCALE_MAP[code] || LOCALE_MAP.en;
  document.documentElement.lang = meta.code;
  document.documentElement.dir = meta.dir;
}

const initialLocale = detectInitialLocale();
applyDocumentLocale(initialLocale);

export const i18n = createI18n({
  legacy: false,
  locale: initialLocale,
  fallbackLocale: 'en',
  messages: {
    zh,
    'zh-TW': zhTwMsg,
    en,
    ru,
    fa,
    ja,
    ko,
    vi,
    tr,
    es,
  },
});

export function getLocaleMeta(code) {
  return LOCALE_MAP[code] || LOCALE_MAP.en;
}

export function setLocale(lang) {
  const meta = LOCALE_MAP[lang] || LOCALE_MAP.en;
  i18n.global.locale.value = meta.code;
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem('shoes_panel_lang', meta.code);
  }
  applyDocumentLocale(meta.code);
}
