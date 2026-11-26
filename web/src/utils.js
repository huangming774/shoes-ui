export function formatBytes(bytes, decimals = 2) {
  const n = Number(bytes || 0);
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(k)), sizes.length - 1);
  return `${parseFloat((n / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}

export function formatSpeed(bytesPerSec) {
  return `${formatBytes(bytesPerSec, 1)}/s`;
}

export function formatDuration(totalSecs, isZh = true) {
  const s = Math.max(0, Math.floor(Number(totalSecs || 0)));
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  if (days > 0) {
    return isZh ? `${days}天 ${hours}小时 ${mins}分` : `${days}d ${hours}h ${mins}m`;
  }
  if (hours > 0) {
    return isZh ? `${hours}小时 ${mins}分 ${secs}秒` : `${hours}h ${mins}m ${secs}s`;
  }
  return isZh ? `${mins}分 ${secs}秒` : `${mins}m ${secs}s`;
}

export async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
}

export const PROTOCOL_COLORS = {
  vless: 'purple',
  vmess: 'geekblue',
  trojan: 'magenta',
  shadowsocks: 'cyan',
  hysteria2: 'volcano',
  tuic: 'gold',
  anytls: 'green',
  naiveproxy: 'lime',
  snell: 'orange',
  socks: 'blue',
  http: 'default',
  mixed: 'processing',
  portforward: 'geekblue',
  wireguard: 'orange',
};
