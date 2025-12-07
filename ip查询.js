/**
 * Cloudflare Worker - IP 地址查询工具
 * 可以直接复制粘贴到 Cloudflare Workers 编辑器部署
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // IP 端点，只返回 IP 和 ASN 信息
    if (url.pathname === '/ip') {
      const ipInfo = extractIPandASN(request);
      return new Response(JSON.stringify(ipInfo, null, 2), {
        headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }
    
    // API 端点，返回 JSON
    if (url.pathname === '/api') {
      const info = extractAllInfo(request);
      return new Response(JSON.stringify(info, null, 2), {
        headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    // HTML 页面
    const html = generateHTML(request);
    return new Response(html, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
      },
    });
  },
};

/**
 * 提取 IP 和 ASN 相关信息
 */
function extractIPandASN(request) {
  const headers = request.headers;
  
  // 获取IP地址（优先级：CF-Connecting-IP > X-Forwarded-For > X-Real-IP）
  const ip = headers.get('CF-Connecting-IP') || 
             headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
             headers.get('X-Real-IP') ||
             '未提供';

  if (!request.cf) {
    return {
      ip: ip,
      error: 'request.cf 不可用',
    };
  }

  const cf = request.cf;
  
  return {
    // IP地址
    ip: ip,
    
    // ASN 网络信息
    asn: cf.asn || null,
    asOrganization: cf.asOrganization || null,
    
    // 额外的地理位置信息（可选）
    country: cf.country || null,
    city: cf.city || null,
    region: cf.region || null,
    timezone: cf.timezone || null,
  };
}

/**
 * 提取所有可用的信息（包括IP地址和request.cf属性）
 */
function extractAllInfo(request) {
  const headers = request.headers;
  
  // 获取IP地址（优先级：CF-Connecting-IP > X-Forwarded-For > X-Real-IP）
  const ip = headers.get('CF-Connecting-IP') || 
             headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
             headers.get('X-Real-IP') ||
             '未提供';

  // 获取其他有用的请求头信息
  const requestHeaders = {
    userAgent: headers.get('User-Agent') || null,
    acceptLanguage: headers.get('Accept-Language') || null,
    accept: headers.get('Accept') || null,
    acceptEncoding: headers.get('Accept-Encoding') || null,
    referer: headers.get('Referer') || null,
    origin: headers.get('Origin') || null,
    cfRay: headers.get('CF-Ray') || null,
    cfVisitor: headers.get('CF-Visitor') || null,
    cfCountry: headers.get('CF-IPCountry') || null,
  };

  if (!request.cf) {
    return {
      ip,
      requestHeaders,
      error: 'request.cf 不可用',
    };
  }

  const cf = request.cf;
  
  return {
    // IP地址信息
    ip: {
      address: ip,
      cfConnectingIP: headers.get('CF-Connecting-IP'),
      xForwardedFor: headers.get('X-Forwarded-For'),
      xRealIP: headers.get('X-Real-IP'),
    },
    
    // 地理位置信息
    location: {
      colo: cf.colo,
      country: cf.country,
      city: cf.city,
      continent: cf.continent,
      latitude: cf.latitude,
      longitude: cf.longitude,
      postalCode: cf.postalCode,
      metroCode: cf.metroCode,
      region: cf.region,
      regionCode: cf.regionCode,
      timezone: cf.timezone,
      isEUCountry: cf.isEUCountry,
    },
    
    // 网络信息
    network: {
      asn: cf.asn,
      asOrganization: cf.asOrganization,
    },
    
    // HTTP/TLS 信息
    protocol: {
      httpProtocol: cf.httpProtocol,
      tlsVersion: cf.tlsVersion,
      tlsCipher: cf.tlsCipher,
      tlsClientAuth: cf.tlsClientAuth,
      tlsClientCiphersSha1: cf.tlsClientCiphersSha1,
      tlsClientExtensionsSha1: cf.tlsClientExtensionsSha1,
      tlsClientExtensionsSha1Le: cf.tlsClientExtensionsSha1Le,
      tlsClientHelloLength: cf.tlsClientHelloLength,
      tlsClientRandom: cf.tlsClientRandom,
    },
    
    // 请求信息
    request: {
      clientAcceptEncoding: cf.clientAcceptEncoding,
      requestPriority: cf.requestPriority,
      hostMetadata: cf.hostMetadata,
    },
    
    // 请求头信息
    requestHeaders,
    
    // Bot 管理 (需要启用 Bot Management)
    botManagement: cf.botManagement,
  };
}

/**
 * 生成 HTML 页面
 */
function generateHTML(request) {
  const info = extractAllInfo(request);
  
  // 格式化值显示
  function formatValue(value) {
    if (value === null || value === undefined) {
      return '<span class="italic" style="color: var(--muted);">未提供</span>';
    }
    if (typeof value === 'object' && value !== null) {
      const entries = Object.entries(value).filter(([_, v]) => v !== null && v !== undefined);
      if (entries.length === 0) return '<span class="italic" style="color: var(--muted);">未提供</span>';
      return `<pre class="inline-block text-xs p-2 rounded max-w-full overflow-auto" style="background-color: var(--silver-1); color: var(--text); border: 2px solid var(--border);">${JSON.stringify(value, null, 2)}</pre>`;
    }
    return `<span class="font-mono">${escapeHtml(String(value))}</span>`;
  }

  // HTML转义（服务器端）
  function escapeHtml(text) {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  }

  // 生成分类卡片
  function generateCategoryCard(title, icon, data, highlight = false, footerContent = '') {
    const entries = Object.entries(data).filter(([_, value]) => value !== null && value !== undefined);
    if (entries.length === 0) {
      return '';
    }
    
    const cardBg = highlight 
      ? 'background-color: var(--glass-green); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);'
      : 'background-color: var(--card)';
    
    const titleColor = 'var(--text)';
    const labelColor = 'var(--muted)';
    const valueColor = 'var(--text)';
    const borderColor = 'var(--border)';
    
    return `
      <div class="masonry-item rounded-lg p-6 transition-colors duration-200" style="${cardBg}; border: 2px solid ${borderColor};">
        <div class="flex items-center mb-4">
          <span class="text-3xl mr-3">${icon}</span>
          <h2 class="text-2xl font-bold" style="color: ${titleColor};">${title}</h2>
        </div>
        <div class="space-y-3">
          ${entries.map(([key, value]) => `
            <div class="border-b pb-3 last:border-0" style="border-color: ${borderColor};">
              <div class="text-sm font-semibold mb-1.5" style="color: ${labelColor};">${formatKeyName(key)}</div>
              <div class="break-words text-base" style="color: ${valueColor};">${formatValue(value)}</div>
            </div>
          `).join('')}
        </div>
        ${footerContent ? `<div class="mt-4 pt-4 border-t" style="border-color: ${borderColor};">${footerContent}</div>` : ''}
      </div>
    `;
  }

  // 格式化键名（驼峰转可读文本）
  function formatKeyName(key) {
    const keyMap = {
      address: 'IP 地址',
      cfConnectingIP: 'CF-Connecting-IP',
      xForwardedFor: 'X-Forwarded-For',
      xRealIP: 'X-Real-IP',
      userAgent: '用户代理',
      acceptLanguage: '接受语言',
      accept: '接受类型',
      acceptEncoding: '接受编码',
      referer: '来源页面',
      origin: '来源域',
      cfRay: 'CF-Ray',
      cfVisitor: 'CF-Visitor',
      cfCountry: 'CF-IPCountry',
    };
    
    if (keyMap[key]) return keyMap[key];
    
    return key
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase())
      .trim();
  }

  // 生成IP地址卡片（突出显示）
  const ipCard = info.ip ? generateCategoryCard('IP 地址信息', '🖥️', info.ip, true) : '';
  
  // 地理位置卡片（添加地图链接）
  let locationCard = '';
  if (info.location) {
    const locationData = { ...info.location };
    const mapLink = (info.location.latitude && info.location.longitude) 
      ? `<a href="https://www.google.com/maps?q=${info.location.latitude},${info.location.longitude}" target="_blank" class="inline-flex items-center px-4 py-2 text-white rounded-lg transition-colors" style="background-color: var(--accent);" onmouseover="this.style.backgroundColor='#FF8888'" onmouseout="this.style.backgroundColor='var(--accent)'">
          📍 在地图上查看位置
        </a>`
      : '';
    locationCard = generateCategoryCard('地理位置信息', '🌍', locationData, false, mapLink);
  }
  
  const networkCard = info.network ? generateCategoryCard('网络信息', '📡', info.network) : '';
  const protocolCard = info.protocol ? generateCategoryCard('HTTP/TLS 协议', '🔒', info.protocol) : '';
  const requestCard = info.request ? generateCategoryCard('请求信息', '📋', info.request) : '';
  const headersCard = info.requestHeaders ? generateCategoryCard('HTTP 请求头', '📨', info.requestHeaders) : '';
  const botCard = info.botManagement 
    ? generateCategoryCard('Bot 管理信息', '🤖', info.botManagement) 
    : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IP 地址查询工具 - Cloudflare Worker</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            'custom-light-mint': '#B7E5CD',
            'custom-teal': '#8ABEB9',
            'custom-dark-teal': '#305669',
            'custom-orange': '#C1785A',
          }
        }
      }
    }
  </script>
  <style>
    :root {
      --bg: #FCF9EA;
      --text: #1D1D1F;
      --muted: #6E6E73;
      --card: #FFFFFF;
      --border: #FFBDBD;
      --accent: #FFA4A4;
      --silver-1: #BADFDB;
      --silver-2: #E8E8ED;
      --glass-green: rgba(216, 243, 220, 0.4);
    }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'SF Pro Display', 'Helvetica Neue', 'Segoe UI', Arial, 'Noto Sans', sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji';
      color: var(--text);
    }
    @media (prefers-color-scheme: dark) {
      .dark-mode {
        background-color: #000000;
        color: #F5F5F7;
      }
    }
    pre {
      white-space: pre-wrap;
      word-break: break-all;
    }
    /* Masonry layout for uneven card heights */
    .masonry { column-gap: 24px; }
    @media (min-width: 768px) { .masonry { columns: 2; } }
    @media (min-width: 1024px) { .masonry { columns: 3; } }
    .masonry-item { 
      break-inside: avoid; 
      -webkit-column-break-inside: avoid; 
      -moz-column-break-inside: avoid; 
      margin-bottom: 24px; /* matches gap-6 */
    }
    .copy-btn {
      cursor: pointer;
      transition: opacity 0.2s;
    }
    .copy-btn:hover {
      opacity: 0.8;
    }
    .copy-btn:active {
      opacity: 0.6;
    }
  </style>
  </head>
  <body class="min-h-screen py-8 px-4" style="background-color: var(--bg);">
  <div class="max-w-7xl mx-auto">
    <!-- 顶部标题区域 -->
    <div class="text-center mb-8">
      <h1 class="text-5xl font-bold mb-3" style="color: var(--text);">
        🔍 IP 地址查询工具
      </h1>
      <p class="text-lg mb-6" style="color: var(--muted);">
        实时获取您的 IP 地址及详细网络信息
      </p>
      <div class="flex justify-center gap-4 flex-wrap">
        <a href="/api" class="px-6 py-2 rounded-lg transition-colors" style="background-color: var(--card); color: var(--text); border: 2px solid var(--border);" onmouseover="this.style.backgroundColor='var(--silver-1)'" onmouseout="this.style.backgroundColor='var(--card)'" target="_blank">
          📄 JSON API
        </a>
        <button onclick="location.reload()" class="px-6 py-2 rounded-lg transition-colors" style="background-color: var(--card); color: var(--text); border: 2px solid var(--border);" onmouseover="this.style.backgroundColor='var(--silver-1)'" onmouseout="this.style.backgroundColor='var(--card)'">
          🔄 刷新数据
        </button>
        <button onclick="copyAllInfo()" class="px-6 py-2 text-white rounded-lg transition-colors" style="background-color: var(--accent);" onmouseover="this.style.backgroundColor='#FF8888'" onmouseout="this.style.backgroundColor='var(--accent)'">
          📋 复制全部信息
        </button>
      </div>
    </div>

    <!-- IP地址卡片（最突出） -->
    ${ipCard ? `<div class="mb-6">${ipCard}</div>` : ''}

    <!-- 信息卡片：响应式 Masonry，避免不等高留白 -->
    <div class="masonry">
      ${locationCard}
      ${networkCard}
      ${protocolCard}
      ${requestCard}
      ${headersCard}
      ${botCard}
    </div>

    <!-- 原始数据展示（可折叠） -->
    <div class="mt-8 bg-white dark:bg-gray-800 rounded-lg p-6" style="background-color: var(--card); border: 2px solid var(--border);">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-xl font-bold flex items-center" style="color: var(--text);">
          <span class="text-2xl mr-2">📦</span>
          原始 JSON 数据
        </h2>
        <button onclick="toggleJson()" class="px-4 py-2 rounded transition-colors" style="background-color: var(--card); color: var(--text); border: 2px solid var(--border);" onmouseover="this.style.backgroundColor='var(--silver-1)'" onmouseout="this.style.backgroundColor='var(--card)'">
          <span id="toggleText">展开</span>
        </button>
      </div>
      <div id="jsonData" class="hidden">
        <pre class="p-4 rounded-lg overflow-auto text-xs max-h-96" style="background-color: var(--silver-1); color: var(--text); border: 2px solid var(--border);"><code id="jsonContent">${JSON.stringify(info, null, 2)}</code></pre>
        <button onclick="copyJson()" class="mt-3 px-4 py-2 text-white rounded transition-colors text-sm" style="background-color: var(--accent);" onmouseover="this.style.backgroundColor='#FF8888'" onmouseout="this.style.backgroundColor='var(--accent)'">
          📋 复制 JSON
        </button>
      </div>
    </div>

    <!-- 页脚 -->
    <div class="text-center mt-8 text-sm" style="color: var(--muted);">
      <p>⚡ 由 Cloudflare Workers 驱动 | 🌐 数据来自 Cloudflare 全球网络</p>
      <p class="mt-2 text-xs">实时查询 | 无需安装 | 完全免费</p>
    </div>
  </div>

  <script>
    // 自动检测暗色模式
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.body.classList.add('dark-mode');
    }

    // 切换JSON显示
    function toggleJson() {
      const jsonData = document.getElementById('jsonData');
      const toggleText = document.getElementById('toggleText');
      if (jsonData.classList.contains('hidden')) {
        jsonData.classList.remove('hidden');
        toggleText.textContent = '收起';
      } else {
        jsonData.classList.add('hidden');
        toggleText.textContent = '展开';
      }
    }

    // 复制JSON
    function copyJson() {
      const jsonContent = document.getElementById('jsonContent').textContent;
      navigator.clipboard.writeText(jsonContent).then(() => {
        alert('✅ JSON 数据已复制到剪贴板！');
      }).catch(() => {
        alert('❌ 复制失败，请手动复制');
      });
    }

    // 复制全部信息
    function copyAllInfo() {
      const info = ${JSON.stringify(info, null, 2)};
      const text = JSON.stringify(info, null, 2);
      navigator.clipboard.writeText(text).then(() => {
        alert('✅ 所有信息已复制到剪贴板！');
      }).catch(() => {
        alert('❌ 复制失败，请手动复制');
      });
    }

    // HTML转义函数（用于格式化值）
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
  </script>
</body>
</html>`;
}