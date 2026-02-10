let DoH = "cloudflare-dns.com";
const jsonDoH = `https://${DoH}/resolve`;
const dnsDoH = `https://${DoH}/dns-query`;
let DoH路径 = 'dns-query';
export default {
  async fetch(request, env) {
    if (env.DOH) {
      DoH = env.DOH;
      const match = DoH.match(/:\/\/([^\/]+)/);
      if (match) {
        DoH = match[1];
      }
    }
    DoH路径 = env.PATH || env.TOKEN || DoH路径;//DoH路径也单独设置 变量PATH
    if (DoH路径.includes("/")) DoH路径 = DoH路径.split("/")[1];
    const url = new URL(request.url);
    const path = url.pathname;
    const hostname = url.hostname;

    // 处理 OPTIONS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // 如果请求路径，则作为 DoH 服务器处理
    if (path === `/${DoH路径}`) {
      return await DOHRequest(request);
    }

    // 添加IP地理位置信息查询代理
    if (path === '/ip-info') {
      if (env.TOKEN) {
        const token = url.searchParams.get('token');
        if (token != env.TOKEN) {
          return new Response(JSON.stringify({
            status: "error",
            message: "Token不正确",
            code: "AUTH_FAILED",
            timestamp: new Date().toISOString()
          }, null, 4), {
            status: 403,
            headers: {
              "content-type": "application/json; charset=UTF-8",
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) {
        return new Response(JSON.stringify({
          status: "error",
          message: "IP参数未提供",
          code: "MISSING_PARAMETER",
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 400,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      try {
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
        const data = await response.json();
        data.timestamp = new Date().toISOString();
        return new Response(JSON.stringify(data, null, 4), {
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      } catch (error) {
        console.error("IP查询失败:", error);
        return new Response(JSON.stringify({
          status: "error",
          message: `IP查询失败: ${error.message}`,
          code: "API_REQUEST_FAILED",
          query: ip,
          timestamp: new Date().toISOString(),
          details: { errorType: error.name, stack: error.stack ? error.stack.split('\n')[0] : null }
        }, null, 4), {
          status: 500,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    }

    // 如果请求参数中包含 domain 和 doh，则执行 DNS 解析
    if (url.searchParams.has("doh")) {
      const domain = url.searchParams.get("domain") || url.searchParams.get("name") || "www.google.com";
      const doh = url.searchParams.get("doh") || dnsDoH;
      const type = url.searchParams.get("type") || "all";

      if (doh.includes(url.host)) {
        return await handleLocalDohRequest(domain, type, hostname);
      }

      try {
        if (type === "all") {
          const ipv4Result = await queryDns(doh, domain, "A");
          const ipv6Result = await queryDns(doh, domain, "AAAA");
          const nsResult = await queryDns(doh, domain, "NS");

          const combinedResult = {
            Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
            TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
            RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
            RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
            AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
            CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
            Question: [],
            Answer: [...(ipv4Result.Answer || []), ...(ipv6Result.Answer || [])],
            ipv4: { records: ipv4Result.Answer || [] },
            ipv6: { records: ipv6Result.Answer || [] },
            ns: { records: [] }
          };

          [ipv4Result, ipv6Result, nsResult].forEach(r => {
            if (r.Question) {
              combinedResult.Question.push(...(Array.isArray(r.Question) ? r.Question : [r.Question]));
            }
          });

          const nsRecords = [];
          if (nsResult.Answer?.length) nsResult.Answer.forEach(record => { if (record.type === 2) nsRecords.push(record); });
          if (nsResult.Authority?.length) nsResult.Authority.forEach(record => {
            if (record.type === 2 || record.type === 6) { nsRecords.push(record); combinedResult.Answer.push(record); }
          });
          combinedResult.ns.records = nsRecords;

          return new Response(JSON.stringify(combinedResult, null, 2), {
            headers: { "content-type": "application/json; charset=UTF-8" }
          });
        } else {
          const result = await queryDns(doh, domain, type);
          return new Response(JSON.stringify(result, null, 2), {
            headers: { "content-type": "application/json; charset=UTF-8" }
          });
        }
      } catch (err) {
        console.error("DNS 查询失败:", err);
        return new Response(JSON.stringify({
          error: `DNS 查询失败: ${err.message}`,
          doh: doh,
          domain: domain,
          stack: err.stack
        }, null, 2), {
          headers: { "content-type": "application/json; charset=UTF-8" },
          status: 500
        });
      }
    }

    if (env.URL302) return Response.redirect(env.URL302, 302);
    else if (env.URL) {
      if (env.URL.toString().toLowerCase() == 'nginx') {
        return new Response(await nginx(), {
          headers: { 'Content-Type': 'text/html; charset=UTF-8' }
        });
      } else return await 代理URL(env.URL, url);
    } else return await HTML();
  }
};

async function queryDns(dohServer, domain, type) {
  const dohUrl = new URL(dohServer);
  dohUrl.searchParams.set("name", domain);
  dohUrl.searchParams.set("type", type);
  const fetchOptions = [
    { headers: { 'Accept': 'application/dns-json' } },
    { headers: {} },
    { headers: { 'Accept': 'application/json' } },
    { headers: { 'Accept': 'application/dns-json', 'User-Agent': 'Mozilla/5.0 DNS Client' } }
  ];
  let lastError = null;
  for (const options of fetchOptions) {
    try {
      const response = await fetch(dohUrl.toString(), options);
      if (response.ok) {
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('json') || contentType.includes('dns-json')) return await response.json();
        const textResponse = await response.text();
        try { return JSON.parse(textResponse); } catch (e) { throw new Error(`无法解析响应: ${textResponse.substring(0, 100)}`); }
      }
      lastError = new Error(`DoH 错误 (${response.status}): ${(await response.text()).substring(0, 200)}`);
    } catch (err) { lastError = err; }
  }
  throw lastError || new Error("无法完成 DNS 查询");
}

async function handleLocalDohRequest(domain, type, hostname) {
  try {
    if (type === "all") {
      const [ipv4Result, ipv6Result, nsResult] = await Promise.all([
        queryDns(dnsDoH, domain, "A"),
        queryDns(dnsDoH, domain, "AAAA"),
        queryDns(dnsDoH, domain, "NS")
      ]);
      const nsRecords = [];
      if (nsResult.Answer?.length) nsRecords.push(...nsResult.Answer.filter(r => r.type === 2));
      if (nsResult.Authority?.length) nsRecords.push(...nsResult.Authority.filter(r => r.type === 2 || r.type === 6));
      const combinedResult = {
        Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
        TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
        RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
        RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
        AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
        CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
        Question: [...(ipv4Result.Question || []), ...(ipv6Result.Question || []), ...(nsResult.Question || [])],
        Answer: [...(ipv4Result.Answer || []), ...(ipv6Result.Answer || []), ...nsRecords],
        ipv4: { records: ipv4Result.Answer || [] },
        ipv6: { records: ipv6Result.Answer || [] },
        ns: { records: nsRecords }
      };
      return new Response(JSON.stringify(combinedResult, null, 2), {
        headers: { "content-type": "application/json; charset=UTF-8", 'Access-Control-Allow-Origin': '*' }
      });
    } else {
      const result = await queryDns(dnsDoH, domain, type);
      return new Response(JSON.stringify(result, null, 2), {
        headers: { "content-type": "application/json; charset=UTF-8", 'Access-Control-Allow-Origin': '*' }
      });
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: `DoH 查询失败: ${err.message}`, stack: err.stack }, null, 2), {
      headers: { "content-type": "application/json; charset=UTF-8", 'Access-Control-Allow-Origin': '*' },
      status: 500
    });
  }
}

async function DOHRequest(request) {
  const { method, headers, body } = request;
  const UA = headers.get('User-Agent') || 'DoH Client';
  const url = new URL(request.url);
  const { searchParams } = url;
  try {
    if (method === 'GET' && !url.search) {
      return new Response('Bad Request', {
        status: 400,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
      });
    }
    let response;
    if (method === 'GET' && searchParams.has('name')) {
      const searchDoH = searchParams.has('type') ? url.search : url.search + '&type=A';
      response = await fetch(dnsDoH + searchDoH, { headers: { 'Accept': 'application/dns-json', 'User-Agent': UA } });
      if (!response.ok) response = await fetch(jsonDoH + searchDoH, { headers: { 'Accept': 'application/dns-json', 'User-Agent': UA } });
    } else if (method === 'GET') {
      response = await fetch(dnsDoH + url.search, { headers: { 'Accept': 'application/dns-message', 'User-Agent': UA } });
    } else if (method === 'POST') {
      response = await fetch(dnsDoH, {
        method: 'POST',
        headers: { 'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message', 'User-Agent': UA },
        body: body
      });
    } else {
      return new Response('不支持的请求格式', {
        status: 400,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
      });
    }
    if (!response.ok) throw new Error(`DoH 返回错误 (${response.status})`);
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', '*');
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message, stack: error.stack }, null, 4), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}

async function HTML() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DNS-over-HTTPS Resolver</title>
  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", "PingFang SC", "Microsoft YaHei", sans-serif;
      background: linear-gradient(135deg, #ffb861, #ff8a5c);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #333;
    }
    .container {
      width: 100%;
      max-width: 960px;
      padding: 32px 16px;
    }
    .card {
      background: #fff7f0;
      border-radius: 18px;
      box-shadow: 0 14px 40px rgba(0,0,0,0.12);
      padding: 32px 28px 28px;
    }
    .title {
      font-size: 28px;
      font-weight: 700;
      color: #f05a28;
      text-align: center;
      margin-bottom: 24px;
    }
    .section-title {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 12px;
      color: #444;
    }
    .form-row {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
      align-items: center;
    }
    label {
      font-size: 14px;
      color: #555;
      min-width: 90px;
    }
    select, input[type="text"] {
      flex: 1;
      min-width: 0;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid #ffd1a8;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s, background-color 0.2s;
      background-color: #fff;
    }
    select:focus, input[type="text"]:focus {
      border-color: #ff8a5c;
      box-shadow: 0 0 0 2px rgba(255,138,92,0.25);
    }
    .btn-row {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
    }
    button {
      border: none;
      border-radius: 8px;
      padding: 10px 18px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s, box-shadow 0.2s, transform 0.05s;
    }
    .btn-primary {
      background-color: #ff6b3d;
      color: #fff;
      flex: 1;
    }
    .btn-primary:hover {
      background-color: #ff5a26;
      box-shadow: 0 6px 16px rgba(255,91,37,0.35);
    }
    .btn-primary:active {
      transform: translateY(1px);
      box-shadow: 0 3px 8px rgba(255,91,37,0.3);
    }
    .btn-secondary {
      background-color: #ffe0c4;
      color: #aa5b2d;
      min-width: 70px;
    }
    .btn-secondary:hover {
      background-color: #ffd2aa;
    }
    .result-section {
      margin-top: 12px;
    }
    .result-title {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 6px;
      color: #444;
    }
    .result-box {
      background: #fff;
      border-radius: 10px;
      padding: 12px 12px;
      min-height: 80px;
      border: 1px solid #ffe0c4;
      font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 13px;
      white-space: pre-wrap;
      word-break: break-all;
      overflow-x: auto;
      background-image: linear-gradient(transparent 50%, rgba(255, 243, 230, 0.9) 50%);
      background-size: 100% 32px;
    }
    .footer {
      margin-top: 18px;
      font-size: 13px;
      color: #85501e;
      text-align: center;
      line-height: 1.6;
    }
    .footer a {
      color: #ff4f1a;
      text-decoration: none;
    }
    .footer a:hover {
      text-decoration: underline;
    }
    .small {
      font-size: 12px;
      color: #aa6b39;
    }
    @media (max-width: 600px) {
      .card {
        padding: 20px 16px 18px;
      }
      .title {
        font-size: 22px;
      }
      .form-row {
        flex-direction: column;
        align-items: stretch;
      }
      label {
        min-width: auto;
      }
      .btn-row {
        flex-direction: column;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="title">DNS-over-HTTPS Resolver</div>

      <div class="section-title">DNS 查询设置</div>

      <div class="form-row">
        <label for="dohSelect">选择 DoH 地址：</label>
        <select id="dohSelect">
          <option value="" id="currentDohOption">当前站点 DoH</option>
          <option value="https://${DoH}/dns-query">cloudflare-dns.com（官方）</option>
        </select>
      </div>

      <div class="form-row">
        <label for="domainInput">待解析域名：</label>
        <input type="text" id="domainInput" placeholder="例如：outlook.live.com" />
        <button class="btn-secondary" type="button" id="clearBtn">清除</button>
      </div>

      <div class="btn-row">
        <button class="btn-primary" type="button" id="resolveBtn">解析</button>
      </div>

      <div class="result-section">
        <div class="result-title">解析结果</div>
        <div id="resultBox" class="result-box"></div>
      </div>

      <div class="footer">
        <div>DNS-over-HTTPS：<a href="#" id="currentDohLink"></a></div>
        <div class="small">基于 Cloudflare Workers 上游 ${DoH} 的 DoH (DNS over HTTPS) 解析服务</div>
        <div class="small">DoH 路径：/<span id="pathSpan">${DoH路径}</span>　上游：<span id="upstreamSpan">${DoH}</span></div>
      </div>
    </div>
  </div>

  <script>
    (function () {
      var dohSelect = document.getElementById('dohSelect');
      var domainInput = document.getElementById('domainInput');
      var resultBox = document.getElementById('resultBox');
      var resolveBtn = document.getElementById('resolveBtn');
      var clearBtn = document.getElementById('clearBtn');
      var currentDohOption = document.getElementById('currentDohOption');
      var currentDohLink = document.getElementById('currentDohLink');

      function init() {
        try {
          var currentOrigin = window.location.origin;
          var dohPath = '/${DoH路径}';
          var currentUrl = currentOrigin + dohPath;
          currentDohOption.value = currentUrl;
          currentDohOption.textContent = currentUrl + '（当前站点）';
          currentDohLink.textContent = currentUrl;
          currentDohLink.href = currentUrl;
          dohSelect.value = currentUrl;
        } catch (e) {
          // ignore
        }
      }

      function formatError(message) {
        return '错误：' + message;
      }

      async function doResolve() {
        var domain = (domainInput.value || '').trim();
        if (!domain) {
          resultBox.textContent = formatError('请输入要解析的域名');
          return;
        }
        var doh = dohSelect.value;
        if (!doh) {
          resultBox.textContent = formatError('请选择 DoH 地址');
          return;
        }
        resultBox.textContent = '正在查询 ' + domain + ' ...';
        try {
          var url = doh + '?name=' + encodeURIComponent(domain) + '&type=A';
          var res = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
          if (!res.ok) {
            var text = await res.text();
            throw new Error('HTTP ' + res.status + ': ' + text.slice(0, 200));
          }
          var data = await res.json();
          resultBox.textContent = JSON.stringify(data, null, 2);
        } catch (err) {
          resultBox.textContent = formatError(err.message || String(err));
        }
      }

      resolveBtn.addEventListener('click', doResolve);
      clearBtn.addEventListener('click', function () {
        domainInput.value = '';
        resultBox.textContent = '';
        domainInput.focus();
      });
      domainInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          doResolve();
        }
      });

      init();
    })();
  </script>
</body>
</html>`;
  return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8" } });
}

async function 代理URL(代理网址, 目标网址) {
  const 网址列表 = await 整理(代理网址);
  const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];
  const 解析后的网址 = new URL(完整网址);
  const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
  const 主机名 = 解析后的网址.hostname;
  let 路径名 = 解析后的网址.pathname;
  const 查询参数 = 解析后的网址.search;
  if (路径名.charAt(路径名.length - 1) == '/') 路径名 = 路径名.slice(0, -1);
  路径名 += 目标网址.pathname;
  const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;
  const 响应 = await fetch(新网址);
  const 新响应 = new Response(响应.body, { status: 响应.status, statusText: 响应.statusText, headers: 响应.headers });
  新响应.headers.set('X-New-URL', 新网址);
  return 新响应;
}

async function 整理(内容) {
  var 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
  if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
  if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
  return 替换后的内容.split(',');
}

async function nginx() {
  return `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>`;
}
