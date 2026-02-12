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
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS-over-HTTPS Resolver</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <style>
    body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;min-height:100vh;margin:0;padding:30px 20px;box-sizing:border-box;
      background:url('https://cf-assets.www.cloudflare.com/dzlvafdwdttg/5B5shLB8bSKIyB9NJ6R1jz/87e7617be2c61603d46003cb3f1bd382/Hero-globe-bg-takeover-xxl.png'),linear-gradient(135deg,rgba(253,101,60,.85) 0%,rgba(251,152,30,.85) 100%);
      background-size:cover;background-position:center;background-attachment:fixed;}
    .page-wrapper{max-width:800px;margin:0 auto;}
    .container{max-width:800px;margin:20px auto;background:rgba(255,255,255,.65);border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.15);padding:30px;backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,.4);}
    h1{background-image:linear-gradient(to right,rgb(249,171,76),rgb(252,103,60));color:rgb(252,103,60);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;font-weight:600;}
    .card{margin-bottom:20px;border:none;box-shadow:0 2px 10px rgba(0,0,0,.05);background:rgba(255,255,255,.8);backdrop-filter:blur(5px);}
    .card-header{background:rgba(255,242,235,.9);font-weight:600;padding:12px 20px;border-bottom:none;}
    .form-select,.form-control{border-radius:6px;padding:10px;border:1px solid rgba(253,101,60,.3);background:rgba(255,255,255,.9);}
    .btn-primary{background:rgb(253,101,60);border:none;border-radius:6px;padding:10px 20px;font-weight:500;}
    .btn-primary:hover{background:rgb(230,90,50);transform:translateY(-1px);}
    pre{background:rgba(255,245,240,.9);padding:15px;border-radius:6px;border:1px solid rgba(253,101,60,.2);white-space:pre-wrap;word-break:break-all;font-size:14px;max-height:400px;overflow:auto;}
    .loading{display:none;text-align:center;padding:20px 0;}
    .loading-spinner{border:4px solid rgba(0,0,0,.1);border-left:4px solid rgb(253,101,60);border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:0 auto 10px;}
    @keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}
    .nav-tabs .nav-link{border-radius:6px 6px 0 0;padding:8px 16px;font-weight:500;color:rgb(150,80,50);}
    .nav-tabs .nav-link.active{background:rgba(255,245,240,.8);border-bottom-color:rgba(255,245,240,.8);color:rgb(253,101,60);}
    .tab-content{background:rgba(255,245,240,.8);border-radius:0 0 6px 6px;padding:15px;border:1px solid rgba(253,101,60,.2);border-top:none;}
    .ip-record{padding:5px 10px;margin-bottom:5px;border-radius:4px;background:rgba(255,255,255,.9);border:1px solid rgba(253,101,60,.15);}
    .ip-address{font-family:monospace;font-weight:600;cursor:pointer;color:rgb(80,60,50);}
    .ip-address:hover{color:rgb(253,101,60);}
    .ip-address.copied:after{content:' ✓ 已复制';font-size:12px;color:rgb(253,101,60);}
    .beian-info{text-align:center;font-size:13px;margin-top:20px;}
    .beian-info a{color:rgb(253,101,60);text-decoration:none;border-bottom:1px dashed rgb(253,101,60);}
    .copy-link{cursor:pointer;}
    .copy-link.copied:after{content:' ✓ 已复制';font-size:12px;color:rgb(253,101,60);}
    .github-corner svg{fill:#fff;color:rgb(251,152,30);position:absolute;top:0;right:0;border:0;width:80px;height:80px;}
  </style>
</head>
<body>
  <a href="https://github.com/danxiaonuo" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
  </a>
  <div class="container">
    <h1 class="text-center mb-4">DNS-over-HTTPS Resolver</h1>
    <div class="card">
      <div class="card-header">DNS 查询设置</div>
      <div class="card-body">
        <form id="resolveForm">
          <div class="mb-3">
            <label for="dohSelect" class="form-label">选择 DoH 地址:</label>
            <select id="dohSelect" class="form-select">
              <option value="current" selected id="currentDohOption">自动 (当前站点)</option>
              <option value="https://dns.alidns.com/resolve">https://dns.alidns.com/resolve (阿里)</option>
              <option value="https://doh.pub/dns-query">https://doh.pub/dns-query (腾讯)</option>
              <option value="https://doh.360.cn/resolve">https://doh.360.cn/resolve (360)</option>
              <option value="https://cloudflare-dns.com/dns-query">https://cloudflare-dns.com/dns-query (Cloudflare)</option>
              <option value="https://dns.google/resolve">https://dns.google/resolve (谷歌)</option>
              <option value="https://dns.adguard-dns.com/resolve">https://dns.adguard-dns.com/resolve (AdGuard)</option>
              <option value="https://dns.sb/dns-query">https://dns.sb/dns-query (DNS.SB)</option>
              <option value="https://dns.twnic.tw/dns-query">https://dns.twnic.tw/dns-query (Quad101 TWNIC)</option>
              <option value="custom">自定义...</option>
            </select>
          </div>
          <div id="customDohContainer" class="mb-3" style="display:none;">
            <label for="customDoh" class="form-label">输入自定义 DoH 地址:</label>
            <input type="text" id="customDoh" class="form-control" placeholder="https://example.com/dns-query">
          </div>
          <div class="mb-3">
            <label for="domain" class="form-label">待解析域名:</label>
            <div class="input-group">
              <input type="text" id="domain" class="form-control" placeholder="输入域名,如 example.com">
              <button type="button" class="btn btn-outline-secondary" id="clearBtn">清除</button>
            </div>
          </div>
          <div class="d-grid">
            <button type="submit" class="btn btn-primary">解析</button>
          </div>
        </form>
      </div>
    </div>
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>解析结果</span>
        <button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display:none;">复制结果</button>
      </div>
      <div class="card-body">
        <div id="loading" class="loading">
          <div class="loading-spinner"></div>
          <p>正在查询中，请稍候...</p>
        </div>
        <div id="resultContainer" style="display:none;">
          <ul class="nav nav-tabs result-tabs" id="resultTabs" role="tablist">
            <li class="nav-item" role="presentation"><button class="nav-link active" id="ipv4-tab" data-bs-toggle="tab" data-bs-target="#ipv4" type="button" role="tab">IPv4 地址</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" id="ipv6-tab" data-bs-toggle="tab" data-bs-target="#ipv6" type="button" role="tab">IPv6 地址</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" id="ns-tab" data-bs-toggle="tab" data-bs-target="#ns" type="button" role="tab">NS 记录</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button" role="tab">原始数据</button></li>
          </ul>
          <div class="tab-content" id="resultTabContent">
            <div class="tab-pane fade show active" id="ipv4" role="tabpanel"><div class="result-summary" id="ipv4Summary"></div><div id="ipv4Records"></div></div>
            <div class="tab-pane fade" id="ipv6" role="tabpanel"><div class="result-summary" id="ipv6Summary"></div><div id="ipv6Records"></div></div>
            <div class="tab-pane fade" id="ns" role="tabpanel"><div class="result-summary" id="nsSummary"></div><div id="nsRecords"></div></div>
            <div class="tab-pane fade" id="raw" role="tabpanel"><pre id="result">等待查询...</pre></div>
          </div>
        </div>
        <div id="errorContainer" style="display:none;"><pre id="errorMessage" class="error-message"></pre></div>
      </div>
    </div>
    <div class="beian-info">
      <p><strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="点击复制">https://<span id="currentDomain">...</span>/${DoH路径}</span></strong><br>基于 Cloudflare Workers 上游 ${DoH} 的 DoH (DNS over HTTPS) 解析服务</p>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    var currentHost = window.location.host;
    var currentProtocol = window.location.protocol;
    var currentDohPath = '${DoH路径}';
    var currentDohUrl = currentProtocol + '//' + currentHost + '/' + currentDohPath;

    document.getElementById('dohSelect').addEventListener('change', function() {
      document.getElementById('customDohContainer').style.display = (this.value === 'custom') ? 'block' : 'none';
    });
    document.getElementById('clearBtn').addEventListener('click', function() {
      document.getElementById('domain').value = '';
      document.getElementById('domain').focus();
    });
    document.getElementById('copyBtn').addEventListener('click', function() {
      var t = document.getElementById('result').textContent;
      navigator.clipboard.writeText(t).then(function() {
        var btn = document.getElementById('copyBtn');
        btn.textContent = '已复制';
        setTimeout(function(){ btn.textContent = '复制结果'; }, 2000);
      });
    });

    function formatTTL(s) {
      var t = parseInt(s, 10);
      if (isNaN(t)) return s;
      if (t < 60) return t + '秒';
      if (t < 3600) return Math.floor(t / 60) + '分钟';
      if (t < 86400) return Math.floor(t / 3600) + '小时';
      return Math.floor(t / 86400) + '天';
    }

    async function queryIpGeoInfo(ip) {
      try {
        var r = await fetch('./ip-info?ip=' + encodeURIComponent(ip) + '&token=' + encodeURIComponent(currentDohPath));
        if (!r.ok) return null;
        return await r.json();
      } catch (e) { return null; }
    }

    function handleCopyClick(el, text) {
      navigator.clipboard.writeText(text).then(function() {
        el.classList.add('copied');
        setTimeout(function() { el.classList.remove('copied'); }, 2000);
      });
    }

    function displayRecords(data) {
      document.getElementById('resultContainer').style.display = 'block';
      document.getElementById('errorContainer').style.display = 'none';
      document.getElementById('result').textContent = JSON.stringify(data, null, 2);
      document.getElementById('copyBtn').style.display = 'block';

      var ipv4Records = data.ipv4 && data.ipv4.records ? data.ipv4.records : [];
      var el4 = document.getElementById('ipv4Records');
      var sum4 = document.getElementById('ipv4Summary');
      el4.innerHTML = '';
      sum4.innerHTML = ipv4Records.length ? '<strong>找到 ' + ipv4Records.length + ' 条 IPv4 记录</strong>' : '<strong>未找到 IPv4 记录</strong>';
      ipv4Records.forEach(function(r) {
        var d = document.createElement('div');
        d.className = 'ip-record';
        if (r.type === 5) {
          d.innerHTML = '<span class="ip-address" data-copy="' + (r.data||'') + '">' + (r.data||'') + '</span> <span class="badge bg-success">CNAME</span> TTL: ' + formatTTL(r.TTL);
        } else {
          d.innerHTML = '<span class="ip-address" data-copy="' + (r.data||'') + '">' + (r.data||'') + '</span> TTL: ' + formatTTL(r.TTL);
        }
        var span = d.querySelector('.ip-address');
        if (span) span.addEventListener('click', function() { handleCopyClick(this, this.getAttribute('data-copy')); });
        el4.appendChild(d);
      });

      var ipv6Records = data.ipv6 && data.ipv6.records ? data.ipv6.records : [];
      var el6 = document.getElementById('ipv6Records');
      var sum6 = document.getElementById('ipv6Summary');
      el6.innerHTML = '';
      sum6.innerHTML = ipv6Records.length ? '<strong>找到 ' + ipv6Records.length + ' 条 IPv6 记录</strong>' : '<strong>未找到 IPv6 记录</strong>';
      ipv6Records.forEach(function(r) {
        var d = document.createElement('div');
        d.className = 'ip-record';
        d.innerHTML = '<span class="ip-address" data-copy="' + (r.data||'') + '">' + (r.data||'') + '</span> TTL: ' + formatTTL(r.TTL);
        var span = d.querySelector('.ip-address');
        if (span) span.addEventListener('click', function() { handleCopyClick(this, this.getAttribute('data-copy')); });
        el6.appendChild(d);
      });

      var nsRecords = data.ns && data.ns.records ? data.ns.records : [];
      var elNs = document.getElementById('nsRecords');
      var sumNs = document.getElementById('nsSummary');
      elNs.innerHTML = '';
      sumNs.innerHTML = nsRecords.length ? '<strong>找到 ' + nsRecords.length + ' 条 NS 记录</strong>' : '<strong>未找到 NS 记录</strong>';
      nsRecords.forEach(function(r) {
        var d = document.createElement('div');
        d.className = 'ip-record';
        if (r.type === 6) {
          var parts = (r.data||'').split(' ');
          var admin = (parts[1]||'').replace('.', '@');
          if (admin.endsWith('.')) admin = admin.slice(0, -1);
          d.innerHTML = '<strong>SOA</strong> ' + (r.name||'') + ' TTL: ' + formatTTL(r.TTL) + '<br><small>主NS: ' + (parts[0]||'') + ' 管理邮箱: ' + admin + '</small>';
        } else {
          d.innerHTML = '<span class="ip-address" data-copy="' + (r.data||'') + '">' + (r.data||'') + '</span> <span class="badge bg-info">NS</span> TTL: ' + formatTTL(r.TTL);
          var span = d.querySelector('.ip-address');
          if (span) span.addEventListener('click', function() { handleCopyClick(this, this.getAttribute('data-copy')); });
        }
        elNs.appendChild(d);
      });
    }

    function displayError(msg) {
      document.getElementById('resultContainer').style.display = 'none';
      document.getElementById('errorContainer').style.display = 'block';
      document.getElementById('errorMessage').textContent = msg;
      document.getElementById('copyBtn').style.display = 'none';
    }

    document.getElementById('resolveForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      var dohVal = document.getElementById('dohSelect').value;
      var doh = dohVal === 'current' ? currentDohUrl : (dohVal === 'custom' ? document.getElementById('customDoh').value : dohVal);
      if (dohVal === 'custom' && !doh) { alert('请输入自定义 DoH 地址'); return; }
      var domain = document.getElementById('domain').value;
      if (!domain) { alert('请输入需要解析的域名'); return; }
      document.getElementById('loading').style.display = 'block';
      document.getElementById('resultContainer').style.display = 'none';
      document.getElementById('errorContainer').style.display = 'none';
      try {
        var url = '?doh=' + encodeURIComponent(doh) + '&domain=' + encodeURIComponent(domain) + '&type=all';
        var res = await fetch(url);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        var json = await res.json();
        if (json.error) displayError(json.error);
        else displayRecords(json);
      } catch (err) {
        displayError('查询失败: ' + (err.message || String(err)));
      } finally {
        document.getElementById('loading').style.display = 'none';
      }
    });

    document.addEventListener('DOMContentLoaded', function() {
      var lastDomain = localStorage.getItem('lastDomain');
      if (lastDomain) document.getElementById('domain').value = lastDomain;
      document.getElementById('domain').addEventListener('input', function() { localStorage.setItem('lastDomain', this.value); });
      document.getElementById('currentDomain').textContent = currentHost;
      document.getElementById('currentDohOption').textContent = currentDohUrl + ' (当前站点)';
      document.getElementById('dohUrlDisplay').addEventListener('click', function() {
        navigator.clipboard.writeText(currentProtocol + '//' + currentHost + '/' + currentDohPath).then(function() {
          document.getElementById('dohUrlDisplay').classList.add('copied');
          setTimeout(function() { document.getElementById('dohUrlDisplay').classList.remove('copied'); }, 2000);
        });
      });
    });
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
