#!/usr/bin/env node
/**
 * docs site builder for pxgo
 *
 * Pure Node.js — zero external dependencies.
 * Reads docs/*.md → outputs a polished static site to dist/docs-site/
 *
 * Features: sidebar nav, sticky ToC, dark/light toggle, syntax highlighting,
 * copy buttons, hero on index page, llms.txt, .nojekyll, CNAME support.
 */

import {
  readFileSync, writeFileSync, mkdirSync, existsSync,
} from "fs";
import { join, basename } from "path";

// ── Config ────────────────────────────────────────────────────────────────────

const TOOL      = "pxgo";
const REPO_URL  = "https://github.com/pavelsimo/pxgo";
const DESC      = "single-binary HTTP/HTTPS proxy for NTLM and Kerberos corporate networks";
const HERO_COPY = "Run a local proxy that lets browsers, package managers, CLIs, and build tools authenticate cleanly through enterprise upstream proxies.";
const INSTALL_CMD = "make build && ./bin/pxgo";
const SITE_BASE = existsSync("docs/CNAME")
  ? `https://${readFileSync("docs/CNAME","utf8").trim()}`
  : `https://pavelsimo.github.io/pxgo`;

const SRC = "docs";
const OUT = join("dist", "docs-site");
mkdirSync(OUT, { recursive: true });

// ── Markdown parser ───────────────────────────────────────────────────────────

function esc(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function stash(s, buf) { const k=`\x00${buf.length}\x00`; buf.push(s); return k; }
function unstash(s, buf) { return s.replace(/\x00(\d+)\x00/g,(_,i)=>buf[+i]); }

// ── Syntax highlighting ───────────────────────────────────────────────────────

function hlBash(code) {
  const b=[]; let s=esc(code);
  s=s.replace(/"(?:[^"\\]|\\.)*"/g, m=>stash(`<span class=hs>${m}</span>`,b));
  s=s.replace(/'[^']*'/g,           m=>stash(`<span class=hs>${m}</span>`,b));
  s=s.replace(/(#.*)$/gm,           m=>stash(`<span class=hc>${m}</span>`,b));
  s=s.replace(/(--?[\w-]+=?\S*)/g,  m=>stash(`<span class=hf>${m}</span>`,b));
  s=s.replace(/^(\s*)(\$\s+)?(\w[\w.-]*)/gm,
    (_,sp,pr,cmd)=>`${sp}${pr||""}<span class=hk>${cmd}</span>`);
  return unstash(s,b);
}

function hlGo(code) {
  const kw=/\b(package|import|func|type|struct|interface|var|const|return|if|else|for|range|switch|case|default|break|continue|go|defer|select|chan|map|make|new|nil|true|false|error|string|int|bool|byte|rune|any)\b/g;
  const b=[]; let s=esc(code);
  s=s.replace(/("(?:[^"\\]|\\.)*"|`[^`]*`)/g, m=>stash(`<span class=hs>${m}</span>`,b));
  s=s.replace(/(\/\/.*)$/gm,                   m=>stash(`<span class=hc>${m}</span>`,b));
  s=s.replace(kw,                               m=>`<span class=hk>${m}</span>`);
  s=s.replace(/\b(\d+)\b/g,                     `<span class=hn>$1</span>`);
  return unstash(s,b);
}

function hlYaml(code) {
  const b=[]; let s=esc(code);
  s=s.replace(/(#.*)$/gm,   m=>stash(`<span class=hc>${m}</span>`,b));
  s=s.replace(/^(\s*)([\w-]+)(\s*:)/gm,
    (_,sp,k,col)=>`${sp}<span class=hk>${k}</span>${col}`);
  s=s.replace(/:\s*(.+)$/gm,
    (m,v)=>m.replace(v,`<span class=hs>${v}</span>`));
  return unstash(s,b);
}

function hlIni(code) {
  const b=[]; let s=esc(code);
  s=s.replace(/(;.*)$/gm,  m=>stash(`<span class=hc>${m}</span>`,b));
  s=s.replace(/(#.*)$/gm,  m=>stash(`<span class=hc>${m}</span>`,b));
  s=s.replace(/^\[([^\]]+)\]/gm, (_,sec)=>`[<span class=hk>${sec}</span>]`);
  s=s.replace(/^([\w-]+)(\s*=)/gm, (_,k,eq)=>`<span class=hf>${k}</span>${eq}`);
  return unstash(s,b);
}

function hlJson(code) {
  const b=[]; let s=esc(code);
  s=s.replace(/"(?:[^"\\]|\\.)*"/g, m=>stash(`<span class=hs>${m}</span>`,b));
  s=s.replace(/\b(true|false|null)\b/g, `<span class=hk>$1</span>`);
  s=s.replace(/\b(\d+\.?\d*)\b/g,       `<span class=hn>$1</span>`);
  return unstash(s,b);
}

function highlight(lang, code) {
  if (lang==="bash"||lang==="sh"||lang==="zsh") return hlBash(code);
  if (lang==="go")   return hlGo(code);
  if (lang==="yaml"||lang==="yml") return hlYaml(code);
  if (lang==="ini"||lang==="toml") return hlIni(code);
  if (lang==="json") return hlJson(code);
  return esc(code);
}

// ── Inline Markdown ───────────────────────────────────────────────────────────

function inline(text, buf) {
  text=text.replace(/`([^`]+)`/g,
    (_,c)=>stash(`<code>${esc(c)}</code>`,buf));
  text=text.replace(/\*\*\*(.+?)\*\*\*/g,"<strong><em>$1</em></strong>");
  text=text.replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>");
  text=text.replace(/\*(.+?)\*/g,"<em>$1</em>");
  text=text.replace(/\[([^\]]+)\]\(([^)]+)\)/g,(_,label,href)=>{
    const ext=href.startsWith("http")?` target="_blank" rel="noopener"`:"";
    return stash(`<a href="${href}"${ext}>${label}</a>`,buf);
  });
  return text;
}

// ── Markdown → HTML ───────────────────────────────────────────────────────────

function slugify(t) {
  return t.toLowerCase().replace(/[^\w\s-]/g,"").trim().replace(/\s+/g,"-");
}

function parse(src) {
  const lines = src.split("\n");
  const buf=[], toc=[], out=[];
  let i=0, inPara=false, inUl=false, inOl=false, inFence=false;
  let fLang="", fLines=[];

  if (lines[0]==="---") {
    i=1; while(i<lines.length&&lines[i]!=="---") i++; i++;
  }

  function flushPara()  { if(inPara){out.push("</p>");inPara=false;} }
  function flushUl()    { if(inUl){out.push("</ul>");inUl=false;} }
  function flushOl()    { if(inOl){out.push("</ol>");inOl=false;} }
  function flushBlock() { flushPara();flushUl();flushOl(); }

  for(;i<lines.length;i++) {
    const line=lines[i];

    if(line.startsWith("```")) {
      if(!inFence) {
        flushBlock();
        inFence=true; fLang=line.slice(3).trim(); fLines=[];
      } else {
        const body=highlight(fLang,fLines.join("\n"));
        out.push(`<div class="code-wrap"><pre><code>${body}</code></pre>`+
          `<button class="copy-btn">Copy</button></div>`);
        inFence=false; fLines=[];
      }
      continue;
    }
    if(inFence){fLines.push(line);continue;}

    const hm=line.match(/^(#{1,4})\s+(.*)/);
    if(hm) {
      flushBlock();
      const lvl=hm[1].length, rawText=hm[2];
      const id=slugify(rawText);
      const text=unstash(inline(rawText,buf),buf);
      if(lvl<=3) toc.push({level:lvl,id,text:rawText});
      out.push(`<h${lvl} id="${id}"><a class="anchor" href="#${id}">#</a>${text}</h${lvl}>`);
      continue;
    }

    if(line.startsWith(">")) {
      flushBlock();
      const text=unstash(inline(line.slice(1).trim(),buf),buf);
      out.push(`<blockquote><p>${text}</p></blockquote>`);
      continue;
    }

    if(line.match(/^-{3,}$/)){flushBlock();out.push("<hr>");continue;}

    if(line.startsWith("|")) {
      flushBlock();
      const rows=[line];
      while(i+1<lines.length&&lines[i+1].startsWith("|")) rows.push(lines[++i]);
      out.push('<table>');
      rows.forEach((row,ri)=>{
        if(row.match(/^\|[-| :]+\|$/)) return;
        const cells=row.split("|").slice(1,-1);
        const tag=ri===0?"th":"td";
        out.push("<tr>"+cells.map(c=>`<${tag}>${unstash(inline(c.trim(),buf),buf)}</${tag}>`).join("")+"</tr>");
      });
      out.push("</table>");
      continue;
    }

    if(line.match(/^[-*]\s/)) {
      flushPara(); flushOl();
      if(!inUl){out.push("<ul>");inUl=true;}
      out.push(`<li>${unstash(inline(line.replace(/^[-*]\s/,""),buf),buf)}</li>`);
      continue;
    }

    if(line.match(/^\d+\.\s/)) {
      flushPara(); flushUl();
      if(!inOl){out.push("<ol>");inOl=true;}
      out.push(`<li>${unstash(inline(line.replace(/^\d+\.\s/,""),buf),buf)}</li>`);
      continue;
    }

    if(line.trim()===""){flushBlock();continue;}
    if(line.match(/^\[[^\]]+\]:\s+\S+/)){flushBlock();continue;}

    flushUl();flushOl();
    if(!inPara){out.push("<p>");inPara=true;} else out.push(" ");
    out.push(unstash(inline(line,buf),buf));
  }
  flushBlock();
  return {html:out.join("\n"),toc};
}

// ── Page structure ────────────────────────────────────────────────────────────

function tocHtml(toc) {
  if(toc.length<2) return "";
  const items=toc.map(({id,text,level})=>
    `<li class="toc-${level}"><a href="#${id}">${esc(text)}</a></li>`
  ).join("\n");
  return `<nav class="toc" aria-label="On this page">
  <p class="toc-title">On this page</p>
  <ul>${items}</ul>
</nav>`;
}

function sidebarHtml(pages, currentSlug) {
  const slugSection = {};
  for (const [sectionLabel, files] of sections) {
    for (const f of files) slugSection[basename(f, ".md")] = sectionLabel;
  }

  let items = "", lastSection = null;
  for (const { slug, label } of pages) {
    const sec = slugSection[slug];
    if (sec !== lastSection) {
      items += `<li class="nav-group" data-nav-group><h2>${esc(sec)}</h2></li>\n`;
      lastSection = sec;
    }
    const active = slug === currentSlug ? ' class="active"' : "";
    items += `<li data-nav-item><a href="${slug}.html"${active} data-search-text="${esc(`${label} ${sec} ${PAGE_KEYWORDS[slug] || ""}`)}">${esc(label)}</a></li>\n`;
  }

  return `<aside class="sidebar" id="sidebar" aria-label="Site navigation">
  <div class="sidebar-head">
    <a href="index.html" class="brand-link" aria-label="pxgo docs home">
      <span class="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 64 64" role="img">
          <defs>
            <linearGradient id="markA" x1="10" x2="54" y1="8" y2="56">
              <stop offset="0" stop-color="#ff8a6d"/>
              <stop offset=".55" stop-color="#ff6b4a"/>
              <stop offset="1" stop-color="#d9482e"/>
            </linearGradient>
            <linearGradient id="markB" x1="54" x2="10" y1="10" y2="58">
              <stop offset="0" stop-color="#47c2b1"/>
              <stop offset="1" stop-color="#1f8f83"/>
            </linearGradient>
          </defs>
          <rect x="8" y="9" width="48" height="46" rx="14" fill="url(#markA)"/>
          <path d="M18 24h18c5.5 0 10 4.5 10 10s-4.5 10-10 10H18v-7h18a3 3 0 0 0 0-6H18z" fill="#fff" opacity=".94"/>
          <path d="M46 19l8 8-8 8v-6H29v-4h17z" fill="url(#markB)"/>
          <path d="M18 45l-8-8 8-8v6h17v4H18z" fill="url(#markB)"/>
        </svg>
      </span>
      <span>
        <strong>${TOOL}</strong>
        <small>authenticated proxy</small>
      </span>
    </a>
    <button class="theme-toggle" id="themeBtn" type="button" aria-label="Toggle dark mode" aria-pressed="true">
      <span class="theme-toggle-indicator">
        <svg class="theme-icon-moon" viewBox="0 0 20 20" aria-hidden="true">
          <path d="M14.6 12.1A6.5 6.5 0 0 1 7.4 2.7a6.5 6.5 0 1 0 7.2 9.4z" fill="currentColor"/>
        </svg>
        <svg class="theme-icon-sun" viewBox="0 0 20 20" aria-hidden="true">
          <circle cx="10" cy="10" r="3.4" fill="currentColor"/>
          <g stroke="currentColor" stroke-width="1.6" stroke-linecap="round">
            <line x1="10" y1="2" x2="10" y2="4"/><line x1="10" y1="16" x2="10" y2="18"/>
            <line x1="2" y1="10" x2="4" y2="10"/><line x1="16" y1="10" x2="18" y2="10"/>
            <line x1="4.2" y1="4.2" x2="5.6" y2="5.6"/><line x1="14.4" y1="14.4" x2="15.8" y2="15.8"/>
            <line x1="4.2" y1="15.8" x2="5.6" y2="14.4"/><line x1="14.4" y1="5.6" x2="15.8" y2="4.2"/>
          </g>
        </svg>
      </span>
    </button>
  </div>
  <label class="search">
    <span>Search</span>
    <input id="docSearch" type="search" placeholder="kerberos, pac, docker" autocomplete="off">
  </label>
  <ul class="sidebar-nav">${items}</ul>
  <div class="sidebar-footer">
    <a href="${REPO_URL}" target="_blank" rel="noopener" class="gh-link">
      <svg height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      GitHub
    </a>
  </div>
</aside>`;
}

function heroHtml() {
  return `<header class="home-hero">
  <p class="eyebrow">HTTP/HTTPS Proxy · NTLM · Kerberos</p>
  <h1>${TOOL}</h1>
  <p class="lede">${esc(HERO_COPY)}</p>
  <div class="home-cta">
    <a class="btn btn-primary" href="installation.html">Get started</a>
    <a class="btn btn-ghost" href="configuration.html">Configuration</a>
    <div class="home-install" aria-label="Build and run pxgo">
      <span class="prompt" aria-hidden="true">$</span>
      <code>${esc(INSTALL_CMD)}</code>
      <button class="install-copy" type="button" data-copy="${esc(INSTALL_CMD)}">Copy</button>
    </div>
  </div>
  <p class="muted">Go 1.24+ • local default 127.0.0.1:3128 • Docker-ready runtime</p>
</header>`;
}

function featureGridHtml() {
  const cards = [
    ["↔", "HTTP and CONNECT", "Proxies HTTP traffic and HTTPS tunnels through direct, manual, PAC, or system proxy routes."],
    ["🔐", "Enterprise auth", "Supports NTLM, Negotiate, Digest, Basic, Kerberos ticket refresh, and optional local client auth."],
    ["🧭", "PAC and bypass rules", "Loads local or remote PAC files and applies host, suffix, CIDR, range, and wildcard bypass rules."],
    ["🪟", "Windows startup", "Builds install and uninstall commands for Windows startup while keeping other platforms explicit."],
    ["📦", "Single Go binary", "Runs as a compact CLI, Docker image, or locally built executable with no Python runtime required."],
    ["✅", "Race-tested core", "Proxy state, Kerberos renewal, config parsing, PAC helpers, and bypass behavior have focused Go tests."],
  ];
  return `<section class="features-grid" aria-label="pxgo capabilities">
${cards.map(([icon,title,text]) => `  <article class="feature-card">
    <div class="feature-icon" aria-hidden="true">${icon}</div>
    <h3>${esc(title)}</h3>
    <p>${esc(text)}</p>
  </article>`).join("\n")}
</section>`;
}

// ── Full page HTML ────────────────────────────────────────────────────────────

function renderPage({slug, title, bodyHtml, toc, pages, isIndex}) {
  const sidebar  = sidebarHtml(pages, slug);
  const tocBlock = tocHtml(toc);
  const hero     = isIndex ? heroHtml() : "";
  const pageTitle= isIndex ? TOOL : `${title} — ${TOOL}`;

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${pageTitle}</title>
<meta name="description" content="${esc(DESC)}">
<meta property="og:type" content="website">
<meta property="og:title" content="${pageTitle}">
<meta property="og:description" content="${esc(DESC)}">
<meta property="og:url" content="${SITE_BASE}/${slug === "index" ? "" : slug + ".html"}">
<meta name="twitter:card" content="summary">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box}
:root{
  --sidebar-w:280px;
  --font-sans:"Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
  --font-mono:"JetBrains Mono","SF Mono",ui-monospace,monospace;
  --coral:#ff6b4a;--coral-dark:#df5034;--coral-light:#ff9a7d;
  --teal:#269d90;--teal-deep:#17786f;--teal-light:#47c2b1;
  --gold:#f4b24f;--shell:#fff4ed;
  --hl-keyword:#6bb6ff;--hl-string:#52b788;--hl-number:#ffb86c;
  --hl-comment:#7c8597;--hl-flag:#c084fc;
}
html[data-theme=light]{
  --bg:#fff9f4;--paper:#ffffff;--surface:#fff2e9;--surface2:#f7eadf;
  --line:#eaded4;--line-soft:#f5ece4;
  --ink:#0b1729;--text:#2c3c4e;--muted:#6c7888;--subtle:#98a2af;
  --accent:var(--coral);--accent-soft:rgba(255,107,74,.11);--accent-strong:var(--coral-dark);
  --secondary:var(--teal);--code-bg:#0f1d2f;--code-fg:#e6f1f5;--code-border:#1f2937;
  --shadow-card:0 4px 16px rgba(255,107,74,.12);--shadow-float:0 12px 32px rgba(38,157,144,.18);
}
html[data-theme=dark]{
  --bg:#0a1018;--paper:#141b28;--surface:#1a2333;--surface2:#151e2d;
  --line:#1f2937;--line-soft:#182234;
  --ink:#f3f5f9;--text:#cbd2dc;--muted:#8d96a4;--subtle:#5d6371;
  --accent:#ff8a6d;--accent-soft:rgba(255,138,109,.18);--accent-strong:#ffb4a2;
  --secondary:var(--teal-light);--code-bg:#050a12;--code-fg:#e6f1f5;--code-border:#1a2333;
  --shadow-card:0 6px 20px rgba(0,0,0,.42);--shadow-float:0 12px 32px rgba(0,0,0,.55);
}
html{scroll-behavior:smooth;scroll-padding-top:24px;font-size:16px}
body{
  margin:0;background:var(--bg);color:var(--text);
  font:1rem/1.65 var(--font-sans);min-height:100vh;overflow-x:hidden;
  -webkit-font-smoothing:antialiased;font-feature-settings:"cv02","cv03","cv04","cv11";
  transition:background-color .25s,color .25s;
}
::selection{background:var(--accent);color:#fff}
a{color:var(--accent);text-decoration:none;transition:color .15s}
a:hover{text-decoration:underline;text-underline-offset:.2em}
img{max-width:100%}
hr{border:0;border-top:1px solid var(--line);margin:2rem 0}
.shell{display:grid;grid-template-columns:var(--sidebar-w) minmax(0,1fr);min-height:100vh}
.sidebar{
  position:sticky;top:0;height:100vh;overflow:auto;padding:28px 24px;
  background:var(--paper);border-right:2px solid var(--line);
  scrollbar-width:thin;scrollbar-color:var(--line) transparent;
  transition:background-color .25s,border-color .25s;
}
.sidebar::-webkit-scrollbar{width:6px}.sidebar::-webkit-scrollbar-thumb{background:var(--line);border-radius:6px}
.sidebar-head{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.brand-link{display:flex;align-items:center;gap:12px;color:var(--ink);text-decoration:none;flex:1;min-width:0}
.brand-link:hover{text-decoration:none}.brand-mark{width:36px;height:36px;flex:0 0 36px}
.brand-mark svg{width:100%;height:100%;display:block;filter:drop-shadow(0 4px 10px rgba(255,107,74,.16));transition:transform .25s ease}
.brand-link:hover .brand-mark svg{transform:rotate(-4deg) scale(1.04)}
.brand-link strong{display:block;font-size:1.1rem;line-height:1.1;font-weight:700;color:var(--ink)}
.brand-link small{display:block;color:var(--muted);font-size:.75rem;margin-top:3px}
.theme-toggle{
  position:relative;display:inline-flex;align-items:center;justify-content:flex-start;
  flex:0 0 auto;width:64px;height:32px;border-radius:16px;border:0;
  background:linear-gradient(135deg,#ffd89b 0%,#ffb86c 100%);
  cursor:pointer;padding:3px;box-shadow:inset 0 2px 6px rgba(0,0,0,.15),0 2px 8px rgba(255,107,74,.2);
  transition:all .3s cubic-bezier(.4,0,.2,1);
}
.theme-toggle::before{
  content:"";position:absolute;inset:0;border-radius:16px;
  background:linear-gradient(135deg,transparent 0%,rgba(255,255,255,.22) 50%,transparent 100%),
    repeating-linear-gradient(90deg,transparent,transparent 3px,rgba(255,255,255,.12) 3px,rgba(255,255,255,.12) 6px);
  background-size:auto,12px 100%;animation:tide 3s linear infinite;pointer-events:none;
}
@keyframes tide{to{background-position:0 0,12px 0}}
html[data-theme=dark] .theme-toggle{background:linear-gradient(135deg,#1a3a52 0%,#2a4a62 100%);box-shadow:inset 0 2px 6px rgba(0,0,0,.4),0 2px 8px rgba(38,157,144,.24)}
.theme-toggle-indicator{
  position:absolute;left:3px;width:26px;height:26px;border-radius:50%;
  background:linear-gradient(135deg,var(--coral) 0%,var(--coral-dark) 100%);
  box-shadow:0 2px 4px rgba(0,0,0,.2),inset 0 1px 2px rgba(255,255,255,.3);
  display:flex;align-items:center;justify-content:center;color:#fff;transition:all .3s cubic-bezier(.4,0,.2,1);
}
html[data-theme=dark] .theme-toggle-indicator{left:35px;background:linear-gradient(135deg,var(--teal-light) 0%,var(--teal) 100%)}
.theme-toggle svg{width:14px;height:14px;display:block;filter:drop-shadow(0 1px 1px rgba(0,0,0,.3))}
.theme-icon-moon{display:block}.theme-icon-sun{display:none}
html[data-theme=dark] .theme-icon-moon{display:none}html[data-theme=dark] .theme-icon-sun{display:block}
.theme-toggle:hover .theme-toggle-indicator{transform:scale(1.08)}
.search{display:block;margin:0 0 24px}
.search span,.toc-title,.nav-group h2{
  display:block;color:var(--muted);font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
}
.search span{margin-bottom:8px}
.search input{
  width:100%;border:2px solid var(--line);background:var(--paper);border-radius:10px;
  padding:10px 14px;font:inherit;font-size:.9rem;color:var(--text);outline:0;
  transition:border-color .2s,box-shadow .2s,background-color .25s;
}
.search input:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft)}
.sidebar-nav{list-style:none;margin:0;padding:0;min-height:280px}
.nav-group h2{margin:22px 0 8px}.nav-group:first-child h2{margin-top:0}
.sidebar-nav a{
  display:block;color:var(--text);border-radius:8px;padding:7px 12px;margin:2px 0;
  font-size:.9rem;line-height:1.4;transition:background .15s,color .15s;
}
.sidebar-nav a:hover{background:var(--accent-soft);color:var(--accent);text-decoration:none}
.sidebar-nav a.active{background:var(--accent-soft);color:var(--accent);font-weight:700}
.sidebar-footer{margin-top:28px;padding-top:18px;border-top:1px solid var(--line)}
.gh-link{display:flex;align-items:center;gap:.45rem;color:var(--muted);font-size:.86rem}
.gh-link:hover{color:var(--text);text-decoration:none}
.body-col{min-width:0}.mob-bar{display:none}
.content-row{display:flex;min-width:0}.main{min-width:0;width:100%;max-width:1240px;margin:0 auto;padding:40px clamp(24px,5vw,64px) 96px}
.doc{min-width:0;max-width:76ch;overflow-wrap:break-word}
.toc{
  width:220px;flex:0 0 220px;position:sticky;top:0;height:100vh;overflow:auto;
  padding:40px 24px 32px 14px;border-left:1px solid var(--line);font-size:.84rem;
}
.toc-title{margin:0 0 .75rem}.toc ul{list-style:none;margin:0;padding:0}
.toc a{
  display:block;padding:4px 0 4px 10px;border-left:2px solid transparent;margin-left:-12px;
  color:var(--muted);transition:color .12s,border-color .12s;
}
.toc a:hover,.toc a.active{color:var(--accent);border-left-color:var(--accent);text-decoration:none}
.toc-3 a{padding-left:22px;font-size:.8rem}
.home-hero{
  position:relative;padding:24px 0 40px;margin-bottom:12px;border-bottom:2px solid var(--line);
  overflow:hidden;
}
.home-hero::before{
  content:"";position:absolute;top:-58%;right:-24%;width:62%;height:210%;
  background:radial-gradient(circle,var(--accent-soft) 0%,transparent 68%);
  opacity:.62;pointer-events:none;animation:floatGlow 18s ease-in-out infinite;
}
@keyframes floatGlow{50%{transform:translateY(-20px) rotate(4deg)}}
.eyebrow{margin:0 0 10px;color:var(--secondary);font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em}
.home-hero h1{
  margin:0 0 .35em;font-size:clamp(2.5rem,7vw,4.5rem);line-height:1.02;font-weight:800;
  color:var(--ink);background:linear-gradient(135deg,var(--coral) 0%,var(--teal) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
}
.lede{font-size:1.22rem;line-height:1.6;color:var(--text);margin:0 0 1.4em;max-width:66ch}
.home-cta{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:0 0 24px}
.btn{
  display:inline-flex;align-items:center;gap:8px;border-radius:10px;padding:12px 20px;
  font-weight:700;font-size:.95rem;text-decoration:none;transition:all .2s;box-shadow:var(--shadow-card);
}
.btn-primary{background:linear-gradient(135deg,var(--coral) 0%,var(--coral-dark) 100%);color:#fff;border:2px solid var(--coral)}
.btn-primary:hover{background:var(--coral-dark);transform:translateY(-2px);box-shadow:var(--shadow-float);text-decoration:none}
.btn-ghost{background:var(--paper);color:var(--text);border:2px solid var(--line)}
.btn-ghost:hover{border-color:var(--secondary);color:var(--secondary);text-decoration:none}
.home-install{
  display:flex;align-items:center;gap:12px;background:var(--code-bg);color:var(--code-fg);
  border-radius:10px;padding:10px 10px 10px 16px;border:2px solid var(--code-border);
  box-shadow:var(--shadow-card);font:500 .9rem/1.3 var(--font-mono);max-width:min(100%,38rem);
}
.home-install .prompt{color:var(--hl-comment);user-select:none;flex:0 0 auto}
.home-install code{background:transparent;border:0;color:var(--code-fg);font:inherit;padding:0;white-space:pre;overflow:hidden;text-overflow:ellipsis}
.install-copy{
  border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.08);color:#d9e2ec;
  border-radius:7px;padding:6px 10px;font:700 .72rem/1 var(--font-sans);cursor:pointer;
}
.install-copy:hover{background:rgba(255,255,255,.16)}
.muted{color:var(--muted);font-size:.92rem}
.features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px;margin:28px 0 34px}
.feature-card{
  background:var(--paper);border:2px solid var(--line);border-radius:12px;padding:24px;
  transition:all .22s;box-shadow:var(--shadow-card);
}
.feature-card:hover{border-color:var(--accent);transform:translateY(-4px);box-shadow:var(--shadow-float)}
.feature-icon{
  width:48px;height:48px;background:var(--accent-soft);border-radius:10px;display:flex;
  align-items:center;justify-content:center;margin-bottom:16px;font-size:1.4rem;color:var(--accent);
}
.feature-card h3{font-size:1.1rem;margin:0 0 8px;color:var(--ink);font-weight:700}
.feature-card p{margin:0;color:var(--muted);font-size:.92rem;line-height:1.5}
.main h1{font-size:2.5rem;font-weight:800;line-height:1.08;color:var(--ink);margin:0 0 1rem;position:relative}
.main h2{font-size:1.6rem;line-height:1.2;margin:2.2em 0 .65em;font-weight:800;color:var(--ink);scroll-margin-top:24px;position:relative}
.main h3{font-size:1.2rem;margin:1.8em 0 .45em;font-weight:700;color:var(--ink);scroll-margin-top:24px;position:relative}
.main h4{font-size:1rem;margin:1.5em 0 .45em;font-weight:700;color:var(--muted);scroll-margin-top:24px}
.main p{margin:0 0 1.15em;line-height:1.7}.main ul,.main ol{padding-left:1.4rem;margin:0 0 1.2em}.main li{margin:.3em 0;line-height:1.7}
.main blockquote{border-left:4px solid var(--accent);background:var(--accent-soft);padding:12px 16px;border-radius:0 10px 10px 0;margin:1.5em 0}
.anchor{position:absolute;right:100%;padding-right:.45rem;opacity:0;font-size:.8em;color:var(--muted);text-decoration:none}.main h1:hover .anchor,.main h2:hover .anchor,.main h3:hover .anchor{opacity:1}
code{
  font-family:var(--font-mono);font-size:.87em;background:var(--accent-soft);border:1px solid var(--line);
  border-radius:6px;padding:.1em .4em;color:var(--accent-strong);font-weight:500;
}
html[data-theme=dark] code{color:#ffb4a2}
.code-wrap{position:relative;margin:1.5em 0}
pre{
  overflow:auto;background:var(--code-bg);color:var(--code-fg);border-radius:10px;
  padding:18px 20px;margin:0;font:400 .88rem/1.65 var(--font-mono);
  border:2px solid var(--code-border);box-shadow:var(--shadow-card);scrollbar-width:thin;scrollbar-color:#334155 transparent;
}
pre code{display:block;background:transparent;border:0;color:inherit;padding:0;font:inherit;white-space:pre}
.copy-btn{
  position:absolute;top:.65rem;right:.65rem;background:rgba(255,255,255,.08);
  border:1px solid rgba(255,255,255,.16);color:#d9e2ec;border-radius:7px;
  padding:6px 10px;font:700 .72rem/1 var(--font-sans);cursor:pointer;transition:background .12s,color .12s;
}
.copy-btn:hover{background:rgba(255,255,255,.16)}.copy-btn.ok,.install-copy.ok{background:var(--accent);border-color:var(--accent);color:#fff}
.hk{color:var(--hl-keyword);font-weight:700}.hs{color:var(--hl-string)}.hn{color:var(--hl-number)}.hc{color:var(--hl-comment);font-style:italic}.hf{color:var(--hl-flag)}
table{width:100%;border-collapse:separate;border-spacing:0;margin:1.4em 0;font-size:.92rem;overflow:hidden;border:1px solid var(--line);border-radius:10px}
th{background:var(--line-soft);text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);font-size:.78rem;font-weight:800;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}td code{font-size:.82em}
@media(max-width:1200px){.toc{display:none}.main{max-width:980px}}
@media(max-width:900px){
  .shell{display:block}.sidebar{position:static;height:auto;transform:none;box-shadow:none}
  .mob-bar{display:none}.content-row{display:block}.main{padding:32px 20px 60px}.home-hero h1{font-size:2.7rem}
}
@media(max-width:560px){.home-install{flex-wrap:wrap}.home-install code{width:100%}.features-grid{grid-template-columns:1fr}.home-hero h1{font-size:2.25rem}}
</style>
</head>
<body>
<div class="shell">
  ${sidebar}
  <div class="body-col">
    <div class="mob-bar">
      <button class="hamburger" id="ham" aria-label="Toggle menu">
        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="3" y1="6"  x2="17" y2="6"/>
          <line x1="3" y1="10" x2="17" y2="10"/>
          <line x1="3" y1="14" x2="17" y2="14"/>
        </svg>
      </button>
      <a class="mob-brand" href="index.html">${TOOL}</a>
    </div>
    <div class="content-row">
      <main class="main">
        ${hero}
        ${isIndex ? featureGridHtml() : ""}
        ${bodyHtml}
      </main>
      ${tocBlock}
    </div>
  </div>
</div>

<script>
const root=document.documentElement;
const btn=document.getElementById("themeBtn");
const stored=localStorage.getItem("theme")||"dark";
root.dataset.theme=stored;
btn && btn.setAttribute("aria-pressed", stored==="dark" ? "true" : "false");
btn.addEventListener("click",()=>{
  const next=root.dataset.theme==="dark"?"light":"dark";
  root.dataset.theme=next;
  localStorage.setItem("theme",next);
  btn.setAttribute("aria-pressed", next==="dark" ? "true" : "false");
});

const ham=document.getElementById("ham");
const sidebar=document.getElementById("sidebar");
ham.addEventListener("click",()=>sidebar.classList.toggle("open"));
document.addEventListener("click",e=>{
  if(!sidebar.contains(e.target)&&!ham.contains(e.target))
    sidebar.classList.remove("open");
});

document.querySelectorAll(".copy-btn").forEach(btn=>{
  btn.addEventListener("click",()=>{
    const pre=btn.previousElementSibling;
    const text=btn.dataset.copy||(pre&&pre.innerText)||"";
    navigator.clipboard.writeText(text.trim()).then(()=>{
      btn.textContent="Copied!";btn.classList.add("ok");
      setTimeout(()=>{btn.textContent="Copy";btn.classList.remove("ok");},2000);
    });
  });
});
document.querySelectorAll(".install-copy").forEach(btn=>{
  btn.addEventListener("click",()=>{
    navigator.clipboard.writeText(btn.dataset.copy||"").then(()=>{
      btn.textContent="Copied";btn.classList.add("ok");
      setTimeout(()=>{btn.textContent="Copy";btn.classList.remove("ok");},1600);
    });
  });
});

const search=document.getElementById("docSearch");
if(search){
  const links=[...document.querySelectorAll("[data-nav-item]")];
  const groups=[...document.querySelectorAll("[data-nav-group]")];
  search.addEventListener("input",()=>{
    const q=search.value.trim().toLowerCase();
    links.forEach(li=>{
      const a=li.querySelector("a");
      li.hidden=q && !a.dataset.searchText.toLowerCase().includes(q);
    });
    groups.forEach(group=>{
      let next=group.nextElementSibling, any=false;
      while(next && !next.matches("[data-nav-group]")){
        if(!next.hidden) any=true;
        next=next.nextElementSibling;
      }
      group.hidden=q && !any;
    });
  });
}

const tocLinks=[...document.querySelectorAll(".toc a")];
if(tocLinks.length){
  const heads=[...document.querySelectorAll("h2[id],h3[id]")];
  const obs=new IntersectionObserver(entries=>{
    entries.forEach(e=>{
      if(e.isIntersecting){
        tocLinks.forEach(a=>a.classList.remove("active"));
        const a=document.querySelector('.toc a[href="#'+e.target.id+'"]');
        if(a)a.classList.add("active");
      }
    });
  },{rootMargin:"0px 0px -70% 0px"});
  heads.forEach(h=>obs.observe(h));
}
</script>
</body>
</html>`;
}

// ── Navigation ────────────────────────────────────────────────────────────────

const sections = [
  ["Get Started",  ["index.md", "installation.md", "usage.md"]],
  ["Configuration",["configuration.md"]],
  ["Development",  ["architecture.md", "build.md", "testing.md"]],
];

const LABELS = {
  "index":        "Home",
  "installation": "Installation",
  "usage":        "Usage",
  "configuration":"Configuration",
  "architecture": "Architecture",
  "build":        "Build",
  "testing":      "Testing",
};

const PAGE_KEYWORDS = {
  "index": "overview proxy ntlm kerberos pac docker quick start",
  "installation": "go build docker windows startup install path kerberos",
  "usage": "basic proxy upstream pac bypass ntlm kerberos client authentication gateway logging self test",
  "configuration": "px env ini config proxy client settings passwords kerberos pac noproxy",
  "architecture": "runtime flow packages concurrency proxy pac kerberos system proxy windows startup",
  "build": "local build cross compile docker image version",
  "testing": "make test race detector coverage kerberos docker lint ci",
};

function fileToLabel(filename) {
  const slug = basename(filename, ".md");
  if (LABELS[slug]) return LABELS[slug];
  return slug
    .replace(/-/g, " ")
    .replace(/\b\w/g, c => c.toUpperCase());
}

const pages = sections.flatMap(([, files]) =>
  files.map(f => ({ slug: basename(f, ".md"), label: fileToLabel(f), file: f }))
);

// ── Build ─────────────────────────────────────────────────────────────────────

for(const {slug,label,file} of pages) {
  const filePath = join(SRC, file);
  if (!existsSync(filePath)) {
    console.error(`  ERROR: docs/${file} not found — check sections array`);
    process.exit(1);
  }
  const src    = readFileSync(filePath,"utf8");
  const {html,toc} = parse(src);
  const output = renderPage({
    slug, title:label, bodyHtml:html, toc, pages,
    isIndex: slug==="index",
  });
  writeFileSync(join(OUT,`${slug}.html`), output);
  console.log(`  wrote ${slug}.html  (${toc.length} ToC entries)`);
}

writeFileSync(join(OUT,".nojekyll"),"");
writeFileSync(join(OUT,"favicon.svg"),`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs>
<linearGradient id="a" x1="10" x2="54" y1="8" y2="56"><stop offset="0" stop-color="#ff8a6d"/><stop offset=".55" stop-color="#ff6b4a"/><stop offset="1" stop-color="#d9482e"/></linearGradient>
<linearGradient id="b" x1="54" x2="10" y1="10" y2="58"><stop offset="0" stop-color="#47c2b1"/><stop offset="1" stop-color="#1f8f83"/></linearGradient>
</defs>
<rect x="8" y="9" width="48" height="46" rx="14" fill="url(#a)"/>
<path d="M18 24h18c5.5 0 10 4.5 10 10s-4.5 10-10 10H18v-7h18a3 3 0 0 0 0-6H18z" fill="#fff" opacity=".94"/>
<path d="M46 19l8 8-8 8v-6H29v-4h17zM18 45l-8-8 8-8v6h17v4H18z" fill="url(#b)"/>
</svg>`);

if(existsSync(join(SRC,"CNAME")))
  writeFileSync(join(OUT,"CNAME"),readFileSync(join(SRC,"CNAME")));

writeFileSync(join(OUT,"llms.txt"),
`# ${TOOL}

> ${DESC}

## Install

\`\`\`bash
${INSTALL_CMD}
\`\`\`

## Source

${REPO_URL}

## Docs

${SITE_BASE}/
`);

console.log(`\nSite built → ${OUT}/  (${pages.length} page${pages.length===1?"":"s"})`);
