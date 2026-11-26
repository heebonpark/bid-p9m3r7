(() => {
'use strict';
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];

/* ==================== Storage & IndexedDB ==================== */
const store = {
  get(k, d) { try { const v = localStorage.getItem('bidopp:' + k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem('bidopp:' + k, JSON.stringify(v)); } catch {} },
  del(k) { try { localStorage.removeItem('bidopp:' + k); } catch {} },
};
const idb = (() => {
  let dbp = null;
  const open = () => dbp || (dbp = new Promise((res, rej) => {
    const r = indexedDB.open('bidopp_db', 2);
    r.onupgradeneeded = () => {
      const db = r.result;
      if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv');
      if (!db.objectStoreNames.contains('vault')) db.createObjectStore('vault');
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  }));
  const tx = (st, m, f) => open().then(db => new Promise((res, rej) => {
    const t = db.transaction(st, m), q = f(t.objectStore(st));
    t.oncomplete = () => res(q && q.result); t.onerror = () => rej(t.error);
  }));
  return {
    get: k => tx('kv', 'readonly', s => s.get(k)).catch(() => undefined),
    set: (k, v) => tx('kv', 'readwrite', s => s.put(v, k)).then(() => true).catch(() => false),
    del: k => tx('kv', 'readwrite', s => s.delete(k)).catch(() => {}),
    getKey: () => tx('vault', 'readonly', s => s.get('key')).catch(() => undefined),
    setKey: v => tx('vault', 'readwrite', s => s.put(v, 'key')).then(() => true).catch(() => false),
    delKey: () => tx('vault', 'readwrite', s => s.delete('key')).catch(() => {}),
  };
})();

/* ==================== WebCrypto AES-256-GCM Vault ==================== */
const CANARY = 'BIDOPP-VAULT-OK-V1';
let VAULT_META = null, VAULT_KEY = null, APP_BOOTED = false;
function b64ToBytes(b64) { const bin = atob(b64), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
async function deriveVaultKey(password, saltB64, iter) {
  const bk = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations: iter, hash: 'SHA-256' }, bk, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
async function verifyKey(key, vault) {
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(vault.checkIv) }, key, b64ToBytes(vault.checkCt));
    return new TextDecoder().decode(pt) === CANARY;
  } catch { return false; }
}
async function fetchDecJson(name) {
  const res = await fetch(`./data/${name}.enc?v=${encodeURIComponent(VAULT_META.salt.slice(0, 8))}`);
  if (!res.ok) throw new Error(`${name}.enc 로드 실패 (${res.status})`);
  const buf = new Uint8Array(await res.arrayBuffer());
  const gz = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.subarray(0, 12) }, VAULT_KEY, buf.subarray(12));
  const ds = new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(ds).text());
}
async function lockAppNow() { await idb.delKey(); VAULT_KEY = null; location.reload(); }

function applyTheme(th) {
  store.set('theme', th);
  if (th === 'light' || th === 'dark') document.documentElement.dataset.theme = th;
  else delete document.documentElement.dataset.theme;
  $$('#themeChips .chip').forEach(b => b.setAttribute('aria-pressed', b.dataset.th === th));
}
applyTheme(store.get('theme', 'auto'));

/* ==================== Utils ==================== */
const fmt = n => Math.round(n).toLocaleString('ko-KR');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const CHO = 'ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ';
function cho(s) { let o = ''; for (const ch of String(s || '')) { const c = ch.charCodeAt(0); if (c >= 0xAC00 && c <= 0xD7A3) o += CHO[((c - 0xAC00) / 588) | 0]; else if (/[0-9a-zA-Z]/.test(ch)) o += ch.toLowerCase(); } return o; }
const isCho = s => /^[ㄱ-ㅎ]+$/.test(s);
const digits = s => String(s || '').replace(/\D/g, '');
const ok = v => v === v && v !== null && v !== undefined;
const clamp01 = v => v < 0 ? 0 : v > 1 ? 1 : v;
const todayStr = () => { const d = new Date(); return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`; };
const fmtBudget = man => !man ? '-' : man >= 10000 ? (man / 10000).toFixed(man >= 100000 ? 0 : 1) + '억' : fmt(man) + '만';
function toast(t) { const e = $('#toast'); e.textContent = t; e.classList.add('on'); clearTimeout(toast.t); toast.t = setTimeout(() => e.classList.remove('on'), 2100); }
async function copy(t, msg) { try { await navigator.clipboard.writeText(t); toast(msg || '복사했습니다'); } catch { toast('복사가 허용되지 않는 환경입니다'); } }
const homeUrl = h => !h ? '' : (/^https?:\/\//i.test(h) ? h : 'http://' + h);
const debounce = (f, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => f(...a), ms); }; };

/* ==================== Domain Classification & Pro Quant Engine ==================== */
const DOMAINS = [
  { k: 'sec', l: '🛡 보안·CCTV·출입', re: /CCTV|보안|출입통제|방범|비상벨|관제|경보|화재감지|열화상|무인/, pts: 95, tip: 'AI 선별관제·열화상 화재감지·출입통제 통합 패키지로 제안하세요.' },
  { k: 'ai', l: '🤖 AI·스마트·주차', re: /AI|지능형|스마트|주차관제|LPR|차량번호|IoT|BEMS|무인택배|홈네트워크/, pts: 92, tip: 'AI 주차관제(LPR)·스마트홈/BEMS 연동으로 유지비 절감 ROI를 강조하세요.' },
  { k: 'fac', l: '🏢 시설·경비·미화', re: /경비|미화|청소|시설관리|위탁|유지보수|유지관리|소독|조경/, pts: 80, tip: '인력 절감형 무인/하이브리드 순찰·출입관제 결합 제안이 효과적입니다.' },
  { k: 'mep', l: '⚡ 전기·통신·소방', re: /전기|통신|소방|방재|LED|디밍|방송|네트워크|전력/, pts: 78, tip: '전기차 화재감지·지능형 분전반·LED 디밍 절전 패키지를 함께 제안하세요.' },
  { k: 'con', l: '🏗 건축·리모델링', re: /신축|착공|리모델링|재건축|재개발|방수|도장|외벽|지식산업|물류센터|공사/, pts: 75, tip: '중대재해처벌법 대응 현장 안전 AI CCTV 및 준공 후 보안·주차관제를 조기 선점하세요.' },
  { k: 'elv', l: '🛗 승강기·기계설비', re: /승강기|엘리베이터|배관|보일러|공조|기계설비/, pts: 72, tip: '승강기 교체 시 비상통화·영상관제 연동 및 장기수선 컨설팅을 결합하세요.' },
];

const CAT_LBL = { apt: '🏘 공동주택', gov: '🏛 관공서', construction: '🏗 건설·착공' };
const CAT_CLS = { apt: 's-apt', gov: 's-gov', construction: 's-con' };
const STAGE_LBL = { bid: '📢 입찰공고', prespec: '🔭 사전규격', plan: '📋 발주계획', complex: '🏢 노후단지', permit: '🏗 건축인허가' };
const CRM_STAGES = ['발굴', '검토', '현장답사', '제안·투찰', '낙찰·계약', '보류'];
const SEC_LBL = { apt_builder: '공동주택 건설사', general: '종합·토목·공공', specialty: '전문건설·시공', facility: '시설·경비·보안', mep: '전기·통신·소방' };
const CRED_LBL = ['', 'AAA', 'AA', 'A', 'BBB', 'BB', 'B', 'CCC', 'D'];

const W_PRESETS = {
  balanced: { name: '균형 기본', w: { budget: 20, urgency: 20, fit: 25, region: 10, stage: 15, scale: 10 } },
  secai:    { name: '보안·AI CCTV 특화', w: { budget: 15, urgency: 15, fit: 40, region: 10, stage: 10, scale: 10 } },
  biggov:   { name: '대형 관공서·공사', w: { budget: 35, urgency: 15, fit: 15, region: 10, stage: 10, scale: 15 } },
  aptgold:  { name: '공동주택 노후단지', w: { budget: 15, urgency: 10, fit: 25, region: 10, stage: 15, scale: 25 } },
  early:    { name: '조기포착(사전규격·착공)', w: { budget: 15, urgency: 5, fit: 20, region: 10, stage: 40, scale: 10 } },
};
const SIGUNGU_PRESETS = [
  ['28237', '인천 부평구'], ['28200', '인천 남동구'], ['28185', '인천 연수구'], ['28260', '인천 서구'], ['28245', '인천 계양구'],
  ['11680', '서울 강남구'], ['11440', '서울 마포구'], ['11305', '서울 강북구'], ['11110', '서울 종로구'], ['11350', '서울 노원구'],
  ['41280', '경기 고양시'], ['41135', '경기 성남시'], ['41360', '경기 남양주시'], ['41480', '경기 파주시'], ['41150', '경기 의정부시'],
  ['51130', '강원 원주시'], ['51150', '강원 강릉시'],
];

let MAP, META, BUILDERS = [], BLD_IND = [], OPPS = [], RES = [];
let PRO_W = Object.assign({}, W_PRESETS.balanced.w, store.get('proW', {}));
let FAV = new Set(store.get('fav', []));
let CRM = store.get('crm', {}); // { id: { stage, estMan, text, updated } }
let PRESETS = store.get('presets', []);
let CMP = [];
let CUR_ID = null;
let MAPMODE = 'precision';
let VW_MAIN = null;

// Builder view state
const BS = { q: '', sec: '', cred: '', activeOnly: true, sido: '', sort: 'score' };

// Main opportunity filter state
const S = { q: '', cats: [], stages: [], dday: '', doms: [], buds: [], grade: '', sido: '', sggs: [], crm: [], fav: false, hideSample: false, hideCancelled: true, myKwOnly: false, sort: 'score' };
let MY_KW = store.get('myBidKeywords', 'CCTV,관제,보안,소방,승강기,시설,경비,미화,전기,통신,보험');
const isCancelledOpp = it => /취소/.test(it?.detail?.ntceKind || '') || /\(취소공고\)|\[취소공고\]/.test(it?.title || '');
const getMyKwList = () => String(MY_KW || '').split(/[,\n/|]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
const matchesMyKw = (it, list = getMyKwList()) => {
  if (!list.length) return true;
  const hay = `${it.title || ''} ${it.org || ''} ${it.detail?.categoryNm || ''} ${(it._doms || []).map(d => d.l).join(' ')}`.toLowerCase();
  return list.some(k => hay.includes(k));
};

function calcDday(closeDate) {
  if (!closeDate) return null;
  const m = String(closeDate).match(/(\d{4})-?(\d{2})-?(\d{2})/);
  if (!m) return null;
  const target = new Date(+m[1], +m[2] - 1, +m[3]);
  const now = new Date(); now.setHours(0, 0, 0, 0);
  return Math.round((target - now) / 86400000);
}

// #3: 공동주택 노후화 교체 골든타임 스코어 (준공 10~25년 + 대단지)
function calcAptGolden(it) {
  if (it.category !== 'apt') return 0;
  const yr = Number(it.meta?.builtYear || 0);
  const hh = Number(it.meta?.households || 0);
  const curY = new Date().getFullYear();
  let sc = 40;
  if (yr > 1970) {
    const age = curY - yr;
    if (age >= 10 && age <= 16) sc += 35;      // CCTV/주차/출입 교체 골든타임
    else if (age >= 17 && age <= 26) sc += 30; // 승강기/방수/대수선 골든타임
    else if (age > 26) sc += 20;               // 재건축/임시관제
    else sc += 12;
  }
  if (hh >= 1500) sc += 25;
  else if (hh >= 1000) sc += 20;
  else if (hh >= 500) sc += 14;
  else if (hh >= 300) sc += 8;
  return Math.min(100, sc);
}

function classifyDomains(it) {
  const txt = `${it.title || ''} ${it.org || ''} ${it.method || ''} ${it.meta?.purp || ''}`;
  const hit = DOMAINS.filter(d => d.re.test(txt));
  return hit.length ? hit : [DOMAINS[4]];
}

// #1: 6-Factor Customizable Opportunity Score
function enrichOpp(it) {
  it._dday = calcDday(it.closeDate);
  it._doms = classifyDomains(it);
  it._aptGold = calcAptGolden(it);
  it._search = `${it.title} ${it.org} ${it.region} ${it.source} ${it.method}`.toLowerCase();
  it._cho = cho(`${it.title}${it.org}${it.region}`);

  // 6 normalized axes (0..100)
  const bud = it.budgetMan > 0 ? Math.min(100, Math.round(clamp01(Math.log10(Math.max(100, it.budgetMan)) / 5.5) * 100)) : 45;
  const urg = it._dday === null ? 55 : it._dday < 0 ? 5 : it._dday <= 3 ? 98 : it._dday <= 7 ? 85 : it._dday <= 14 ? 70 : 55;
  const fit = Math.max(...it._doms.map(d => d.pts));
  const reg = it.rid >= 0 ? 85 : 50;
  const stg = it.stageType === 'prespec' ? 95 : it.stageType === 'plan' ? 90 : it.stageType === 'permit' ? 88 : it.stageType === 'bid' ? 80 : 75;
  const scl = it.category === 'apt' ? (it._aptGold || 65) : it.category === 'gov' ? 82 : (it.meta?.area >= 30000 ? 92 : 74);

  it._axes = [bud, urg, fit, reg, stg, scl];
  const W = PRO_W;
  const wSum = (W.budget + W.urgency + W.fit + W.region + W.stage + W.scale) || 1;
  let score = (bud * W.budget + urg * W.urgency + fit * W.fit + reg * W.region + stg * W.stage + scl * W.scale) / wSum;
  if (it._dday !== null && it._dday < 0) score *= 0.4;
  it._score = Math.max(0, Math.min(100, Math.round(score)));
  it._grade = it._score >= 80 ? 'S' : it._score >= 70 ? 'A' : it._score >= 60 ? 'B' : 'C';
  return it;
}

function recomputeAllOpps() { OPPS.forEach(enrichOpp); }

/* ==================== Builder Real Dataset Quant Engine (12,198 companies) ==================== */
let BLD_SCORED = [];
let NAT_BLD_SEC = {};
function scoreBuilders() {
  const curY = new Date().getFullYear();
  NAT_BLD_SEC = {};
  BLD_SCORED = BUILDERS.map((r, idx) => {
    // [0:name,1:stock,2:ceo,3:corp,4:biz,5:addr,6:tel,7:home,8:indId,9:est,10:rid,11:sdIdx,12:stat,13:sec,14:rev,15:rev1,16:op,17:emp,18:nNew,19:nLost,20:wage]
    const st = r[12], sec = r[13], rev = r[14], rev1 = r[15], op = r[16], emp = r[17], nw = r[18], ls = r[19], wage = r[20];
    NAT_BLD_SEC[sec] = (NAT_BLD_SEC[sec] || 0) + 1;
    const mrg = ok(rev) && rev > 0 && ok(op) ? (op / rev) * 100 : NaN;
    const grw = ok(rev) && rev > 0 && ok(rev1) && rev1 > 0 ? (rev / rev1 - 1) * 100 : NaN;
    const r40 = ok(mrg) && ok(grw) && rev >= 10 ? Math.max(-100, Math.min(200, mrg + grw)) : NaN;
    const rpe = ok(rev) && ok(emp) && emp >= 1 ? rev / emp : NaN;
    const yrs = r[9] ? Math.max(0, curY - Math.floor(r[9] / 10000)) : null;

    let z = NaN, cred = 0;
    if (st === 2 || st === 3) { z = st === 3 ? 5 : 18; cred = st === 3 ? 8 : 7; }
    else {
      let pts = 0, w = 0;
      if (ok(mrg)) { pts += 30 * clamp01((mrg + 5) / 20); w += 30; }
      if (ok(grw)) { pts += 15 * clamp01((grw + 15) / 40); w += 15; }
      if (ok(emp) && emp > 0) {
        const es = clamp01(Math.log10(Math.max(1, emp)) / 2.7);
        const qtr = ok(ls) ? (ls / emp) * 100 : 2;
        pts += 25 * (es * 0.5 + clamp01((5 - qtr) / 4.5) * 0.5); w += 25;
      }
      if (ok(wage) && wage > 0) { pts += 15 * clamp01((wage - 220) / 380); w += 15; }
      if (w >= 20) {
        pts += 15 * ((yrs !== null ? clamp01(yrs / 20) : 0.45) * 0.5 + (st === 1 ? 0.9 : 0.5) * 0.5); w += 15;
        z = Math.round((pts / w) * 100);
        if (ok(op) && op < 0) z = Math.min(z, 54);
        cred = z >= 84 ? 1 : z >= 75 ? 2 : z >= 66 ? 3 : z >= 56 ? 4 : z >= 46 ? 5 : z >= 36 ? 6 : z >= 22 ? 7 : 8;
      }
    }
    const score = (st === 2 || st === 3) ? 0 : Math.round(
      (ok(rev) ? clamp01(Math.log10(Math.max(1, rev)) / 4) * 35 : (ok(emp) ? clamp01(Math.log10(Math.max(1, emp)) / 2.7) * 28 : 10)) +
      (ok(z) ? z * 0.45 : (st === 1 ? 22 : 12)) +
      (r[3] < 3 ? 15 : 5) + (r[7] ? 5 : 0)
    );
    return {
      idx, r, st, sec, rev, op, emp, nw, ls, wage, mrg, grw, r40, rpe, z, cred, score,
      _search: `${r[0]} ${r[2]} ${r[4]} ${r[5]} ${BLD_IND[r[8]] || ''}`.toLowerCase(),
      _cho: cho(r[0]),
    };
  });
}

/* ==================== Query & List Render ==================== */
function getTodayKstIso() {
  const d = new Date(Date.now() + 9 * 3600000);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
}
function isTodayOpp(it, todayIso = getTodayKstIso()) {
  return String(it?.pubDate || '').slice(0, 10) === todayIso;
}
function oppDateSummary(it) {
  const pub = it?.pubDateTime || it?.pubDate || '-';
  const cls = it?.closeDate
    ? `${it.closeDate}${it._dday !== null && it._dday >= 0 ? ` (D-${it._dday})` : (it._dday !== null && it._dday < 0 ? ' (마감)' : '')}`
    : '-';
  return `📅 공고 ${pub} · ⏰ 마감 ${cls}`;
}

function run() {
  const q = S.q.toLowerCase(), qc = isCho(S.q.replace(/\s/g, '')) ? S.q.replace(/\s/g, '') : '';
  const sggSet = S.sggs.length ? new Set(S.sggs) : null;
  const todayIso = getTodayKstIso();
  const kwList = S.myKwOnly ? getMyKwList() : null;
  RES = OPPS.filter(it => {
    if (S.hideCancelled && isCancelledOpp(it)) return false;
    if (kwList && !matchesMyKw(it, kwList)) return false;
    if (S.hideSample && it.sample) return false;
    if (S.cats.length && !S.cats.includes(it.category)) return false;
    if (S.stages.length && !S.stages.includes(it.stageType)) return false;
    if (S.dday) {
      if (S.dday === 'todayBid') { if (!(it.stageType === 'bid' && isTodayOpp(it, todayIso))) return false; }
      else if (S.dday === 'today') { if (!isTodayOpp(it, todayIso)) return false; }
      else if (S.dday === 'early') { if (!['prespec', 'plan', 'permit', 'complex'].includes(it.stageType)) return false; }
      else { const lim = +S.dday; if (it._dday === null || it._dday < 0 || it._dday > lim) return false; }
    }
    if (S.doms.length && !it._doms.some(d => S.doms.includes(d.k))) return false;
    if (S.buds.length) {
      const b = it.budgetMan || 0;
      const hit = S.buds.some(k => (k === 0 && b > 0 && b < 10000) || (k === 1 && b >= 10000 && b < 50000) || (k === 2 && b >= 50000 && b < 200000) || (k === 3 && b >= 200000));
      if (!hit) return false;
    }
    if (S.grade) { const min = S.grade === 'S' ? 80 : S.grade === 'A' ? 70 : 60; if (it._score < min) return false; }
    if (sggSet) { if (!sggSet.has(it.rid)) return false; }
    else if (S.sido) { const reg = it.rid >= 0 ? MAP.regions[it.rid] : null; if (!reg || reg.sd !== S.sido) return false; }
    if (S.crm.length) { const c = CRM[it.id]; if (!c || !S.crm.includes(c.stage)) return false; }
    if (S.fav && !FAV.has(it.id)) return false;
    if (q) { if (qc ? !it._cho.includes(qc) : !it._search.includes(q)) return false; }
    return true;
  });

  const sorters = {
    score: (a, b) => b._score - a._score || (b.budgetMan || 0) - (a.budgetMan || 0),
    dday: (a, b) => (a._dday === null ? 999 : a._dday < 0 ? 998 : a._dday) - (b._dday === null ? 999 : b._dday < 0 ? 998 : b._dday),
    budget: (a, b) => (b.budgetMan || 0) - (a.budgetMan || 0),
    new: (a, b) => String(b.pubDateTime || b.pubDate || '').localeCompare(String(a.pubDateTime || a.pubDate || '')),
    aptgold: (a, b) => b._aptGold - a._aptGold || b._score - a._score,
  };
  RES.sort(sorters[S.sort] || sorters.score);

  renderActive();
  renderList();
  renderPro();
  renderMap();
  if ($('#vCrm').classList.contains('on')) renderCrm();
  $('#cnt').textContent = fmt(RES.length);
  const fc = activeCount(); $('#fcount').hidden = !fc; $('#fcount').textContent = fc;
}

function activeCount() {
  return S.cats.length + S.stages.length + (S.dday ? 1 : 0) + S.doms.length + S.buds.length + (S.grade ? 1 : 0) + (S.sido ? 1 : 0) + S.sggs.length + S.crm.length + (S.fav ? 1 : 0) + (S.hideSample ? 1 : 0) + (S.myKwOnly ? 1 : 0);
}

const regName = id => { const r = MAP.regions[id]; return MAP.sidos.find(s => s.sd === r.sd).s + ' ' + r.n; };

function renderActive() {
  const a = []; const add = (lbl, fn) => a.push({ lbl, fn });
  if (S.q) add(`검색: ${S.q}`, () => { S.q = ''; $('#q').value = ''; $('#searchBox').classList.remove('has'); });
  S.cats.forEach(c => add(CAT_LBL[c], () => { S.cats = S.cats.filter(x => x !== c); }));
  S.stages.forEach(st => add(STAGE_LBL[st], () => { S.stages = S.stages.filter(x => x !== st); }));
  if (S.dday) {
    const ddLbl = S.dday === 'todayBid' ? '📅 당일 입찰만' : S.dday === 'today' ? '🗓️ 당일 전체' : S.dday === 'early' ? '🔭 조기포착' : `D-${S.dday} 이내`;
    add(ddLbl, () => { S.dday = ''; });
  }
  S.doms.forEach(k => add(DOMAINS.find(d => d.k === k).l, () => { S.doms = S.doms.filter(x => x !== k); }));
  const bLbl = ['1억 미만', '1~5억', '5~20억', '20억+'];
  S.buds.forEach(k => add('예산 ' + bLbl[k], () => { S.buds = S.buds.filter(x => x !== k); }));
  if (S.grade) add(`우선순위 ${S.grade}+`, () => { S.grade = ''; });
  if (S.sido && !S.sggs.length) add(MAP.sidos.find(s => s.sd === S.sido).n, () => { S.sido = ''; $('#fSido').value = ''; fillSgg(); });
  S.sggs.forEach(id => add('📍 ' + regName(id), () => { S.sggs = S.sggs.filter(x => x !== id); }));
  S.crm.forEach(c => add('💼 ' + c, () => { S.crm = S.crm.filter(x => x !== c); }));
  if (S.fav) add('⭐ 즐겨찾기', () => { S.fav = false; $('#fFav').checked = false; });
  if (S.myKwOnly) add('⭐ 내 키워드만', () => { S.myKwOnly = false; });
  if (S.hideSample) add('실 API만', () => { S.hideSample = false; $('#fHideSample').checked = false; });

  const el = $('#activeF');
  el.innerHTML = a.map((x, k) => `<button class="chip" data-k="${k}" aria-pressed="true">${esc(x.lbl)} ✕</button>`).join('') + (a.length > 1 ? '<button class="resetbtn" data-all>모두 해제</button>' : '');
  el.onclick = e => { if (e.target.closest('[data-all]')) { resetAll(); return; } const b = e.target.closest('.chip'); if (b) { a[+b.dataset.k].fn(); run(); } };

  $$('#catChips .chip').forEach(b => b.setAttribute('aria-pressed', S.cats.includes(b.dataset.cat)));
  $$('#stageChips .chip').forEach(b => b.setAttribute('aria-pressed', S.stages.includes(b.dataset.st)));
  $$('#ddayChips .chip').forEach(b => b.setAttribute('aria-pressed', S.dday === b.dataset.dd));
  $$('#domChips .chip').forEach(b => b.setAttribute('aria-pressed', S.doms.includes(b.dataset.dom)));
  $$('#budChips .chip').forEach(b => b.setAttribute('aria-pressed', S.buds.includes(+b.dataset.bd)));
  $$('#gradeChips .chip').forEach(b => b.setAttribute('aria-pressed', S.grade === b.dataset.gr));
  $$('#crmChips .chip').forEach(b => b.setAttribute('aria-pressed', S.crm.includes(b.dataset.crm)));
  $('#sggChips').innerHTML = S.sggs.map(id => `<button class="chip" data-r="${id}" aria-pressed="true">${esc(regName(id))} ✕</button>`).join('');
  $('#sort').value = S.sort;
}

function ddayBadge(it) {
  if (it.stageType === 'prespec' || it.stageType === 'plan' || it.stageType === 'permit') return `<span class="sb s-pre">${STAGE_LBL[it.stageType]}</span>`;
  if (it._dday === null) return '';
  if (it._dday < 0) return `<span class="sb s-smp">마감</span>`;
  if (it._dday <= 3) return `<span class="sb s-urg">🚨 D-${it._dday}</span>`;
  if (it._dday <= 7) return `<span class="sb s-warn">⏰ D-${it._dday}</span>`;
  return `<span class="sb s-ok">D-${it._dday}</span>`;
}

function itemHTML(it) {
  const inCmp = CMP.includes(it.id);
  const crm = CRM[it.id];
  const gCls = it._grade === 'S' ? 'g-s' : it._grade === 'A' ? 'g-a' : it._grade === 'B' ? 'g-b' : 'g-c';
  return `<li class="item${it.id === CUR_ID ? ' on' : ''}" data-id="${esc(it.id)}">
    <div class="nm">${FAV.has(it.id) ? '⭐ ' : ''}${esc(it.title)}</div>
    <span style="display:flex;gap:4px;align-self:start;align-items:center">
      <button type="button" class="cmp-mini${inCmp ? ' on' : ''}" data-cmp="${esc(it.id)}">${inCmp ? '✓비교' : '+비교'}</button>
      <span class="grd ${gCls}">🏆 ${it._grade} ${it._score}</span>
    </span>
    <div class="meta">
      <span><b>${esc(it.org)}</b></span>
      <span class="num">예산 <b>${fmtBudget(it.budgetMan)}</b></span>
      <span>${esc(it.method || it.source)}</span>
    </div>
    <div class="meta" style="margin-top:2px;font-weight:600;color:var(--ink)">
      <span class="num">${esc(oppDateSummary(it))}</span>
    </div>
    <div class="addr">${esc(it.region || '전국/미지정')}${it.meta?.households ? ` · ${fmt(it.meta.households)}세대 (${it.meta.builtYear || '-'}년 준공)` : ''}${it.meta?.area ? ` · 연면적 ${fmt(it.meta.area)}㎡` : ''}</div>
    <div class="sbrow">
      <span class="sb ${CAT_CLS[it.category]}">${CAT_LBL[it.category]}</span>
      ${ddayBadge(it)}
      ${it._doms.slice(0, 2).map(d => `<span class="sb s-smp">${d.l}</span>`).join('')}
      ${it._aptGold >= 75 ? `<span class="sb s-ok">🔥 교체적기 ${it._aptGold}</span>` : ''}
      ${crm && crm.stage ? `<span class="sb s-crm">💼 ${esc(crm.stage)}${crm.estMan ? ' ' + fmtBudget(crm.estMan) : ''}</span>` : ''}
      ${isTodayOpp(it) ? `<span class="sb s-ok">📅 오늘${it.pubDateTime ? ' ' + esc(String(it.pubDateTime).slice(11, 16)) : ''}</span>` : ''}
      ${it.detail?.ntceKind && /취소/.test(it.detail.ntceKind) ? '<span class="sb s-urg">⛔ 취소공고</span>' : (it.detail?.ntceKind && /변경|정정/.test(it.detail.ntceKind) ? '<span class="sb s-pre">📝 변경공고</span>' : '')}
      ${it.attachments?.length ? `<span class="sb s-crm">📎 첨부 ${it.attachments.length}건</span>` : ''}
      ${it.sample ? '<span class="sb s-smp">예시</span>' : (it.isLive ? '<span class="sb s-ok">⚡ 카톡실시간</span>' : '<span class="sb s-ok">실API</span>')}
    </div>
  </li>`;
}

function renderList() {
  const ul = $('#list');
  if (!RES.length) {
    ul.innerHTML = `<li class="empty">조건에 맞는 영업기회가 없습니다.<br><button class="resetbtn" onclick="document.getElementById('resetAll').click()">필터 초기화</button></li>`;
    return;
  }
  ul.innerHTML = RES.map(itemHTML).join('');
}

/* ==================== Pro Quant TOP 10 Dashboard ==================== */
function radarSVG(seriesList) {
  const labels = ['예산규모', '마감긴급', '보안·AI', '지역적합', '조기포착', '단지·규모'];
  const cx = 105, cy = 100, R = 66;
  const pt = (k, r) => { const a = -Math.PI / 2 + (k * Math.PI * 2) / 6; return [cx + Math.cos(a) * r, cy + Math.sin(a) * r]; };
  let h = `<svg viewBox="0 0 210 200" class="radar-svg">`;
  [0.25, 0.5, 0.75, 1].forEach(f => { h += `<polygon points="${labels.map((_, k) => pt(k, R * f).map(v => v.toFixed(1)).join(',')).join(' ')}" class="grid"/>`; });
  labels.forEach((lb, k) => {
    const [x, y] = pt(k, R), [lx, ly] = pt(k, R + 16);
    h += `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" class="axis"/><text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="middle" dominant-baseline="middle" class="lbl">${lb}</text>`;
  });
  h += `<polygon points="${labels.map((_, k) => pt(k, R * 0.5).map(v => v.toFixed(1)).join(',')).join(' ')}" class="med"/>`;
  seriesList.forEach(s => {
    const pts = s.vals.map((v, k) => pt(k, R * (Math.max(8, v || 0) / 100)).map(x => x.toFixed(1)).join(',')).join(' ');
    h += `<polygon points="${pts}" style="fill:color-mix(in srgb,${s.color} 22%,transparent);stroke:${s.color};stroke-width:2"><title>${esc(s.name)}</title></polygon>`;
  });
  return h + '</svg>';
}

function renderPro() {
  const el = $('#pro'); if (!el) return;
  const n = RES.length;
  let urg3 = 0, sa = 0, aptGoldCnt = 0, pipeSum = 0, pipeCnt = 0;
  const domCnt = Object.fromEntries(DOMAINS.map(d => [d.k, 0]));
  const catCnt = { apt: 0, gov: 0, construction: 0 };
  const buds = []; let budSum = 0;

  for (const it of RES) {
    if (it._dday !== null && it._dday >= 0 && it._dday <= 3) urg3++;
    if (it._score >= 70) sa++;
    if (it._aptGold >= 75) aptGoldCnt++;
    catCnt[it.category] = (catCnt[it.category] || 0) + 1;
    it._doms.forEach(d => { domCnt[d.k]++; });
    if (it.budgetMan > 0) { buds.push(it.budgetMan); budSum += it.budgetMan; }
  }
  for (const c of Object.values(CRM)) {
    if (c.stage && c.stage !== '보류') { pipeCnt++; pipeSum += Number(c.estMan || 0); }
  }

  // HHI & Pareto
  buds.sort((a, b) => b - a);
  let hhi = 0, cr3 = 0, top20 = 0, gini = NaN;
  const pPts = [[0, 0]];
  if (buds.length >= 3 && budSum > 0) {
    const m = buds.length;
    const asc = [...buds].reverse();
    let cum = 0;
    for (let k = 0; k < m; k++) {
      const sh = (buds[k] / budSum) * 100;
      hhi += sh * sh; if (k < 3) cr3 += sh; cum += buds[k];
      if (k === Math.max(0, Math.floor(m * 0.2) - 1)) top20 = (cum / budSum) * 100;
    }
    for (let step = 1; step <= 10; step++) {
      const idx = Math.min(m - 1, Math.floor((m - 1) * (step / 10)));
      let s = 0; for (let j = 0; j <= idx; j++) s += buds[j];
      pPts.push([step * 10, (s / budSum) * 100]);
    }
    let ac = 0, area = 0;
    for (let k = 0; k < m; k++) { ac += asc[k]; area += (ac - asc[k] / 2) / budSum; }
    gini = 1 - (2 * area) / m;
  }

  const paretoSvg = buds.length >= 3 ? (() => {
    const W = 500, H = 160, p = 24;
    const X = x => p + (x / 100) * (W - p * 2), Y = y => H - p - (y / 100) * (H - p * 2);
    const poly = pPts.map(([x, y]) => `${X(x).toFixed(1)},${Y(y).toFixed(1)}`).join(' ') + ` ${X(100)},${Y(0)} ${X(0)},${Y(0)}`;
    return `<svg viewBox="0 0 ${W} ${H}" class="pareto-svg">
      <line x1="${X(0)}" y1="${Y(0)}" x2="${X(100)}" y2="${Y(100)}" class="diag"/>
      <polygon points="${poly}" class="curve"/>
      <circle cx="${X(20)}" cy="${Y(top20)}" r="4" fill="var(--sel)"/>
      <text x="${X(20) + 7}" y="${Y(top20) + 4}" class="lbl" style="font-weight:700;fill:var(--sel)">상위 20% 공고 → 예산 ${top20.toFixed(0)}%</text>
      <text x="${W / 2}" y="${H - 5}" class="lbl" text-anchor="middle">공고 누적 비율 →</text>
    </svg>`;
  })() : '<p class="tiny">예산이 있는 공고가 3건 이상일 때 계산됩니다.</p>';

  const aptTop = RES.filter(x => x.category === 'apt').sort((a, b) => b._aptGold - a._aptGold).slice(0, 6);
  const wItems = [['budget', '예산 규모'], ['urgency', '마감 긴급도'], ['fit', '보안·AI 적합'], ['region', '지역 적합'], ['stage', '조기포착(사전규격/착공)'], ['scale', '단지·발주 규모']];
  const bar = (items, attr) => {
    const mx = Math.max(1, ...items.map(x => x.v));
    return `<div class="hbar">${items.map(x => `<div class="r" ${attr}="${x.k}"><span class="l">${x.l}</span><span class="t"><i style="width:${x.v / mx * 100}%;${x.c ? `background:${x.c}` : ''}"></i></span><span class="n">${fmt(x.v)}건</span></div>`).join('')}</div>`;
  };

  el.innerHTML = `
  <div class="card pro-hero">
    <h3>🏆 입찰·영업기회 전문가 분석 TOP 10 <span class="tiny">조회 ${fmt(n)}건 · 총 예산 ${fmtBudget(budSum)}</span></h3>
    <div class="sub">카드를 클릭하면 해당 전략 조건이 즉시 필터로 적용됩니다.</div>
    <div class="kpis4">
      <div class="kpi-box" data-pq="urg"><div class="k">🚨 D-3 긴급마감</div><div class="v num" style="color:var(--c8)">${fmt(urg3)}건</div><div class="s">즉시 검토 대상</div></div>
      <div class="kpi-box" data-pq="sa"><div class="k">🏆 영업우선 S·A</div><div class="v num" style="color:var(--accent)">${fmt(sa)}건</div><div class="s">커스텀 70점+</div></div>
      <div class="kpi-box" data-pq="apt"><div class="k">🏘 노후 교체적기</div><div class="v num" style="color:var(--c3)">${fmt(aptGoldCnt)}건</div><div class="s">준공 10~25년 대단지</div></div>
      <div class="kpi-box" data-pq="crm"><div class="k">💼 수주 파이프라인</div><div class="v num" style="color:var(--c7)">${fmtBudget(pipeSum)}</div><div class="s">관리중 ${pipeCnt}건</div></div>
    </div>
  </div>

  <div class="card">
    <h3>① 영업기회 ICP 전략 가중치 커스텀 (6축 실시간 재채점)</h3>
    <div class="sub">전략 프리셋을 누르거나 슬라이더를 조절하면 모든 공고·단지의 S/A/B/C 우선순위가 즉시 재계산됩니다.</div>
    <div class="chips">${Object.entries(W_PRESETS).map(([k, p]) => `<button class="chip" data-wp="${k}">${p.name}</button>`).join('')}</div>
    <div class="wgrid">${wItems.map(([k, l]) => `<div class="wrow"><span>${l}</span><b id="wv_${k}">${PRO_W[k]}%</b><input type="range" min="0" max="50" step="5" value="${PRO_W[k]}" data-wk="${k}"></div>`).join('')}</div>
  </div>

  <div class="card">
    <h3>④ 자동 분류 타깃 분야별 기회 분포</h3>
    <div class="sub">공고명·현장 용도를 자동 분석해 6대 B2B 핵심 분야로 태깅 · 누르면 필터</div>
    ${bar(DOMAINS.map((d, idx) => ({ k: d.k, l: d.l, v: domCnt[d.k], c: `var(--c${(idx % 7) + 1})` })), 'data-pdom')}
  </div>

  <div class="card">
    <h3>③ 공동주택(K-apt) 노후화·교체 골든타임 랭킹</h3>
    <div class="sub">준공 10~16년(CCTV·주차관제 교체) / 17~25년(승강기·방수) + 세대수 가중 점수 · 누르면 상세</div>
    ${aptTop.length ? `<ul class="peers">${aptTop.map(x => `<li data-pid="${esc(x.id)}"><span>${esc(x.title.slice(0, 34))}</span><span class="num"><b style="color:var(--accent)">${x._aptGold}점</b> <span class="tiny">${x.meta?.households ? fmt(x.meta.households) + '세대' : ''}</span></span></li>`).join('')}</ul>` : '<p class="tiny">조회된 공동주택 항목이 없습니다.</p>'}
  </div>

  <div class="card">
    <h3>⑤ 발주 예산 집중도(HHI) & 파레토(80/20) · 지니계수</h3>
    <div class="sub">상위 대형 사업에 예산이 얼마나 집중되어 있는지 분석 (예산 확인 ${buds.length}건)</div>
    <div class="fkpi" style="margin-bottom:10px">
      <div><span>총 발주 예산</span><b class="num">${fmtBudget(budSum)}</b><em>조회 기준 합계</em></div>
      <div><span>HHI 집중도</span><b class="num">${buds.length >= 3 ? fmt(hhi) : '-'}</b><em>${hhi >= 2500 ? '대형건 집중' : '분산 분포'}</em></div>
      <div><span>상위 3건(CR3)</span><b class="num">${buds.length >= 3 ? cr3.toFixed(0) + '%' : '-'}</b><em>상위20% ${top20.toFixed(0)}%</em></div>
      <div><span>지니계수</span><b class="num">${ok(gini) ? gini.toFixed(2) : '-'}</b><em>예산 편중도</em></div>
    </div>
    ${paretoSvg}
  </div>`;
}

/* ==================== Interactive Korea Map ==================== */
const NS = 'http://www.w3.org/2000/svg';
let VB, VB0, REG_EL = [], REG_CNT, LABELS;
function initMap() {
  const svg = $('#map'); VB0 = [-20, -20, MAP.w + 40, MAP.h + 40]; VB = [...VB0];
  const g = document.createElementNS(NS, 'g'); svg.appendChild(g);
  MAP.regions.forEach(r => { const p = document.createElementNS(NS, 'path'); p.setAttribute('d', r.d); p.setAttribute('class', 'rg'); p.dataset.id = r.id; g.appendChild(p); REG_EL[r.id] = p; });
  const sg = document.createElementNS(NS, 'g'); MAP.sidos.forEach(s => { const p = document.createElementNS(NS, 'path'); p.setAttribute('d', s.d); p.setAttribute('class', 'sdl'); sg.appendChild(p); }); g.appendChild(sg);
  LABELS = document.createElementNS(NS, 'g'); g.appendChild(LABELS);
  applyVB();
  $('#sdbar').innerHTML = '<button data-sd="" class="on">전국</button>' + MAP.sidos.map(s => `<button data-sd="${s.sd}">${s.s}</button>`).join('');
  $('#sdbar').onclick = e => { const b = e.target.closest('button'); if (!b) return; const sd = b.dataset.sd; S.sido = sd; S.sggs = []; $('#fSido').value = sd; fillSgg(); run(); zoomToSido(sd); };
  $('#mapMode').onclick = e => { const b = e.target.closest('button'); if (!b) return; MAPMODE = b.dataset.m; $$('#mapMode button').forEach(x => x.classList.toggle('on', x.dataset.m === MAPMODE)); renderMap(); };

  const wrap = $('#mapwrap'), tip = $('#tip');
  let drag = null, moved = false;
  const toSvg = (cx, cy) => { const rc = svg.getBoundingClientRect(), s = Math.max(VB[2] / rc.width, VB[3] / rc.height); const ox = (rc.width * s - VB[2]) / 2, oy = (rc.height * s - VB[3]) / 2; return [VB[0] - ox + (cx - rc.left) * s, VB[1] - oy + (cy - rc.top) * s, s]; };
  svg.addEventListener('pointerdown', e => { svg.setPointerCapture(e.pointerId); moved = false; drag = { x: e.clientX, y: e.clientY, vb: [...VB] }; });
  svg.addEventListener('pointermove', e => {
    if (drag) {
      const [, , s] = toSvg(0, 0), dx = (e.clientX - drag.x) * s, dy = (e.clientY - drag.y) * s;
      if (Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y) > 4) moved = true;
      if (moved) { VB = [drag.vb[0] - dx, drag.vb[1] - dy, drag.vb[2], drag.vb[3]]; applyVB(); tip.style.display = 'none'; }
      return;
    }
    const t = e.target.closest('.rg');
    if (t) { const id = +t.dataset.id, r = MAP.regions[id], sd = MAP.sidos.find(s => s.sd === r.sd), rc = wrap.getBoundingClientRect(); tip.innerHTML = `<b>${sd.s} ${esc(r.n)}</b><br>${fmt(REG_CNT[id])}${MAPMODE === 'opp' ? '건 영업기회' : '개 건설·시설사'}`; tip.style.left = (e.clientX - rc.left) + 'px'; tip.style.top = (e.clientY - rc.top) + 'px'; tip.style.display = 'block'; }
    else tip.style.display = 'none';
  });
  const end = e => {
    if (!moved) {
      const t = document.elementFromPoint(e.clientX, e.clientY), rg = t && t.closest && t.closest('.rg');
      if (rg) { const id = +rg.dataset.id; S.sggs = S.sggs.includes(id) ? S.sggs.filter(x => x !== id) : [...S.sggs, id]; run(); toast(`${regName(id)} 필터 ${S.sggs.includes(id) ? '추가' : '해제'}`); }
    }
    drag = null;
  };
  svg.addEventListener('pointerup', end); svg.addEventListener('pointercancel', end); svg.addEventListener('pointerleave', () => tip.style.display = 'none');
  svg.addEventListener('wheel', e => { e.preventDefault(); const [x, y] = toSvg(e.clientX, e.clientY); zoomAt(x, y, Math.exp(e.deltaY * 0.0015), VB); }, { passive: false });
  $('#zin').onclick = () => zoomAt(VB[0] + VB[2] / 2, VB[1] + VB[3] / 2, 0.68, VB);
  $('#zout').onclick = () => zoomAt(VB[0] + VB[2] / 2, VB[1] + VB[3] / 2, 1.48, VB);
  $('#zreset').onclick = () => { VB = [...VB0]; applyVB(); };
}
function zoomAt(x, y, k, base) { const w = Math.min(VB0[2] * 1.2, Math.max(45, base[2] * k)), kk = w / base[2], h = base[3] * kk; VB = [x - (x - base[0]) * kk, y - (y - base[1]) * kk, w, h]; applyVB(); }
function applyVB() { $('#map').setAttribute('viewBox', VB.join(' ')); renderLabels(); }
function zoomToSido(sd) { $$('#sdbar button').forEach(b => b.classList.toggle('on', b.dataset.sd === sd)); if (!sd) { VB = [...VB0]; applyVB(); return; } const s = MAP.sidos.find(x => x.sd === sd); if (s) { const b = s.b, w = b[2] - b[0], h = b[3] - b[1], p = Math.max(w, h, 50) * .18 + 10; VB = [b[0] - p, b[1] - p, w + 2 * p, h + 2 * p]; applyVB(); } }
let RADAR_MAP = null, RADAR_LAYER = null, RADAR_STAGE = 'early', RADAR_MODE = 'cluster', RADAR_URG = '';
let KAKAO_SYNC = { syncing: false, lastAt: '', liveCnt: 0 };

function radarCentroidLatLon(rid) {
  const reg = MAP?.regions?.[rid];
  if (!reg?.c) return [37.5665, 126.9780];
  const [x, y] = reg.c;
  return [
    Math.round((-0.0058438 * y + 38.61497) * 1e5) / 1e5,
    Math.round((0.0073628 * x + 124.59339) * 1e5) / 1e5,
  ];
}

function radarOppStageMeta(st) {
  if (st === 'prespec') return { label: '🔭 사전규격', color: '#7c3aed', early: true };
  if (st === 'permit') return { label: '🏗️ 인허가·신축', color: '#e11d48', early: true };
  if (st === 'complex') return { label: '🏘️ K-apt', color: '#059669', early: false };
  return { label: '📢 입찰공고', color: '#d97706', early: false };
}

function ensureRadarShell() {
  const box = $('#radarMapBox');
  if (!box || box.dataset.ready === '1') return;
  box.dataset.ready = '1';
  box.innerHTML = `
    <div class="radar-bar" id="radarBar">
      <button class="radar-pill" data-rs="">전체</button>
      <button class="radar-pill on" data-rs="early">⚡ 조기포착</button>
      <button class="radar-pill" data-rs="prespec">🔭 사전규격</button>
      <button class="radar-pill" data-rs="permit">🏗️ 인허가·신축</button>
      <button class="radar-pill" data-rs="complex">🏘️ K-apt</button>
      <button class="radar-pill" data-rs="bid">📢 입찰</button>
      <button class="radar-pill" data-ru="todayBid">📅 당일입찰</button>
      <button class="radar-pill" data-ru="d3">🚨 D-3</button>
      <button class="radar-pill" data-ru="live">🟢 카톡실시간</button>
      <button class="radar-pill on" data-rm="cluster" style="margin-left:auto">🔵 시군구</button>
      <button class="radar-pill" data-rm="pins">📍 개별핀</button>
      <button class="radar-pill" id="btnRadarFit">🎯 맞춤</button>
      <button class="radar-pill on-green" id="btnRadarSync">🔄 최신화</button>
    </div>
    <div id="radarLeaflet" class="radar-canvas"></div>
    <div class="radar-foot" id="radarFoot">
      <span>🟣 사전규격</span><span>🔴 인허가·신축</span><span>🟢 K-apt</span><span>🟠 입찰(빨간테=D-3)</span>
      <span id="radarStatTxt" style="margin-left:auto;font-weight:700"></span>
    </div>
  `;
  $('#radarBar').onclick = e => {
    const rs = e.target.closest('[data-rs]');
    if (rs) { RADAR_STAGE = rs.dataset.rs; renderRadarMap(true); return; }
    const ru = e.target.closest('[data-ru]');
    if (ru) {
      RADAR_URG = RADAR_URG === ru.dataset.ru ? '' : ru.dataset.ru;
      if (RADAR_URG === 'todayBid' && RADAR_STAGE && RADAR_STAGE !== 'bid') RADAR_STAGE = '';
      renderRadarMap(true);
      return;
    }
    const rm = e.target.closest('[data-rm]');
    if (rm) { RADAR_MODE = rm.dataset.rm; renderRadarMap(false); return; }
  };
  $('#btnRadarFit').onclick = () => renderRadarMap(true);
  $('#btnRadarSync').onclick = () => autoSyncKakaoLiveFeeds(false);

  const vwKey = String(store.get('vworldKey', '') || META?.vaultKeys?.vworld || '').replace(/\s+/g, '');
  RADAR_MAP = L.map($('#radarLeaflet'), { preferCanvas: true }).setView([36.85, 127.4], 7);
  if (vwKey) {
    L.tileLayer(`https://api.vworld.kr/req/wmts/1.0.0/${encodeURIComponent(vwKey)}/Base/{z}/{y}/{x}.png`, { maxZoom: 19, attribution: '© VWorld 국토교통부' }).addTo(RADAR_MAP);
  } else {
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '© OpenStreetMap' }).addTo(RADAR_MAP);
  }
  RADAR_LAYER = L.layerGroup().addTo(RADAR_MAP);
  window._bidOpenDet = id => openDetail(id);
}

function renderRadarMap(fit = false) {
  ensureRadarShell();
  if (!RADAR_MAP || !RADAR_LAYER) return;
  setTimeout(() => RADAR_MAP.invalidateSize(), 60);

  $$('#radarBar [data-rs]').forEach(b => b.classList.toggle('on', b.dataset.rs === RADAR_STAGE));
  $$('#radarBar [data-ru]').forEach(b => b.classList.toggle('on-green', b.dataset.ru === RADAR_URG));
  $$('#radarBar [data-rm]').forEach(b => b.classList.toggle('on', b.dataset.rm === RADAR_MODE));

  const todayIso = getTodayKstIso();
  const items = RES.filter(o => {
    const sm = radarOppStageMeta(o.stageType);
    if (RADAR_STAGE === 'early' && !sm.early) return false;
    if (RADAR_STAGE && RADAR_STAGE !== 'early' && o.stageType !== RADAR_STAGE) return false;
    if (RADAR_URG === 'todayBid' && !(o.stageType === 'bid' && isTodayOpp(o, todayIso))) return false;
    if (RADAR_URG === 'd3' && !(o._dday !== null && o._dday >= 0 && o._dday <= 3)) return false;
    if (RADAR_URG === 'live' && !o.isLive) return false;
    return true;
  });

  RADAR_LAYER.clearLayers();
  const bounds = [];
  const mapped = items.filter(o => o.rid >= 0);

  if (RADAR_MODE === 'cluster') {
    const byRid = new Map();
    for (const o of mapped) {
      let g = byRid.get(o.rid);
      if (!g) {
        const [la, lo] = radarCentroidLatLon(o.rid);
        g = { rid: o.rid, name: regName(o.rid), lat: la, lon: lo, list: [], early: 0, urgent: 0 };
        byRid.set(o.rid, g);
      }
      g.list.push(o);
      if (radarOppStageMeta(o.stageType).early) g.early++;
      if (o._dday !== null && o._dday >= 0 && o._dday <= 3) g.urgent++;
    }
    for (const g of byRid.values()) {
      bounds.push([g.lat, g.lon]);
      const cnt = g.list.length;
      const sz = cnt >= 40 ? 34 : cnt >= 15 ? 29 : cnt >= 5 ? 25 : 21;
      const bg = g.early > 0 ? '#7c3aed' : (g.list[0].stageType === 'complex' ? '#059669' : '#d97706');
      const ring = g.urgent > 0 ? 'urgent-ring' : (g.early > 0 ? 'early-ring' : '');
      const icon = L.divIcon({ className: '', html: `<div class="nx-bid-pin ${ring}" style="width:${sz}px;height:${sz}px;background:${bg}">${cnt > 99 ? '99+' : cnt}</div>`, iconSize: [sz, sz], iconAnchor: [sz / 2, sz / 2] });
      const mk = L.marker([g.lat, g.lon], { icon });
      mk.bindTooltip(`<b>${esc(g.name)}</b> · ${cnt}건 (조기포착 ${g.early}${g.urgent ? ` · 🚨D-3 ${g.urgent}` : ''})`, { direction: 'top', offset: [0, -sz / 2] });
      mk.bindPopup(() => {
        const cPre = g.list.filter(x => x.stageType === 'prespec').length;
        const cPer = g.list.filter(x => x.stageType === 'permit').length;
        const cKap = g.list.filter(x => x.stageType === 'complex').length;
        const cBid = g.list.filter(x => x.stageType === 'bid').length;
        return `<div style="min-width:240px;max-width:300px;font-size:12px">
          <b>📍 ${esc(g.name)} (${cnt}건)</b>
          <div style="display:flex;flex-wrap:wrap;gap:4px;margin:4px 0 6px;font-size:10.5px;font-weight:700">
            ${cPre ? `<span style="background:#ede9fe;color:#6d28d9;padding:1px 5px;border-radius:4px">🔭사전 ${cPre}</span>` : ''}
            ${cPer ? `<span style="background:#ffe4e6;color:#be123c;padding:1px 5px;border-radius:4px">🏗️인허가·신축 ${cPer}</span>` : ''}
            ${cKap ? `<span style="background:#d1fae5;color:#047857;padding:1px 5px;border-radius:4px">🏘️K-apt ${cKap}</span>` : ''}
            ${cBid ? `<span style="background:#fef3c7;color:#b45309;padding:1px 5px;border-radius:4px">📢입찰 ${cBid}</span>` : ''}
          </div>
          <div style="max-height:170px;overflow-y:auto;border-top:1px solid #e2e8f0;padding-top:4px">
            ${g.list.slice(0, 20).map(it => `<div onclick="window._bidOpenDet('${esc(it.id)}')" style="padding:4px 2px;border-bottom:1px dashed #e2e8f0;cursor:pointer">
              <div style="font-weight:700;font-size:11.5px">${esc(it.title)}</div>
              <div style="font-size:10.5px;color:#64748b">${esc(it.org || '-')} · ${it.budgetMan > 0 ? fmt(it.budgetMan) + '만원' : '미기재'}</div>
              <div style="font-size:10px;color:#334155;font-weight:600;margin-top:1px">${esc(oppDateSummary(it))}</div>
            </div>`).join('')}
          </div>
        </div>`;
      }, { maxWidth: 320 });
      mk.addTo(RADAR_LAYER);
    }
  } else {
    for (const o of mapped.slice(0, 700)) {
      const [la0, lo0] = radarCentroidLatLon(o.rid);
      let h = 0; const s = String(o.id || o.title);
      for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
      const ang = (Math.abs(h) % 360) * Math.PI / 180, rad = 0.002 + ((Math.abs(h >> 8) % 100) / 100) * 0.012;
      const la = la0 + Math.sin(ang) * rad, lo = lo0 + Math.cos(ang) * rad * 1.25;
      bounds.push([la, lo]);
      const sm = radarOppStageMeta(o.stageType);
      const urg = o._dday !== null && o._dday >= 0 && o._dday <= 3;
      const mk = L.circleMarker([la, lo], { radius: sm.early || urg ? 7 : 5.5, color: urg ? '#ef4444' : '#fff', fillColor: sm.color, fillOpacity: 0.92, weight: urg ? 2.5 : 1.5 });
      mk.bindTooltip(`<b>${sm.label} ${esc(o.title)}</b><br><span style="font-size:11px">${esc(oppDateSummary(o))}</span>`, { direction: 'top', offset: [0, -6] });
      mk.bindPopup(`<div style="min-width:230px;font-size:12px">
        <span style="padding:1px 6px;border-radius:4px;background:${sm.color};color:#fff;font-size:10.5px;font-weight:800">${sm.label}</span>
        ${o.isLive ? '<span style="margin-left:4px;padding:1px 6px;border-radius:4px;background:#dbeafe;color:#1d4ed8;font-size:10.5px;font-weight:800">🟢실시간</span>' : ''}
        <div style="font-weight:800;margin:4px 0">${esc(o.title)}</div>
        <div style="font-size:11px;color:#475569">🏛️ ${esc(o.org || '-')} · ${esc(o.region || regName(o.rid))}</div>
        <div style="font-size:11px;color:#1e293b;font-weight:700;margin-top:3px">${esc(oppDateSummary(o))}</div>
        <div style="margin-top:6px;display:flex;gap:5px">
          <button onclick="window._bidOpenDet('${esc(o.id)}')" style="padding:4px 8px;border:none;border-radius:6px;background:#4f46e5;color:#fff;font-size:11px;font-weight:700;cursor:pointer">📄 상세보기</button>
          ${o.url ? `<a href="${esc(o.url)}" target="_blank" rel="noopener" style="padding:4px 8px;border:1px solid #cbd5e1;border-radius:6px;color:#0f172a;font-size:11px;font-weight:700;text-decoration:none">🔗 원문</a>` : ''}
        </div>
      </div>`);
      mk.addTo(RADAR_LAYER);
    }
  }

  const stEl = $('#radarStatTxt');
  if (stEl) stEl.textContent = `조건 ${fmt(items.length)}건 (지도 ${fmt(mapped.length)}건)${KAKAO_SYNC.lastAt ? ` · 🟢실시간 ${KAKAO_SYNC.lastAt}` : ''}`;
  if (fit && bounds.length) RADAR_MAP.fitBounds(bounds, { maxZoom: 13, padding: [22, 22] });
}

function syncMainMapMode() {
  const isPrec = MAPMODE === 'precision';
  const isRadar = MAPMODE === 'radar';
  const wrap = $('#mapwrap');
  const box = $('#vwMainMap');
  const rbox = $('#radarMapBox');
  if (wrap) {
    wrap.classList.toggle('precision-on', isPrec);
    wrap.classList.toggle('radar-on', isRadar);
  }
  if (box) box.hidden = !isPrec;
  if (rbox) rbox.hidden = !isRadar;
  if (isRadar) { renderRadarMap(false); return; }
  if (isPrec && box && window.VWorldTwin) {
    if (!VW_MAIN) {
      VW_MAIN = window.VWorldTwin.createMainMap(box, {
        store,
        getMeta: () => META,
        getItems: lim => RES.slice(0, lim).map(it => ({
          id: it.id,
          name: it.org || it.title,
          addr: it.region || it.org,
          sub: `${CAT_LBL[it.category]} · ${it.title.slice(0, 26)}`,
          color: it.category === 'apt' ? '#059669' : it.category === 'construction' ? '#d97706' : '#2563eb',
          grade: it._grade,
          score: it._score,
        })),
        onOpenItem: id => openDetail(id),
        toast,
        itemLabel: '입찰·단지',
      });
    }
    VW_MAIN.show();
  }
}
function renderMap() {
  if (!REG_EL.length) return;
  $$('#mapMode button').forEach(x => x.classList.toggle('on', x.dataset.m === MAPMODE));
  syncMainMapMode();
  if (MAPMODE === 'precision' || MAPMODE === 'radar') return;
  REG_CNT = new Int32Array(MAP.regions.length);
  if (MAPMODE === 'opp') { for (const it of RES) if (it.rid >= 0) REG_CNT[it.rid]++; }
  else { for (const b of BLD_SCORED) if (b.r[10] >= 0 && (!BS.activeOnly || b.st === 1 || b.st === 0)) REG_CNT[b.r[10]]++; }
  const mx = Math.max(1, ...REG_CNT);
  const cols = ['var(--zero)', 'var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)', 'var(--s6)', 'var(--s7)'];
  REG_EL.forEach((p, id) => {
    const v = REG_CNT[id]; const c = !v ? 0 : Math.min(7, 1 + Math.floor(Math.log1p(v) / Math.log1p(mx) * 6.9));
    p.style.fill = cols[c]; p.classList.toggle('selr', S.sggs.includes(id));
  });
  $('#legend').innerHTML = `<div style="font-weight:700">${MAPMODE === 'opp' ? '시군구별 영업기회' : '시군구별 건설·시설사'}</div><div class="sw">${cols.map(c => `<i style="background:${c}"></i>`).join('')}</div><div class="tiny" style="display:flex;justify-content:space-between"><span>0</span><span>최대 ${fmt(mx)}</span></div>`;
  renderLabels();
}
function renderLabels() {
  if (!LABELS || !REG_CNT) return;
  const rc = $('#map').getBoundingClientRect(); if (!rc.width) return;
  const z = VB0[2] / VB[2], upx = Math.max(VB[2] / rc.width, VB[3] / rc.height), fs = upx * 16;
  LABELS.style.strokeWidth = (upx * 3) + 'px';
  let h = '';
  if (z < 2.2) {
    MAP.sidos.forEach(s => { let c = 0; MAP.regions.forEach(r => { if (r.sd === s.sd) c += REG_CNT[r.id]; }); h += `<text class="mlabel" x="${s.c[0]}" y="${s.c[1]}" style="font-size:${fs * .62}px">${s.s}<tspan x="${s.c[0]}" dy="${fs * .72}" style="font-size:${fs * .5}px">${fmt(c)}</tspan></text>`; });
  } else {
    const [x0, y0, w, hh] = VB;
    MAP.regions.forEach(r => { if (r.c[0] < x0 || r.c[0] > x0 + w || r.c[1] < y0 || r.c[1] > y0 + hh) return; if ((r.b[2] - r.b[0]) < upx * 38) return; h += `<text class="mlabel" x="${r.c[0]}" y="${r.c[1]}" style="font-size:${fs * .58}px">${esc(r.n)}${REG_CNT[r.id] ? `<tspan x="${r.c[0]}" dy="${fs * .68}" style="font-size:${fs * .5}px">${fmt(REG_CNT[r.id])}</tspan>` : ''}</text>`; });
  }
  LABELS.innerHTML = h;
}

/* ==================== Real Construction & Facility DB Tab (12,198 companies) ==================== */
function renderBuilders() {
  const el = $('#builders'); if (!el) return;
  const q = BS.q.toLowerCase(), qc = isCho(BS.q.replace(/\s/g, '')) ? BS.q.replace(/\s/g, '') : '';
  const list = BLD_SCORED.filter(b => {
    if (BS.activeOnly && (b.st === 2 || b.st === 3)) return false;
    if (BS.sec && b.sec !== BS.sec) return false;
    if (BS.cred === 'hi' && !(b.cred >= 1 && b.cred <= 3)) return false;
    if (BS.sido) { const reg = b.r[10] >= 0 ? MAP.regions[b.r[10]] : null; if (!reg || reg.sd !== BS.sido) return false; }
    if (q) { if (qc ? !b._cho.includes(qc) : !b._search.includes(q)) return false; }
    return true;
  });
  const sorters = {
    score: (a, b) => b.score - a.score,
    rev: (a, b) => (ok(b.rev) ? b.rev : -1) - (ok(a.rev) ? a.rev : -1),
    emp: (a, b) => (ok(b.emp) ? b.emp : -1) - (ok(a.emp) ? a.emp : -1),
    r40: (a, b) => (ok(b.r40) ? b.r40 : -999) - (ok(a.r40) ? a.r40 : -999),
  };
  list.sort(sorters[BS.sort] || sorters.score);

  // Location Quotient (LQ) when sido selected
  let lqHtml = '';
  if (BS.sido && list.length >= 20) {
    const loc = {}; list.forEach(b => { loc[b.sec] = (loc[b.sec] || 0) + 1; });
    const lqs = Object.entries(loc).map(([k, c]) => ({ k, c, lq: (c / list.length) / ((NAT_BLD_SEC[k] || 1) / BLD_SCORED.length) })).sort((a, b) => b.lq - a.lq);
    lqHtml = `<div class="tiny" style="margin-top:8px"><b>지역 특화 입지계수(LQ):</b> ${lqs.map(x => `${SEC_LBL[x.k]} <b>${x.lq.toFixed(2)}배</b>`).join(' · ')}</div>`;
  }

  el.innerHTML = `
  <div class="card">
    <h3>🏗 전국 건설사 · 시설관리 · 전기통신 실데이터 <span class="tiny">총 ${fmt(BLD_SCORED.length)}개사 (조회 ${fmt(list.length)}개사)</span></h3>
    <div class="sub">DART 재무 + 국민연금 직원·입퇴사 + 국세청 휴폐업 + Hybrid 신용등급(AAA~D) 실시간 연동</div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
      <input class="inp" id="bQ" value="${esc(BS.q)}" placeholder="건설사명·대표자·주소·초성 검색" style="flex:1;min-width:160px;height:34px">
      <select class="inp" id="bSido" style="width:120px;height:34px"><option value="">전국</option>${MAP.sidos.map(s => `<option value="${s.sd}"${BS.sido === s.sd ? ' selected' : ''}>${s.s}</option>`).join('')}</select>
      <select class="inp" id="bSort" style="width:130px;height:34px"><option value="score"${BS.sort === 'score' ? ' selected' : ''}>우량 종합순</option><option value="rev"${BS.sort === 'rev' ? ' selected' : ''}>매출액순</option><option value="emp"${BS.sort === 'emp' ? ' selected' : ''}>직원수순</option><option value="r40"${BS.sort === 'r40' ? ' selected' : ''}>Rule of 40순</option></select>
      <button class="iconbtn sm" id="bCsv">CSV</button>
    </div>
    <div class="chips" id="bSecChips">
      <button class="chip" data-bsec="" aria-pressed="${!BS.sec}">전체</button>
      ${Object.entries(SEC_LBL).map(([k, l]) => `<button class="chip" data-bsec="${k}" aria-pressed="${BS.sec === k}">${l}</button>`).join('')}
      <button class="chip" data-bcred="hi" aria-pressed="${BS.cred === 'hi'}">🛡 신용 우량(AAA~A)</button>
      <button class="chip" data-bact="1" aria-pressed="${BS.activeOnly}">계속사업자만</button>
    </div>
    ${lqHtml}
  </div>
  <div class="card">
    <div class="tblwrap"><table class="tbl"><thead><tr><th>회사명</th><th>분야</th><th>신용</th><th>매출(억)</th><th>이익률</th><th>직원</th><th>최근입사</th></tr></thead><tbody>
      ${list.slice(0, 80).map(b => `<tr data-bi="${b.idx}">
        <td style="max-width:170px;overflow:hidden;text-overflow:ellipsis"><b>${esc(b.r[0])}</b></td>
        <td class="tiny">${esc(SEC_LBL[b.sec])}</td>
        <td>${b.cred ? `<span class="grd ${b.cred <= 3 ? 'g-s' : b.cred <= 5 ? 'g-a' : 'g-c'}">${CRED_LBL[b.cred]}</span>` : '-'}</td>
        <td class="num">${ok(b.rev) ? fmt(b.rev) : '-'}</td>
        <td class="num">${ok(b.mrg) ? b.mrg.toFixed(1) + '%' : '-'}</td>
        <td class="num">${ok(b.emp) ? fmt(b.emp) : '-'}</td>
        <td class="num" style="color:var(--c3)">${ok(b.nw) ? '+' + b.nw : '-'}</td>
      </tr>`).join('')}
    </tbody></table></div>
    ${list.length > 80 ? `<p class="tiny" style="margin:8px 0 0">상위 80개 표시 중 (전체 ${fmt(list.length)}개사 · CSV 버튼으로 최대 10,000개 저장 가능)</p>` : ''}
  </div>`;

  $('#bQ').oninput = debounce(e => { BS.q = e.target.value.trim(); renderBuilders(); }, 200);
  $('#bSido').onchange = e => { BS.sido = e.target.value; renderBuilders(); };
  $('#bSort').onchange = e => { BS.sort = e.target.value; renderBuilders(); };
  $('#bSecChips').onclick = e => {
    const b = e.target.closest('.chip'); if (!b) return;
    if (b.dataset.bsec !== undefined) BS.sec = b.dataset.bsec;
    else if (b.dataset.bcred) BS.cred = BS.cred === 'hi' ? '' : 'hi';
    else if (b.dataset.bact) BS.activeOnly = !BS.activeOnly;
    renderBuilders();
  };
  $('#bCsv').onclick = () => {
    const lim = Math.min(list.length, 10000);
    const rows = [['회사명', '분야', '업종', '대표자', '사업자번호', '상태', '신용등급', '매출(억)', '영업이익(억)', '직원수', '월입사', '전화번호', '홈페이지', '주소']];
    for (let k = 0; k < lim; k++) {
      const b = list[k], r = b.r;
      rows.push([r[0], SEC_LBL[b.sec], BLD_IND[r[8]] || '', r[2], r[4], ['', '계속', '휴업', '폐업'][b.st] || '미확인', b.cred ? CRED_LBL[b.cred] : '', ok(b.rev) ? b.rev : '', ok(b.op) ? b.op : '', ok(b.emp) ? b.emp : '', ok(b.nw) ? b.nw : '', r[6], r[7], r[5]]);
    }
    downloadCsv(rows, `건설사_시설관리_${todayStr()}.csv`);
  };
  el.querySelectorAll('tr[data-bi]').forEach(tr => tr.onclick = () => openBuilderDetail(+tr.dataset.bi));
}

function openBuilderDetail(idx) {
  const b = BLD_SCORED[idx], r = b.r, q = encodeURIComponent;
  const tel = r[6], home = homeUrl(r[7]), addr = r[5];
  $('#dbody').innerHTML = `
  <div class="dh"><div style="flex:1;min-width:0"><h2>${esc(r[0])}</h2><div class="tiny" style="margin-top:4px">${esc(SEC_LBL[b.sec])} · ${esc(BLD_IND[r[8]] || '')}</div></div>
    <button class="close" id="dclose">✕</button></div>
  <div class="db">
    <div class="actions">
      <a href="${tel ? 'tel:' + digits(tel) : '#'}" class="${tel ? '' : 'dis'}"><span class="ico">📞</span>전화</a>
      <a href="${home || '#'}" target="_blank" rel="noopener" class="${home ? '' : 'dis'}"><span class="ico">🌐</span>홈페이지</a>
      <a href="https://map.naver.com/p/search/${q(addr || r[0])}" target="_blank" rel="noopener"><span class="ico">📍</span>네이버지도</a>
      <a href="https://map.kakao.com/?q=${q(addr || r[0])}" target="_blank" rel="noopener"><span class="ico">🗺</span>카카오맵</a>
    </div>
    <div class="sec"><h4>🏆 건설사 퀀트·신용 진단</h4><div class="sales"><div class="fkpi">
      <div><span>신용등급</span><b>${b.cred ? `${CRED_LBL[b.cred]} (${b.z}점)` : '-'}</b><em>${['미확인', '국세청 계속', '휴업', '폐업'][b.st] || '-'}</em></div>
      <div><span>매출액</span><b class="num">${ok(b.rev) ? fmt(b.rev) + '억' : '-'}</b><em>${ok(b.grw) ? `성장 ${b.grw >= 0 ? '+' : ''}${b.grw.toFixed(1)}%` : 'DART 기준'}</em></div>
      <div><span>영업이익</span><b class="num">${ok(b.op) ? fmt(b.op) + '억' : '-'}</b><em>${ok(b.mrg) ? `이익률 ${b.mrg.toFixed(1)}%` : ''}</em></div>
      <div><span>직원 / 입사</span><b class="num">${ok(b.emp) ? fmt(b.emp) + '명' : '-'}</b><em>${ok(b.nw) ? `월 입사 +${b.nw} / 퇴사 ${b.ls || 0}` : ''}</em></div>
      <div><span>추정 연봉</span><b class="num">${ok(b.wage) ? fmt(b.wage * 12) + '만' : '-'}</b><em>국민연금 기준</em></div>
      <div><span>1인당 매출</span><b class="num">${ok(b.rpe) ? b.rpe.toFixed(1) + '억' : '-'}</b><em>Rule of 40: ${ok(b.r40) ? b.r40.toFixed(0) : '-'}</em></div>
    </div></div></div>
    <dl class="kv">
      <dt>대표자</dt><dd><span>${esc(r[2] || '-')}</span></dd>
      <dt>사업자번호</dt><dd><span class="num">${esc(r[4])}</span><button class="cp" data-cp="${esc(r[4])}">복사</button></dd>
      <dt>주소</dt><dd><span>${esc(addr || '-')}</span>${addr ? `<button class="cp" data-cp="${esc(addr)}">복사</button>` : ''}</dd>
      <dt>전화번호</dt><dd><span class="num">${esc(tel || '-')}</span>${tel ? `<button class="cp" data-cp="${esc(tel)}">복사</button>` : ''}</dd>
      <dt>설립일</dt><dd><span class="num">${r[9] ? `${String(r[9]).slice(0, 4)}.${String(r[9]).slice(4, 6)}.${String(r[9]).slice(6, 8)}` : '-'}</span></dd>
    </dl>
    <div class="sec"><h4>🗺 일반 정밀지도 · 지적 · 공시지가 (브이월드)</h4><div class="sales" id="vwBldBox">
      <p class="tiny" style="margin:0 0 8px">건설사·시설관리업체 소재지의 일반 정밀지도(도로·건물)·항공·연속지적도·용도지역·개별공시지가를 실시간 확인합니다.</p>
      <button type="button" class="aibtn" id="btnVwBld" style="margin:0;background:linear-gradient(135deg,#0f766e,#0284c7)">🗺 일반 정밀지도 · 지적 · 공시지가 보기</button>
    </div></div>
  </div>`;
  $('#dclose').onclick = closeDetail;
  const loadBldVw = () => window.VWorldTwin?.renderInspector($('#vwBldBox'), { addr, name: r[0], store, meta: META });
  $('#btnVwBld')?.addEventListener('click', loadBldVw);
  if (window.VWorldTwin?.getKey(store, META)) loadBldVw();
  if (MAPMODE === 'precision' && VW_MAIN && (addr || r[0])) VW_MAIN.focusItem({ id: idx, name: r[0], addr });
  $('#dbody').querySelectorAll('[data-cp]').forEach(x => x.onclick = () => copy(x.dataset.cp));
  $('#detail').classList.add('on'); $('#detail').setAttribute('aria-hidden', 'false'); updateScrim();
}

/* ==================== Live OpenAPI Collector & File Upload Tab ==================== */
let LAST_API_LOG = '대기 중… 버튼을 누르면 실시간 API를 호출합니다.';
let LAST_API_DIAG = null;
function normalizeDataGoKey(raw) {
  const clean = String(raw || '').replace(/\s+/g, '');
  if (!clean) return '';
  try {
    const dec = clean.includes('%') ? decodeURIComponent(clean) : clean;
    return encodeURIComponent(dec);
  } catch {
    return clean.includes('%') ? clean : encodeURIComponent(clean);
  }
}
function maskKeyPreview(raw) {
  const s = String(raw || '').replace(/\s+/g, '');
  if (!s) return '미입력';
  if (s.length <= 16) return `${s.slice(0, 4)}… (${s.length}자)`;
  return `${s.slice(0, 7)}…${s.slice(-7)} (${s.length}자)`;
}
function getEffectiveDataGoKey() {
  const inputEl = $('#apiKeyIn');
  const typed = (inputEl ? inputEl.value : '').replace(/\s+/g, '');
  const local = String(store.get('dataGoKey', '') || '').replace(/\s+/g, '');
  const vault = String(META?.vaultKeys?.dataGo || '').replace(/\s+/g, '');
  if (typed && typed.length >= 50) return typed;
  if (local && local.length >= 50) return local;
  return vault || typed || local;
}
function renderDiagBoardHtml() {
  if (!LAST_API_DIAG) return '';
  const { checkedAt, keyMask, items } = LAST_API_DIAG;
  return `
  <div style="margin-top:10px;padding:10px;border:1px solid var(--bd);border-radius:10px;background:var(--bg)">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
      <strong style="font-size:12.5px">🩺 API 실시간 연결 진단 결과</strong>
      <span class="tiny">키: <code>${esc(keyMask)}</code> · ${esc(checkedAt)}</span>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px">
      ${items.map(it => {
        const bg = it.ok ? 'rgba(5,150,105,.12)' : it.status === 403 ? 'rgba(217,119,6,.12)' : 'rgba(220,38,38,.12)';
        const fg = it.ok ? '#059669' : it.status === 403 ? '#d97706' : '#dc2626';
        const icon = it.ok ? '🟢' : it.status === 403 ? '🟡' : '🔴';
        return `<div style="padding:8px 10px;border-radius:8px;background:${bg};font-size:12px">
          <div style="font-weight:700;color:${fg}">${icon} ${esc(it.name)}</div>
          <div style="margin-top:2px;font-weight:600">${esc(it.summary)}</div>
          <div class="tiny" style="margin-top:2px;opacity:.9">${esc(it.hint)}</div>
        </div>`;
      }).join('')}
    </div>
  </div>`;
}
function renderApiPanel() {
  const el = $('#apiPanel'); if (!el) return;
  const localKey = String(store.get('dataGoKey', '') || '').replace(/\s+/g, '');
  const vaultKey = String(META?.vaultKeys?.dataGo || '').replace(/\s+/g, '');
  const effKey = (localKey && localKey.length >= 50) ? localKey : (vaultKey || localKey);
  const keySrcLbl = (localKey && localKey.length >= 50) ? '수동 저장' : (vaultKey ? 'Vault 자동 적용' : '');
  const liveCnt = OPPS.filter(x => !x.sample).length;
  el.innerHTML = `
  <div class="card">
    <h3>🔌 공공데이터포털 OpenAPI 실시간 연동 <span class="tiny">실데이터 ${fmt(liveCnt)}건 수집됨</span></h3>
    <div class="sub">공공데이터포털(data.go.kr) 인증키가 암호화 볼트에 자동 적용되어 있습니다. 다른 키로 교체할 때만 입력 후 [키 저장]을 누르세요.</div>
    <div style="display:flex;gap:6px;margin-bottom:4px">
      <input class="inp" type="password" id="apiKeyIn" value="${esc(localKey)}" placeholder="${vaultKey ? '암호화 기본 인증키 자동 적용됨 (교체 시에만 입력)' : '공공데이터포털 일반 인증키 (Encoding 또는 Decoding)'}">
      <button class="iconbtn sm" id="apiToggleEye" style="height:36px" title="키 보기/숨기기">👁</button>
      <button class="iconbtn sm" id="apiSaveKey" style="height:36px">키 저장</button>
    </div>
    <div class="tiny" style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
      <span>공공데이터 키: <code id="apiKeyMask">${esc(maskKeyPreview(effKey))}${keySrcLbl ? ` (${keySrcLbl})` : ''}</code> · 브이월드: <code>${esc(window.VWorldTwin ? VWorldTwin.maskKey(VWorldTwin.getKey(store, META)) : '미로드')}</code></span>
      <button class="iconbtn sm" id="btnCheckApis" style="font-weight:700">🩺 전체 API 연결 진단 (6종)</button>
    </div>
    <div id="apiDiagBoard">${renderDiagBoardHtml()}</div>
    <div class="row2" style="margin:8px 0">
      <label class="tiny">조회 기간(일)<select class="inp" id="apiDays"><option value="3" selected>최근 3일</option><option value="5">최근 5일</option><option value="7">최근 7일</option></select></label>
      <label class="tiny">공동주택 지역(법정동)<select class="inp" id="apiBjd">${SIGUNGU_PRESETS.map(([c, n]) => `<option value="${c}">${n} (${c})</option>`).join('')}</select></label>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <button class="aibtn" id="btnFetchG2b" style="margin:0">📢 나라장터 입찰 (공사·용역·물품)</button>
      <button class="aibtn" id="btnFetchPre" style="margin:0;background:linear-gradient(135deg,#6d28d9,#1e40af)">🔭 나라장터 사전규격 (조기포착)</button>
      <button class="aibtn apt" id="btnFetchApt" style="margin:0">🏘 K-apt 공동주택 단지목록</button>
      <button class="aibtn" id="btnFetchArch" style="margin:0;background:linear-gradient(135deg,#b45309,#ea580c)">🏗 청약홈 신축아파트 분양</button>
    </div>
    <div class="apilog" id="apiLog">${esc(LAST_API_LOG)}</div>
    <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
      <button class="iconbtn sm" id="btnClearLive">수집 데이터 초기화</button>
      <a class="iconbtn sm" style="text-decoration:none" href="https://www.data.go.kr/tcs/dss/selectApiDataDetailView.do?publicDataPk=15129394" target="_blank" rel="noopener">나라장터 활용신청 ↗</a>
      <a class="iconbtn sm" style="text-decoration:none" href="https://www.data.go.kr/tcs/dss/selectApiDataDetailView.do?publicDataPk=15057332" target="_blank" rel="noopener">K-apt 활용신청 ↗</a>
      <a class="iconbtn sm" style="text-decoration:none" href="https://www.data.go.kr/tcs/dss/selectApiDataDetailView.do?publicDataPk=15044713" target="_blank" rel="noopener">건축인허가 활용신청 ↗</a>
    </div>
  </div>

  <div class="card">
    <h3>📂 K-apt · 나라장터 · 착공현장 엑셀/CSV 바로 올리기</h3>
    <div class="sub">K-apt(k-apt.go.kr)나 나라장터(g2b.go.kr)에서 내려받은 엑셀/CSV를 올리면 자동으로 공고명·발주처·예산·마감일·지역을 인식해 합쳐집니다.</div>
    <label class="aibtn" style="margin:0;cursor:pointer">📂 입찰·단지 엑셀/CSV 올리기<input type="file" id="oppUpload" accept=".csv,.txt,.xlsx,.xls" hidden></label>
  </div>

  <div class="card">
    <h3>💻 터미널 대량 자동수집 명령어 (CORS 무관)</h3>
    <div class="sub">브라우저 보안(CORS)으로 일부 공공API가 막히거나 전국 데이터를 대량 수집할 때는 폴더 내 Node 스크립트를 실행하세요.</div>
    <div class="codebox" id="cliCmd">node scripts/fetch_apis.mjs --key "내_공공데이터_인증키" --days 3 --bjd 28237</div>
    <button class="iconbtn sm" id="copyCli" style="margin-top:8px">명령어 복사</button>
  </div>`;

  $('#apiToggleEye').onclick = () => {
    const inp = $('#apiKeyIn');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  };
  $('#apiSaveKey').onclick = () => {
    const k = $('#apiKeyIn').value.replace(/\s+/g, '');
    if (k) { store.set('dataGoKey', k); toast('공공데이터포털 수동 인증키 저장'); }
    else { store.del('dataGoKey'); toast(META?.vaultKeys?.dataGo ? '수동 키 삭제 · Vault 기본 인증키로 복원됨' : '인증키 삭제'); }
    renderApiPanel();
  };
  $('#btnCheckApis').onclick = () => runApiHealthCheck();
  $('#copyCli').onclick = () => copy($('#cliCmd').textContent, '수집 명령어를 복사했습니다');
  $('#btnClearLive').onclick = async () => { await idb.del('live_opps'); OPPS = OPPS.filter(x => x.sample); recomputeAllOpps(); run(); renderApiPanel(); toast('수집 데이터를 초기화했습니다'); };
  $('#btnFetchG2b').onclick = () => runBrowserApi('g2b');
  $('#btnFetchPre').onclick = () => runBrowserApi('prespec');
  $('#btnFetchApt').onclick = () => runBrowserApi('apt');
  $('#btnFetchArch').onclick = () => runBrowserApi('arch');
  $('#oppUpload').onchange = e => { if (e.target.files[0]) uploadOppFile(e.target.files[0]); e.target.value = ''; };
}

async function runApiHealthCheck() {
  const typedKey = ($('#apiKeyIn')?.value || '').replace(/\s+/g, '');
  if (typedKey && typedKey.length >= 50) store.set('dataGoKey', typedKey);
  const rawKey = getEffectiveDataGoKey();
  const vwKey = window.VWorldTwin ? VWorldTwin.getKey(store, META) : '';
  if (!rawKey && !vwKey) { toast('먼저 공공데이터포털 또는 브이월드 인증키를 입력하세요'); $('#apiKeyIn')?.focus(); return; }
  if ($('#apiKeyMask')) $('#apiKeyMask').textContent = maskKeyPreview(rawKey);
  const keyEnc = normalizeDataGoKey(rawKey);
  const bjd = $('#apiBjd')?.value || '28237';
  const ymd = d => { const dt = new Date(Date.now() + d * 86400000); return `${dt.getFullYear()}${String(dt.getMonth() + 1).padStart(2, '0')}${String(dt.getDate()).padStart(2, '0')}`; };
  const bgn = `${ymd(-3)}0000`, end = `${ymd(0)}2359`;

  const board = $('#apiDiagBoard');
  if (board) board.innerHTML = '<div class="tiny" style="padding:8px 0">🩺 6개 공공·국토(브이월드) API 연결 상태를 동시에 점검 중입니다…</div>';

  const targets = [
    { name: '나라장터 입찰 (02)', url: `https://apis.data.go.kr/1230000/ad/BidPublicInfoService02/getBidPblancListInfoCnstwk02?serviceKey=${keyEnc}&pageNo=1&numOfRows=1&inqryDiv=1&inqryBgnDt=${bgn}&inqryEndDt=${end}&type=json`, parse: j => j?.response?.body?.totalCount ?? (j?.response?.body?.items ? 1 : 0) },
    { name: '나라장터 사전규격', url: `https://apis.data.go.kr/1230000/ao/HrcspSsstndrdInfoService/getPublicPrcureThngInfoServc?serviceKey=${keyEnc}&pageNo=1&numOfRows=1&inqryDiv=1&inqryBgnDt=${bgn}&inqryEndDt=${end}&type=json`, parse: j => j?.response?.body?.totalCount ?? 0 },
    { name: 'K-apt 공동주택 (V4)', url: `https://apis.data.go.kr/1613000/AptListService4/getSigunguAptList4?serviceKey=${keyEnc}&sigunguCode=${bjd}&pageNo=1&numOfRows=1&type=json`, parse: j => j?.response?.body?.totalCount ?? (j?.response?.body?.items ? 1 : 0) },
    { name: '청약홈 신축분양', url: `https://api.odcloud.kr/api/ApplyhomeInfoDetailSvc/v1/getAPTLttotPblancDetail?page=1&perPage=1&serviceKey=${keyEnc}`, parse: j => j?.totalCount ?? (j?.data?.length || 0) },
  ];

  const dataGoItemsP = Promise.all(targets.map(async t => {
    if (!rawKey) return { name: t.name, ok: false, status: 403, summary: '공공데이터 키 미입력', hint: '상단 공공데이터포털 일반 인증키를 입력하세요.' };
    const t0 = performance.now();
    try {
      const r = await fetch(t.url);
      const ms = Math.round(performance.now() - t0);
      const txt = await r.text();
      if (r.ok) {
        let cnt = 0;
        try { cnt = t.parse(JSON.parse(txt)); } catch {}
        return { name: t.name, ok: true, status: r.status, summary: `정상 연결 (HTTP 200 · ${ms}ms)`, hint: `조회 가능 데이터 ${Number(cnt || 0).toLocaleString('ko-KR')}건` };
      }
      if (r.status === 401) return { name: t.name, ok: false, status: 401, summary: `인증키 오류 (HTTP 401 · ${ms}ms)`, hint: '입력창 키를 지우고 공공데이터포털 일반 인증키를 다시 붙여넣으세요.' };
      if (r.status === 403) return { name: t.name, ok: false, status: 403, summary: `활용신청 미승인 (HTTP 403 · ${ms}ms)`, hint: 'data.go.kr에서 해당 API 활용신청 승인 후 바로 열립니다.' };
      return { name: t.name, ok: false, status: r.status, summary: `응답 오류 (HTTP ${r.status} · ${ms}ms)`, hint: txt.slice(0, 60).replace(/\s+/g, ' ') };
    } catch (e) {
      return { name: t.name, ok: false, status: 0, summary: '네트워크 / CORS 오류', hint: e.message };
    }
  }));
  const vwItemsP = window.VWorldTwin ? VWorldTwin.healthChecks(store, META) : Promise.resolve([]);
  const [vwItems, dgItems] = await Promise.all([vwItemsP, dataGoItemsP]);
  const items = [...vwItems, ...dgItems];

  const okCnt = items.filter(x => x.ok).length;
  const nowStr = new Date().toTimeString().slice(0, 8);
  LAST_API_DIAG = { checkedAt: nowStr, keyMask: rawKey ? maskKeyPreview(rawKey) : `VW:${window.VWorldTwin ? VWorldTwin.maskKey(vwKey) : ''}`, items };
  if (board) board.innerHTML = renderDiagBoardHtml();
  LAST_API_LOG = `[진단 완료 ${nowStr}] ${items.length}개 중 ${okCnt}개 API 정상 연결 (${items.map(x => `${x.name}:${x.ok ? 'OK' : x.status}`).join(', ')})`;
  const logEl = $('#apiLog');
  if (logEl) logEl.textContent = LAST_API_LOG;
  toast(`API 진단 완료: ${okCnt}/${items.length} 정상 연결`);
}

function matchRegionId(text) {
  const t = String(text || '').replace(/\s+/g, ''); if (!t) return -1;
  const sd = MAP.sidos.find(s => t.includes(s.n) || t.includes(s.s));
  const cands = sd ? MAP.regions.filter(r => r.sd === sd.sd) : MAP.regions;
  const hit = cands.find(r => t.includes(r.n.replace(/\s+/g, '')) || t.includes(r.n.replace(/(시|군|구)$/, '')));
  return hit ? hit.id : -1;
}

async function mergeLiveItems(newItems) {
  const prev = (await idb.get('live_opps')) || [];
  const liveMap = new Map(prev.map(x => [x.id, x]));
  newItems.forEach(x => liveMap.set(x.id, x));
  const mergedLive = [...liveMap.values()];
  await idb.set('live_opps', mergedLive);
  const allMap = new Map(OPPS.map(x => [x.id, x]));
  mergedLive.forEach(x => allMap.set(x.id, x));
  OPPS = [...allMap.values()];
  recomputeAllOpps();
  run();
  renderApiPanel();
}

async function runBrowserApi(kind) {
  const typedKey = ($('#apiKeyIn')?.value || '').replace(/\s+/g, '');
  if (typedKey && typedKey.length >= 50) store.set('dataGoKey', typedKey);
  const rawKey = getEffectiveDataGoKey();
  if (!rawKey) { toast('공공데이터포털 인증키를 먼저 입력하세요'); $('#apiKeyIn')?.focus(); return; }
  const keyEnc = normalizeDataGoKey(rawKey);
  const days = Number($('#apiDays').value || 3);
  const g2bDays = Math.min(days, 5); // 차세대 나라장터 7일 조회 한도 보호
  const bjd = $('#apiBjd').value || '28237';
  const ymd = d => { const dt = new Date(Date.now() + d * 86400000); return `${dt.getFullYear()}${String(dt.getMonth() + 1).padStart(2, '0')}${String(dt.getDate()).padStart(2, '0')}`; };
  const bgn = `${ymd(-g2bDays)}0000`, end = `${ymd(0)}2359`;
  const append = msg => {
    LAST_API_LOG += '\n' + msg;
    const el = $('#apiLog');
    if (el) { el.textContent = LAST_API_LOG; el.scrollTop = el.scrollHeight; }
  };
  LAST_API_LOG = `[시작] ${kind.toUpperCase()} 실시간 API 호출 중…`;
  const initLog = $('#apiLog');
  if (initLog) initLog.textContent = LAST_API_LOG;

  const extract = j => { const it = j?.response?.body?.items; if (!it) return []; if (Array.isArray(it)) return it; if (Array.isArray(it.item)) return it.item; return it.item ? [it.item] : []; };
  const out = [];
  try {
    if (kind === 'g2b') {
      for (const [sub, op, cat] of [['공사', 'getBidPblancListInfoCnstwk02', 'construction'], ['용역', 'getBidPblancListInfoServc02', 'gov'], ['물품', 'getBidPblancListInfoThng02', 'gov']]) {
        const u = `https://apis.data.go.kr/1230000/ad/BidPublicInfoService02/${op}?serviceKey=${keyEnc}&pageNo=1&numOfRows=30&inqryDiv=1&inqryBgnDt=${bgn}&inqryEndDt=${end}&type=json`;
        const r = await fetch(u); const txt = await r.text();
        if (!r.ok) { append(`⚠ 나라장터(${sub}) HTTP ${r.status}: data.go.kr 활용신청 승인 여부를 확인하세요.`); continue; }
        const items = extract(JSON.parse(txt)); append(`✓ 나라장터(${sub}): ${items.length}건 수신`);
        items.forEach(x => {
          const title = x.bidNtceNm || '', org = x.dminsttNm || x.ntceInsttNm || '';
          out.push({ id: `g2b-${x.bidNtceNo}-${x.bidNtceOrd || '00'}`, source: `나라장터(${sub})`, category: /아파트|공동주택|주택관리/.test(title + org) ? 'apt' : cat, stageType: 'bid', title, org, region: x.cnstrtsiteRgnNm || '', rid: matchRegionId((x.cnstrtsiteRgnNm || '') + ' ' + org + ' ' + title), budgetMan: Math.round(Number(x.presmptPrce || x.asignBdgtAmt || 0) / 1e4), pubDate: String(x.bidNtceDt || '').slice(0, 10), closeDate: String(x.bidClseDt || '').slice(0, 10), method: x.cntrctCnclsMthdNm || '', url: x.bidNtceDtlUrl || 'https://www.g2b.go.kr/', meta: { bidNo: x.bidNtceNo || '', kind: sub } });
        });
      }
    } else if (kind === 'prespec') {
      for (const [sub, op] of [['용역', 'getPublicPrcureThngInfoServc'], ['공사', 'getPublicPrcureThngInfoCnstwk']]) {
        const u = `https://apis.data.go.kr/1230000/ao/HrcspSsstndrdInfoService/${op}?serviceKey=${keyEnc}&pageNo=1&numOfRows=30&inqryDiv=1&inqryBgnDt=${bgn}&inqryEndDt=${end}&type=json`;
        const r = await fetch(u); const txt = await r.text();
        if (!r.ok) { append(`⚠ 사전규격(${sub}) HTTP ${r.status}: 활용신청 여부를 확인하세요.`); continue; }
        const items = extract(JSON.parse(txt)); append(`✓ 사전규격(${sub}): ${items.length}건 수신`);
        items.forEach(x => {
          const title = x.prdctClsfcNoNm || '', org = x.rlDminsttNm || x.orderInsttNm || '';
          out.push({ id: `pre-${x.bfSpecRgstNo || Math.random()}`, source: `사전규격(${sub})`, category: /아파트|공동주택/.test(title + org) ? 'apt' : (sub === '공사' ? 'construction' : 'gov'), stageType: 'prespec', title: `[사전규격] ${title}`, org, region: '', rid: matchRegionId(org + ' ' + title), budgetMan: Math.round(Number(x.asignBdgtAmt || 0) / 1e4), pubDate: String(x.rcptDt || '').slice(0, 10), closeDate: String(x.opninRgstClseDt || '').slice(0, 10), method: '사전규격', url: 'https://www.g2b.go.kr/', meta: { regNo: x.bfSpecRgstNo || '' } });
        });
      }
    } else if (kind === 'apt') {
      const u = `https://apis.data.go.kr/1613000/AptListService4/getSigunguAptList4?serviceKey=${keyEnc}&sigunguCode=${bjd}&pageNo=1&numOfRows=50&type=json`;
      const r = await fetch(u); const txt = await r.text();
      if (!r.ok) append(`⚠ K-apt HTTP ${r.status}: 공동주택 단지목록 활용신청 여부를 확인하세요.`);
      else {
        const items = extract(JSON.parse(txt)); append(`✓ K-apt 공동주택(${bjd}): ${items.length}건 수신`);
        items.forEach(x => {
          const addr = [x.as1, x.as2, x.as3, x.as4].filter(Boolean).join(' ');
          out.push({ id: `kapt-${x.kaptCode}`, source: 'K-apt 공동주택', category: 'apt', stageType: 'complex', title: `${x.kaptName} (공동주택 영업기회)`, org: `${x.kaptName} 관리사무소`, region: addr, rid: matchRegionId(addr), budgetMan: 0, pubDate: todayStr().replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3'), closeDate: '', method: '의무관리대상 단지', url: 'https://www.k-apt.go.kr/', meta: { kaptCode: x.kaptCode } });
        });
      }
    } else if (kind === 'arch') {
      const u = `https://api.odcloud.kr/api/ApplyhomeInfoDetailSvc/v1/getAPTLttotPblancDetail?page=1&perPage=30&serviceKey=${keyEnc}`;
      const r = await fetch(u); const txt = await r.text();
      if (!r.ok) append(`⚠ 청약홈 분양정보 HTTP ${r.status}: 활용신청 여부를 확인하세요.`);
      else {
        const j = JSON.parse(txt);
        const items = Array.isArray(j.data) ? j.data : [];
        append(`✓ 청약홈 신축아파트 분양: ${items.length}건 수신`);
        items.forEach(x => {
          const nm = x.HOUSE_NM || '신축아파트', units = Number(x.TOT_SUPLY_HSHLDCO || 0);
          const area = x.SUBSCRPT_AREA_CODE_NM || '', builder = x.CNSTRCT_ENTRPS_NM || x.BSNS_MBY_NM || '시공사';
          const ym = String(x.MVN_PREARNGE_YM || ''), ymStr = ym.length === 6 ? `${ym.slice(0, 4)}.${ym.slice(4, 6)} 입주` : '';
          out.push({ id: `applyhome-${x.PBLANC_NO || x.HOUSE_MANAGE_NO || Math.random()}`, source: '청약홈 신축분양', category: 'apt', stageType: 'permit', title: `[신축분양] ${nm} (${units ? units.toLocaleString() + '세대' : '아파트'}${ymStr ? ', ' + ymStr : ''})`, org: builder, region: `${area} ${x.HSSPLY_ADRES || ''}`.trim(), rid: matchRegionId(`${area} ${x.HSSPLY_ADRES || ''}`), budgetMan: units > 0 ? Math.max(2000, units * 25) : 3000, pubDate: String(x.RCRIT_PBLANC_DE || '').slice(0, 10), closeDate: String(x.RCEPT_ENDDE || '').slice(0, 10), method: `청약홈 ${x.HOUSE_DTL_SECD_NM || '분양'}`, url: x.PBLANC_URL || 'https://www.applyhome.co.kr/', meta: { units, builder } });
        });
      }
    }
    if (out.length) { await mergeLiveItems(out); append(`✅ ${out.length}건을 영업기회 목록에 반영·저장했습니다!`); toast(`${out.length}건 실시간 API 반영 완료`); }
    else append('→ 수신 건수가 0건입니다. 위 [활용신청] 링크에서 승인 후 다시 시도하거나 터미널 수집기를 이용하세요.');
  } catch (err) {
    append(`⚠ 호출 오류(${err.message}) — 브라우저 CORS 차단 시 아래 터미널 명령어(node scripts/fetch_apis.mjs)를 사용하세요.`);
  }
}

let XLSX_P = null;
function loadXLSX() {
  if (window.XLSX) return Promise.resolve(window.XLSX);
  return XLSX_P || (XLSX_P = new Promise((res, rej) => { const s = document.createElement('script'); s.src = 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js'; s.onload = () => res(window.XLSX); s.onerror = () => rej(new Error('엑셀 라이브러리 로드 실패')); document.head.appendChild(s); }));
}
async function uploadOppFile(file) {
  try {
    const buf = await file.arrayBuffer();
    let rows;
    if (/\.xlsx?$/i.test(file.name)) { const X = await loadXLSX(); const wb = X.read(buf, { type: 'array' }); rows = X.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header: 1, raw: false, defval: '' }); }
    else {
      let txt; try { txt = new TextDecoder('utf-8', { fatal: true }).decode(buf).replace(/^\uFEFF/, ''); } catch { txt = new TextDecoder('euc-kr').decode(buf); }
      rows = txt.split(/\r?\n/).filter(Boolean).map(l => l.split(',').map(c => c.replace(/^"|"$/g, '').trim()));
    }
    if (rows.length < 2) throw new Error('데이터 행이 없습니다');
    const head = rows[0].map(h => String(h).trim());
    const find = re => head.findIndex(h => re.test(h));
    const ti = find(/공고명|입찰명|사업명|단지명|건명|제목/);
    const oi = find(/기관|발주|단지|관리사무소|시공사|업체/);
    const bi = find(/예산|추정가격|금액|공사비/);
    const di = find(/마감|입찰일|종료/);
    const ai = find(/지역|주소|소재지|시군구/);
    if (ti < 0) throw new Error('공고명/사업명/단지명 열을 찾지 못했습니다');
    const items = [];
    rows.slice(1).forEach((r, k) => {
      const title = String(r[ti] || '').trim(); if (!title) return;
      const org = oi >= 0 ? String(r[oi] || '').trim() : file.name.replace(/\.[^.]+$/, '');
      const reg = ai >= 0 ? String(r[ai] || '').trim() : '';
      const rawBud = bi >= 0 ? Number(String(r[bi] || '').replace(/[^\d.]/g, '')) : 0;
      const budgetMan = rawBud > 1e6 ? Math.round(rawBud / 1e4) : Math.round(rawBud);
      const isApt = /아파트|공동주택|단지|입주자|K-apt/i.test(title + org + file.name);
      items.push({ id: `up-${Date.now()}-${k}`, source: file.name.slice(0, 16), category: isApt ? 'apt' : (/신축|착공|건설|건축/.test(title) ? 'construction' : 'gov'), stageType: 'bid', title, org, region: reg, rid: matchRegionId(reg + ' ' + org + ' ' + title), budgetMan, pubDate: todayStr().replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3'), closeDate: di >= 0 ? String(r[di] || '').slice(0, 10) : '', method: '업로드 공고', url: isApt ? 'https://www.k-apt.go.kr/' : 'https://www.g2b.go.kr/', meta: {} });
    });
    await mergeLiveItems(items);
    toast(`${items.length}건 업로드·병합 완료!`);
  } catch (e) { toast('업로드 실패: ' + e.message); }
}

/* ==================== Pipeline CRM Tab ==================== */
function renderCrm() {
  const el = $('#crmPanel'); if (!el) return;
  const bySt = Object.fromEntries(CRM_STAGES.map(s => [s, { cnt: 0, sum: 0, list: [] }]));
  let totCnt = 0, totSum = 0;
  for (const it of OPPS) {
    const c = CRM[it.id];
    if (!c || !c.stage) continue;
    const est = Number(c.estMan || it.budgetMan || 0);
    if (bySt[c.stage]) { bySt[c.stage].cnt++; bySt[c.stage].sum += est; bySt[c.stage].list.push({ it, c, est }); }
    if (c.stage !== '보류') { totCnt++; totSum += est; }
  }
  el.innerHTML = `
  <div class="card pro-hero">
    <h3>💼 내 수주 파이프라인 현황 <span class="tiny">활성 ${totCnt}건 · 총 예상수주액 ${fmtBudget(totSum)}</span></h3>
    <div class="sub">각 영업기회 상세 화면에서 단계와 예상수주액·메모를 기록하면 여기에 자동 집계됩니다.</div>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>단계</th><th>건수</th><th>예상 수주액</th></tr></thead><tbody>
      ${CRM_STAGES.map(st => `<tr data-crmst="${st}"><td><b>${st}</b></td><td class="num">${bySt[st].cnt}건</td><td class="num"><b>${fmtBudget(bySt[st].sum)}</b></td></tr>`).join('')}
    </tbody></table></div>
  </div>
  <div class="card">
    <h3>기록된 영업기회 목록</h3>
    ${totCnt || bySt['보류'].cnt ? `<ul class="peers">${CRM_STAGES.flatMap(st => bySt[st].list.map(({ it, c, est }) => `<li data-pid="${esc(it.id)}"><span><span class="sb s-crm">${st}</span> ${esc(it.title.slice(0, 34))}</span><span class="num"><b>${fmtBudget(est)}</b></span></li>`)).join('')}</ul>` : '<p class="tiny">아직 파이프라인에 등록된 영업기회가 없습니다. 좌측 목록에서 공고를 눌러 단계와 메모를 저장해 보세요.</p>'}
  </div>`;
  el.querySelectorAll('tr[data-crmst]').forEach(tr => tr.onclick = () => { S.crm = [tr.dataset.crmst]; run(); if (isMobile()) setView('list'); });
  el.querySelectorAll('li[data-pid]').forEach(li => li.onclick = () => openDetail(li.dataset.pid));
}

/* ==================== Detail Sheet + CRM + Gemini AI ==================== */
function downloadOppIcs(it) {
  const dt = it.detail || {};
  const toIcsDt = (str, fb = '100000') => {
    const m = String(str || '').match(/(\d{4})-(\d{2})-(\d{2})(?:[\sT](\d{2}):(\d{2})(?::(\d{2}))?)?/);
    return m ? `${m[1]}${m[2]}${m[3]}T${m[4] ? `${m[4]}${m[5]}${m[6] || '00'}` : fb}` : null;
  };
  const escIcs = s => String(s || '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n');
  const events = [];
  const addEv = (suf, sum, dtStr, desc, alarm) => {
    const start = toIcsDt(dtStr); if (!start) return;
    const endH = String(Math.min(23, Number(start.slice(9, 11)) + 1)).padStart(2, '0');
    events.push([
      'BEGIN:VEVENT', `UID:${escIcs(it.id)}-${suf}@bidopp.pwa`,
      `DTSTART;TZID=Asia/Seoul:${start}`, `DTEND;TZID=Asia/Seoul:${start.slice(0, 9)}${endH}${start.slice(11)}`,
      `SUMMARY:${escIcs(sum)}`, `LOCATION:${escIcs(dt.opengPlce || it.org || '나라장터')}`, `DESCRIPTION:${escIcs(desc)}`,
      ...(alarm ? [
        'BEGIN:VALARM', 'TRIGGER:-P1D', 'ACTION:DISPLAY', `DESCRIPTION:${escIcs(sum)} (1일 전)`, 'END:VALARM',
        'BEGIN:VALARM', 'TRIGGER:-PT3H', 'ACTION:DISPLAY', `DESCRIPTION:${escIcs(sum)} (3시간 전)`, 'END:VALARM',
      ] : []),
      'END:VEVENT',
    ].join('\r\n'));
  };
  const baseDesc = `발주기관: ${it.org || '-'}\n공고번호: ${dt.bidNo || it.id}\n예산: ${fmtBudget(it.budgetMan)}\n낙찰하한율: ${dt.awardRate || '-'}\n원문: ${it.url || ''}`;
  if (dt.qualDt) addEv('qual', `[참가자격마감] ${it.title}`, dt.qualDt, baseDesc, true);
  if (dt.bidClseDt || it.closeDate) addEv('close', `[입찰마감] ${it.title}`, dt.bidClseDt || it.closeDate, baseDesc, true);
  if (dt.opengDt) addEv('open', `[개찰] ${it.title}`, dt.opengDt, baseDesc, false);
  if (!events.length) { toast('마감·개찰 일정이 없어 캘린더를 생성할 수 없습니다.'); return; }
  const ics = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//BidOpp PWA//Bid Schedule//KO', 'CALSCALE:GREGORIAN', ...events, 'END:VCALENDAR'].join('\r\n');
  const blob = new Blob(['\uFEFF' + ics], { type: 'text/calendar;charset=utf-8' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `${String(dt.bidNo || it.id).replace(/[^a-zA-Z0-9_-]/g, '')}_입찰일정.ics`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  toast(`📅 입찰 일정 ${events.length}건 캘린더(.ics) 다운로드 완료`);
}

function findPartnerBuilders(it, limit = 5) {
  if (!BLD_SCORED?.length) return [];
  const domKey = it._doms?.[0]?.k || '';
  const wantSec = (domKey === 'sec' || domKey === 'ai' || domKey === 'elec') ? 'elec'
    : (domKey === 'fac' || it.category === 'apt') ? 'facility'
    : domKey === 'elev' ? 'special'
    : 'general';
  const targetRid = it.rid >= 0 ? it.rid : -1;
  const targetSd = targetRid >= 0 ? MAP.regions[targetRid]?.sd : '';
  const scored = [];
  for (const b of BLD_SCORED) {
    if (b.st === 2 || b.st === 3) continue;
    const sameRid = targetRid >= 0 && b.r[10] === targetRid;
    const bSd = b.r[10] >= 0 ? MAP.regions[b.r[10]]?.sd : '';
    const sameSd = Boolean(targetSd && bSd === targetSd);
    if (!sameRid && !sameSd) continue;
    let pts = sameRid ? 50 : 25;
    if (b.sec === wantSec) pts += 35;
    else if (b.sec === 'special') pts += 15;
    pts += (b.score || 0) * 0.4 + (b.r[6] ? 5 : 0);
    scored.push({ b, pts, sameRid });
  }
  scored.sort((a, c) => c.pts - a.pts || (c.b.rev || 0) - (a.b.rev || 0));
  return scored.slice(0, limit);
}

// ===== K-BID GRADE ENGINE (v22): G2B 기초금액·A값·순공사원가 · 복수예가 15개(1,365조합) · 적격심사 · 분포도 =====
let QUAL_PROFILE = (() => {
  try { return Object.assign({ credit: 'BBB', perfEok: 15, bonus: 1.5, cutoff: 95 }, JSON.parse(localStorage.getItem('bid_qual_profile_v1') || '{}') || {}); }
  catch { return { credit: 'BBB', perfEok: 15, bonus: 1.5, cutoff: 95 }; }
})();

async function fetchBidBsisAmountLive(bidNtceNo) {
  const rawKey = getEffectiveDataGoKey();
  if (!rawKey || !bidNtceNo) return null;
  const keyEnc = normalizeDataGoKey(rawKey);
  const cleanNo = String(bidNtceNo).split('-')[0].trim();
  const ops = [
    'getBidPblancListInfoCnstwkBsisAmount02',
    'getBidPblancListInfoServcBsisAmount02',
    'getBidPblancListInfoThngBsisAmount02',
  ];
  const results = await Promise.all(ops.map(async op => {
    try {
      const r = await fetch(`https://apis.data.go.kr/1230000/ad/BidPublicInfoService02/${op}?serviceKey=${keyEnc}&inqryDiv=2&bidNtceNo=${encodeURIComponent(cleanNo)}&pageNo=1&numOfRows=5&type=json`);
      if (!r.ok) return null;
      const j = await r.json();
      const raw = j?.response?.body?.items;
      const arr = Array.isArray(raw) ? raw : (raw?.item ? (Array.isArray(raw.item) ? raw.item : [raw.item]) : []);
      return arr[0] || null;
    } catch { return null; }
  }));
  const x = results.find(Boolean);
  if (!x) return null;
  const num = v => { const n = Number(String(v ?? '').replace(/[^0-9.-]/g, '')); return Number.isFinite(n) && n > 0 ? Math.round(n) : 0; };
  const bssamt = num(x.bssamt);
  const netCost = num(x.bssamtPurcnstcst || x.purcnstcst);
  const aItems = [
    ['안전보건', num(x.sftyMngcst)], ['안전관리', num(x.sftyChckMngcst)], ['품질관리', num(x.qltyMngcst)],
    ['퇴직공제', num(x.rtrfundNon)], ['건강보험', num(x.mrfnHealthInsrprm)], ['국민연금', num(x.npnInsrprm)], ['노인요양', num(x.odsnLngtrmrcprInsrprm)],
  ].filter(([, v]) => v > 0);
  const aVal = aItems.reduce((s, [, v]) => s + v, 0);
  const rngRaw = Math.abs(parseFloat(String(x.rsrvtnPrceRngBgnRate || x.rsrvtnPrceRngEndRate || '').replace(/[^0-9.-]/g, '')));
  return {
    bssamt, netCost, aVal,
    aBreakdown: aItems.map(([k, v]) => `${k} ${fmt(Math.round(v / 10000))}만`).join(' · '),
    rngPct: rngRaw === 2 || rngRaw === 3 ? rngRaw : 3,
  };
}

function calcBidOptimalWon(estPrice, lwltPct, aVal = 0, netCost = 0) {
  const raw = aVal > 0 ? (estPrice - aVal) * (lwltPct / 100) + aVal : estPrice * (lwltPct / 100);
  const calcBid = Math.ceil(Math.max(0, raw) / 1000) * 1000;
  const netFloor = netCost > 0 ? Math.ceil((netCost * 0.98) / 1000) * 1000 : 0;
  const netWarn = netFloor > 0 && calcBid < netFloor;
  return { calcBid, netFloor, netWarn, finalBid: netWarn ? netFloor : calcBid };
}

function gen15Slots(rngPct = 3) {
  const slots = [];
  const step = (rngPct * 2) / 15;
  for (let i = 0; i < 15; i++) slots.push(Number((-rngPct + i * step + (Math.random() * 0.65 + 0.175) * step).toFixed(3)));
  return slots;
}

function analyze1365(slots, baseWon, lwltPct, aVal, netCost) {
  const rates = [];
  for (let a = 0; a < 12; a++) for (let b = a + 1; b < 13; b++) for (let c = b + 1; c < 14; c++) for (let d = c + 1; d < 15; d++) {
    rates.push((slots[a] + slots[b] + slots[c] + slots[d]) / 4);
  }
  rates.sort((x, y) => x - y);
  const pick = p => rates[Math.min(rates.length - 1, Math.floor(rates.length * p))] || 0;
  const toBid = r => calcBidOptimalWon(Math.round(baseWon * (1 + r / 100)), lwltPct, aVal, netCost).finalBid;
  const rMin = rates[0] || 0, rMax = rates[rates.length - 1] || 0;
  const bins = Array(7).fill(0);
  const span = Math.max(0.001, rMax - rMin);
  rates.forEach(r => { bins[Math.min(6, Math.floor(((r - rMin) / span) * 7))]++; });
  return {
    count: rates.length, rP10: pick(0.1), rMed: pick(0.5), rP90: pick(0.9),
    bidP10: toBid(pick(0.1)), bidMed: toBid(pick(0.5)), bidP90: toBid(pick(0.9)),
    bins, maxBin: Math.max(1, ...bins),
  };
}

function evalQualScore(it) {
  const qp = QUAL_PROFILE;
  const dt = it.detail || {};
  const bsis = it._bsis || {};
  const baseWon = bsis.bssamt || dt.asignWon || dt.presmptWon || (it.budgetMan > 0 ? it.budgetMan * 10000 : 0);
  const creditMap = { AAA: 15, AA: 15, A: 14.5, BBB: 14, BB: 13.5, B: 12.5, CCC: 11 };
  const creditScore = creditMap[qp.credit] ?? 14;
  const perfWon = (Number(qp.perfEok) || 0) * 1e8;
  const ratio = baseWon > 0 ? perfWon / baseWon : 1;
  const perfScore = ratio >= 1 ? 15 : (ratio >= 0.7 ? 13.5 : (ratio >= 0.5 ? 12 : Math.max(6, Number((ratio * 15).toFixed(1)))));
  const priceScore = 65;
  const bonusScore = Math.min(3, Math.max(0, Number(qp.bonus) || 0));
  const total = Number((creditScore + perfScore + priceScore + bonusScore).toFixed(1));
  const cutoff = Number(qp.cutoff) || 95;
  return { creditScore, perfScore, priceScore, bonusScore, total, cutoff, pass: total >= cutoff, ratio, baseWon };
}

function renderQualBoxHtml(it) {
  const qp = QUAL_PROFILE;
  const q = evalQualScore(it);
  return `
    <div class="sec"><h4>✅ 적격심사 자사 점수 자동 판정 <button type="button" class="iconbtn sm" id="dQualEditBtn" style="margin-left:auto">⚙️ 자사 스펙</button></h4><div class="sales">
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 9px;border-radius:8px;background:var(--surface);border:1px solid ${q.pass ? '#a7f3d0' : '#fecaca'};margin-bottom:6px">
        <div>
          <div style="font-size:12px;font-weight:800;color:${q.pass ? '#059669' : '#dc2626'}">${q.pass ? `🟢 통과 유력 (${q.total}점 / 기준 ${q.cutoff}점)` : `🟠 보완 필요 (${q.total}점 · ${(q.cutoff - q.total).toFixed(1)}점 부족)`}</div>
          <div class="tiny" style="margin-top:2px">신용 ${qp.credit}(${q.creditScore}) + 실적 ${qp.perfEok}억(${q.perfScore}, ${q.baseWon > 0 ? (q.ratio * 100).toFixed(0) + '%' : '충족'}) + 가격 ${q.priceScore} + 신인도 ${q.bonusScore}</div>
        </div>
        <span class="sb" style="background:${q.pass ? '#ecfdf5' : '#fef2f2'};color:${q.pass ? '#047857' : '#b91c1c'}">${q.pass ? 'PASS' : '공동도급권장'}</span>
      </div>
      <div id="dQualForm" hidden style="display:grid;grid-template-columns:1fr 1fr;gap:6px;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--surface)">
        <label class="tiny">신용등급<select class="inp" id="dQpCredit" style="height:30px;margin-top:2px">${['AAA', 'AA', 'A', 'BBB', 'BB', 'B', 'CCC'].map(g => `<option value="${g}" ${qp.credit === g ? 'selected' : ''}>${g}</option>`).join('')}</select></label>
        <label class="tiny">최근 실적(억)<input class="inp" id="dQpPerf" type="number" step="0.5" value="${qp.perfEok}" style="height:30px;margin-top:2px"></label>
        <label class="tiny">신인도 가점<input class="inp" id="dQpBonus" type="number" step="0.5" min="0" max="3" value="${qp.bonus}" style="height:30px;margin-top:2px"></label>
        <label class="tiny">통과 기준점<input class="inp" id="dQpCut" type="number" min="70" max="100" value="${qp.cutoff}" style="height:30px;margin-top:2px"></label>
        <button type="button" class="iconbtn sm" id="dQpSave" style="grid-column:span 2;background:var(--accent);color:#fff;border-color:var(--accent)">💾 자사 스펙 저장 · 재판정</button>
      </div>
    </div></div>`;
}

function wireQualBox(it) {
  if ($('#dQualEditBtn')) $('#dQualEditBtn').onclick = () => { const f = $('#dQualForm'); if (f) f.hidden = !f.hidden; };
  if ($('#dQpSave')) $('#dQpSave').onclick = () => {
    QUAL_PROFILE = {
      credit: $('#dQpCredit')?.value || 'BBB',
      perfEok: Math.max(0, Number($('#dQpPerf')?.value) || 0),
      bonus: Math.min(3, Math.max(0, Number($('#dQpBonus')?.value) || 0)),
      cutoff: Math.min(100, Math.max(70, Number($('#dQpCut')?.value) || 95)),
    };
    try { localStorage.setItem('bid_qual_profile_v1', JSON.stringify(QUAL_PROFILE)); } catch {}
    toast('✅ 자사 적격심사 프로필 저장 완료!');
    openDetail(it.id);
  };
}

function renderAwardHist(rates) {
  if (!rates || rates.length < 2) return '';
  const minR = Math.floor(Math.min(...rates) * 2) / 2;
  const maxR = Math.ceil(Math.max(...rates) * 2) / 2;
  const span = Math.max(0.5, maxR - minR);
  const bCnt = Math.min(7, Math.max(3, Math.ceil(span / 0.5)));
  const step = span / bCnt;
  const bins = Array.from({ length: bCnt }, (_, i) => ({ lo: minR + i * step, hi: minR + (i + 1) * step, cnt: 0 }));
  rates.forEach(r => { bins[Math.min(bCnt - 1, Math.max(0, Math.floor((r - minR) / step)))].cnt++; });
  const maxC = Math.max(1, ...bins.map(b => b.cnt));
  const modeBin = bins.reduce((best, b) => (b.cnt > best.cnt ? b : best), bins[0]);
  const modeMid = Number(((modeBin.lo + modeBin.hi) / 2).toFixed(2));
  return `<div style="padding:7px 8px;border-radius:8px;background:var(--surface);border:1px solid var(--line);margin-bottom:8px">
    <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px"><b>📈 낙찰률 분포도</b><span style="color:var(--accent);font-weight:800">최빈 ${modeBin.lo.toFixed(1)}~${modeBin.hi.toFixed(1)}% (${modeBin.cnt}건)</span></div>
    <div style="display:flex;align-items:flex-end;gap:4px;height:42px">${bins.map(b => {
      const h = Math.max(12, Math.round((b.cnt / maxC) * 100));
      const isM = b === modeBin;
      return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;height:100%;justify-content:flex-end"><div style="font-size:9px;color:${isM ? 'var(--accent)' : 'var(--muted)'}">${b.cnt || ''}</div><div style="width:100%;height:${h}%;border-radius:3px 3px 0 0;background:${isM ? 'var(--accent)' : 'rgba(100,116,139,.28)'}"></div></div>`;
    }).join('')}</div>
    <div style="display:flex;justify-content:space-between;font-size:9.5px;color:var(--muted);margin-top:2px"><span>${minR.toFixed(1)}%</span><button type="button" id="dApplyModeRate" data-mode="${modeMid}" style="border:none;background:none;color:var(--accent);font-weight:800;font-size:10.5px;cursor:pointer;padding:0">⚡ 최빈 중앙(${modeMid}%) 적용</button><span>${maxR.toFixed(1)}%</span></div>
  </div>`;
}

function renderBidSimHtml(it) {
  const dt = it.detail || {};
  const bsis = it._bsis || {};
  const initBase = bsis.bssamt || dt.asignWon || dt.presmptWon || (it.budgetMan > 0 ? it.budgetMan * 10000 : 0);
  if (!initBase && it.stageType !== 'bid') return '';
  const rateNum = parseFloat(String(dt.awardRate || '').replace('%', '')) || 87.745;
  const bidNoHint = dt.bidNo || (String(it.id || '').startsWith('g2b-') ? String(it.id).slice(4) : '');
  const initRng = bsis.rngPct || 3;
  return `
    <div class="sec"><h4>🎯 K-Bid급 투찰가 · A값 · 복수예가 시뮬레이터 ${bidNoHint ? `<button type="button" class="iconbtn sm" id="dSimLoadBsis" style="margin-left:auto">${bsis.bssamt ? '🔄 기초금액 재조회' : '🔍 기초금액·A값 자동조회'}</button>` : ''}</h4><div class="sales">
      ${bsis.bssamt ? `<div style="font-size:11px;padding:5px 8px;border-radius:6px;background:rgba(16,185,129,.1);color:#047857;margin-bottom:7px;font-weight:600">✅ 실측 기초금액 ${fmt(bsis.bssamt)}원 · ±${bsis.rngPct}%${bsis.aVal > 0 ? ` · A값 ${fmt(bsis.aVal)}원` : ''}${bsis.netCost > 0 ? ` · 순공사 ${fmt(bsis.netCost)}원` : ''}</div>` : ''}
      <div style="display:grid;grid-template-columns:1fr 105px;gap:6px;margin-bottom:6px">
        <label class="tiny">기초금액/배정예산 (원)<input class="inp" id="dSimBase" type="number" value="${initBase || 100000000}" step="100000" style="height:32px;margin-top:2px"></label>
        <label class="tiny">낙찰하한율 (%)<input class="inp" id="dSimRate" type="number" value="${rateNum}" step="0.005" min="10" max="100" style="height:32px;margin-top:2px"></label>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:8px">
        <label class="tiny">A값 합계 (안전·보험, 원)<input class="inp" id="dSimAVal" type="number" value="${bsis.aVal || 0}" step="10000" min="0" style="height:30px;margin-top:2px"></label>
        <label class="tiny">순공사원가 (98% 검증, 원)<input class="inp" id="dSimNetCost" type="number" value="${bsis.netCost || 0}" step="100000" min="0" style="height:30px;margin-top:2px"></label>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px"><span>예상 사정률</span><b id="dSimLbl" style="color:var(--accent)">0.00% (예정가격 100.00%)</b></div>
      <input id="dSimRange" type="range" min="-3" max="3" step="0.05" value="0" style="width:100%;margin-bottom:8px">
      <div id="dSimRes" style="padding:8px 10px;border-radius:8px;background:var(--surface);border:1px solid var(--line);margin-bottom:8px"></div>
      <div id="dSimGrid" style="display:grid;grid-template-columns:repeat(3,1fr);gap:5px;font-size:11px;margin-bottom:8px"></div>
      <div style="padding:8px;border-radius:8px;background:var(--surface);border:1px solid var(--line)">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:4px;flex-wrap:wrap;margin-bottom:6px">
          <b style="font-size:11.5px;color:var(--accent)">🎲 복수예가 15개 · 1,365조합</b>
          <div style="display:flex;gap:4px">
            <button type="button" class="chip" data-dsim-rng="2" aria-pressed="${initRng === 2}" style="padding:2px 7px;font-size:10.5px">±2%</button>
            <button type="button" class="chip" data-dsim-rng="3" aria-pressed="${initRng !== 2}" style="padding:2px 7px;font-size:10.5px">±3%</button>
            <button type="button" class="iconbtn sm" id="dSimDraw4" style="padding:2px 7px;font-size:10.5px">🎲 4개 추첨</button>
            <button type="button" class="iconbtn sm" id="dSimRegen15" style="padding:2px 7px;font-size:10.5px">🔄</button>
          </div>
        </div>
        <div id="dSim15Grid" style="display:grid;grid-template-columns:repeat(5,1fr);gap:4px;margin-bottom:6px"></div>
        <div id="dSim1365" class="tiny"></div>
      </div>
    </div></div>`;
}

function wireBidSim(it) {
  const baseEl = $('#dSimBase'), rateEl = $('#dSimRate'), rngEl = $('#dSimRange');
  const aEl = $('#dSimAVal'), netEl = $('#dSimNetCost');
  const lblEl = $('#dSimLbl'), resEl = $('#dSimRes'), gridEl = $('#dSimGrid');
  const g15 = $('#dSim15Grid'), stEl = $('#dSim1365');
  if (!baseEl || !rateEl || !rngEl || !resEl) return;
  let rngPct = it?._bsis?.rngPct || 3;
  let slots15 = gen15Slots(rngPct);
  let picked = new Set([4, 6, 8, 10]);

  const calc = () => {
    const base = Math.max(0, Number(baseEl.value) || 0);
    const lwlt = Math.max(1, Math.min(100, Number(rateEl.value) || 87.745));
    const aVal = Math.max(0, Number(aEl?.value) || 0);
    const netCost = Math.max(0, Number(netEl?.value) || 0);
    const ass = Number(rngEl.value) || 0;
    const est = Math.round(base * (1 + ass / 100));
    const { calcBid, netFloor, netWarn, finalBid } = calcBidOptimalWon(est, lwlt, aVal, netCost);
    window._lastBidSimWon = finalBid;
    lblEl.textContent = `${ass >= 0 ? '+' : ''}${ass.toFixed(2)}% (예정가격 ${(100 + ass).toFixed(2)}%)`;
    resEl.innerHTML = `<div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px"><span class="tiny">예상 예정가격${aVal > 0 ? ' (A값 공식)' : ''}</span><b class="num">${fmt(est)}원</b></div>
      <div style="display:flex;justify-content:space-between;align-items:center"><span style="font-size:12px;font-weight:700;color:var(--accent)">${netWarn ? '안전 최저한도 (순공사 98%)' : `최적 투찰 하한가 (${lwlt}%)`}</span>
      <span style="display:flex;align-items:center;gap:6px"><b class="num" style="font-size:14px;color:${netWarn ? '#dc2626' : '#059669'}">${fmt(finalBid)}원</b><button type="button" class="cp" id="dSimCopy">복사</button></span></div>
      ${aVal > 0 ? `<div class="tiny" style="margin-top:3px">산식: (${fmt(est)} - A값 ${fmt(aVal)}) × ${lwlt}% + A값 = ${fmt(calcBid)}원</div>` : ''}
      ${netWarn ? `<div style="margin-top:5px;padding:4px 7px;border-radius:6px;background:rgba(220,38,38,.1);color:#b91c1c;font-size:11px;font-weight:700">⚠️ 순공사원가 98% 미달 경고! 최소 ${fmt(netFloor)}원 이상 투찰 필수</div>` : ''}`;
    $('#dSimCopy').onclick = () => copy(String(finalBid));
    gridEl.innerHTML = [-2, -1, 0, 0.5, 1, 2].map(s => {
      const bid = calcBidOptimalWon(Math.round(base * (1 + s / 100)), lwlt, aVal, netCost).finalBid;
      const on = Math.abs(s - ass) < 0.06;
      return `<div style="padding:5px;border-radius:6px;border:1px solid ${on ? 'var(--accent)' : 'var(--line)'};text-align:center;background:var(--surface)"><div class="tiny">${s >= 0 ? '+' : ''}${s.toFixed(1)}%</div><b class="num">${(bid / 1e8).toFixed(2)}억</b></div>`;
    }).join('');
    if (g15 && stEl) {
      g15.innerHTML = slots15.map((v, idx) => {
        const on = picked.has(idx);
        return `<button type="button" data-ds15="${idx}" style="padding:4px 2px;border-radius:6px;border:1px solid ${on ? 'var(--accent)' : 'var(--line)'};background:${on ? 'var(--accent)' : 'var(--card)'};color:${on ? '#fff' : 'var(--ink)'};font-size:10px;font-weight:${on ? 800 : 600};cursor:pointer"><div>#${String(idx + 1).padStart(2, '0')}</div><div>${v >= 0 ? '+' : ''}${v.toFixed(2)}%</div></button>`;
      }).join('');
      g15.querySelectorAll('[data-ds15]').forEach(b => {
        b.onclick = () => {
          const idx = Number(b.dataset.ds15);
          if (picked.has(idx)) picked.delete(idx);
          else { if (picked.size >= 4) picked.delete([...picked][0]); picked.add(idx); }
          if (picked.size === 4) rngEl.value = ([...picked].reduce((s, i) => s + slots15[i], 0) / 4).toFixed(2);
          calc();
        };
      });
      const st = analyze1365(slots15, base, lwlt, aVal, netCost);
      stEl.innerHTML = `<div style="display:flex;justify-content:space-between;margin-bottom:4px"><span>선택 ${picked.size}/4 · <b>${fmt(st.count)}조합</b></span><b style="color:#059669">중앙 추천 ${fmt(st.bidMed)}원</b></div>
        <div style="display:flex;align-items:flex-end;gap:3px;height:26px;margin-bottom:3px">${st.bins.map((cnt, bi) => `<div style="flex:1;height:${Math.max(15, Math.round((cnt / st.maxBin) * 100))}%;border-radius:3px 3px 0 0;background:${bi === 3 ? 'var(--accent)' : 'rgba(15,118,110,.32)'}"></div>`).join('')}</div>
        <div style="display:flex;justify-content:space-between;font-size:10px"><span>10%: ${(st.bidP10 / 1e8).toFixed(2)}억</span><span>90%: ${(st.bidP90 / 1e8).toFixed(2)}억</span></div>`;
    }
  };
  if ($('#dSimDraw4')) $('#dSimDraw4').onclick = () => {
    const idxs = Array.from({ length: 15 }, (_, i) => i).sort(() => Math.random() - 0.5).slice(0, 4);
    picked = new Set(idxs);
    rngEl.value = (idxs.reduce((s, i) => s + slots15[i], 0) / 4).toFixed(2);
    calc();
    toast(`🎲 4개 예가 추첨 완료 → 사정률 ${Number(rngEl.value) >= 0 ? '+' : ''}${rngEl.value}%`);
  };
  if ($('#dSimRegen15')) $('#dSimRegen15').onclick = () => { slots15 = gen15Slots(rngPct); calc(); toast(`🔄 ±${rngPct}% 15예가 재생성`); };
  $$('[data-dsim-rng]').forEach(b => {
    b.onclick = () => {
      rngPct = Number(b.dataset.dsimRng) || 3;
      $$('[data-dsim-rng]').forEach(x => x.setAttribute('aria-pressed', Number(x.dataset.dsimRng) === rngPct));
      slots15 = gen15Slots(rngPct); calc();
    };
  });
  if ($('#dSimLoadBsis')) $('#dSimLoadBsis').onclick = async e => {
    const b = e.currentTarget;
    const bidNo = it?.detail?.bidNo || (String(it?.id || '').startsWith('g2b-') ? String(it.id).slice(4) : '');
    if (!bidNo) return;
    b.disabled = true; b.textContent = '조회 중…';
    const bsis = await fetchBidBsisAmountLive(bidNo);
    if (bsis && bsis.bssamt > 0) { it._bsis = bsis; toast(`✅ 기초금액 ${fmt(bsis.bssamt)}원 자동 반영!`); openDetail(it.id); }
    else { b.disabled = false; b.textContent = '🔍 재시도'; toast('ℹ️ 기초금액 미공개 공고입니다.'); }
  };
  baseEl.oninput = rateEl.oninput = rngEl.oninput = calc;
  if (aEl) aEl.oninput = calc;
  if (netEl) netEl.oninput = calc;
  calc();
}

let AWARD_CACHE = { loading: false, loaded: false, list: [] };

async function ensureAwardHistoryLoaded() {
  if (AWARD_CACHE.loaded) return AWARD_CACHE.list;
  if (AWARD_CACHE.loading) {
    for (let i = 0; i < 40 && AWARD_CACHE.loading; i++) await new Promise(r => setTimeout(r, 150));
    return AWARD_CACHE.list;
  }
  const rawKey = getEffectiveDataGoKey();
  if (!rawKey) return [];
  const keyEnc = normalizeDataGoKey(rawKey);
  AWARD_CACHE.loading = true;
  try {
    const nowMs = Date.now();
    const kst = ms => {
      const d = new Date(ms + 9 * 3600000);
      const p = n => String(n).padStart(2, '0');
      const ymd = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}`;
      return { ymd, dt: `${ymd}${p(d.getUTCHours())}${p(d.getUTCMinutes())}` };
    };
    const w1Bgn = `${kst(nowMs - 4 * 86400000).ymd}0000`, w1End = kst(nowMs).dt;
    const w2Bgn = `${kst(nowMs - 8 * 86400000).ymd}0000`, w2End = `${kst(nowMs - 4 * 86400000).ymd}0000`;
    const all = [];
    const seen = new Set();
    const tasks = [];
    for (const [div, op] of [['용역', 'getScsbidListSttusServc'], ['공사', 'getScsbidListSttusCnstwk'], ['물품', 'getScsbidListSttusThng']]) {
      for (const [bgnDt, endDt] of [[w1Bgn, w1End], [w2Bgn, w2End]]) {
        tasks.push((async () => {
          try {
            const r = await fetch(`https://apis.data.go.kr/1230000/as/ScsbidInfoService/${op}?serviceKey=${keyEnc}&inqryDiv=1&inqryBgnDt=${bgnDt}&inqryEndDt=${endDt}&pageNo=1&numOfRows=500&type=json`);
            if (!r.ok) return;
            const j = await r.json();
            const raw = j?.response?.body?.items;
            const arr = Array.isArray(raw) ? raw : (raw?.item ? (Array.isArray(raw.item) ? raw.item : [raw.item]) : []);
            arr.forEach(x => {
              const k = `${x.bidNtceNo || ''}-${x.bidNtceOrd || ''}-${x.bidwinnrNm || ''}`;
              if (seen.has(k)) return;
              seen.add(k);
              const rate = parseFloat(x.sucsfbidRate);
              if (!x.bidwinnrNm && !rate) return;
              all.push({
                div, bidNo: x.bidNtceNo || '', title: x.bidNtceNm || '', org: x.dminsttNm || '',
                winner: x.bidwinnrNm || '-', amt: Number(x.sucsfbidAmt || 0) || 0,
                rate: Number.isFinite(rate) ? rate : null, bidders: Number(x.prtcptCnum || 0) || 0,
                date: String(x.fnlSucsfDate || x.rlOpengDt || '').slice(0, 10),
              });
            });
          } catch {}
        })());
      }
    }
    await Promise.all(tasks);
    all.sort((a, b) => String(b.date).localeCompare(String(a.date)));
    AWARD_CACHE.list = all;
    AWARD_CACHE.loaded = all.length > 0;
    return all;
  } finally {
    AWARD_CACHE.loading = false;
  }
}

function matchAwardBenchmarks(it, awards) {
  if (!awards?.length) return { sameOrg: [], similar: [], pool: [], avgRate: null, avgBidders: null, totalScanned: 0 };
  const norm = s => String(s || '').replace(/\s+/g, '').replace(/(주식회사|\(주\)|특별자치시|특별자치도|광역시|특별시)/g, '').toLowerCase();
  const oOrg = norm(it.org);
  const toks = String(it.org || '').split(/\s+/).filter(t => t.length >= 2);
  const sameOrg = awards.filter(a => {
    const aOrg = norm(a.org);
    if (!aOrg || !oOrg) return false;
    return aOrg === oOrg || (oOrg.length >= 4 && (aOrg.includes(oOrg) || oOrg.includes(aOrg))) || (toks.length >= 2 && toks.every(t => a.org.includes(t)));
  });
  const stop = new Set(['2026', '2026년', '2027', '2027년', '공사', '용역', '물품', '구매', '입찰', '공고', '긴급', '사업', '설치', '교체', '유지', '관리', '위탁']);
  const kws = [...new Set((String(it.title || '').match(/[가-힣A-Za-z0-9]{2,}/g) || []).filter(w => !stop.has(w)))].slice(0, 6);
  const similar = awards.filter(a => !sameOrg.includes(a) && kws.some(k => `${a.title} ${a.org}`.includes(k)));
  const pool = [...sameOrg.slice(0, 12), ...similar.slice(0, Math.max(0, 12 - sameOrg.length))];
  const rates = pool.map(x => x.rate).filter(v => v !== null && v > 20 && v <= 105);
  const bids = pool.map(x => x.bidders).filter(v => v > 0);
  return {
    sameOrg: sameOrg.slice(0, 5), similar: similar.slice(0, 5), pool: pool.slice(0, 5), rates,
    avgRate: rates.length ? rates.reduce((s, v) => s + v, 0) / rates.length : null,
    avgBidders: bids.length ? bids.reduce((s, v) => s + v, 0) / bids.length : null,
    totalScanned: awards.length,
  };
}

function openA4BidReview(it) {
  const dt = it.detail || {};
  const bsis = it._bsis || {};
  const files = it.attachments || [];
  const partners = findPartnerBuilders(it, 5);
  const bm = AWARD_CACHE.loaded ? matchAwardBenchmarks(it, AWARD_CACHE.list) : null;
  const qual = evalQualScore(it);
  const baseWon = Number($('#dSimBase')?.value) || bsis.bssamt || dt.asignWon || dt.presmptWon || (it.budgetMan > 0 ? it.budgetMan * 10000 : 0);
  const lwlt = Number($('#dSimRate')?.value) || parseFloat(String(dt.awardRate || '').replace('%', '')) || 87.745;
  const aVal = Number($('#dSimAVal')?.value) || bsis.aVal || 0;
  const netCost = Number($('#dSimNetCost')?.value) || bsis.netCost || 0;
  const simRows = baseWon > 0 ? [-2, -1, 0, 0.5, 1, 2].map(s => {
    const est = Math.round(baseWon * (1 + s / 100));
    const { finalBid, netWarn } = calcBidOptimalWon(est, lwlt, aVal, netCost);
    return `<tr><td>${s >= 0 ? '+' : ''}${s.toFixed(1)}%</td><td>${fmt(est)}원</td><td><b>${fmt(finalBid)}원</b>${netWarn ? ' ⚠️98%' : ''}</td><td>${(finalBid / 1e8).toFixed(2)}억</td></tr>`;
  }).join('') : '';
  const ex = $('#bidA4Overlay'); if (ex) ex.remove();
  const wrap = document.createElement('div');
  wrap.id = 'bidA4Overlay';
  wrap.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(15,23,42,.72);overflow:auto;padding:18px;display:flex;justify-content:center;align-items:flex-start';
  wrap.innerHTML = `<style>#bidA4Sheet{width:100%;max-width:820px;background:#fff;color:#0f172a;border-radius:12px;padding:24px 26px;box-shadow:0 24px 60px rgba(0,0,0,.35);font-size:12px;line-height:1.45}#bidA4Sheet .bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding-bottom:10px;border-bottom:2px solid #1e293b;gap:10px}#bidA4Sheet .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:10px 0}#bidA4Sheet .kpi{border:1px solid #cbd5e1;border-radius:8px;padding:8px 10px;background:#f8fafc}#bidA4Sheet .kpi .l{font-size:10.5px;color:#64748b}#bidA4Sheet .kpi .v{font-size:14px;font-weight:800;margin-top:2px}#bidA4Sheet h3{font-size:12.5px;margin:12px 0 6px;padding-left:7px;border-left:3.5px solid #4f46e5}#bidA4Sheet table{width:100%;border-collapse:collapse;font-size:11px;margin-bottom:6px}#bidA4Sheet th,#bidA4Sheet td{border:1px solid #cbd5e1;padding:4px 7px;text-align:left}#bidA4Sheet th{background:#f1f5f9;font-weight:700;width:18%}#bidA4Sheet .grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}#bidA4Sheet .sign{display:grid;grid-template-columns:1fr 220px;gap:12px;margin-top:12px;align-items:end}#bidA4Sheet .sign table th,#bidA4Sheet .sign table td{text-align:center;width:auto}@media print{@page{size:A4 portrait;margin:10mm}html,body{background:#fff!important;height:auto!important;overflow:visible!important;margin:0!important;padding:0!important}body>*:not(#bidA4Overlay){display:none!important}#bidA4Overlay{display:block!important;position:static!important;inset:auto!important;width:100%!important;height:auto!important;background:#fff!important;padding:0!important;overflow:visible!important}#bidA4Sheet{display:block!important;box-shadow:none!important;border-radius:0!important;max-width:none!important;width:100%!important;padding:0!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}#bidA4Sheet .no-print{display:none!important}}</style>
  <div id="bidA4Sheet">
  <div class="bar"><div><div style="font-size:10px;color:#4f46e5;font-weight:800">공동주택·관공서 입찰 PRO · 1페이지 수주 검토 보고서</div><h1 style="font-size:16px;margin:2px 0 0">${esc(it.title)}</h1></div>
  <div style="text-align:right;flex-shrink:0"><div style="font-size:10.5px;color:#475569;margin-bottom:5px">작성일: ${getTodayKstIso()}</div><div class="no-print" style="display:flex;gap:6px;justify-content:flex-end"><button id="bidA4PrintBtn" type="button" style="padding:6px 12px;border:none;border-radius:7px;background:#4f46e5;color:#fff;font-weight:700;cursor:pointer;font-size:12px">🖨️ A4 인쇄 / PDF</button><button id="bidA4CloseBtn" type="button" style="padding:6px 11px;border:1px solid #cbd5e1;border-radius:7px;background:#fff;color:#0f172a;font-weight:700;cursor:pointer;font-size:12px">✕ 닫기</button></div></div></div>
  <div class="kpis">
    <div class="kpi"><div class="l">배정예산 / 추정가격</div><div class="v">${baseWon > 0 ? (baseWon / 1e8).toFixed(2) + '억' : fmtBudget(it.budgetMan)}</div></div>
    <div class="kpi"><div class="l">입찰마감 (D-Day)</div><div class="v">${esc(it.closeDate || '-')}${it._dday !== null && it._dday >= 0 ? ` (D-${it._dday})` : ''}</div></div>
    <div class="kpi"><div class="l">적격심사 자사 판정</div><div class="v" style="color:${qual.pass ? '#059669' : '#dc2626'}">${qual.pass ? '통과유력' : '보완필요'} (${qual.total}점)</div></div>
    <div class="kpi"><div class="l">첨부서류 / 공고구분</div><div class="v">${files.length}건 · ${esc(dt.ntceKind || '등록공고')}</div></div>
  </div>
  ${aVal > 0 || netCost > 0 ? `<div style="padding:6px 10px;border:1px solid #cbd5e1;border-radius:7px;background:#f8fafc;font-size:11px;margin-bottom:8px">${aVal > 0 ? `<b>A값 적용:</b> ${fmt(aVal)}원 &nbsp;` : ''}${netCost > 0 ? `<b>순공사원가 98%:</b> ${fmt(Math.ceil((netCost * 0.98) / 1000) * 1000)}원` : ''}</div>` : ''}
  <h3>1. 입찰 상세내역 및 일정</h3>
  <table>
    <tr><th>발주기관</th><td>${esc(it.org || '-')}</td><th>공고번호/차수</th><td>${esc(dt.bidNo || it.id)}</td></tr>
    <tr><th>소재지</th><td>${esc(it.region || '-')}</td><th>계약/낙찰방법</th><td>${esc([dt.contractMethod, dt.awardMethod].filter(Boolean).join(' / ') || it.method || '-')}</td></tr>
    <tr><th>공고 / 개시일시</th><td>${esc(it.pubDateTime || it.pubDate || '-')} / ${esc(dt.bidBeginDt || '-')}</td><th>마감 / 개찰일시</th><td>${esc(dt.bidClseDt || it.closeDate || '-')} / ${esc(dt.opengDt || '-')}</td></tr>
    <tr><th>예가방식 / 공동도급</th><td>${esc(dt.priceMethod || '-')} · ${esc(dt.jointMethod || '-')}</td><th>담당자 / 업종제한</th><td>${esc([dt.ofclNm, dt.ofclTel, dt.ofclEmail].filter(Boolean).join(' · ') || '-')} / ${esc(dt.industryLimit || '-')}</td></tr>
  </table>
  <div class="grid2">
    <div><h3>2. 사정률별 투찰가 시뮬레이션 (하한율 ${lwlt}%)</h3>${simRows ? `<table><tr><th>사정률</th><th>예상 예정가격</th><th>권장 투찰 하한가</th><th>억 환산</th></tr>${simRows}</table>` : '<p>예산 미기재</p>'}</div>
    <div><h3>3. 과거 낙찰·경쟁사 벤치마크 (최근 8일)</h3>${bm && bm.pool?.length ? `<div style="margin-bottom:4px">평균 낙찰률: <b>${bm.avgRate ? bm.avgRate.toFixed(2) + '%' : '-'}</b> · 평균 경쟁사: <b>${bm.avgBidders ? bm.avgBidders.toFixed(1) + '사' : '-'}</b></div><table><tr><th>낙찰사</th><th>낙찰률</th><th>참가</th><th>일자</th></tr>${bm.pool.slice(0, 4).map(x => `<tr><td>${esc(x.winner)}</td><td>${x.rate ? x.rate.toFixed(2) + '%' : '-'}</td><td>${x.bidders}사</td><td>${esc(x.date)}</td></tr>`).join('')}</table>` : '<p style="color:#64748b">상세 서랍에서 "실시간 낙찰 분석" 조회 후 출력하면 실측 데이터가 반영됩니다.</p>'}</div>
  </div>
  <div class="grid2">
    <div><h3>4. 첨부서류 (${files.length}건)</h3>${files.length ? `<ul style="margin:4px 0 0 16px;padding:0">${files.map(f => `<li>${esc(f.name)}</li>`).join('')}</ul>` : '<p style="color:#64748b">원문공고 참조</p>'}</div>
    <div><h3>5. 지역 추천 협력 파트너 TOP 5</h3>${partners.length ? `<table><tr><th>업체명</th><th>업종</th><th>매출</th><th>연락처</th></tr>${partners.map(({ b }) => `<tr><td>${esc(b.r[0])}</td><td>${esc(BLD_IND[b.r[8]] || b.sec)}</td><td>${ok(b.rev) ? fmt(Math.round(b.rev)) + '억' : '-'}</td><td>${esc(b.r[6] || '-')}</td></tr>`).join('')}</table>` : '<p style="color:#64748b">전국 공고</p>'}</div>
  </div>
  <div class="sign"><div style="border:1px solid #cbd5e1;border-radius:8px;padding:8px 10px;background:#f8fafc"><b>✅ 수주 검토 체크리스트</b><br>[ ] 필수 면허·실적·지역제한 확인 &nbsp; [ ] 과업지시서·내역서 원가 산출 &nbsp; [ ] 협력사 협의 &nbsp; [ ] 마감·개찰 일정 확인</div><table><tr><th>담당</th><th>팀장</th><th>임원</th></tr><tr style="height:36px"><td></td><td></td><td></td></tr></table></div>
  </div>`;
  document.body.appendChild(wrap);
  wrap.onclick = e => { if (e.target === wrap) wrap.remove(); };
  $('#bidA4CloseBtn').onclick = () => wrap.remove();
  $('#bidA4PrintBtn').onclick = () => window.print();
}

function openDetail(id) {
  const it = OPPS.find(x => x.id === id); if (!it) return;
  CUR_ID = id;
  $$('#list .item.on').forEach(x => x.classList.remove('on'));
  const row = $(`#list .item[data-id="${CSS.escape(id)}"]`); row && row.classList.add('on');
  const crm = CRM[id] || { stage: '', estMan: it.budgetMan || '', text: '', updated: '' };
  const q = encodeURIComponent;
  const gCls = it._grade === 'S' ? 'g-s' : it._grade === 'A' ? 'g-a' : it._grade === 'B' ? 'g-b' : 'g-c';

  $('#dbody').innerHTML = `
  <div class="dh"><div style="flex:1;min-width:0"><h2>${esc(it.title)}</h2>
    <div class="sbrow" style="margin-top:6px"><span class="sb ${CAT_CLS[it.category]}">${CAT_LBL[it.category]}</span>${ddayBadge(it)}<span class="grd ${gCls}">🏆 ${it._grade} (${it._score}점)</span></div></div>
    <button class="fav${FAV.has(id) ? ' on' : ''}" id="dfav">${FAV.has(id) ? '★' : '☆'}</button>
    <button class="close" id="dclose">✕</button></div>
  <div class="db">
    <div class="actions">
      <a href="${esc(it.url || '#')}" target="_blank" rel="noopener"><span class="ico">🔗</span>원문공고</a>
      <button type="button" id="dA4Btn"><span class="ico">📑</span>A4검토서</button>
      <button type="button" id="dIcsBtn"><span class="ico">📅</span>캘린더</button>
      <button type="button" id="dRadarJumpBtn"><span class="ico">🗺️</span>주변레이더</button>
      <button type="button" id="dCmpBtn"><span class="ico">⚖️</span>${CMP.includes(id) ? '비교담김' : '비교담기'}</button>
    </div>

    <div class="sec"><h4>💼 내 수주 파이프라인 CRM <span class="tiny">${crm.updated ? '수정 ' + esc(crm.updated) : '로컬 저장'}</span></h4><div class="sales">
      <div class="chips" id="crmStBar" style="margin-bottom:8px">${CRM_STAGES.map(st => `<button type="button" class="chip" data-cst="${st}" aria-pressed="${crm.stage === st}">${st}</button>`).join('')}</div>
      <div style="display:flex;gap:6px;margin-bottom:8px;align-items:center">
        <span class="tiny" style="white-space:nowrap">예상 수주액(만원)</span>
        <input class="inp" type="number" id="crmEstIn" value="${esc(crm.estMan)}" placeholder="예: 35000" style="height:34px">
      </div>
      <textarea class="memo-txt" id="crmTxt" placeholder="현장답사 일정, 발주처 담당자, 경쟁사 동향, 제안 전략 메모…">${esc(crm.text || '')}</textarea>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button type="button" class="iconbtn sm" id="crmSave" style="background:var(--accent);color:#fff;border-color:var(--accent);flex:1">파이프라인 저장</button>
        ${crm.stage || crm.text ? '<button type="button" class="iconbtn sm" id="crmDel">삭제</button>' : ''}
      </div>
    </div></div>

    <div class="sec"><h4>🏆 전문가 6축 영업기회 진단</h4><div class="sales">
      <div class="radar-wrap">${radarSVG([{ vals: it._axes, color: 'var(--accent)', name: it.title }])}
        <div class="tiny" style="line-height:1.7">
          <b>핵심 제안 포인트</b><br>${esc(it._doms[0].tip)}<br><br>
          ${['예산규모', '마감긴급', '보안·AI', '지역적합', '조기포착', '단지·규모'].map((lb, k) => `${lb}: <b>${it._axes[k]}점</b>`).join(' · ')}
        </div>
      </div>
    </div></div>

    <dl class="kv">
      <dt>발주처/단지</dt><dd><span>${esc(it.org)}</span><button class="cp" data-cp="${esc(it.org)}">복사</button></dd>
      <dt>출처/유형</dt><dd><span>${esc(it.source)} · ${STAGE_LBL[it.stageType]}</span></dd>
      <dt>추정 예산</dt><dd><b class="num">${fmtBudget(it.budgetMan)}</b></dd>
      <dt>입찰방식</dt><dd><span>${esc(it.method || '-')}</span></dd>
      <dt>공고 / 마감</dt><dd><span class="num">${esc(it.pubDateTime || it.pubDate || '-')} ~ ${esc(it.closeDate || '상시')}</span></dd>
      <dt>소재지</dt><dd><span>${esc(it.region || '-')}</span>${it.region ? `<button class="cp" data-cp="${esc(it.region)}">복사</button>` : ''}</dd>
      ${it.meta?.households ? `<dt>단지규모</dt><dd><span class="num">${fmt(it.meta.households)}세대 · ${it.meta.builtYear || '-'}년 준공 (${new Date().getFullYear() - it.meta.builtYear}년차) · 노후교체 ${it._aptGold}점</span></dd>` : ''}
      ${it.meta?.area ? `<dt>건축규모</dt><dd><span class="num">연면적 ${fmt(it.meta.area)}㎡ · ${esc(it.meta.purp || '')}</span></dd>` : ''}
    </dl>

    ${(() => {
      const dt = it.detail || null;
      const files = it.attachments || [];
      const bidNoHint = dt?.bidNo || (String(it.id || '').startsWith('g2b-') ? String(it.id).slice(4) : '');
      const fmtWon = w => w > 0 ? `${fmt(w)}원 (${(w / 1e8).toFixed(2)}억)` : '';
      const dRows = dt ? [
        ['공고번호 / 차수', dt.bidNo],
        ['공고구분', dt.ntceKind],
        ['참조번호', dt.refNo],
        ['변경/취소 사유', dt.chgRsn],
        ['계약방법', dt.contractMethod],
        ['낙찰방법', dt.awardMethod],
        ['낙찰하한율', dt.awardRate],
        ['예정가격 방식', dt.priceMethod],
        ['배정예산액', fmtWon(dt.asignWon)],
        ['추정가격', fmtWon(dt.presmptWon)],
        ['부가세(VAT)', dt.vatWon > 0 ? `${fmt(dt.vatWon)}원` : ''],
        ['공동도급', dt.jointMethod],
        ['업종제한 / 재입찰', [dt.industryLimit ? `업종 ${dt.industryLimit}` : '', dt.rebid ? `재입찰 ${dt.rebid}` : ''].filter(Boolean).join(' · ')],
        ['품목·업종 분류', dt.categoryNm],
        ['물품규격', dt.prdctSpec],
        ['입찰개시일시', dt.bidBeginDt],
        ['입찰마감일시', dt.bidClseDt],
        ['참가자격등록마감', dt.qualDt],
        ['개찰일시 / 장소', [dt.opengDt, dt.opengPlce].filter(Boolean).join(' · ')],
        ['납품기한', dt.dlvrDt],
        ['연계 사전규격', dt.bfSpecNo],
        ['발주 담당자', [dt.ofclNm, dt.ofclTel, dt.ofclEmail].filter(Boolean).join(' · ')],
      ].filter(([, v]) => v) : [];
      return `
      <div class="sec"><h4>📎 첨부서류 · 공고문 · 과업지시서 (${files.length}건) ${!dt && bidNoHint ? '<button type="button" class="iconbtn sm" id="btnLoadG2bDet" style="margin-left:auto">🔍 실시간 상세·첨부 조회</button>' : ''}</h4><div class="sales">
        ${files.length ? `<div style="display:flex;flex-direction:column;gap:6px">${files.map(f => `
          <a href="${esc(f.url)}" target="_blank" rel="noopener" style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 9px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);text-decoration:none;font-size:12px">
            <span style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600">${fileIconForName(f.name)} ${esc(f.name)}</span>
            <span style="flex-shrink:0;padding:2px 8px;border-radius:6px;background:var(--accent);color:#fff;font-size:11px;font-weight:700">⬇️ 다운로드</span>
          </a>`).join('')}</div>` : `<p class="tiny" style="margin:0">${dt ? '나라장터 API에 등록된 첨부파일이 없거나 원문공고에서 확인 가능합니다.' : (bidNoHint ? '상단 "실시간 상세·첨부 조회" 버튼을 누르면 공고문·과업지시서 첨부파일과 낙찰조건을 즉시 불러옵니다.' : '상단 원문공고에서 첨부서류를 확인하세요.')}</p>`}
      </div></div>
      ${dRows.length ? `<div class="sec"><h4>📋 입찰 상세내역 · 일정 · 낙찰조건 · 담당자</h4><dl class="kv" style="margin-top:0">${dRows.map(([k, v]) => `<dt>${esc(k)}</dt><dd><span>${esc(v)}</span></dd>`).join('')}</dl></div>` : ''}`;
    })()}

    ${renderBidSimHtml(it)}

    ${renderQualBoxHtml(it)}

    <div class="sec"><h4>📊 과거 낙찰결과 · 경쟁사 투찰률 분석 <button type="button" class="iconbtn sm" id="btnLoadAwards" style="margin-left:auto">${AWARD_CACHE.loaded ? '🔄 재분석' : '🔍 실시간 낙찰 분석'}</button></h4><div class="sales" id="dAwardBox">
      <p class="tiny" style="margin:0">나라장터 낙찰정보 API(최근 8일 용역·공사·물품)에서 동일 발주기관·유사 공고의 평균 낙찰률·분포도와 주요 낙찰사를 분석합니다.</p>
    </div></div>

    ${(() => {
      const partners = findPartnerBuilders(it, 5);
      return `<div class="sec"><h4>🤝 지역 · 업종 추천 협력 파트너 TOP 5 (12,198사 DB)</h4><div class="sales">
        ${partners.length ? `<div style="display:flex;flex-direction:column;gap:6px">${partners.map(({ b, sameRid }) => `
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--surface)">
            <div style="min-width:0">
              <div style="font-weight:800;font-size:12px">${esc(b.r[0])} <span class="tiny" style="color:${sameRid ? '#059669' : 'var(--accent)'}">${sameRid ? '📍동일시군구' : '🗺️동일시도'}</span></div>
              <div class="tiny" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(BLD_IND[b.r[8]] || b.sec)} · 매출 ${ok(b.rev) ? fmt(Math.round(b.rev)) + '억' : '-'} · ${b.cred ? '신용 ' + b.cred + '등급' : ''}</div>
            </div>
            ${b.r[6] ? `<a href="tel:${esc(b.r[6])}" style="flex-shrink:0;padding:3px 7px;border-radius:6px;background:#ecfdf5;color:#047857;font-size:11px;font-weight:700;text-decoration:none">📞 ${esc(b.r[6])}</a>` : ''}
          </div>`).join('')}</div>` : '<p class="tiny" style="margin:0">해당 지역 매칭 건설사가 없습니다 (전국 공고는 상단 건설·시설사 탭에서 검색하세요).</p>'}
      </div></div>`;
    })()}

    <div class="sec"><h4>🗺 일반 정밀지도 · 현장 실사 · 지적 · 공시지가 (브이월드)</h4><div class="sales" id="vwOppBox">
      <p class="tiny" style="margin:0 0 8px">현장답사 전 단지·관공서·착공 부지의 일반 정밀지도(도로·건물)·항공·연속지적도·용도지역·2025 개별공시지가를 실시간 실사합니다.</p>
      <button type="button" class="aibtn" id="btnVwOpp" style="margin:0;background:linear-gradient(135deg,#0f766e,#0284c7)">🗺 일반 정밀지도 · 지적 · 공시지가 보기</button>
    </div></div>

    <div class="sec"><h4>🤖 Gemini AI 입찰·제안 전략</h4><div class="sales" id="aiBox">
      <p class="tiny" style="margin:0 0 8px">공고·단지 데이터를 기반으로 핵심 제안 포인트·예상 리스크·영업 접근 멘트를 생성합니다.</p>
      <button type="button" class="aibtn" id="btnAiStrat" style="margin:0">AI 입찰·제안 전략 생성</button>
    </div></div>
  </div>`;

  $('#dclose').onclick = closeDetail;
  $('#dfav').onclick = e => { if (FAV.has(id)) FAV.delete(id); else FAV.add(id); store.set('fav', [...FAV]); e.currentTarget.classList.toggle('on', FAV.has(id)); e.currentTarget.textContent = FAV.has(id) ? '★' : '☆'; renderList(); };
  $('#dA4Btn').onclick = () => openA4BidReview(it);
  $('#dIcsBtn').onclick = () => downloadOppIcs(it);
  $('#dRadarJumpBtn').onclick = () => {
    closeDetail();
    setSide('map');
    MAPMODE = 'radar';
    RADAR_STAGE = '';
    RADAR_URG = '';
    syncMainMapMode();
    if (it.rid >= 0 && RADAR_MAP) {
      const [la, lo] = radarCentroidLatLon(it.rid);
      setTimeout(() => { RADAR_MAP.setView([la, lo], 12); toast(`🗺️ ${regName(it.rid)} 주변 입찰·노후단지·조기포착 레이더 이동`); }, 160);
    }
  };
  $('#dCmpBtn').onclick = () => { toggleCompare(id); openDetail(id); };
  wireBidSim(it);
  wireQualBox(it);
  const renderAwardUi = awards => {
    const box = $('#dAwardBox'); if (!box) return;
    const bm = matchAwardBenchmarks(it, awards);
    if (!bm.pool.length) { box.innerHTML = `<p class="tiny" style="margin:0">최근 8일 낙찰 ${fmt(bm.totalScanned)}건 중 동일 기관/유사 공고 이력이 없습니다.</p>`; return; }
    box.innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:8px;text-align:center">
        <div style="padding:6px;border-radius:7px;background:var(--surface);border:1px solid var(--line)"><div class="tiny">평균 낙찰률</div><b class="num" style="color:var(--accent)">${bm.avgRate ? bm.avgRate.toFixed(2) + '%' : '-'}</b></div>
        <div style="padding:6px;border-radius:7px;background:var(--surface);border:1px solid var(--line)"><div class="tiny">평균 경쟁률</div><b class="num" style="color:#059669">${bm.avgBidders ? bm.avgBidders.toFixed(1) + '사' : '-'}</b></div>
        <div style="padding:6px;border-radius:7px;background:var(--surface);border:1px solid var(--line)"><div class="tiny">기관/유사</div><b class="num">${bm.sameOrg.length}/${bm.similar.length}건</b></div>
      </div>
      ${renderAwardHist(bm.rates)}
      ${bm.avgRate ? `<button type="button" class="iconbtn sm" id="dApplyAvgRate" style="width:100%;margin-bottom:8px">🎯 평균 낙찰률(${bm.avgRate.toFixed(2)}%) 시뮬레이터 적용</button>` : ''}
      <div style="display:flex;flex-direction:column;gap:5px">${bm.pool.map(x => `
        <div style="padding:6px 8px;border:1px solid var(--line);border-radius:7px;background:var(--surface);font-size:11.5px">
          <div style="font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(x.title)}</div>
          <div style="display:flex;justify-content:space-between;gap:6px;margin-top:2px" class="tiny">
            <span>🏆 <b>${esc(x.winner)}</b> (${esc(x.org)})</span>
            <span style="white-space:nowrap;color:var(--accent);font-weight:800">${x.rate ? x.rate.toFixed(2) + '%' : '-'} · ${x.bidders}사</span>
          </div>
        </div>`).join('')}</div>`;
    if ($('#dApplyAvgRate')) $('#dApplyAvgRate').onclick = () => {
      const el = $('#dSimRate');
      if (el && bm.avgRate) { el.value = bm.avgRate.toFixed(3); el.dispatchEvent(new Event('input')); toast(`🎯 평균 낙찰률 ${bm.avgRate.toFixed(2)}% 반영`); }
    };
    if ($('#dApplyModeRate')) $('#dApplyModeRate').onclick = ev => {
      const el = $('#dSimRate');
      const mv = parseFloat(ev.currentTarget.dataset.mode);
      if (el && Number.isFinite(mv)) { el.value = mv.toFixed(3); el.dispatchEvent(new Event('input')); toast(`⚡ 최빈 중앙값 ${mv.toFixed(2)}% 반영`); }
    };
  };
  if (AWARD_CACHE.loaded) renderAwardUi(AWARD_CACHE.list);
  if ($('#btnLoadAwards')) $('#btnLoadAwards').onclick = async e => {
    const b = e.currentTarget; b.disabled = true; b.textContent = '분석 중…';
    const awards = await ensureAwardHistoryLoaded();
    b.disabled = false; b.textContent = '🔄 재분석';
    renderAwardUi(awards);
  };
  $('#dbody').querySelectorAll('[data-cp]').forEach(x => x.onclick = () => copy(x.dataset.cp));
  const btnLoadDet = $('#btnLoadG2bDet');
  if (btnLoadDet) {
    btnLoadDet.onclick = async () => {
      const bidNo = it.detail?.bidNo || (String(it.id || '').startsWith('g2b-') ? String(it.id).slice(4) : '');
      btnLoadDet.disabled = true; btnLoadDet.textContent = '조회 중…';
      const res = await fetchSingleBidDetailLive(bidNo);
      if (res) {
        it.attachments = res.attachments;
        it.detail = res.detail;
        toast(`✅ 상세내역 · 첨부서류 ${res.attachments.length}건 불러오기 완료`);
        openDetail(id);
      } else {
        btnLoadDet.disabled = false; btnLoadDet.textContent = '🔍 재시도';
        toast('나라장터 단건 조회 결과가 없습니다. 원문공고를 확인하세요.');
      }
    };
  }

  let selSt = crm.stage || '';
  $('#crmStBar').onclick = e => { const b = e.target.closest('[data-cst]'); if (!b) return; selSt = selSt === b.dataset.cst ? '' : b.dataset.cst; $$('#crmStBar .chip').forEach(x => x.setAttribute('aria-pressed', x.dataset.cst === selSt)); };
  $('#crmSave').onclick = () => {
    const text = $('#crmTxt').value.trim(), estMan = Number($('#crmEstIn').value || 0);
    if (!selSt && !text) delete CRM[id];
    else CRM[id] = { stage: selSt || '발굴', estMan, text, updated: new Date().toLocaleString('ko-KR', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) };
    store.set('crm', CRM); toast('파이프라인에 저장했습니다'); run(); openDetail(id);
  };
  $('#crmDel')?.addEventListener('click', () => { delete CRM[id]; store.set('crm', CRM); toast('삭제했습니다'); run(); openDetail(id); });
  const loadOppVw = () => window.VWorldTwin?.renderInspector($('#vwOppBox'), { addr: it.region || it.org, name: it.org || it.title, store, meta: META });
  $('#btnVwOpp')?.addEventListener('click', loadOppVw);
  if (window.VWorldTwin?.getKey(store, META)) loadOppVw();
  if (MAPMODE === 'precision' && VW_MAIN && (it.region || it.org)) VW_MAIN.focusItem({ id, name: it.org || it.title, addr: it.region || it.org });
  $('#btnAiStrat').onclick = () => runAiStrategy(it, $('#aiBox'));

  $('#detail').classList.add('on'); $('#detail').setAttribute('aria-hidden', 'false'); updateScrim();
}
function closeDetail() { window.VWorldTwin?.destroyActiveMap(); $('#detail').classList.remove('on'); $('#detail').setAttribute('aria-hidden', 'true'); updateScrim(); }

async function runAiStrategy(it, box) {
  const key = store.get('geminiKey', '');
  if (!key) { toast('설정(⚙️)에서 Gemini API 키를 먼저 입력하세요'); openSettings(true); return; }
  box.innerHTML = '<p class="tiny">Gemini AI가 입찰·제안 전략을 분석 중입니다…</p>';
  try {
    const prompt = `당신은 한국 공동주택·관공서·건설사 B2B 입찰 영업 전문가입니다. 아래 영업기회 데이터만 근거로 한국어 불릿 5개로 정리하세요: 1) 핵심 공략 포인트 2) 추천 제품/솔루션(보안·AI CCTV·출입/주차관제·시설관리 등) 3) 입찰/경쟁 리스크 4) 발주처 첫 미팅 질문 2가지 5) 즉시 실행 액션.\n데이터: ${JSON.stringify({ 제목: it.title, 발주처: it.org, 구분: CAT_LBL[it.category], 단계: STAGE_LBL[it.stageType], 예산만원: it.budgetMan, 마감일: it.closeDate, 방식: it.method, 지역: it.region, 메타: it.meta })}`;
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(key)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    const txt = j?.candidates?.[0]?.content?.parts?.[0]?.text || '응답 없음';
    box.innerHTML = `<div style="font-size:13px;line-height:1.65">${esc(txt).replace(/\n/g, '<br>')}</div>`;
  } catch (e) { box.innerHTML = `<p class="tiny">AI 오류: ${esc(e.message)}</p>`; }
}

/* ==================== Compare Matrix & 1-Page Briefing ==================== */
function toggleCompare(id) {
  const idx = CMP.indexOf(id);
  if (idx >= 0) { CMP.splice(idx, 1); toast('비교함에서 뺐습니다'); }
  else { if (CMP.length >= 5) { toast('최대 5건까지 비교 가능합니다'); return; } CMP.push(id); toast(`비교함에 담았습니다 (${CMP.length}/5)`); }
  $('#cmpTray').hidden = CMP.length === 0;
  $('#cmpCnt').textContent = CMP.length;
  $('#cmpNames').innerHTML = CMP.map(x => { const it = OPPS.find(o => o.id === x); return `<span class="cpill">${esc((it?.title || '').slice(0, 10))}<button type="button" data-cmprm="${esc(x)}">✕</button></span>`; }).join('');
  renderList();
}
function openCompare() {
  const items = CMP.map(id => OPPS.find(o => o.id === id)).filter(Boolean); if (!items.length) return;
  const cols = ['var(--c1)', 'var(--c2)', 'var(--c3)', 'var(--c7)', 'var(--c4)'];
  const series = items.map((it, k) => ({ vals: it._axes, color: cols[k % 5], name: it.title.slice(0, 18) }));
  const metrics = [
    ['구분 / 단계', it => `${CAT_LBL[it.category]} · ${STAGE_LBL[it.stageType]}`, null],
    ['발주처', it => it.org, null],
    ['🏆 영업기회 점수', it => `${it._score}점 (${it._grade})`, it => it._score],
    ['예산 규모', it => fmtBudget(it.budgetMan), it => it.budgetMan || 0],
    ['마감 D-Day', it => it._dday === null ? '상시' : `D-${it._dday}`, it => it._dday === null ? -999 : -it._dday],
    ['핵심 분야', it => it._doms[0].l, null],
    ['노후 교체적기', it => it._aptGold ? it._aptGold + '점' : '-', it => it._aptGold || NaN],
    ['지역', it => it.region || '-', null],
    ['입찰방식', it => it.method || '-', null],
  ];
  const rowsHtml = metrics.map(([lbl, fn, numFn]) => {
    let best = -Infinity; if (numFn) items.forEach(it => { const v = numFn(it); if (ok(v) && v > best) best = v; });
    return `<tr><td>${lbl}</td>${items.map(it => { const v = numFn ? numFn(it) : NaN; const win = numFn && items.length > 1 && ok(v) && v === best; return `<td class="num${win ? ' win' : ''}">${esc(fn(it))}</td>`; }).join('')}</tr>`;
  }).join('');

  $('#cmpBody').innerHTML = `
    <div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-bottom:12px">
      <div style="width:210px;margin:0 auto">${radarSVG(series)}</div>
      <div style="flex:1;min-width:200px">${series.map(s => `<div style="font-size:12.5px;margin:3px 0"><span class="dot" style="background:${s.color}"></span> <b>${esc(s.name)}</b></div>`).join('')}</div>
    </div>
    <div class="tblwrap"><table class="tbl cmp-tbl"><thead><tr><th>지표</th>${items.map((it, k) => `<th><span class="dot" style="background:${cols[k % 5]}"></span> ${esc(it.title.slice(0, 14))}</th>`).join('')}</tr></thead><tbody>${rowsHtml}</tbody></table></div>`;
  $('#cmpCopyBtn').onclick = () => copy([['지표', ...items.map(it => it.title)].join('\t'), ...metrics.map(([l, fn]) => [l, ...items.map(it => fn(it))].join('\t'))].join('\n'), '비교 표를 복사했습니다');
  $('#cmpModal').classList.add('on'); $('#cmpModal').setAttribute('aria-hidden', 'false'); updateScrim();
}
function closeCompare() { $('#cmpModal').classList.remove('on'); $('#cmpModal').setAttribute('aria-hidden', 'true'); updateScrim(); }

function openBriefing(it) {
  const c = CRM[it.id];
  const txt = [
    `[입찰·영업기회 브리핑] ${it.title}`,
    `━━━━━━━━━━━━━━━━━━━━━━━━`,
    `• 구분/단계: ${CAT_LBL[it.category]} · ${STAGE_LBL[it.stageType]} (${it.source})`,
    `• 발주처/단지: ${it.org}`,
    `• 소재지: ${it.region || '-'}`,
    `• 추정 예산: ${fmtBudget(it.budgetMan)}  |  방식: ${it.method || '-'}`,
    `• 공고/마감: ${it.pubDate || '-'} ~ ${it.closeDate || '상시'}${it._dday !== null ? ` (D-${it._dday})` : ''}`,
    `• 영업기회 점수: ${it._score}점 (${it._grade}등급)${it._aptGold ? ` · 노후 교체적기 ${it._aptGold}점` : ''}`,
    `• 자동 분류 분야: ${it._doms.map(d => d.l).join(', ')}`,
    `• 추천 제안 포인트: ${it._doms[0].tip}`,
    it.url ? `• 원문 링크: ${it.url}` : '',
    c && (c.stage || c.text) ? `\n[내 CRM 메모 (${c.stage} / 예상 ${fmtBudget(c.estMan)})]\n${c.text}` : '',
  ].filter(Boolean).join('\n');
  $('#briefBody').textContent = txt;
  $('#briefCopyBtn').onclick = () => copy(txt, '1페이지 브리핑을 복사했습니다');
  $('#briefModal').classList.add('on'); $('#briefModal').setAttribute('aria-hidden', 'false'); updateScrim();
}
function closeBriefing() { $('#briefModal').classList.remove('on'); $('#briefModal').setAttribute('aria-hidden', 'true'); updateScrim(); }

/* ==================== Export & Presets ==================== */
function downloadCsv(rows, filename) {
  const csv = '\uFEFF' + rows.map(cols => cols.map(v => { const s = String(v ?? '').replace(/\r|\n/g, ' '); return /[",]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }).join(',')).join('\r\n');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' })); a.download = filename; a.click();
  toast(`${rows.length - 1}건 CSV 저장 완료`);
}
function exportOpps(mode) {
  const rows = [['구분', '단계', '출처', '우선등급', '점수', '공고/단지명', '발주처', '지역', '예산(만원)', '마감일', 'D-Day', '분야', '노후교체점수', 'CRM단계', '예상수주(만원)', '메모', '링크']];
  RES.forEach(it => {
    const c = CRM[it.id] || {};
    rows.push([CAT_LBL[it.category], STAGE_LBL[it.stageType], it.source, it._grade, it._score, it.title, it.org, it.region, it.budgetMan || '', it.closeDate || '', it._dday ?? '', it._doms.map(d => d.l).join('/'), it._aptGold || '', c.stage || '', c.estMan || '', c.text || '', it.url || '']);
  });
  if (mode === 'csv') downloadCsv(rows, `입찰_영업기회_${todayStr()}.csv`);
  else copy(rows.map(r => r.join('\t')).join('\n'), `${RES.length}건을 표 형식으로 복사했습니다`);
}
function renderPresets() {
  $('#presetList').innerHTML = PRESETS.length
    ? PRESETS.map((p, k) => `<div class="preset-item"><button type="button" class="load" data-pl="${k}">🔖 ${esc(p.name)}</button><button type="button" class="cp" data-pd="${k}">✕</button></div>`).join('')
    : '<div class="tiny">자주 쓰는 필터를 저장해 원클릭으로 불러오세요.</div>';
}
function fillSgg() {
  const s = $('#fSgg'); s.innerHTML = '<option value="">+ 시·군·구 추가</option>';
  if (S.sido) MAP.regions.filter(r => r.sd === S.sido).sort((a, b) => a.n.localeCompare(b.n, 'ko')).forEach(r => s.insertAdjacentHTML('beforeend', `<option value="${r.id}">${r.n}</option>`));
  s.disabled = !S.sido;
}
function resetAll() {
  Object.assign(S, { q: '', cats: [], stages: [], dday: '', doms: [], buds: [], grade: '', sido: '', sggs: [], crm: [], fav: false, hideSample: false });
  $('#q').value = ''; $('#searchBox').classList.remove('has'); $('#fSido').value = ''; fillSgg(); $('#fFav').checked = false; $('#fHideSample').checked = false; run();
}

/* ==================== Navigation & Boot ==================== */
const isMobile = () => matchMedia('(max-width:767px)').matches;
function updateScrim() { $('#scrim').classList.toggle('on', $('#detail').classList.contains('on') || $('#filterPanel').classList.contains('on') || $('#settingsModal').classList.contains('on') || $('#cmpModal').classList.contains('on') || $('#briefModal').classList.contains('on')); }
function openFilter(on) { $('#filterPanel').classList.toggle('on', on); updateScrim(); }
function openSettings(on) {
  $('#settingsModal').classList.toggle('on', on); $('#settingsModal').setAttribute('aria-hidden', String(!on));
  if (on) {
    $('#dataGoKeyIn').value = store.get('dataGoKey', ''); $('#geminiKeyIn').value = store.get('geminiKey', '');
    if ($('#vwKeyInSet') && window.VWorldTwin) {
      const localVw = store.get('vworldKey', '');
      const effVw = VWorldTwin.getKey(store, META);
      $('#vwKeyInSet').value = localVw;
      $('#vwMaskSet').textContent = localVw ? `${VWorldTwin.maskKey(effVw)} (수동 저장)` : effVw ? `${VWorldTwin.maskKey(effVw)} (Vault 암호화)` : '미입력';
    }
    applyTheme(store.get('theme', 'auto'));
    if (VAULT_META) $('#vaultInfo').textContent = `데이터 빌드일: ${VAULT_META.builtAt} · AES-256-GCM 암호화 (${(VAULT_META.totalBytes / 1024).toFixed(0)} KB)`;
  }
  updateScrim();
}
function setSide(v) {
  ['pro', 'map', 'builders', 'api', 'crm'].forEach(k => {
    const cap = k[0].toUpperCase() + k.slice(1);
    $('#v' + cap).classList.toggle('on', v === k);
    $('#tab' + cap).setAttribute('aria-selected', v === k);
  });
  if (v === 'map') {
    syncMainMapMode();
    if (MAPMODE === 'precision') VW_MAIN?.invalidate();
    else requestAnimationFrame(renderLabels);
  }
  if (v === 'builders') renderBuilders();
  if (v === 'api') renderApiPanel();
  if (v === 'crm') renderCrm();
}
function setView(v) {
  document.body.dataset.view = v;
  $$('.bnav button').forEach(b => b.setAttribute('aria-selected', b.dataset.v === v));
  if (v !== 'list') setSide(v);
}

async function fetchG2bTailNewest(baseUrl, todayBgn, yestBgn, end) {
  const extract = j => { const it = j?.response?.body?.items; if (!it) return []; if (Array.isArray(it)) return it; if (Array.isArray(it.item)) return it.item; return it.item ? [it.item] : []; };
  const collectWindow = async (bgnDt, endDt, maxPages = 3) => {
    const r1 = await fetch(`${baseUrl}&numOfRows=999&pageNo=1&type=json&inqryDiv=1&inqryBgnDt=${bgnDt}&inqryEndDt=${endDt}`);
    if (!r1.ok) return [];
    const j1 = await r1.json();
    const total = Number(j1?.response?.body?.totalCount || 0);
    let out = extract(j1);
    if (total > 999) {
      const pages = Math.min(maxPages, Math.ceil(total / 999));
      const extras = await Promise.all(
        Array.from({ length: pages - 1 }, (_, i) => i + 2).map(async p => {
          try {
            const rp = await fetch(`${baseUrl}&numOfRows=999&pageNo=${p}&type=json&inqryDiv=1&inqryBgnDt=${bgnDt}&inqryEndDt=${endDt}`);
            return rp.ok ? extract(await rp.json()) : [];
          } catch { return []; }
        })
      );
      extras.forEach(arr => { out = out.concat(arr); });
    }
    return out;
  };
  const [todayItems, yestItems] = await Promise.all([
    collectWindow(todayBgn, end, 4),
    collectWindow(yestBgn, todayBgn, 1),
  ]);
  const merged = [...todayItems, ...yestItems];
  merged.sort((a, b) => String(b.bidNtceDt || b.rcptDt || '').localeCompare(String(a.bidNtceDt || a.rcptDt || '')));
  return merged;
}

function extractG2bDetail(x, isPre) {
  const attachments = [];
  const seen = new Set();
  const pushFile = (name, url) => {
    const u = String(url || '').trim();
    if (!u || seen.has(u)) return;
    seen.add(u);
    attachments.push({ name: String(name || '첨부서류').trim(), url: u });
  };
  if (isPre) {
    for (let i = 1; i <= 5; i++) {
      if (x[`specDocFileUrl${i}`]) pushFile(`사전규격 첨부문서 #${i}`, x[`specDocFileUrl${i}`]);
    }
  } else {
    for (let i = 1; i <= 10; i++) {
      const u = x[`ntceSpecDocUrl${i}`];
      if (u) pushFile(x[`ntceSpecFileNm${i}`] || `공고 첨부서류 #${i}`, u);
    }
    if (x.stdNtceDocUrl) pushFile('표준공고서', x.stdNtceDocUrl);
  }
  const telRaw = String(x.ntceInsttOfclTelNo || x.ofclTelNo || '').trim();
  const telClean = telRaw && !/^\*+$/.test(telRaw) ? telRaw : '';
  const clsPath = [x.pubPrcrmntLrgClsfcNm, x.pubPrcrmntMidClsfcNm, x.pubPrcrmntClsfcNm].filter(Boolean).join(' > ');
  const priceMthd = x.prearngPrceDcsnMthdNm
    ? `${x.prearngPrceDcsnMthdNm}${x.totPrdprcNum ? ` (${x.totPrdprcNum}개 중 ${x.drwtPrdprcNum || 4}개 추첨)` : ''}`
    : '';
  return {
    attachments,
    detail: {
      bidNo: isPre ? (x.bfSpecRgstNo || '') : `${x.bidNtceNo || ''}${x.bidNtceOrd ? '-' + x.bidNtceOrd : ''}`,
      ntceKind: isPre ? '사전규격공개' : (x.ntceKindNm || '등록공고'),
      refNo: x.refNo || '',
      chgRsn: x.chgNtceRsn || '',
      contractMethod: x.cntrctCnclsMthdNm || '',
      awardMethod: x.sucsfbidMthdNm || '',
      awardRate: x.sucsfbidLwltRate ? `${x.sucsfbidLwltRate}%` : '',
      priceMethod: priceMthd,
      presmptWon: Number(x.presmptPrce || 0) || 0,
      asignWon: Number(x.asignBdgtAmt || 0) || 0,
      vatWon: Number(x.VAT || 0) || 0,
      jointMethod: x.cmmnSpldmdMethdNm || '',
      industryLimit: x.indstrytyLmtYn ? (x.indstrytyLmtYn === 'Y' ? '제한 있음 (공고문 확인)' : '제한 없음') : '',
      rebid: x.rbidPermsnYn ? (x.rbidPermsnYn === 'Y' ? '허용' : '불가') : '',
      categoryNm: clsPath || x.srvceDivNm || x.bsnsDivNm || '',
      bidBeginDt: x.bidBeginDt || '',
      bidClseDt: x.bidClseDt || x.opninRgstClseDt || '',
      opengDt: x.opengDt || '',
      opengPlce: x.opengPlce || '',
      qualDt: x.bidQlfctRgstDt || '',
      dlvrDt: x.dlvrTmlmtDt || '',
      ofclNm: x.ntceInsttOfclNm || x.ofclNm || '',
      ofclTel: telClean,
      ofclEmail: x.ntceInsttOfclEmailAdrs || '',
      bfSpecNo: x.bfSpecRgstNo || '',
      prdctSpec: x.prdctSpecNm || '',
    },
  };
}

function fileIconForName(name) {
  const s = String(name || '').toLowerCase();
  if (s.endsWith('.pdf')) return '📄';
  if (s.endsWith('.hwp') || s.endsWith('.hwpx') || s.endsWith('.doc') || s.endsWith('.docx')) return '📝';
  if (s.endsWith('.xls') || s.endsWith('.xlsx') || s.endsWith('.csv')) return '📊';
  if (s.endsWith('.zip') || s.endsWith('.7z') || s.endsWith('.rar')) return '🗜️';
  return '📎';
}

async function fetchSingleBidDetailLive(bidNtceNo) {
  const rawKey = getEffectiveDataGoKey();
  if (!rawKey || !bidNtceNo) return null;
  const keyEnc = normalizeDataGoKey(rawKey);
  const cleanNo = String(bidNtceNo).split('-')[0].trim();
  for (const op of ['getBidPblancListInfoServc02', 'getBidPblancListInfoCnstwk02', 'getBidPblancListInfoThng02']) {
    try {
      const r = await fetch(`https://apis.data.go.kr/1230000/ad/BidPublicInfoService02/${op}?serviceKey=${keyEnc}&inqryDiv=2&bidNtceNo=${encodeURIComponent(cleanNo)}&pageNo=1&numOfRows=5&type=json`);
      if (!r.ok) continue;
      const j = await r.json();
      const raw = j?.response?.body?.items;
      const arr = Array.isArray(raw) ? raw : (raw?.item ? (Array.isArray(raw.item) ? raw.item : [raw.item]) : []);
      if (arr.length) return extractG2bDetail(arr[0], false);
    } catch {}
  }
  return null;
}

async function autoSyncKakaoLiveFeeds(silent = true) {
  const rawKey = getEffectiveDataGoKey();
  if (!rawKey || KAKAO_SYNC.syncing) return;
  KAKAO_SYNC.syncing = true;
  if (!silent) toast('🔄 카톡 알림봇 동일 소스(오늘 00시~현재 전수 + 어제 최신 입찰·사전규격·청약홈) 동기화 중…');
  const keyEnc = normalizeDataGoKey(rawKey);
  const nowMs = Date.now();
  const kst = ms => {
    const d = new Date(ms + 9 * 3600000);
    const pad = n => String(n).padStart(2, '0');
    const ymd = `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}`;
    return { ymd, dt: `${ymd}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}` };
  };
  const todayBgn = `${kst(nowMs).ymd}0000`, yestBgn = `${kst(nowMs - 24 * 3600000).ymd}0000`, end = kst(nowMs + 10 * 60000).dt;
  const out = [];

  await Promise.all([
    ...[
      ['bid', 'construction', `https://apis.data.go.kr/1230000/ad/BidPublicInfoService02/getBidPblancListInfoCnstwk02?serviceKey=${keyEnc}`],
      ['bid', 'gov', `https://apis.data.go.kr/1230000/ad/BidPublicInfoService02/getBidPblancListInfoServc02?serviceKey=${keyEnc}`],
      ['bid', 'gov', `https://apis.data.go.kr/1230000/ad/BidPublicInfoService02/getBidPblancListInfoThng02?serviceKey=${keyEnc}`],
      ['prespec', 'construction', `https://apis.data.go.kr/1230000/ao/HrcspSsstndrdInfoService/getPublicPrcureThngInfoCnstwk?serviceKey=${keyEnc}`],
      ['prespec', 'gov', `https://apis.data.go.kr/1230000/ao/HrcspSsstndrdInfoService/getPublicPrcureThngInfoServc?serviceKey=${keyEnc}`],
      ['prespec', 'gov', `https://apis.data.go.kr/1230000/ao/HrcspSsstndrdInfoService/getPublicPrcureThngInfoThng?serviceKey=${keyEnc}`],
    ].map(async ([st, cat, baseUrl]) => {
      try {
        const items = await fetchG2bTailNewest(baseUrl, todayBgn, yestBgn, end);
        items.forEach(x => {
          const isPre = st === 'prespec';
          const title = isPre ? (x.prdctClsfcNoNm || x.bsnsDivNm || '사전규격') : (x.bidNtceNm || '입찰공고');
          const org = x.dminsttNm || x.orderInsttNm || x.ntceInsttNm || '';
          const reg = x.dminsttOfclAddr || org;
          const extra = extractG2bDetail(x, isPre);
          out.push({
            id: isPre ? `pre-${x.bfSpecRgstNo || title}` : `g2b-${x.bidNtceNo}-${x.bidNtceOrd || '00'}`,
            isLive: true,
            source: isPre ? '나라장터 사전규격(실시간)' : '나라장터 입찰(실시간)',
            category: cat, stageType: st,
            title: isPre ? `[사전규격] ${title}` : title,
            org, region: reg, rid: matchRegionId(`${reg} ${title}`),
            budgetMan: Math.round(Number(isPre ? x.asignBdgtAmt : (x.presmptPrce || x.asignBdgtAmt || 0)) / 1e4),
            pubDate: String(isPre ? x.rcptDt : x.bidNtceDt || '').slice(0, 10),
            pubDateTime: String(isPre ? x.rcptDt : x.bidNtceDt || '').slice(0, 16),
            closeDate: String(isPre ? x.opninRgstClseDt : x.bidClseDt || '').slice(0, 10),
            method: isPre ? '사전규격 의견수렴' : (x.bidMethdNm || ''),
            url: x.bidNtceDtlUrl || 'https://www.g2b.go.kr/',
            attachments: extra.attachments,
            detail: extra.detail,
          });
        });
      } catch {}
    }),
    (async () => {
      try {
        const r = await fetch(`https://api.odcloud.kr/api/ApplyhomeInfoDetailSvc/v1/getAPTLttotPblancDetail?page=1&perPage=30&serviceKey=${keyEnc}`);
        if (!r.ok) return;
        const j = await r.json();
        (j?.data || []).forEach(x => {
          const nm = x.HOUSE_NM || '신축아파트', units = Number(x.TOT_SUPLY_HSHLDCO || 0);
          const area = x.SUBSCRPT_AREA_CODE_NM || '', builder = x.CNSTRCT_ENTRPS_NM || x.BSNS_MBY_NM || '시공사';
          const ym = String(x.MVN_PREARNGE_YM || ''), ymStr = ym.length === 6 ? `${ym.slice(0, 4)}.${ym.slice(4, 6)} 입주` : '';
          out.push({
            id: `applyhome-${x.PBLANC_NO || x.HOUSE_MANAGE_NO}`,
            isLive: true,
            source: '청약홈 신축분양(실시간)', category: 'apt', stageType: 'permit',
            title: `[신축분양] ${nm} (${units ? units.toLocaleString() + '세대' : '아파트'}${ymStr ? ', ' + ymStr : ''})`,
            org: builder, region: `${area} ${x.HSSPLY_ADRES || ''}`.trim(),
            rid: matchRegionId(`${area} ${x.HSSPLY_ADRES || ''}`),
            budgetMan: units > 0 ? Math.max(2000, units * 25) : 3000,
            pubDate: String(x.RCRIT_PBLANC_DE || '').slice(0, 10),
            closeDate: String(x.RCEPT_ENDDE || '').slice(0, 10),
            method: '청약홈 신축분양', url: x.PBLANC_URL || 'https://www.applyhome.co.kr/',
          });
        });
      } catch {}
    })(),
  ]);

  KAKAO_SYNC.syncing = false;
  KAKAO_SYNC.lastAt = new Date().toTimeString().slice(0, 5);
  KAKAO_SYNC.liveCnt = out.length;
  if (out.length) {
    await mergeLiveItems(out);
    $('#srcTxt').textContent = `🟢 카톡실시간 ${KAKAO_SYNC.lastAt} · 기회 ${fmt(OPPS.length)}건 · 건설·시설 ${fmt(BUILDERS.length)}사`;
    if (MAPMODE === 'radar') renderRadarMap(false);
    if (!silent) toast(`🟢 카톡 동일소스 ${out.length}건 실시간 반영 완료!`);
  }
}

async function bootWithKey(key) {
  VAULT_KEY = key;
  $('#lockScreen').hidden = true;
  $('#loader').hidden = false;
  const bar = $('#lbar'), txt = $('#ltxt');
  try {
    bar.style.width = '20%'; txt.textContent = '지도·건설사·입찰 데이터 복호화 중…';
    const [mapData, metaData, bldData, oppData] = await Promise.all([
      fetchDecJson('map'), fetchDecJson('meta'), fetchDecJson('builders'), fetchDecJson('opportunities'),
    ]);
    bar.style.width = '80%'; txt.textContent = '전문가 퀀트 지표 계산 중…';
    MAP = mapData; META = metaData; BUILDERS = bldData.rows || []; BLD_IND = bldData.industries || [];
    const savedLive = (await idb.get('live_opps')) || [];
    const byId = new Map();
    savedLive.forEach(x => byId.set(x.id, x));
    (oppData.items || []).forEach(x => { if (!byId.has(x.id)) byId.set(x.id, x); });
    OPPS = [...byId.values()];

    scoreBuilders();
    recomputeAllOpps();

    if (!APP_BOOTED) {
      APP_BOOTED = true;
      $('#srcTxt').textContent = `기회 ${fmt(OPPS.length)}건 · 건설·시설 ${fmt(BUILDERS.length)}사`;
      MAP.sidos.forEach(s => $('#fSido').insertAdjacentHTML('beforeend', `<option value="${s.sd}">${s.n}</option>`));
      $('#domChips').innerHTML = DOMAINS.map(d => `<button class="chip" data-dom="${d.k}">${d.l}</button>`).join('');
      $('#crmChips').innerHTML = CRM_STAGES.map(st => `<button class="chip" data-crm="${st}">${st}</button>`).join('');
      fillSgg(); renderPresets(); initMap();

      const tog = (arrKey, attr, num = false) => e => { const b = e.target.closest('.chip'); if (!b) return; const v = num ? +b.dataset[attr] : b.dataset[attr]; S[arrKey] = S[arrKey].includes(v) ? S[arrKey].filter(x => x !== v) : [...S[arrKey], v]; run(); };
      $('#catChips').onclick = tog('cats', 'cat');
      $('#stageChips').onclick = tog('stages', 'st');
      $('#domChips').onclick = tog('doms', 'dom');
      $('#budChips').onclick = tog('buds', 'bd', true);
      $('#crmChips').onclick = tog('crm', 'crm');
      $('#ddayChips').onclick = e => { const b = e.target.closest('.chip'); if (!b) return; S.dday = S.dday === b.dataset.dd ? '' : b.dataset.dd; run(); };
      $('#gradeChips').onclick = e => { const b = e.target.closest('.chip'); if (!b) return; S.grade = S.grade === b.dataset.gr ? '' : b.dataset.gr; run(); };
      $('#fSido').onchange = e => { S.sido = e.target.value; S.sggs = []; fillSgg(); run(); zoomToSido(S.sido); };
      $('#fSgg').onchange = e => { const v = e.target.value; if (v !== '' && !S.sggs.includes(+v)) S.sggs.push(+v); e.target.value = ''; run(); };
      $('#sggChips').onclick = e => { const b = e.target.closest('.chip'); if (b) { S.sggs = S.sggs.filter(x => x !== +b.dataset.r); run(); } };
      $('#fFav').onchange = e => { S.fav = e.target.checked; run(); };
      $('#fHideSample').onchange = e => { S.hideSample = e.target.checked; run(); };
      if ($('#fHideCancel')) { $('#fHideCancel').checked = S.hideCancelled; $('#fHideCancel').onchange = e => { S.hideCancelled = e.target.checked; run(); toast(S.hideCancelled ? '🚫 취소공고 자동 숨김 ON' : '👁️ 취소공고 포함 표시'); }; }
      $('#q').oninput = debounce(e => { S.q = e.target.value.trim(); $('#searchBox').classList.toggle('has', !!S.q); run(); }, 150);
      $('#qclr').onclick = () => { $('#q').value = ''; S.q = ''; $('#searchBox').classList.remove('has'); run(); };
      $('#sort').onchange = e => { S.sort = e.target.value; run(); };
      $('#resetAll').onclick = resetAll;
      $('#dlCsv').onclick = () => exportOpps('csv');
      $('#copyRes').onclick = () => exportOpps('copy');

      $('#qTodayBid').onclick = () => { resetAll(); S.dday = 'todayBid'; S.sort = 'new'; run(); openFilter(false); if (isMobile()) setView('list'); toast(`📅 오늘(${getTodayKstIso()}) 당일 입찰 ${RES.length}건`); };
      if ($('#qMyKw')) $('#qMyKw').onclick = () => { S.myKwOnly = !S.myKwOnly; run(); openFilter(false); if (isMobile()) setView('list'); toast(S.myKwOnly ? `⭐ 내 관심 키워드 매칭 ${RES.length}건` : '⭐ 내 관심 키워드 필터 해제'); };
      if ($('#qEditKw')) $('#qEditKw').onclick = () => {
        const next = prompt('내 관심 입찰 키워드를 쉼표(,)로 구분해 입력하세요:', MY_KW);
        if (next === null) return;
        MY_KW = next.trim() || 'CCTV,관제,보안,소방,승강기,시설,경비,미화,전기,통신,보험';
        store.set('myBidKeywords', MY_KW);
        S.myKwOnly = true; run(); toast(`✅ 관심 키워드 저장 완료 (${RES.length}건 매칭)`);
      };
      $('#qUrgent').onclick = () => { resetAll(); S.dday = '3'; S.sort = 'dday'; run(); openFilter(false); if (isMobile()) setView('list'); toast(`🚨 D-3 긴급입찰 ${RES.length}건`); };
      $('#qSecAi').onclick = () => { resetAll(); S.doms = ['sec', 'ai']; S.sort = 'score'; run(); openFilter(false); if (isMobile()) setView('list'); toast(`🛡 보안·AI 특화 ${RES.length}건`); };
      $('#qAptGold').onclick = () => { resetAll(); S.cats = ['apt']; S.sort = 'aptgold'; run(); openFilter(false); if (isMobile()) setView('list'); toast(`🏘 공동주택 교체적기순 ${RES.length}건`); };

      $('#savePresetBtn').onclick = () => {
        const name = $('#presetNameIn').value.trim(); if (!name) return;
        PRESETS = [{ name, state: JSON.parse(JSON.stringify(S)) }, ...PRESETS.filter(p => p.name !== name)];
        store.set('presets', PRESETS); $('#presetNameIn').value = ''; renderPresets(); toast(`"${name}" 저장`);
      };
      $('#presetList').onclick = e => {
        const ld = e.target.closest('[data-pl]'); if (ld) { Object.assign(S, PRESETS[+ld.dataset.pl].state); $('#q').value = S.q || ''; $('#fSido').value = S.sido || ''; fillSgg(); run(); openFilter(false); toast('프리셋 적용'); return; }
        const dl = e.target.closest('[data-pd]'); if (dl) { PRESETS.splice(+dl.dataset.pd, 1); store.set('presets', PRESETS); renderPresets(); }
      };

      $('#list').onclick = e => {
        const cb = e.target.closest('[data-cmp]'); if (cb) { e.stopPropagation(); toggleCompare(cb.dataset.cmp); return; }
        const li = e.target.closest('.item'); if (li) openDetail(li.dataset.id);
      };
      $('#pro').onclick = e => {
        const pq = e.target.closest('[data-pq]');
        if (pq) {
          const k = pq.dataset.pq;
          if (k === 'urg') { S.dday = '3'; S.sort = 'dday'; }
          else if (k === 'sa') { S.grade = 'A'; S.sort = 'score'; }
          else if (k === 'apt') { S.cats = ['apt']; S.sort = 'aptgold'; }
          else if (k === 'crm') { setSide('crm'); if (isMobile()) setView('crm'); return; }
          run(); if (isMobile()) setView('list'); return;
        }
        const wp = e.target.closest('[data-wp]'); if (wp) { PRO_W = Object.assign({}, W_PRESETS[wp.dataset.wp].w); store.set('proW', PRO_W); recomputeAllOpps(); S.sort = 'score'; run(); toast(`전략 "${W_PRESETS[wp.dataset.wp].name}" 적용`); return; }
        const pd = e.target.closest('[data-pdom]'); if (pd) { const k = pd.dataset.pdom; if (!S.doms.includes(k)) S.doms.push(k); run(); return; }
        const pi = e.target.closest('[data-pid]'); if (pi) openDetail(pi.dataset.pid);
      };
      $('#pro').oninput = e => {
        const r = e.target.closest('input[data-wk]'); if (!r) return;
        PRO_W[r.dataset.wk] = +r.value; const lbl = $('#wv_' + r.dataset.wk); if (lbl) lbl.textContent = r.value + '%';
        store.set('proW', PRO_W); clearTimeout(bootWithKey.wt); bootWithKey.wt = setTimeout(() => { recomputeAllOpps(); run(); }, 150);
      };

      $('#cmpNames').onclick = e => { const b = e.target.closest('[data-cmprm]'); if (b) toggleCompare(b.dataset.cmprm); };
      $('#cmpOpenBtn').onclick = openCompare;
      $('#cmpClearBtn').onclick = () => { CMP = []; $('#cmpTray').hidden = true; renderList(); };
      $('#closeCmp').onclick = closeCompare;
      $('#closeBrief').onclick = closeBriefing;
      $$('.tabs button').forEach(b => b.onclick = () => setSide(b.dataset.v));
      $$('.bnav button').forEach(b => b.onclick = () => setView(b.dataset.v));
      $('#openF').onclick = () => openFilter(true); $('#closeF').onclick = () => openFilter(false);
      $('#openSettings').onclick = () => openSettings(true); $('#closeSettings').onclick = () => openSettings(false);
      $('#lockNowBtn').onclick = lockAppNow; $('#modalLockBtn').onclick = lockAppNow;
      $('#clearCacheBtn').onclick = async () => { if ('caches' in window) { const ks = await caches.keys(); await Promise.all(ks.map(k => caches.delete(k))); } toast('캐시를 비웠습니다…'); setTimeout(() => location.reload(), 500); };
      $('#scrim').onclick = () => { closeDetail(); openFilter(false); openSettings(false); closeCompare(); closeBriefing(); };
      $('#themeChips').onclick = e => { const b = e.target.closest('.chip'); if (b) applyTheme(b.dataset.th); };
      $('#saveDataGoKey').onclick = () => { const k = $('#dataGoKeyIn').value.trim(); if (k) { store.set('dataGoKey', k); toast('공공데이터포털 키 저장'); } else { store.del('dataGoKey'); toast('키 삭제'); } };
      $('#vwEyeSet')?.addEventListener('click', () => { const inp = $('#vwKeyInSet'); inp.type = inp.type === 'password' ? 'text' : 'password'; });
      $('#saveVwKeySet')?.addEventListener('click', () => { const k = $('#vwKeyInSet').value.replace(/\s+/g, ''); if (k) { store.set('vworldKey', k); toast('브이월드 키 저장'); } else { store.del('vworldKey'); toast('수동 키 해제 · Vault 기본 키 사용'); } openSettings(true); });
      $('#saveGeminiKey').onclick = () => { const k = $('#geminiKeyIn').value.trim(); if (k) { store.set('geminiKey', k); toast('Gemini 키 저장'); } else { store.del('geminiKey'); toast('키 삭제'); } };
      $('#backupExport').onclick = async () => {
        const payload = { version: 1, exportedAt: new Date().toISOString(), fav: [...FAV], crm: CRM, presets: PRESETS, proW: PRO_W, live: (await idb.get('live_opps')) || [] };
        const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })); a.download = `입찰영업기회_백업_${todayStr()}.json`; a.click();
        toast('파이프라인·프리셋·수집데이터 백업 완료');
      };
      $('#backupImport').onchange = async e => {
        const f = e.target.files[0]; if (!f) return;
        try {
          const j = JSON.parse(await f.text());
          if (Array.isArray(j.fav)) { FAV = new Set(j.fav); store.set('fav', [...FAV]); }
          if (j.crm) { CRM = Object.assign({}, CRM, j.crm); store.set('crm', CRM); }
          if (Array.isArray(j.presets)) { PRESETS = j.presets; store.set('presets', PRESETS); renderPresets(); }
          if (j.proW) { PRO_W = Object.assign({}, PRO_W, j.proW); store.set('proW', PRO_W); }
          if (Array.isArray(j.live) && j.live.length) await mergeLiveItems(j.live);
          else { recomputeAllOpps(); run(); }
          toast('백업을 복원했습니다');
        } catch { toast('백업 파일 형식이 올바르지 않습니다'); }
        e.target.value = '';
      };
    }

    bar.style.width = '100%';
    $('#appShell').hidden = false;
    run();
    setTimeout(() => { $('#loader').hidden = true; }, 120);
    setTimeout(() => autoSyncKakaoLiveFeeds(true), 450);
  } catch (err) {
    console.error(err);
    txt.textContent = '복호화 실패: ' + err.message;
    await idb.delKey();
  }
}

async function initVault() {
  if ('serviceWorker' in navigator && location.protocol !== 'file:') navigator.serviceWorker.register('./sw.js').catch(() => {});
  $('#pwToggle').onclick = () => { const inp = $('#pwInput'); inp.type = inp.type === 'password' ? 'text' : 'password'; };
  try {
    const res = await fetch('./data/vault.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error('vault.json 로드 실패');
    VAULT_META = await res.json();
  } catch (err) {
    $('#lockErr').textContent = '데이터 메타 정보를 불러올 수 없습니다: ' + err.message;
    return;
  }

  const saved = await idb.getKey();
  if (saved && saved.salt === VAULT_META.salt && saved.key) {
    if (await verifyKey(saved.key, VAULT_META)) { await bootWithKey(saved.key); return; }
    await idb.delKey();
  }

  $('#pwInput').focus();
  $('#lockForm').onsubmit = async e => {
    e.preventDefault();
    const pw = $('#pwInput').value, errEl = $('#lockErr'), btn = $('#pwSubmit');
    if (!pw) return;
    errEl.textContent = ''; btn.disabled = true; btn.textContent = '키 검증 중…';
    try {
      const key = await deriveVaultKey(pw, VAULT_META.salt, VAULT_META.iter);
      if (!(await verifyKey(key, VAULT_META))) {
        errEl.textContent = '비밀번호가 일치하지 않습니다.';
        btn.disabled = false; btn.textContent = '잠금 해제'; $('#pwInput').select(); return;
      }
      if ($('#pwRemember').checked) await idb.setKey({ salt: VAULT_META.salt, key });
      $('#pwInput').value = '';
      await bootWithKey(key);
    } catch (err) {
      errEl.textContent = '인증 오류: ' + err.message;
      btn.disabled = false; btn.textContent = '잠금 해제';
    }
  };
}

initVault();
})();
