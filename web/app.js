const API = '/api';

// 로그인 정보는 sessionStorage에 저장 (탭을 닫으면 사라짐)
const session = {
  get() {
    try { return JSON.parse(sessionStorage.getItem('session')); } catch { return null; }
  },
  set(s) { sessionStorage.setItem('session', JSON.stringify(s)); },
  clear() { sessionStorage.removeItem('session'); },
};

async function login(username, password) {
  const res = await fetch(`${API}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (res.status === 401) throw new Error('아이디 또는 비밀번호가 올바르지 않습니다.');
  if (!res.ok) throw new Error(`로그인에 실패했습니다. (${res.status})`);
  const { userId, accessToken, refreshToken } = await res.json();
  session.set({ userId, username, accessToken, refreshToken });
}

async function refresh() {
  const s = session.get();
  if (!s) return false;
  const res = await fetch(`${API}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: s.refreshToken }),
  });
  if (!res.ok) return false;
  const { accessToken, refreshToken } = await res.json();
  session.set({ ...s, accessToken, refreshToken });
  return true;
}

async function readBody(res) {
  if (res.status === 204) return null;
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error(body?.message ?? `요청 실패 (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return body;
}

const loginUrl = () => `/login.html?next=${encodeURIComponent(location.pathname + location.search)}`;

// 로그인이 필요한 API: accessToken이 만료돼 401이 오면 한 번 재발급받고 다시 시도
async function api(path, { method = 'GET', body } = {}) {
  const call = () => fetch(`${API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${session.get()?.accessToken}`,
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  let res = await call();
  if (res.status === 401 && await refresh()) res = await call();
  if (res.status === 401) {
    session.clear();
    location.href = loginUrl();
    throw new Error('로그인이 필요합니다.');
  }
  return readBody(res);
}

// 공개 API (상품·카테고리·상품 리뷰): 토큰을 보내지 않음
async function pub(path) {
  return readBody(await fetch(`${API}${path}`));
}

function requireLogin() {
  const s = session.get();
  if (!s) location.href = loginUrl();
  return s;
}

async function logout() {
  const s = session.get();
  if (s) {
    await fetch(`${API}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: s.refreshToken }),
    }).catch(() => {});
  }
  session.clear();
  location.href = '/';
}

// ---------------------------------------------------------------- 화면 도우미 (출력은 textContent만 사용: XSS 방지)
const won = (n) => `${Number(n).toLocaleString()}원`;
const fmtDate = (v) => (v ? new Date(v).toLocaleDateString('ko-KR') : '-');
const fmtDateTime = (v) => (v ? new Date(v).toLocaleString('ko-KR') : '-');
const imgSrc = (key) => `/img/${key || 'keyboard'}.svg`;
const params = new URLSearchParams(location.search);

const ORDER_STATUS = {
  pending: '결제 대기', paid: '결제 완료', preparing: '상품 준비중',
  shipped: '배송중', delivered: '배송 완료', cancelled: '주문 취소',
};
const PAY_METHOD = { card: '신용카드', bank_transfer: '계좌이체', virtual_account: '가상계좌', points: '적립금' };
const PAY_STATUS = { ready: '결제 대기', paid: '결제 완료', cancelled: '결제 취소', refunded: '환불 완료', failed: '결제 실패' };

// el('div', { class: 'x', onclick }, child1, 'text', ...)
function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

const stars = (n) => '★'.repeat(Math.round(n)) + '☆'.repeat(5 - Math.round(n));

function priceEl(p) {
  const rate = p.sale_price ? Math.round((1 - p.sale_price / p.price) * 100) : 0;
  return el('div', { class: 'price' },
    rate ? el('span', { class: 'rate' }, `${rate}%`) : null,
    won(p.final_price ?? p.sale_price ?? p.price),
    rate ? el('s', {}, won(p.price)) : null);
}

function productCard(p) {
  return el('a', { class: 'card', href: `/product.html?id=${p.id}` },
    el('div', { class: 'thumb' }, el('img', { src: imgSrc(p.image), alt: '' })),
    el('div', { class: 'brand' }, p.brand),
    el('div', { class: 'name' }, p.name),
    priceEl(p),
    p.review_count ? el('div', { class: 'stars' }, `★ ${p.avg_rating} (${p.review_count.toLocaleString()})`) : null);
}

function toast(msg) {
  const t = el('div', { class: 'toast' }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 2200);
}

function errorText(ex) {
  if (ex.message === 'blocked by security policy') return '보안 정책에 의해 이용이 제한된 계정입니다.';
  if (ex.message === 'account suspended') return '이용이 정지된 계정입니다. 고객센터로 문의해 주세요.';
  const byStatus = {
    403: '접근 권한이 없습니다.',
    404: '요청하신 정보를 찾을 수 없습니다.',
    429: '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.',
  };
  return byStatus[ex.status] ?? ex.message;
}

function showError(ex, target = document.getElementById('error')) {
  if (!target) return toast(errorText(ex));
  target.textContent = errorText(ex);
  target.hidden = false;
}

// ---------------------------------------------------------------- 공통 헤더 · 푸터
const ICON = {
  logo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 8h14l-1.5 11h-11z"/><path d="M9 8V6a3 3 0 0 1 6 0v2"/></svg>',
  search: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>',
  cart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="20" r="1.4"/><circle cx="17" cy="20" r="1.4"/><path d="M3 4h2l2.4 11h10.8L21 8H6.2"/></svg>',
  user: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/></svg>',
  logout: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15 4h4v16h-4"/><path d="M10 8l-4 4 4 4"/><path d="M6 12h10"/></svg>',
};

function svgIcon(name) {
  const span = document.createElement('span');
  span.innerHTML = ICON[name];      // 고정된 아이콘 문자열만 넣음 (사용자 입력 아님)
  return span.firstChild;
}

const cartCount = el('span', { class: 'badge-count', hidden: true });

async function updateCartCount() {
  if (!session.get()) return;
  try {
    const items = await api('/cart');
    cartCount.textContent = items.length;
    cartCount.hidden = items.length === 0;
  } catch { /* 헤더 숫자는 실패해도 무시 */ }
}

function renderHeader() {
  const s = session.get();
  const q = params.get('q') ?? '';
  const searchForm = el('form', { class: 'search', action: '/products.html' },
    el('input', { name: 'q', value: q, placeholder: '찾으시는 상품을 검색해 보세요', 'aria-label': '상품 검색' }),
    el('button', { type: 'submit', 'aria-label': '검색' }, svgIcon('search')));

  const icons = el('div', { class: 'head-icons' },
    el('a', { class: 'head-icon', href: '/cart.html' }, svgIcon('cart'), '장바구니', cartCount),
    el('a', { class: 'head-icon', href: s ? '/mypage.html' : '/login.html' }, svgIcon('user'), s ? '마이페이지' : '로그인'),
    s ? el('button', { class: 'head-icon', type: 'button', onclick: logout }, svgIcon('logout'), '로그아웃') : null);

  const onList = location.pathname === '/products.html';
  const nav = el('nav', { class: 'cat-nav wrap' },
    el('a', { href: '/products.html', class: onList && !params.get('category') && !params.get('sort') && !q ? 'on' : null }, '전체'),
    el('a', { href: '/products.html?sort=popular', class: onList && params.get('sort') === 'popular' ? 'on' : null }, '베스트'),
    el('a', { href: '/products.html?sort=new', class: onList && params.get('sort') === 'new' ? 'on' : null }, '신상품'));

  document.body.prepend(el('header', { class: 'site-header' },
    el('div', { class: 'wrap head-row' },
      el('a', { class: 'logo', href: '/' }, svgIcon('logo'), 'BOLA Shop'),
      searchForm, icons),
    el('div', { style: 'border-top:1px solid var(--line)' }, nav)));

  document.body.append(el('footer', { class: 'site-footer' },
    el('div', { class: 'wrap' },
      el('div', {}, '(주)볼라샵 · 대표 000 · 사업자등록번호 000-00-00000 · 통신판매업 0000-00-0000'),
      el('div', {}, '00시 00구 00로 000 · 고객센터 0000-0000 (평일 09:00~18:00)'),
      el('div', { style: 'margin-top:8px' }, '© 2026 BOLA Shop'))));

  pub('/categories').then((cats) => {
    for (const c of cats) {
      nav.append(el('a', { href: `/products.html?category=${c.id}`, class: params.get('category') === String(c.id) ? 'on' : null }, c.name));
    }
  }).catch(() => {});

  updateCartCount();
}

renderHeader();
