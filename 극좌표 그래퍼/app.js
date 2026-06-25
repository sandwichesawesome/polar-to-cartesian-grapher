/* =====================================================================
 *  극좌표 그래퍼 (Polar → Cartesian Plotter)
 *  -------------------------------------------------------------------
 *  설계 개요
 *   1) 입력 폼에서 극좌표 방정식 r = f(θ) 문자열을 수집한다.
 *   2) 자체 구현한 토크나이저 + 재귀 하강 파서로 식을 파싱한다.
 *      → 외부 수식/변환 라이브러리(math.js 등)와 eval()을 일절 쓰지 않음.
 *        (eval 금지 = 코드 인젝션/XSS 방어. 허용된 토큰만 통과시킴)
 *   3) θ를 [start, end] 범위에서 잘게 증가시키며 r 값을 평가하고,
 *      변환 공식 x = r·cosθ, y = r·sinθ 를 '직접' 적용해 (x, y) 점을 만든다.
 *   4) Canvas에 좌표축·격자·곡선을 직접(수동) 그린다.
 *   5) 가능하면 기호적 변환(예: r=2sinθ → x²+y²=2y)도 유도해 과정으로 보여준다.
 * ===================================================================== */

/* =====================================================================
 *  [A] 토크나이저 — 입력 문자열을 토큰 배열로 분해
 *      허용 문자만 통과시켜 보안 위협(스크립트 주입 등)을 차단한다.
 * ===================================================================== */
const FUNCTIONS = ['sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'sqrt', 'abs', 'exp', 'log', 'ln'];
const CONSTANTS = { pi: Math.PI, '\u03c0': Math.PI, e: Math.E }; // π 기호도 허용

function tokenize(src) {
  // θ(theta)와 π 기호를 내부 식별자로 정규화
  const input = src
    .replace(/\u03b8/g, 'theta')   // θ → theta
    .replace(/\u03c0/g, 'pi');     // π → pi

  // 허용 문자 화이트리스트 검사: 영문/숫자/소수점/연산자/괄호/공백만 허용
  // (그 외 문자가 있으면 즉시 거부 — XSS·인젝션 입력 필터링)
  if (/[^a-zA-Z0-9.+\-*/^()\s]/.test(input)) {
    throw new ParseError('허용되지 않는 문자가 포함되어 있습니다. 영문 함수명, 숫자, 연산자(+ - * / ^), 괄호만 사용하세요.');
  }

  const tokens = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i];

    if (/\s/.test(ch)) { i++; continue; }                 // 공백 무시

    if (/[0-9.]/.test(ch)) {                              // 숫자 리터럴
      let num = '';
      while (i < input.length && /[0-9.]/.test(input[i])) num += input[i++];
      if ((num.match(/\./g) || []).length > 1) throw new ParseError(`잘못된 숫자 형식: "${num}"`);
      tokens.push({ type: 'num', value: parseFloat(num) });
      continue;
    }

    if (/[a-zA-Z]/.test(ch)) {                            // 식별자(변수/상수/함수)
      let name = '';
      while (i < input.length && /[a-zA-Z]/.test(input[i])) name += input[i++];
      const lower = name.toLowerCase();
      if (lower === 'theta' || lower === 't') tokens.push({ type: 'var', value: 'theta' });
      else if (lower in CONSTANTS) tokens.push({ type: 'num', value: CONSTANTS[lower] });
      else if (FUNCTIONS.includes(lower)) tokens.push({ type: 'func', value: lower });
      else throw new ParseError(`알 수 없는 이름: "${name}". 사용 가능한 함수/상수만 입력하세요.`);
      continue;
    }

    if ('+-*/^()'.includes(ch)) {                         // 연산자/괄호
      tokens.push({ type: 'op', value: ch });
      i++;
      continue;
    }

    throw new ParseError(`처리할 수 없는 문자: "${ch}"`);
  }
  return tokens;
}

/* 파싱/평가 오류 전용 클래스 */
class ParseError extends Error {}

/* =====================================================================
 *  [B] 재귀 하강 파서 — 토큰 배열을 AST(추상 구문 트리)로 변환
 *      문법(우선순위 낮음 → 높음):
 *        expr   := term (('+' | '-') term)*
 *        term   := factor (('*' | '/') factor)*       (암묵적 곱 2sinθ 포함)
 *        factor := power
 *        power  := unary ('^' factor)?                (^ 는 우결합)
 *        unary  := ('-' | '+')? primary
 *        primary:= num | var | func '(' expr ')' | '(' expr ')'
 * ===================================================================== */
function parse(tokens) {
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  const expect = (val) => {
    const t = next();
    if (!t || t.value !== val) throw new ParseError(`"${val}" 가 필요한 위치에 없습니다.`);
  };

  function parseExpr() {
    let node = parseTerm();
    while (peek() && peek().type === 'op' && (peek().value === '+' || peek().value === '-')) {
      const op = next().value;
      node = { type: 'binary', op, left: node, right: parseTerm() };
    }
    return node;
  }

  function parseTerm() {
    let node = parseUnary();
    while (peek()) {
      const t = peek();
      if (t.type === 'op' && (t.value === '*' || t.value === '/')) {
        const op = next().value;
        node = { type: 'binary', op, left: node, right: parseUnary() };
      } else if (
        // 암묵적 곱셈: 2sinθ, 3(θ+1), (x)(y) 등 → '*' 가 생략된 경우를 보정
        t.type === 'num' || t.type === 'var' || t.type === 'func' ||
        (t.type === 'op' && t.value === '(')
      ) {
        node = { type: 'binary', op: '*', left: node, right: parseUnary() };
      } else break;
    }
    return node;
  }

  function parseUnary() {
    if (peek() && peek().type === 'op' && (peek().value === '-' || peek().value === '+')) {
      const op = next().value;
      return { type: 'unary', op, operand: parseUnary() };
    }
    return parsePower();
  }

  function parsePower() {
    const base = parsePrimary();
    if (peek() && peek().type === 'op' && peek().value === '^') {
      next();
      // 지수는 우결합 → 오른쪽을 다시 unary부터 파싱
      return { type: 'binary', op: '^', left: base, right: parseUnary() };
    }
    return base;
  }

  function parsePrimary() {
    const t = next();
    if (!t) throw new ParseError('수식이 갑자기 끝났습니다. 입력을 확인하세요.');

    if (t.type === 'num') return { type: 'num', value: t.value };
    if (t.type === 'var') return { type: 'var', name: t.value };

    if (t.type === 'func') {
      expect('(');
      const arg = parseExpr();
      expect(')');
      return { type: 'call', name: t.value, arg };
    }
    if (t.type === 'op' && t.value === '(') {
      const node = parseExpr();
      expect(')');
      return node;
    }
    throw new ParseError(`예상치 못한 토큰: "${t.value}"`);
  }

  const ast = parseExpr();
  if (pos < tokens.length) {
    throw new ParseError(`수식 끝에 불필요한 토큰이 남았습니다: "${tokens[pos].value}"`);
  }
  return ast;
}

/* =====================================================================
 *  [C] 평가기 — AST + θ값 → r 값을 계산 (순수 함수, eval 미사용)
 * ===================================================================== */
function evaluate(node, theta) {
  switch (node.type) {
    case 'num': return node.value;
    case 'var': return theta;                 // 유일한 변수 θ
    case 'unary':
      return node.op === '-' ? -evaluate(node.operand, theta) : evaluate(node.operand, theta);
    case 'binary': {
      const a = evaluate(node.left, theta);
      const b = evaluate(node.right, theta);
      switch (node.op) {
        case '+': return a + b;
        case '-': return a - b;
        case '*': return a * b;
        case '/': return a / b;
        case '^': return Math.pow(a, b);
      }
      break;
    }
    case 'call': {
      const x = evaluate(node.arg, theta);
      switch (node.name) {
        case 'sin': return Math.sin(x);
        case 'cos': return Math.cos(x);
        case 'tan': return Math.tan(x);
        case 'asin': return Math.asin(x);
        case 'acos': return Math.acos(x);
        case 'atan': return Math.atan(x);
        case 'sqrt': return Math.sqrt(x);
        case 'abs': return Math.abs(x);
        case 'exp': return Math.exp(x);
        case 'log': case 'ln': return Math.log(x);
      }
      break;
    }
  }
  throw new ParseError('수식을 평가할 수 없습니다.');
}

/* =====================================================================
 *  [D] 점 생성 — θ를 잘게 증가시키며 (x, y) 좌표 배열 생성
 *      ★ 핵심 변환 공식: x = r·cos θ,  y = r·sin θ  ★
 *      라이브러리 없이 직접 적용한다.
 * ===================================================================== */
function generatePoints(ast, thetaStart, thetaEnd, samples = 2000) {
  const pts = [];
  const dTheta = (thetaEnd - thetaStart) / samples;
  for (let k = 0; k <= samples; k++) {
    const theta = thetaStart + k * dTheta;
    const r = evaluate(ast, theta);

    // 발산/비유효값은 곡선을 끊어 표시(선분 연결 방지용 null)
    if (!Number.isFinite(r)) { pts.push(null); continue; }

    // === 수동 변환: 극좌표(r, θ) → 직교좌표(x, y) ===
    const x = r * Math.cos(theta);
    const y = r * Math.sin(theta);
    pts.push({ x, y, r, theta });
  }
  return pts;
}

/* =====================================================================
 *  [E] 기호적 변환 유도 — 잘 알려진 형태를 손계산식으로 설명
 *      목적: "변환 과정"을 수식(LaTeX)으로 명확히 보여주기 위함.
 *      실제 그래프는 [D]의 수치 변환 결과를 사용한다.
 * ===================================================================== */
function deriveSymbolic(rawEq) {
  // 공백 제거 + θ/π 정규화한 비교용 문자열
  const eq = rawEq.replace(/\s+/g, '').replace(/\u03b8/g, 'theta').replace(/\u03c0/g, 'pi').replace(/\bt\b/g, 'theta').toLowerCase();
  const steps = [];

  // 공통 1단계: 변환 공식 명시
  steps.push({
    title: '변환 공식 적용',
    latex: 'x = r\\cos\\theta, \\quad y = r\\sin\\theta, \\quad r^2 = x^2 + y^2',
  });

  // 패턴 1) r = a  (상수) → 원 x²+y² = a²
  let m;
  if ((m = eq.match(/^(-?\d*\.?\d+)$/))) {
    const a = m[1];
    steps.push({ title: '양변 제곱', latex: `r = ${a} \\;\\Rightarrow\\; r^2 = ${a}^2` });
    steps.push({ title: 'r² = x²+y² 대입 (반지름 ' + a + '인 원)', latex: `x^2 + y^2 = ${Math.abs(parseFloat(a)) ** 2}` });
    return steps;
  }

  // 패턴 2) r = a·sinθ  → x² + y² = a·y
  if ((m = eq.match(/^(-?\d*\.?\d*)\*?sin\(theta\)$/))) {
    const a = coef(m[1]);
    steps.push({ title: '양변에 r 곱하기', latex: `r = ${a}\\sin\\theta \\;\\Rightarrow\\; r^2 = ${a}\\,r\\sin\\theta` });
    steps.push({ title: 'r² = x²+y², r sinθ = y 대입', latex: `x^2 + y^2 = ${a}y` });
    steps.push({ title: '완전제곱 → 중심 (0, ' + (parseFloat(a)/2) + ') 인 원', latex: `x^2 + \\left(y - ${parseFloat(a)/2}\\right)^2 = ${(parseFloat(a)/2)**2}` });
    return steps;
  }

  // 패턴 3) r = a·cosθ  → x² + y² = a·x
  if ((m = eq.match(/^(-?\d*\.?\d*)\*?cos\(theta\)$/))) {
    const a = coef(m[1]);
    steps.push({ title: '양변에 r 곱하기', latex: `r = ${a}\\cos\\theta \\;\\Rightarrow\\; r^2 = ${a}\\,r\\cos\\theta` });
    steps.push({ title: 'r² = x²+y², r cosθ = x 대입', latex: `x^2 + y^2 = ${a}x` });
    steps.push({ title: '완전제곱 → 중심 (' + (parseFloat(a)/2) + ', 0) 인 원', latex: `\\left(x - ${parseFloat(a)/2}\\right)^2 + y^2 = ${(parseFloat(a)/2)**2}` });
    return steps;
  }

  // 패턴 4) r = a + b·cosθ  (심장형/달팽이) → r²= a·r + b·r cosθ → x²+y²= a√(x²+y²)+b x
  if ((m = eq.match(/^(-?\d*\.?\d+)\+(-?\d*\.?\d*)\*?cos\(theta\)$/))) {
    const a = m[1], b = coef(m[2]);
    steps.push({ title: '양변에 r 곱하기', latex: `r = ${a} + ${b}\\cos\\theta \\;\\Rightarrow\\; r^2 = ${a}r + ${b}\\,r\\cos\\theta` });
    steps.push({ title: 'r=√(x²+y²), r cosθ = x 대입', latex: `x^2 + y^2 = ${a}\\sqrt{x^2+y^2} + ${b}x` });
    steps.push({ title: '직교좌표 음함수 형태 (일반적으로 더 간단히 정리 불가)', latex: `\\left(x^2+y^2 - ${b}x\\right)^2 = ${parseFloat(a)**2}\\left(x^2+y^2\\right)` });
    return steps;
  }
  if ((m = eq.match(/^(-?\d*\.?\d+)\+(-?\d*\.?\d*)\*?sin\(theta\)$/))) {
    const a = m[1], b = coef(m[2]);
    steps.push({ title: '양변에 r 곱하기', latex: `r = ${a} + ${b}\\sin\\theta \\;\\Rightarrow\\; r^2 = ${a}r + ${b}\\,r\\sin\\theta` });
    steps.push({ title: 'r=√(x²+y²), r sinθ = y 대입', latex: `x^2 + y^2 = ${a}\\sqrt{x^2+y^2} + ${b}y` });
    return steps;
  }

  // 패턴 5) 그 외(장미·나선 등): 기호적 폐형식이 일반적으로 없음 → 파라메트릭 설명
  steps.push({
    title: '일반식: 매개변수(파라메트릭) 변환',
    latex: 'x(\\theta) = f(\\theta)\\cos\\theta, \\quad y(\\theta) = f(\\theta)\\sin\\theta',
  });
  steps.push({
    title: 'θ를 잘게 증가시켜 (x, y) 점을 직접 계산',
    latex: '\\theta \\in [\\theta_0, \\theta_1] \\;\\Rightarrow\\; \\{(x_k, y_k)\\}',
  });
  return steps;
}

/* 계수 문자열 보정: "" 또는 "-" → 1 / -1 */
function coef(s) {
  if (s === '' || s === '+') return '1';
  if (s === '-') return '-1';
  return s;
}

/* =====================================================================
 *  [F] Canvas 렌더링 — 좌표축, 격자, 곡선을 직접 그린다.
 * ===================================================================== */
const canvas = document.getElementById('plot');
const ctx = canvas.getContext('2d');
let currentPoints = null;     // 마우스 hover 좌표 표시용
let currentView = null;       // {scale, cx, cy} 좌표 변환 캐시

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function setupHiDPI() {
  // 고해상도 디스플레이 대응 (선명한 렌더링)
  const ratio = window.devicePixelRatio || 1;
  const size = canvas.clientWidth || 640;
  canvas.width = size * ratio;
  canvas.height = size * ratio;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  return size;
}

function drawPlot(points) {
  const size = setupHiDPI();
  const W = size, H = size;
  ctx.clearRect(0, 0, W, H);

  // --- 데이터 범위 산정 (자동 스케일) ---
  let maxAbs = 1;
  for (const p of points) {
    if (!p) continue;
    maxAbs = Math.max(maxAbs, Math.abs(p.x), Math.abs(p.y));
  }
  const pad = 1.15;                          // 여백 15%
  const range = maxAbs * pad;
  const cx = W / 2, cy = H / 2;
  const scale = (Math.min(W, H) / 2) / range; // 1 수학단위당 픽셀
  currentView = { scale, cx, cy, range };

  // 수학좌표 → 화면픽셀 변환 (y축은 위가 +)
  const sx = (x) => cx + x * scale;
  const sy = (y) => cy - y * scale;

  // --- 격자 ---
  const gridColor = cssVar('--color-grid');
  const axisColor = cssVar('--color-axis');
  const step = niceStep(range);              // 보기 좋은 격자 간격
  ctx.lineWidth = 1;
  ctx.strokeStyle = gridColor;
  ctx.fillStyle = cssVar('--color-text-faint');
  ctx.font = '11px JetBrains Mono, monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';

  for (let v = step; v <= range; v += step) {
    [v, -v].forEach((val) => {
      // 세로선
      ctx.beginPath(); ctx.moveTo(sx(val), 0); ctx.lineTo(sx(val), H); ctx.stroke();
      // 가로선
      ctx.beginPath(); ctx.moveTo(0, sy(val)); ctx.lineTo(W, sy(val)); ctx.stroke();
    });
  }

  // --- 좌표축 ---
  ctx.strokeStyle = axisColor;
  ctx.lineWidth = 1.5;
  ctx.beginPath(); ctx.moveTo(0, cy); ctx.lineTo(W, cy); ctx.stroke();  // x축
  ctx.beginPath(); ctx.moveTo(cx, 0); ctx.lineTo(cx, H); ctx.stroke();  // y축

  // 축 눈금 라벨
  ctx.fillStyle = cssVar('--color-text-muted');
  for (let v = step; v <= range; v += step) {
    const label = formatTick(v);
    ctx.textBaseline = 'top';
    ctx.fillText(label, sx(v), cy + 4);
    ctx.fillText('-' + label, sx(-v), cy + 4);
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ctx.fillText(label, cx - 6, sy(v));
    ctx.fillText('-' + label, cx - 6, sy(-v));
    ctx.textAlign = 'center';
  }

  // --- 곡선 ---
  ctx.strokeStyle = cssVar('--color-primary');
  ctx.lineWidth = 2.2;
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';
  ctx.beginPath();
  let started = false;
  for (const p of points) {
    if (!p) { started = false; continue; }   // null → 곡선 끊기
    const px = sx(p.x), py = sy(p.y);
    if (!started) { ctx.moveTo(px, py); started = true; }
    else ctx.lineTo(px, py);
  }
  ctx.stroke();

  // --- 시작점 강조 ---
  const first = points.find((p) => p);
  if (first) {
    ctx.fillStyle = cssVar('--color-accent');
    ctx.beginPath(); ctx.arc(sx(first.x), sy(first.y), 4, 0, 2 * Math.PI); ctx.fill();
  }

  currentPoints = points;
}

/* 보기 좋은 격자 간격 (1, 2, 5 × 10ⁿ) */
function niceStep(range) {
  const raw = range / 5;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  let nice;
  if (norm < 1.5) nice = 1; else if (norm < 3) nice = 2; else if (norm < 7) nice = 5; else nice = 10;
  return nice * mag;
}
function formatTick(v) {
  return Number.isInteger(v) ? String(v) : v.toFixed(2).replace(/\.?0+$/, '');
}

/* =====================================================================
 *  [G] UI 바인딩 — 폼 제출, 예시, 오류, hover 좌표, 테마
 * ===================================================================== */
const form = document.getElementById('polar-form');
const input = document.getElementById('equation-input');
const errorBox = document.getElementById('error-box');
const stepsBox = document.getElementById('steps');
const stepsList = document.getElementById('steps-list');
const plotMeta = document.getElementById('plot-meta');
const readout = document.getElementById('point-readout');

// HTML 이스케이프 (오류 메시지에 사용자 입력을 안전하게 표시 — XSS 방어)
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function showError(msg) {
  errorBox.innerHTML = `<strong>입력 오류</strong>${esc(msg)}`;
  errorBox.hidden = false;
  stepsBox.hidden = true;
}
function clearError() { errorBox.hidden = true; errorBox.innerHTML = ''; }

// KaTeX 안전 렌더링 (throwOnError:false → 렌더 실패해도 페이지 안깨짐)
function renderLatex(el, tex) {
  if (window.katex) {
    try { katex.render(tex, el, { throwOnError: false, displayMode: false }); return; }
    catch (e) { /* fallthrough */ }
  }
  el.textContent = tex; // KaTeX 미로딩 시 평문 폴백
}

function renderSteps(rawEq) {
  const steps = deriveSymbolic(rawEq);
  stepsList.innerHTML = '';
  for (const s of steps) {
    const li = document.createElement('li');
    const title = document.createElement('span');
    title.className = 'step-title';
    title.textContent = s.title;
    const math = document.createElement('div');
    math.className = 'katex-line';
    renderLatex(math, s.latex);
    li.appendChild(title);
    li.appendChild(math);
    stepsList.appendChild(li);
  }
  stepsBox.hidden = false;
}

function run(rawEq) {
  clearError();

  // 1) 입력 유효성: 비어있음 체크
  if (!rawEq || !rawEq.trim()) { showError('방정식을 입력하세요. 예: 2*sin(theta)'); return; }

  // 2) θ 범위 읽기 (×π 단위)
  const ts = parseFloat(document.getElementById('theta-start').value);
  const te = parseFloat(document.getElementById('theta-end').value);
  if (!Number.isFinite(ts) || !Number.isFinite(te)) { showError('θ 범위 값이 올바른 숫자가 아닙니다.'); return; }
  if (ts < -8 || ts > 8 || te < -8 || te > 8) { showError('θ 범위는 -8π에서 8π 사이(-8에서 8 사이)만 설정 가능합니다.'); return; }
  if (te < ts) { showError('θ 끝 값은 시작 값보다 크거나 같아야 합니다.'); return; }
  const thetaStart = ts * Math.PI;
  const thetaEnd = te * Math.PI;

  // 3) 파싱 + 평가 (오류 시 사용자 친화 메시지)
  let ast;
  try {
    const tokens = tokenize(rawEq);
    if (tokens.length === 0) { showError('수식이 비어 있습니다.'); return; }
    ast = parse(tokens);
  } catch (e) {
    if (e instanceof ParseError) { showError(e.message); return; }
    showError('수식을 해석하지 못했습니다. 형식을 확인하세요.');
    return;
  }

  // 4) 샘플 평가 — 전부 무한대/NaN이면 그릴 수 없음
  let points;
  try {
    points = generatePoints(ast, thetaStart, thetaEnd);
  } catch (e) {
    showError('수식 계산 중 오류가 발생했습니다. 정의역을 확인하세요.');
    return;
  }
  const valid = points.filter((p) => p);
  if (valid.length === 0) {
    showError('이 정의역에서 유효한 점이 없습니다. (모든 r 값이 발산하거나 정의되지 않음)');
    return;
  }

  // 5) 그리기 + 과정 표시 + 메타정보
  drawPlot(points);
  renderSteps(rawEq);
  const rRange = valid.reduce((a, p) => [Math.min(a[0], p.r), Math.max(a[1], p.r)], [Infinity, -Infinity]);
  plotMeta.textContent = `θ ∈ [${fmt(ts)}π, ${fmt(te)}π]  ·  r ∈ [${fmt(rRange[0])}, ${fmt(rRange[1])}]`;
  readout.textContent = '곡선 위 좌표 — 캔버스에 마우스를 올려보세요';
}
function fmt(n) { return Number.isInteger(n) ? n : Number(n.toFixed(3)); }

/* θ 시작값/끝값 연동 (시작값 변경 시 끝값도 이동하여 구간 간격 유지) */
const thetaStartInput = document.getElementById('theta-start');
const thetaEndInput = document.getElementById('theta-end');
const thetaEndVal = document.getElementById('theta-end-val');

// 이전 시작값을 기억하여 변경폭(diff)을 구하기 위한 변수
let prevThetaStart = parseFloat(thetaStartInput.value) || 0;

// theta-start가 변경될 때
thetaStartInput.addEventListener('input', () => {
  const ts = parseFloat(thetaStartInput.value);
  if (Number.isFinite(ts)) {
    const diff = ts - prevThetaStart;
    prevThetaStart = ts; // 마지막으로 확인된 유효한 시작값 저장

    // 슬라이더의 최소값을 새로운 시작값으로 업데이트
    thetaEndInput.min = ts;
    
    // 시작값이 움직인 만큼 끝값도 같은 폭(diff)만큼 이동시켜서 구간 간격을 유지
    let te = parseFloat(thetaEndInput.value) + diff;
    
    // 끝값 제한 적용 (시작값보다는 크거나 같아야 하고, 최대 8π를 넘지 않아야 함)
    if (te < ts) te = ts;
    if (te > 8) te = 8;
    
    thetaEndInput.value = te;
    thetaEndVal.textContent = fmt(te);
    
    if (input.value.trim()) {
      run(input.value);
    }
  }
});

// theta-end 슬라이더 조절 시
thetaEndInput.addEventListener('input', () => {
  const te = parseFloat(thetaEndInput.value);
  if (Number.isFinite(te)) {
    thetaEndVal.textContent = fmt(te);
    if (input.value.trim()) {
      run(input.value);
    }
  }
});

/* 괄호 자동 완성 (IDE 스타일) */
input.addEventListener('keydown', (e) => {
  const start = input.selectionStart;
  const end = input.selectionEnd;
  const value = input.value;

  if (e.key === '(') {
    e.preventDefault();
    // 선택 영역이 있으면 괄호로 감싸고, 없으면 빈 괄호 생성
    const selectedText = value.substring(start, end);
    input.value = value.substring(0, start) + '(' + selectedText + ')' + value.substring(end);

    if (start === end) {
      input.selectionStart = input.selectionEnd = start + 1;
    } else {
      input.selectionStart = start + 1;
      input.selectionEnd = end + 1;
    }
  } else if (e.key === ')') {
    // 바로 다음에 닫는 괄호가 있으면 추가 입력 대신 커서만 한 칸 이동 (Skip)
    if (start === end && start < value.length && value[start] === ')') {
      e.preventDefault();
      input.selectionStart = input.selectionEnd = start + 1;
    }
  } else if (e.key === 'Backspace') {
    // 괄호 안에 커서가 있을 때 Backspace를 누르면 열고 닫는 괄호를 동시에 삭제
    if (start === end && start > 0 && start < value.length && value[start - 1] === '(' && value[start] === ')') {
      e.preventDefault();
      input.value = value.substring(0, start - 1) + value.substring(start + 1);
      input.selectionStart = input.selectionEnd = start - 1;
    }
  }
});

/* 폼 제출 (입력 방식은 폼만 허용) */
form.addEventListener('submit', (ev) => {
  ev.preventDefault();
  run(input.value);
});

/* 예시 칩 클릭 → 입력란 채우고 즉시 실행 */
document.querySelectorAll('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    input.value = chip.dataset.eq;
    run(input.value);
  });
});

/* 마우스 hover → 가장 가까운 곡선 점의 (x,y,r,θ) 표시 */
canvas.addEventListener('mousemove', (ev) => {
  if (!currentPoints || !currentView) return;
  const rect = canvas.getBoundingClientRect();
  const mx = ev.clientX - rect.left;
  const my = ev.clientY - rect.top;
  const { scale, cx, cy } = currentView;
  let best = null, bestD = Infinity;
  for (const p of currentPoints) {
    if (!p) continue;
    const px = cx + p.x * scale, py = cy - p.y * scale;
    const d = (px - mx) ** 2 + (py - my) ** 2;
    if (d < bestD) { bestD = d; best = p; }
  }
  if (best && bestD < 30 * 30) {
    readout.textContent = `θ=${best.theta.toFixed(3)}  r=${best.r.toFixed(3)}  →  (x=${best.x.toFixed(3)}, y=${best.y.toFixed(3)})`;
  } else {
    readout.textContent = '곡선 위 좌표 — 캔버스에 마우스를 올려보세요';
  }
});

/* 창 크기 변경 시 다시 그리기 */
let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { if (currentPoints) drawPlot(currentPoints); }, 150);
});

/* =====================================================================
 *  [H] 다크/라이트 테마 토글
 * ===================================================================== */
(function () {
  const t = document.querySelector('[data-theme-toggle]');
  const r = document.documentElement;
  let d = matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light';
  const sun = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>';
  const moon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  function apply() {
    r.setAttribute('data-theme', d);
    t.innerHTML = d === 'dark' ? sun : moon;
    t.setAttribute('aria-label', (d === 'dark' ? '라이트' : '다크') + ' 모드로 전환');
    if (currentPoints) drawPlot(currentPoints); // 테마색 반영해 다시 그림
  }
  t.addEventListener('click', () => { d = d === 'dark' ? 'light' : 'dark'; apply(); });
  apply();
})();

/* =====================================================================
 *  [I] 초기 데모: 페이지 로드시 r = 2 sin θ 자동 표시
 * ===================================================================== */
window.addEventListener('load', () => {
  input.value = '2*sin(theta)';
  run(input.value);
});
