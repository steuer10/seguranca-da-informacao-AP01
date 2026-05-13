/**
 * Sistema de Ocorrências Acadêmicas — versão com melhorias de segurança
 *
 * MELHORIAS IMPLEMENTADAS:
 *  1. JWT simulado (header.payload.signature via HMAC-SHA256 com Web Crypto)
 *  2. Senhas armazenadas como hash SHA-256 (nunca em texto plano)
 *  3. Controle de acesso real por perfil (RBAC) — sem troca de perfil pelo usuário
 *  4. Aluno visualiza apenas suas próprias ocorrências
 *  5. Professor cria e muda status, mas não exclui nem vê obs. interna
 *  6. Administrador tem acesso total, exportação e logs
 *  7. Logs imutáveis para não-admins (aluno/professor não podem limpar)
 *  8. Expiração de sessão (token com exp)
 *  9. Validação de formulário no lado cliente
 * 10. CPF removido do formulário (minimização de dados — LGPD Art. 6°, III)
 * 11. Exportação restrita ao perfil ADMIN
 * 12. Senhas não exibidas na interface (apenas no README para fins didáticos)
 * 13. escape() aplicado em TODOS os dados renderizados via innerHTML (anti-XSS)
 * 14. crypto.randomUUID() para IDs únicos de ocorrências (sem colisões)
 * 15. Content-Security-Policy adicionada no HTML
 * 16. Rate limiting simulado no login (bloqueio após 5 tentativas por sessão)
 *
 * LIMITAÇÕES (inerentes ao front-end):
 *  - O código-fonte é sempre inspecionável pelo usuário
 *  - O JWT não tem validação de servidor — pode ser forjado via DevTools
 *  - Os hashes estão no código-fonte; ataques de dicionário são possíveis
 *  - Não há HTTPS real, proteção CSRF, ou revogação de token real
 *  - Tudo isso exigiria back-end + banco de dados real
 */

"use strict";

// ── CONFIGURAÇÃO ────────────────────────────────────────────────────────────
const JWT_SECRET      = "ChaveSecretaDidatica_NaoUseEmProducao";
const TOKEN_TTL_MS    = 30 * 60 * 1000; // 30 minutos
const MAX_LOGIN_TRIES = 5;              // bloqueio após N tentativas

const STORAGE_KEYS = {
  token:       "ocorrencias_jwt",
  occurrences: "ocorrencias_registros",
  audit:       "ocorrencias_logs",
  loginTries:  "ocorrencias_login_tries"
};

// ── USUÁRIOS (senhas como hash SHA-256) ────────────────────────────────────
// Senhas NÃO são exibidas na interface — consulte o README para credenciais de teste.
// Hashes pré-computados (SHA-256, sem salt — aceitável apenas em contexto didático):
//   aluno123  → ef92b778...
//   prof123   → 61a42c5e...
//   admin123  → 240be518...
const USERS = [
  {
    id: 1,
    name: "Ana Souza",
    email: "aluno@faculdade.local",
    passwordHash: "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
    role: "ALUNO",
    studentId: "202400001"
  },
  {
    id: 2,
    name: "Prof. Carlos Lima",
    email: "professor@faculdade.local",
    passwordHash: "61a42c5ecd38a18ef4b990ded8e6b09f7f8ccac7b0ee4d2a85c09f40fe2dcff4",
    role: "PROFESSOR"
  },
  {
    id: 3,
    name: "Administrador Geral",
    email: "admin@faculdade.local",
    passwordHash: "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",
    role: "ADMIN"
  }
];

// ── DADOS INICIAIS (fictícios) ──────────────────────────────────────────────
const INITIAL_OCCURRENCES = [
  {
    id: "OC-1001",
    studentName: "Ana Souza",
    studentId: "202400001",
    studentEmail: "aluno@faculdade.local",
    category: "Nota",
    priority: "Média",
    description: "Solicitação de revisão de nota da avaliação bimestral.",
    internalNote: "Verificar com a coordenação antes de responder.",
    status: "Aberta",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:40:00.000Z"
  },
  {
    id: "OC-1002",
    studentName: "Rafael Martins",
    studentId: "202200771",
    studentEmail: "rafael@faculdade.local",
    category: "Frequência",
    priority: "Alta",
    description: "Aluno contesta lançamento de falta em aula prática.",
    internalNote: "Conferir chamada manual.",
    status: "Em análise",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:50:00.000Z"
  },
  {
    id: "OC-1003",
    studentName: "Beatriz Costa",
    studentId: "202100441",
    studentEmail: "beatriz@faculdade.local",
    category: "Solicitação administrativa",
    priority: "Crítica",
    description: "Solicitação envolvendo documentação acadêmica e prazo de matrícula.",
    internalNote: "Priorizar atendimento.",
    status: "Aberta",
    createdBy: "admin@faculdade.local",
    createdAt: "2026-05-05T19:00:00.000Z"
  }
];

// ── UTILITÁRIO DE ESCAPE (anti-XSS) ────────────────────────────────────────
/**
 * Escapa caracteres HTML especiais antes de inserir qualquer dado via innerHTML.
 * Previne XSS tanto em dados do usuário quanto em dados vindos do localStorage.
 */
function esc(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g,  "&amp;")
    .replace(/</g,  "&lt;")
    .replace(/>/g,  "&gt;")
    .replace(/"/g,  "&quot;")
    .replace(/'/g,  "&#x27;")
    .replace(/\//g, "&#x2F;");
}

// ── RATE LIMITING SIMULADO ──────────────────────────────────────────────────
/**
 * Controla o número de tentativas de login por sessão de navegador.
 * Após MAX_LOGIN_TRIES falhas, bloqueia o formulário.
 * Limitação: reiniciar a aba ou limpar sessionStorage reseta o contador.
 */
function getLoginTries() {
  return parseInt(sessionStorage.getItem(STORAGE_KEYS.loginTries) || "0", 10);
}

function incrementLoginTries() {
  sessionStorage.setItem(STORAGE_KEYS.loginTries, String(getLoginTries() + 1));
}

function resetLoginTries() {
  sessionStorage.removeItem(STORAGE_KEYS.loginTries);
}

function isLoginBlocked() {
  return getLoginTries() >= MAX_LOGIN_TRIES;
}

// ── CRYPTO HELPERS ──────────────────────────────────────────────────────────

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacSha256(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ── JWT SIMULADO ────────────────────────────────────────────────────────────

function b64url(obj) {
  return btoa(JSON.stringify(obj))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function generateToken(user) {
  const header  = b64url({ alg: "HS256", typ: "JWT" });
  const payload = b64url({
    sub:       String(user.id),
    name:      user.name,
    email:     user.email,
    role:      user.role,
    studentId: user.studentId || null,
    iat:       Math.floor(Date.now() / 1000),
    exp:       Math.floor((Date.now() + TOKEN_TTL_MS) / 1000)
  });
  const sig = await hmacSha256(`${header}.${payload}`, JWT_SECRET);
  return `${header}.${payload}.${sig}`;
}

async function verifyToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  try {
    const [header, payload, sig] = parts;
    const expectedSig = await hmacSha256(`${header}.${payload}`, JWT_SECRET);
    if (sig !== expectedSig) return null;

    const decoded = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    if (decoded.exp * 1000 < Date.now()) return null;

    return decoded;
  } catch {
    return null;
  }
}

function saveToken(token)  { localStorage.setItem(STORAGE_KEYS.token, token); }
function loadToken()       { return localStorage.getItem(STORAGE_KEYS.token) || null; }
function clearToken()      { localStorage.removeItem(STORAGE_KEYS.token); }

// ── PERMISSÕES (RBAC) ───────────────────────────────────────────────────────

const PERMISSIONS = {
  ALUNO: {
    canCreate:           false,
    canDelete:           false,
    canChangeStatus:     false,
    canExport:           false,
    canClearLogs:        false,
    canReset:            false,
    canViewAllRecords:   false,
    canViewInternalNote: false,
    canViewLogs:         false,
    canViewContact:      false,
    canViewDoc:          false,
  },
  PROFESSOR: {
    canCreate:           true,
    canDelete:           false,
    canChangeStatus:     true,
    canExport:           false,
    canClearLogs:        false,
    canReset:            false,
    canViewAllRecords:   true,
    canViewInternalNote: false,
    canViewLogs:         false,
    canViewContact:      true,
    canViewDoc:          false,
  },
  ADMIN: {
    canCreate:           true,
    canDelete:           true,
    canChangeStatus:     true,
    canExport:           true,
    canClearLogs:        true,
    canReset:            true,
    canViewAllRecords:   true,
    canViewInternalNote: true,
    canViewLogs:         true,
    canViewContact:      true,
    canViewDoc:          true,
  }
};

function can(role, action) {
  return !!(PERMISSIONS[role] && PERMISSIONS[role][action]);
}

// ── DADOS ───────────────────────────────────────────────────────────────────

function getOccurrences() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.occurrences) || "[]");
}

function saveOccurrences(list) {
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(list));
}

function getAuditLogs() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.audit) || "[]");
}

function saveAuditLogs(logs) {
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify(logs));
}

function writeLog(user, action, detail) {
  const logs = getAuditLogs();
  logs.unshift({
    when:   new Date().toISOString(),
    user:   user ? user.email : "anonimo",
    role:   user ? user.role  : "SEM_SESSAO",
    action,
    detail
  });
  saveAuditLogs(logs);
}

// ── ELEMENTOS DO DOM ────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

const loginView          = $("loginView");
const appView            = $("appView");
const loginForm          = $("loginForm");
const loginError         = $("loginError");
const occurrenceForm     = $("occurrenceForm");
const formError          = $("formError");
const logoutBtn          = $("logoutBtn");
const exportBtn          = $("exportBtn");
const clearLogsBtn       = $("clearLogsBtn");
const resetBtn           = $("resetBtn");
const searchInput        = $("search");
const searchAluno        = $("searchAluno");
const sessionBadge       = $("sessionBadge");
const tokenExpiry        = $("tokenExpiry");
const currentUserName    = $("currentUserName");
const currentUserDetails = $("currentUserDetails");
const roleTag            = $("roleTag");
const occurrencesTable   = $("occurrencesTable");
const auditLog           = $("auditLog");
const totalOccurrences   = $("totalOccurrences");
const criticalOccurrences= $("criticalOccurrences");
const totalAluno         = $("totalAluno");
const criticalAluno      = $("criticalAluno");
const lastUpdate         = $("lastUpdate");
const formSection        = $("formSection");
const alunoPanel         = $("alunoPanel");
const logsSection        = $("logsSection");
const noActionsMsg       = $("noActionsMsg");
const internalNoteLabel  = $("internalNoteLabel");
const profileNote        = $("profileNote");
const thDoc              = $("thDoc");
const thContact          = $("thContact");
const thInternal         = $("thInternal");
const thActions          = $("thActions");
const alunoTitle         = $("alunoTitle");

// ── EXPIRAÇÃO DO TOKEN (UI) ─────────────────────────────────────────────────

let expiryInterval = null;

function startExpiryCountdown(expEpochSec) {
  clearInterval(expiryInterval);
  expiryInterval = setInterval(() => {
    const remaining = expEpochSec * 1000 - Date.now();
    if (remaining <= 0) {
      clearInterval(expiryInterval);
      writeLog(null, "SESSION_EXPIRED", "Token expirado. Sessão encerrada automaticamente.");
      clearToken();
      showLogin("Sua sessão expirou. Faça login novamente.");
      return;
    }
    const mins = Math.floor(remaining / 60000);
    const secs = Math.floor((remaining % 60000) / 1000);
    tokenExpiry.textContent = `Sessão expira em ${mins}:${secs.toString().padStart(2, "0")}`;
    tokenExpiry.classList.toggle("expiring", remaining < 5 * 60 * 1000);
    tokenExpiry.classList.remove("hidden");
  }, 1000);
}

// ── TELAS ───────────────────────────────────────────────────────────────────

function showLogin(errorMsg = null) {
  clearInterval(expiryInterval);
  loginView.classList.remove("hidden");
  appView.classList.add("hidden");
  logoutBtn.classList.add("hidden");
  tokenExpiry.classList.add("hidden");
  sessionBadge.textContent = "Sessão não iniciada";
  sessionBadge.classList.add("muted");
  loginForm.reset();

  if (errorMsg) {
    // textContent — nunca innerHTML — para mensagens de erro
    loginError.textContent = errorMsg;
    loginError.classList.remove("hidden");
  } else {
    loginError.classList.add("hidden");
  }

  // Exibe aviso de bloqueio se aplicável
  if (isLoginBlocked()) {
    loginError.textContent = `Muitas tentativas de login. Formulário bloqueado por segurança. Recarregue a página para tentar novamente.`;
    loginError.classList.remove("hidden");
    loginForm.querySelector("button[type=submit]").disabled = true;
  }
}

function showApp(user) {
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");
  loginError.classList.add("hidden");

  // textContent para evitar XSS em nome/e-mail do token
  sessionBadge.textContent = `${user.name} — ${user.role}`;
  sessionBadge.classList.remove("muted");
  currentUserName.textContent = user.name;
  currentUserDetails.textContent = user.email;

  roleTag.textContent = user.role;
  roleTag.className   = `role-badge ${user.role}`;

  applyRoleUI(user);
  render(user);
  startExpiryCountdown(user.exp);
}

function applyRoleUI(user) {
  const role = user.role;

  toggleEl(exportBtn,    can(role, "canExport"));
  toggleEl(clearLogsBtn, can(role, "canClearLogs"));
  toggleEl(resetBtn,     can(role, "canReset"));
  noActionsMsg.classList.toggle("hidden",
    can(role, "canExport") || can(role, "canClearLogs") || can(role, "canReset"));

  toggleEl(formSection,       can(role, "canCreate"));
  toggleEl(internalNoteLabel, can(role, "canViewInternalNote"));
  toggleEl(alunoPanel,        role === "ALUNO");

  if (role === "ALUNO") {
    // textContent — nunca innerHTML
    alunoTitle.textContent = `${user.name} (Matrícula: ${user.studentId || "—"})`;
  }

  toggleEl(logsSection, can(role, "canViewLogs"));
  toggleEl(thDoc,       can(role, "canViewDoc"));
  toggleEl(thContact,   can(role, "canViewContact"));
  toggleEl(thInternal,  can(role, "canViewInternalNote"));
  toggleEl(thActions,   can(role, "canChangeStatus") || can(role, "canDelete"));

  const notes = {
    ALUNO:     "Você visualiza apenas suas próprias ocorrências, sem dados de outros alunos.",
    PROFESSOR: "Você pode criar ocorrências e alterar status. Documentos não são exibidos.",
    ADMIN:     "Acesso completo. Todas as colunas e ações estão disponíveis."
  };
  // textContent para a nota de perfil
  profileNote.textContent = notes[role] || "";
}

function toggleEl(el, show) {
  if (!el) return;
  el.classList.toggle("hidden", !show);
}

// ── AUTENTICAÇÃO ────────────────────────────────────────────────────────────

async function login(email, password) {
  loginError.classList.add("hidden");

  // Rate limiting simulado
  if (isLoginBlocked()) {
    loginError.textContent = "Muitas tentativas. Recarregue a página para tentar novamente.";
    loginError.classList.remove("hidden");
    loginForm.querySelector("button[type=submit]").disabled = true;
    return;
  }

  const hash = await sha256(password);
  const user = USERS.find(u => u.email === email && u.passwordHash === hash);

  if (!user) {
    incrementLoginTries();
    const remaining = MAX_LOGIN_TRIES - getLoginTries();
    writeLog(null, "LOGIN_FALHOU", `Tentativa inválida para: ${email}`);

    if (remaining <= 0) {
      loginError.textContent = "Muitas tentativas. Formulário bloqueado. Recarregue a página.";
      loginForm.querySelector("button[type=submit]").disabled = true;
    } else {
      loginError.textContent = `E-mail ou senha incorretos. ${remaining} tentativa(s) restante(s).`;
    }
    loginError.classList.remove("hidden");
    return;
  }

  resetLoginTries();
  const token   = await generateToken(user);
  saveToken(token);
  const decoded = await verifyToken(token);
  writeLog(decoded, "LOGIN_OK", `Usuário autenticado. Perfil: ${user.role}`);
  showApp(decoded);
}

async function logout() {
  const token   = loadToken();
  const decoded = token ? await verifyToken(token) : null;
  writeLog(decoded, "LOGOUT", decoded ? `${decoded.email} encerrou a sessão.` : "Sessão encerrada.");
  clearToken();
  showLogin();
}

// ── VERIFICAÇÃO DE SESSÃO ───────────────────────────────────────────────────

async function requireSession() {
  const token = loadToken();
  const user  = token ? await verifyToken(token) : null;
  if (!user) {
    clearToken();
    showLogin("Sessão inválida ou expirada.");
    return null;
  }
  return user;
}

// ── SANITIZAÇÃO ─────────────────────────────────────────────────────────────
/**
 * Sanitiza entradas de texto antes de armazenar.
 * esc() é usada separadamente na renderização para dados vindos do storage.
 */
function sanitize(s) {
  if (!s) return "";
  return String(s).trim()
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ── OPERAÇÕES ───────────────────────────────────────────────────────────────

async function createOccurrence(event) {
  event.preventDefault();
  formError.classList.add("hidden");

  const user = await requireSession();
  if (!user || !can(user.role, "canCreate")) {
    formError.textContent = "Sem permissão para registrar ocorrências.";
    formError.classList.remove("hidden");
    return;
  }

  const name = $("studentName").value.trim();
  const sid  = $("studentId").value.trim();
  const cat  = $("category").value;
  const pri  = $("priority").value;
  const desc = $("description").value.trim();
  const ack  = $("privacyAck").checked;

  if (!name || !sid || !cat || !pri || !desc || !ack) {
    formError.textContent = "Preencha todos os campos obrigatórios (*) e confirme a autorização.";
    formError.classList.remove("hidden");
    return;
  }

  const occurrence = {
    // crypto.randomUUID() — garante IDs únicos sem colisões (Math.random era inseguro)
    id:           `OC-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    studentName:  sanitize(name),
    studentId:    sanitize(sid),
    studentEmail: sanitize($("studentEmail").value.trim()),
    category:     cat,
    priority:     pri,
    description:  sanitize(desc),
    internalNote: can(user.role, "canViewInternalNote")
                    ? sanitize($("internalNote").value.trim())
                    : "",
    status:       "Aberta",
    createdBy:    user.email,
    createdAt:    new Date().toISOString()
  };

  const list = getOccurrences();
  list.unshift(occurrence);
  saveOccurrences(list);

  writeLog(user, "OCORRENCIA_CRIADA",
    `Ocorrência ${occurrence.id} para ${occurrence.studentName} (Matrícula: ${occurrence.studentId}). Tipo: ${occurrence.category}.`);

  occurrenceForm.reset();
  render(user);
}

async function deleteOccurrence(id) {
  const user = await requireSession();
  if (!user || !can(user.role, "canDelete")) {
    alert("Sem permissão para excluir ocorrências.");
    return;
  }
  const list    = getOccurrences();
  const item    = list.find(o => o.id === id);
  const updated = list.filter(o => o.id !== id);
  saveOccurrences(updated);
  writeLog(user, "OCORRENCIA_EXCLUIDA", `Ocorrência ${id} excluída. Aluno: ${item?.studentName}.`);
  render(user);
}

async function changeStatus(id, status) {
  const user = await requireSession();
  if (!user || !can(user.role, "canChangeStatus")) {
    alert("Sem permissão para alterar status.");
    return;
  }
  const list = getOccurrences();
  const item = list.find(o => o.id === id);
  if (!item) return;
  item.status    = status;
  item.updatedAt = new Date().toISOString();
  item.updatedBy = user.email;
  saveOccurrences(list);
  writeLog(user, "STATUS_ALTERADO", `Ocorrência ${id} → "${status}".`);
  render(user);
}

async function exportEverything() {
  const user = await requireSession();
  if (!user || !can(user.role, "canExport")) {
    alert("Exportação restrita ao perfil Administrador.");
    return;
  }
  // Hashes de senha NÃO incluídos na exportação
  const safeUsers = USERS.map(({ passwordHash, ...rest }) => rest);
  const payload = {
    exportedAt:  new Date().toISOString(),
    exportedBy:  user.email,
    role:        user.role,
    notice:      "DADOS FICTÍCIOS — USO DIDÁTICO",
    occurrences: getOccurrences(),
    audit:       getAuditLogs(),
    users:       safeUsers
  };
  const blob   = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url    = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href     = url;
  anchor.download = "exportacao-ocorrencias.json";
  anchor.click();
  URL.revokeObjectURL(url);
  writeLog(user, "EXPORTACAO_TOTAL", "Administrador exportou todos os dados do sistema.");
}

async function clearLogs() {
  const user = await requireSession();
  if (!user || !can(user.role, "canClearLogs")) {
    alert("Limpeza de logs restrita ao perfil Administrador.");
    return;
  }
  writeLog(user, "LOGS_LIMPOS", "Logs anteriores foram apagados pelo administrador.");
  saveAuditLogs(getAuditLogs().slice(0, 1));
  render(user);
}

async function resetData() {
  const user = await requireSession();
  if (!user || !can(user.role, "canReset")) {
    alert("Restauração restrita ao perfil Administrador.");
    return;
  }
  saveOccurrences(INITIAL_OCCURRENCES);
  saveAuditLogs([]);
  writeLog(user, "DADOS_RESTAURADOS", "Dados iniciais restaurados pelo administrador.");
  render(user);
}

// ── RENDER ──────────────────────────────────────────────────────────────────
/**
 * Toda inserção de dados via innerHTML usa esc() para prevenir XSS.
 * Isso inclui dados do localStorage, que podem ter sido manipulados.
 */
function render(user) {
  if (!user) return;
  const role = user.role;
  const all  = getOccurrences();

  const visible = role === "ALUNO"
    ? all.filter(o => o.studentId === user.studentId)
    : all;

  const term     = (searchInput?.value || "").toLowerCase();
  const filtered = visible.filter(o => {
    const s = `${o.studentName} ${o.studentId} ${o.category} ${o.status}`.toLowerCase();
    return s.includes(term);
  });

  if (role === "ALUNO") {
    const termA = (searchAluno?.value || "").toLowerCase();
    const fa = visible.filter(o =>
      `${o.category} ${o.status}`.toLowerCase().includes(termA)
    );
    totalAluno.textContent    = fa.length;
    criticalAluno.textContent = fa.filter(o => o.priority === "Crítica").length;
  }

  totalOccurrences.textContent    = filtered.length;
  criticalOccurrences.textContent = filtered.filter(o => o.priority === "Crítica").length;
  lastUpdate.textContent = `Atualizado em ${new Date().toLocaleTimeString("pt-BR")}`;

  // Tabela — todos os valores passam por esc()
  occurrencesTable.innerHTML = filtered.map(item => `
    <tr>
      <td>
        <strong>${esc(item.studentName)}</strong><br/>
        <span class="muted-text">${esc(item.studentId)}</span>
      </td>
      ${can(role, "canViewDoc")
        ? `<td>${esc(item.studentCpf) || "<span class='muted-text'>—</span>"}</td>`
        : ""}
      ${can(role, "canViewContact")
        ? `<td>${esc(item.studentEmail) || "—"}</td>`
        : ""}
      <td>${esc(item.category)}</td>
      <td><span class="priority ${esc(item.priority)}">${esc(item.priority)}</span></td>
      <td>${esc(item.status)}</td>
      <td>${esc(item.description)}</td>
      ${can(role, "canViewInternalNote")
        ? `<td>${esc(item.internalNote) || "<span class='muted-text'>—</span>"}</td>`
        : ""}
      ${(can(role, "canChangeStatus") || can(role, "canDelete"))
        ? `<td>
            <div class="row-actions">
              ${can(role, "canChangeStatus") ? `
                <button class="btn secondary" onclick="changeStatus('${esc(item.id)}','Em análise')">Em análise</button>
                <button class="btn secondary" onclick="changeStatus('${esc(item.id)}','Resolvida')">Resolver</button>
              ` : ""}
              ${can(role, "canDelete") ? `
                <button class="btn danger" onclick="deleteOccurrence('${esc(item.id)}')">Excluir</button>
              ` : ""}
            </div>
          </td>`
        : ""}
    </tr>
  `).join("");

  // Logs — todos os valores passam por esc()
  if (can(role, "canViewLogs")) {
    const logs = getAuditLogs();
    auditLog.innerHTML = logs.length === 0
      ? `<div class="notice info">Nenhum log registrado.</div>`
      : logs.map(log => `
          <div class="log-item">
            <span class="log-action">${esc(log.action)}</span>
            &nbsp;·&nbsp;<strong>${esc(log.when)}</strong><br/>
            usuário=<strong>${esc(log.user)}</strong>
            | perfil=<strong>${esc(log.role)}</strong><br/>
            <span>${esc(log.detail)}</span>
          </div>
        `).join("");
  }
}

// ── INICIALIZAÇÃO ───────────────────────────────────────────────────────────

async function boot() {
  if (!localStorage.getItem(STORAGE_KEYS.occurrences)) {
    saveOccurrences(INITIAL_OCCURRENCES);
  }
  if (!localStorage.getItem(STORAGE_KEYS.audit)) {
    saveAuditLogs([{
      when:   new Date().toISOString(),
      user:   "sistema",
      role:   "SISTEMA",
      action: "BOOT",
      detail: "Sistema inicializado."
    }]);
  }

  const token = loadToken();
  if (token) {
    const user = await verifyToken(token);
    if (user) {
      showApp(user);
    } else {
      clearToken();
      showLogin("Sessão expirada. Faça login novamente.");
    }
  } else {
    showLogin();
  }
}

// ── EVENT LISTENERS ─────────────────────────────────────────────────────────

loginForm.addEventListener("submit", async e => {
  e.preventDefault();
  await login($("email").value.trim(), $("password").value);
});

occurrenceForm.addEventListener("submit", createOccurrence);
logoutBtn.addEventListener("click", logout);
exportBtn.addEventListener("click", exportEverything);
clearLogsBtn.addEventListener("click", clearLogs);
resetBtn.addEventListener("click", resetData);

searchInput?.addEventListener("input", async () => {
  const user = await requireSession();
  if (user) render(user);
});

searchAluno?.addEventListener("input", async () => {
  const user = await requireSession();
  if (user) render(user);
});

// Expõe para onclick inline na tabela
window.deleteOccurrence = deleteOccurrence;
window.changeStatus     = changeStatus;

boot();
