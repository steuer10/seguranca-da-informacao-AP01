# Sistema de Ocorrências Acadêmicas — Versão Melhorada (AP01)

Disciplina: **Segurança da Informação** · Engenharia de Software · Católica SC  
Professor: Edson Vaz Lopes

---

## Melhorias de segurança implementadas

| # | Melhoria | Arquivo |
|---|----------|---------|
| 1 | JWT simulado (HS256 via Web Crypto API) com expiração de sessão (30 min) | `app.js` |
| 2 | Senhas armazenadas como hash SHA-256 — nunca em texto plano | `app.js` |
| 3 | RBAC real: Aluno / Professor / Admin com permissões distintas | `app.js` |
| 4 | Aluno visualiza apenas suas próprias ocorrências | `app.js` |
| 5 | Professor não acessa CPF, obs. interna, logs, exportação nem exclusão | `app.js` / `index.html` |
| 6 | Admin tem acesso total (exportação, logs, exclusão, restauração) | `app.js` |
| 7 | Troca de perfil pelo usuário foi removida | `index.html` / `app.js` |
| 8 | Exportação exclui hashes de senha do arquivo gerado | `app.js` |
| 9 | Logs imutáveis para não-admins (aluno/professor não podem limpar) | `app.js` |
| 10 | Validação de formulário com sanitização básica (escape de HTML) | `app.js` |
| 11 | Minimização de dados: CPF e telefone removidos do formulário padrão | `index.html` |
| 12 | Aviso visível ao usuário sobre limitações do protótipo front-end | `index.html` |
| 13 | Contador de expiração de sessão na topbar | `app.js` / `style.css` |
| 14 | Senhas de demonstração alteradas (sem senha trivial como "admin") | `app.js` |

## Credenciais de demonstração

| Perfil | E-mail | Senha |
|--------|--------|-------|
| Aluno | aluno@faculdade.local | aluno123 |
| Professor | professor@faculdade.local | prof123 |
| Administrador | admin@faculdade.local | admin123 |

## Limitações inerentes ao front-end

- O código-fonte é sempre inspecionável pelo usuário via DevTools
- O JWT não tem validação de servidor — pode ser forjado via console
- Os hashes SHA-256 estão no código; ataques de dicionário são possíveis
- Não há HTTPS real, proteção CSRF, ou revogação de token
- Logs podem ser manipulados diretamente no localStorage
- Persistência local (localStorage) não é backup real

Todas essas limitações exigiriam **back-end real + banco de dados** para serem resolvidas.

## Estrutura

```
├── index.html   # Interface com separação de seções por perfil
├── style.css    # Estilos incluindo badges de perfil, alertas e prioridades coloridas
├── app.js       # Lógica com JWT, SHA-256, RBAC e controle de sessão
└── README.md
```
