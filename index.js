
'use strict';

const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const SITE_URL = (process.env.SITE_URL || '').replace(/\/$/, '');
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const BOT_TOKEN = process.env.TOKEN;
const GUILD_ID = process.env.GUILD_ID;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_IDS = (process.env.ADMIN_DISCORD_IDS || '')
    .split(',')
    .map(id => id.trim())
    .filter(Boolean);

if (
    !SITE_URL ||
    !CLIENT_ID ||
    !CLIENT_SECRET ||
    !SESSION_SECRET ||
    !process.env.DATABASE_URL
) {
    console.error(
        'Configure SITE_URL, DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, SESSION_SECRET e DATABASE_URL.'
    );
    process.exit(1);
}

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'false'
        ? false
        : { rejectUnauthorized: false }
});

app.use(session({
    store: new pgSession({
        pool,
        tableName: 'user_sessions',
        createTableIfMissing: true
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 8
    }
}));

// ======================================
// BANCO DE DADOS
// ======================================

async function prepararBanco() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS verified_users (
            discord_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            avatar TEXT,
            ip_address TEXT NOT NULL,
            verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS user_bans (
            discord_id TEXT PRIMARY KEY,
            username TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT 'Sem motivo informado',
            banned_by TEXT NOT NULL,
            banned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    console.log('Banco de dados preparado.');
}

// ======================================
// FUNÇÕES AUXILIARES
// ======================================

function escapar(valor = '') {
    return String(valor).replace(/[&<>"']/g, caractere => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[caractere]);
}

function pagina(titulo, conteudo) {
    return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapar(titulo)} — Exército Brasileiro</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#101319;color:#f4f4f5;font-family:Arial,sans-serif}
header{padding:22px 16px;text-align:center;background:#171b24;border-bottom:1px solid #303644}
header h1{margin:0;font-size:22px}
main{width:min(900px,92%);margin:32px auto}
.card{background:#1b202b;border:1px solid #343b4a;border-radius:14px;padding:22px;margin-bottom:18px}
h2{margin-top:0}
p{line-height:1.6;color:#d1d5db}
a,.button{display:inline-block;background:#5865f2;color:white;text-decoration:none;border:0;border-radius:8px;padding:12px 16px;font-weight:bold;cursor:pointer}
.secondary{background:#343b4a}
.danger{background:#b42332}
input,textarea{width:100%;padding:11px;margin:7px 0 14px;background:#101319;color:white;border:1px solid #454d5e;border-radius:7px}
label{display:block;color:#e5e7eb}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px;border-bottom:1px solid #343b4a;overflow-wrap:anywhere}
.small{font-size:13px;color:#aeb6c5}
.notice{border-left:4px solid #eab308;padding:12px;background:#292719}
.actions{display:flex;gap:8px;flex-wrap:wrap}
</style>
</head>
<body>
<header><h1>🇧🇷 Exército Brasileiro Roleplay</h1></header>
<main>${conteudo}</main>
</body>
</html>`;
}

function gerarCsrf(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
}

function validarCsrf(req, res) {
    const enviado = req.body.csrfToken;
    const salvo = req.session.csrfToken;

    if (
        !enviado ||
        !salvo ||
        typeof enviado !== 'string' ||
        !crypto.timingSafeEqual(
            Buffer.from(enviado),
            Buffer.from(salvo)
        )
    ) {
        res.status(403).send(
            pagina('Acesso recusado', '<div class="card"><h2>Solicitação inválida</h2><p>Atualize a página e tente novamente.</p><a href="/">Voltar</a></div>')
        );
        return false;
    }

    return true;
}

function exigirAdmin(req, res, next) {
    if (!req.session.usuario) {
        return res.redirect('/auth/login');
    }

    if (!ADMIN_IDS.includes(req.session.usuario.id)) {
        return res.status(403).send(
            pagina('Acesso negado', '<div class="card"><h2>Acesso negado</h2><p>Sua conta não está autorizada a acessar o painel administrativo.</p><a href="/">Voltar</a></div>')
        );
    }

    next();
}

function obterIp(req) {
    // Usa o IP observado pelo servidor/proxy configurado.
    // Não aceite um IP arbitrário enviado pelo visitante.
    return String(req.ip || req.socket.remoteAddress || 'desconhecido')
        .slice(0, 100);
}

// ======================================
// PÁGINA INICIAL
// ======================================

app.get('/', (req, res) => {
    const usuario = req.session.usuario;

    const conta = usuario
        ? `<p>Conectado como <strong>${escapar(usuario.username)}</strong>.</p>
           <a href="/verificar">Concluir verificação</a>
           <a class="secondary" href="/auth/sair">Sair</a>`
        : `<a href="/auth/login">Entrar com Discord</a>`;

    res.send(pagina('Verificação', `
        <section class="card">
            <h2>🛡️ Verificação de conta</h2>
            <p>Entre com sua conta do Discord para iniciar a verificação do servidor.</p>
            ${conta}
        </section>
        <section class="card">
            <h2>🔒 Aviso de privacidade</h2>
            <p>Ao continuar, o site recebe seu identificador e nome público do Discord. Para segurança e prevenção de abusos, também registra o endereço IP da conexão e a data da verificação.</p>
            <p>Esses dados são usados para administrar verificações e investigar possíveis tentativas de contornar banimentos. O acesso aos registros é limitado aos administradores autorizados.</p>
            <p>Um endereço IP pode ser compartilhado por várias pessoas ou mudar com o tempo. Por isso, uma correspondência de IP deve ser analisada com cuidado e não é prova isolada de que as contas pertencem à mesma pessoa.</p>
            <p class="small">Não informe sua senha do Discord neste site. A autenticação acontece nas páginas oficiais do Discord.</p>
        </section>
    `));
});

// ======================================
// LOGIN OFICIAL DISCORD / OAUTH2
// ======================================

app.get('/auth/login', (req, res) => {
    const state = crypto.randomBytes(24).toString('hex');
    req.session.oauthState = state;

    const url = new URL('https://discord.com/oauth2/authorize');
    url.searchParams.set('client_id', CLIENT_ID);
    url.searchParams.set('redirect_uri', `${SITE_URL}/auth/callback`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'identify');
    url.searchParams.set('state', state);

    res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
    try {
        const { code, state, error } = req.query;

        if (error) {
            return res.status(400).send(
                pagina('Login cancelado', '<div class="card"><h2>Login cancelado</h2><p>Você não autorizou o login.</p><a href="/">Voltar</a></div>')
            );
        }

        if (
            typeof state !== 'string' ||
            !req.session.oauthState ||
            state !== req.session.oauthState ||
            typeof code !== 'string'
        ) {
            return res.status(400).send(
                pagina('Erro de autenticação', '<div class="card"><h2>Não foi possível confirmar o login</h2><p>Volte à página inicial e tente novamente.</p><a href="/">Voltar</a></div>')
            );
        }

        delete req.session.oauthState;

        const tokenResponse = await fetch(
            'https://discord.com/api/v10/oauth2/token',
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    client_id: CLIENT_ID,
                    client_secret: CLIENT_SECRET,
                    grant_type: 'authorization_code',
                    code,
                    redirect_uri: `${SITE_URL}/auth/callback`
                })
            }
        );

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok || !tokenData.access_token) {
            console.error('Falha OAuth:', tokenData);
            return res.status(401).send(
                pagina('Erro de login', '<div class="card"><h2>Não foi possível entrar</h2><p>Tente novamente.</p><a href="/">Voltar</a></div>')
            );
        }

        const userResponse = await fetch(
            'https://discord.com/api/v10/users/@me',
            {
                headers: {
                    Authorization: `Bearer ${tokenData.access_token}`
                }
            }
        );

        const usuario = await userResponse.json();

        if (!userResponse.ok || !usuario.id) {
            return res.status(401).send(
                pagina('Erro de login', '<div class="card"><h2>Não foi possível obter sua conta do Discord</h2><a href="/">Voltar</a></div>')
            );
        }

        req.session.usuario = {
            id: usuario.id,
            username: usuario.global_name || usuario.username,
            avatar: usuario.avatar || null
        };

        return res.redirect('/verificar');
    } catch (erro) {
        console.error('Erro no login:', erro);
        res.status(500).send(
            pagina('Erro', '<div class="card"><h2>Erro no login</h2><p>Tente novamente mais tarde.</p><a href="/">Voltar</a></div>')
        );
    }
});

// ======================================
// CONCLUIR VERIFICAÇÃO
// ======================================

app.get('/verificar', async (req, res) => {
    if (!req.session.usuario) {
        return res.redirect('/auth/login');
    }

    const usuario = req.session.usuario;
    const ip = obterIp(req);

    try {
        const banPorId = await pool.query(
            'SELECT * FROM user_bans WHERE discord_id = $1',
            [usuario.id]
        );

        if (banPorId.rowCount > 0) {
            return res.status(403).send(
                pagina('Verificação bloqueada', `
                    <section class="card">
                        <h2>⛔ Verificação bloqueada</h2>
                        <p>Esta conta está banida do sistema de verificação.</p>
                        <p>Se você acredita que isso é um erro, entre em contato com a equipe administrativa.</p>
                    </section>
                `)
            );
        }

        // IP igual a um registro banido gera revisão manual.
        // Não bloqueia automaticamente, pois IPs podem ser compartilhados.
        const banPorIp = await pool.query(
            `SELECT discord_id FROM user_bans
             WHERE ip_address = $1 AND ip_address <> ''
             LIMIT 1`,
            [ip]
        );

        if (banPorIp.rowCount > 0) {
            return res.status(403).send(
                pagina('Revisão necessária', `
                    <section class="card">
                        <h2>🔎 Verificação precisa de revisão</h2>
                        <p>A conexão corresponde a um endereço IP associado a um banimento anterior.</p>
                        <p>Como várias pessoas podem compartilhar um IP, a equipe deverá analisar o caso antes de decidir.</p>
                    </section>
                `)
            );
        }

        await pool.query(
            `INSERT INTO verified_users
             (discord_id, username, avatar, ip_address, verified_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT (discord_id)
             DO UPDATE SET username = EXCLUDED.username,
                           avatar = EXCLUDED.avatar,
                           ip_address = EXCLUDED.ip_address,
                           verified_at = NOW()`,
            [usuario.id, usuario.username, usuario.avatar, ip]
        );

        res.send(pagina('Verificação concluída', `
            <section class="card">
                <h2>✅ Verificação concluída</h2>
                <p>Conta Discord: <strong>${escapar(usuario.username)}</strong></p>
                <p>Seu registro foi salvo. Agora você pode voltar ao Discord.</p>
                <p class="small">ID da conta: ${escapar(usuario.id)}</p>
                <a href="/">Voltar à página inicial</a>
            </section>
        `));
    } catch (erro) {
        console.error('Erro ao verificar:', erro);
        res.status(500).send(
            pagina('Erro', '<div class="card"><h2>Não foi possível concluir</h2><p>Tente novamente mais tarde.</p></div>')
        );
    }
});

// ======================================
// PAINEL ADMINISTRATIVO
// ======================================

app.get('/admin', exigirAdmin, async (req, res) => {
    try {
        const csrf = gerarCsrf(req);
        const busca = String(req.query.q || '').trim().slice(0, 100);

        let usuarios;
        if (busca) {
            usuarios = await pool.query(
                `SELECT * FROM verified_users
                 WHERE discord_id = $1 OR username ILIKE $2
                 ORDER BY verified_at DESC LIMIT 100`,
                [busca, `%${busca}%`]
            );
        } else {
            usuarios = await pool.query(
                'SELECT * FROM verified_users ORDER BY verified_at DESC LIMIT 100'
            );
        }

        const banidos = await pool.query(
            'SELECT * FROM user_bans ORDER BY banned_at DESC LIMIT 100'
        );

        const linhasUsuarios = usuarios.rows.map(u => `
            <tr>
                <td>${escapar(u.username)}</td>
                <td>${escapar(u.discord_id)}</td>
                <td>${escapar(u.ip_address)}</td>
                <td>${escapar(new Date(u.verified_at).toLocaleString('pt-BR'))}</td>
                <td>
                    <form method="POST" action="/admin/banir">
                        <input type="hidden" name="csrfToken" value="${csrf}">
                        <input type="hidden" name="discord_id" value="${escapar(u.discord_id)}">
                        <input type="hidden" name="username" value="${escapar(u.username)}">
                        <input type="hidden" name="ip_address" value="${escapar(u.ip_address)}">
                        <input name="reason" placeholder="Motivo do banimento" required maxlength="300">
                        <button class="button danger" type="submit">Banir</button>
                    </form>
                </td>
            </tr>
        `).join('');

        const linhasBanidos = banidos.rows.map(b => `
            <tr>
                <td>${escapar(b.username)}</td>
                <td>${escapar(b.discord_id)}</td>
                <td>${escapar(b.ip_address)}</td>
                <td>${escapar(b.reason)}</td>
                <td>${escapar(new Date(b.banned_at).toLocaleString('pt-BR'))}</td>
                <td>
                    <form method="POST" action="/admin/desbanir">
                        <input type="hidden" name="csrfToken" value="${csrf}">
                        <input type="hidden" name="discord_id" value="${escapar(b.discord_id)}">
                        <button class="button" type="submit">Desbanir</button>
                    </form>
                </td>
            </tr>
        `).join('');

        res.send(pagina('Painel administrativo', `
            <section class="card">
                <h2>🔐 Painel administrativo</h2>
                <p>Administrador: ${escapar(req.session.usuario.username)}</p>
                <form method="GET" action="/admin">
                    <label>Pesquisar por nome ou ID do Discord</label>
                    <input name="q" value="${escapar(busca)}" placeholder="Nome ou ID">
                    <button class="button" type="submit">Pesquisar</button>
                </form>
                <p class="small">Exibindo no máximo 100 registros por lista.</p>
            </section>
            <section class="card">
                <h2>Usuários verificados</h2>
                <p class="small">O IP é dado pessoal: consulte-o apenas quando necessário para segurança e revisão de abusos.</p>
                <div style="overflow-x:auto"><table>
                    <thead><tr><th>Nome</th><th>ID</th><th>IP</th><th>Data</th><th>Ação</th></tr></thead>
                    <tbody>${linhasUsuarios || '<tr><td colspan="5">Nenhum usuário encontrado.</td></tr>'}</tbody>
                </table></div>
            </section>
            <section class="card">
                <h2>Usuários banidos</h2>
                <div style="overflow-x:auto"><table>
                    <thead><tr><th>Nome</th><th>ID</th><th>IP</th><th>Motivo</th><th>Data</th><th>Ação</th></tr></thead>
                    <tbody>${linhasBanidos || '<tr><td colspan="6">Nenhum banimento.</td></tr>'}</tbody>
                </table></div>
            </section>
            <a class="secondary" href="/auth/sair">Sair</a>
        `));
    } catch (erro) {
        console.error('Erro no painel:', erro);
        res.status(500).send(
            pagina('Erro', '<div class="card"><h2>Erro ao abrir o painel</h2></div>')
        );
    }
});

// ======================================
// BANIR USUÁRIO
// ======================================

app.post('/admin/banir', exigirAdmin, async (req, res) => {
    if (!validarCsrf(req, res)) return;

    const discordId = String(req.body.discord_id || '').trim();
    const username = String(req.body.username || '').slice(0, 100);
    const ip = String(req.body.ip_address || '').slice(0, 100);
    const reason = String(req.body.reason || '').trim().slice(0, 300);

    if (!/^\d{17,20}$/.test(discordId) || !reason) {
        return res.status(400).send(
            pagina('Dados inválidos', '<div class="card"><h2>Dados inválidos</h2><a href="/admin">Voltar</a></div>')
        );
    }

    try {
        await pool.query(
            `INSERT INTO user_bans
             (discord_id, username, ip_address, reason, banned_by, banned_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             ON CONFLICT (discord_id)
             DO UPDATE SET username = EXCLUDED.username,
                           ip_address = EXCLUDED.ip_address,
                           reason = EXCLUDED.reason,
                           banned_by = EXCLUDED.banned_by,
                           banned_at = NOW()`,
            [
                discordId,
                username,
                ip,
                reason,
                req.session.usuario.id
            ]
        );

        res.redirect('/admin');
    } catch (erro) {
        console.error('Erro ao banir:', erro);
        res.status(500).send(
            pagina('Erro', '<div class="card"><h2>Não foi possível banir.</h2><a href="/admin">Voltar</a></div>')
        );
    }
});

// ======================================
// DESBANIR USUÁRIO
// ======================================

app.post('/admin/desbanir', exigirAdmin, async (req, res) => {
    if (!validarCsrf(req, res)) return;

    const discordId = String(req.body.discord_id || '').trim();

    if (!/^\d{17,20}$/.test(discordId)) {
        return res.status(400).send('ID inválido.');
    }

    try {
        await pool.query(
            'DELETE FROM user_bans WHERE discord_id = $1',
            [discordId]
        );

        res.redirect('/admin');
    } catch (erro) {
        console.error('Erro ao desbanir:', erro);
        res.status(500).send('Não foi possível desbanir.');
    }
});

// ======================================
// SAIR
// ======================================

app.get('/auth/sair', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

// ======================================
// INICIAR SITE
// ======================================

prepararBanco()
    .then(() => {
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`Site iniciado na porta ${PORT}`);
        });
    })
    .catch((erro) => {
        console.error('Não foi possível preparar o banco:', erro);
        process.exit(1);
    });
