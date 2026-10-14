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
const SESSION_SECRET = process.env.SESSION_SECRET;
const BAN_API_SECRET = process.env.BAN_API_SECRET;
const LOGS_API_SECRET = process.env.LOGS_API_SECRET;

const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const CARGO_VERIFICADO = process.env.CARGO_VERIFICADO;

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

app.use(express.urlencoded({
    extended: false,
    limit: '20kb'
}));

app.use(express.json({
    limit: '20kb'
}));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'false'
        ? false
        : { rejectUnauthorized: false }
});

pool.on('error', erro => {
    console.error('Erro inesperado no PostgreSQL:', erro);
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
            ip_address TEXT NOT NULL DEFAULT '',
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

    await pool.query(`
        CREATE TABLE IF NOT EXISTS site_logs (
            id BIGSERIAL PRIMARY KEY,
            source TEXT NOT NULL DEFAULT 'bot',
            action TEXT NOT NULL,
            user_id TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            guild_id TEXT NOT NULL DEFAULT '',
            channel_id TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_site_logs_created_at
        ON site_logs (created_at DESC)
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
main{width:min(1100px,94%);margin:32px auto}
.card{background:#1b202b;border:1px solid #343b4a;border-radius:14px;padding:22px;margin-bottom:18px}
h2{margin-top:0}
p{line-height:1.6;color:#d1d5db}
a,.button{display:inline-block;background:#5865f2;color:white;text-decoration:none;border:0;border-radius:8px;padding:12px 16px;font-weight:bold;cursor:pointer;margin:3px 0}
.secondary{background:#343b4a}
.danger{background:#b42332}
input,textarea{width:100%;padding:11px;margin:7px 0 14px;background:#101319;color:white;border:1px solid #454d5e;border-radius:7px}
label{display:block;color:#e5e7eb}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px;border-bottom:1px solid #343b4a;overflow-wrap:anywhere}
.small{font-size:13px;color:#aeb6c5}
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
        typeof enviado !== 'string' ||
        typeof salvo !== 'string'
    ) {
        res.status(403).send(pagina(
            'Acesso recusado',
            '<div class="card"><h2>Solicitação inválida</h2><p>Atualize a página e tente novamente.</p><a href="/admin">Voltar</a></div>'
        ));
        return false;
    }

    const a = Buffer.from(enviado);
    const b = Buffer.from(salvo);

    if (
        a.length !== b.length ||
        !crypto.timingSafeEqual(a, b)
    ) {
        res.status(403).send(pagina(
            'Acesso recusado',
            '<div class="card"><h2>Solicitação inválida</h2><p>Atualize a página e tente novamente.</p><a href="/admin">Voltar</a></div>'
        ));
        return false;
    }

    return true;
}

function exigirAdmin(req, res, next) {
    if (!req.session.usuario) {
        return res.redirect('/auth/login');
    }

    if (!ADMIN_IDS.includes(req.session.usuario.id)) {
        return res.status(403).send(pagina(
            'Acesso negado',
            '<div class="card"><h2>Acesso negado</h2><p>Sua conta não está autorizada a acessar o painel administrativo.</p><a href="/">Voltar</a></div>'
        ));
    }

    next();
}

function obterIp(req) {
    return String(
        req.ip || req.socket.remoteAddress || 'desconhecido'
    ).replace(/^::ffff:/, '').slice(0, 100);
}

function segredoValido(req, segredo) {
    if (!segredo) return false;

    const authorization = req.get('authorization') || '';
    const recebido = authorization.startsWith('Bearer ')
        ? authorization.slice(7)
        : '';

    const a = Buffer.from(segredo);
    const b = Buffer.from(recebido);

    return a.length === b.length &&
        crypto.timingSafeEqual(a, b);
}

// ======================================
// ENTREGA DO CARGO VERIFICADO
// ======================================

async function atribuirCargoVerificado(discordId) {
    if (
        !DISCORD_BOT_TOKEN ||
        !/^\d{17,20}$/.test(DISCORD_GUILD_ID || '') ||
        !/^\d{17,20}$/.test(CARGO_VERIFICADO || '')
    ) {
        throw new Error(
            'Configure DISCORD_BOT_TOKEN, DISCORD_GUILD_ID e CARGO_VERIFICADO.'
        );
    }

    const resposta = await fetch(
        `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members/${discordId}/roles/${CARGO_VERIFICADO}`,
        {
            method: 'PUT',
            headers: {
                Authorization: `Bot ${DISCORD_BOT_TOKEN}`
            },
            signal: AbortSignal.timeout(10000)
        }
    );

    if (!resposta.ok) {
        const detalhe = await resposta.text().catch(() => '');

        console.error(
            'Erro ao atribuir cargo:',
            resposta.status,
            detalhe
        );

        if (resposta.status === 404) {
            throw new Error(
                'Usuário, servidor ou cargo não encontrado. Confira se o usuário está no servidor.'
            );
        }

        if (resposta.status === 403) {
            throw new Error(
                'O bot não tem permissão para entregar o cargo. Confira Gerenciar Cargos e a hierarquia do bot.'
            );
        }

        throw new Error(
            `O Discord recusou a atribuição do cargo (HTTP ${resposta.status}).`
        );
    }
}

// ======================================
// API DE BANIMENTO DO BOT
// ======================================

app.post('/api/ban', async (req, res) => {
    try {
        if (!segredoValido(req, BAN_API_SECRET)) {
            return res.status(BAN_API_SECRET ? 401 : 503).json({
                success: false,
                error: BAN_API_SECRET
                    ? 'Não autorizado.'
                    : 'API de banimento não configurada.'
            });
        }

        const discordId = String(req.body.discord_id || '').trim();
        const usernameInformado = String(req.body.username || '')
            .trim().slice(0, 100);
        const motivo = String(req.body.reason || '')
            .trim().slice(0, 500);
        const responsavel = String(req.body.banned_by || '').trim();

        if (
            !/^\d{17,20}$/.test(discordId) ||
            !/^\d{17,20}$/.test(responsavel) ||
            !motivo
        ) {
            return res.status(400).json({
                success: false,
                error: 'ID do Discord ou motivo inválido.'
            });
        }

        const consulta = await pool.query(
            `SELECT username, ip_address
             FROM verified_users
             WHERE discord_id = $1
             LIMIT 1`,
            [discordId]
        );

        const verificado = consulta.rows[0] || null;

        await pool.query(
            `INSERT INTO user_bans
                (discord_id, username, ip_address, reason, banned_by, banned_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             ON CONFLICT (discord_id)
             DO UPDATE SET
                username = EXCLUDED.username,
                ip_address = EXCLUDED.ip_address,
                reason = EXCLUDED.reason,
                banned_by = EXCLUDED.banned_by,
                banned_at = NOW()`,
            [
                discordId,
                verificado?.username || usernameInformado,
                verificado?.ip_address || '',
                motivo,
                responsavel
            ]
        );

        return res.json({
            success: true,
            ip_registered: Boolean(verificado?.ip_address)
        });
    } catch (erro) {
        console.error('Erro na API /api/ban:', erro);

        return res.status(500).json({
            success: false,
            error: 'Não foi possível registrar o banimento.'
        });
    }
});

// ======================================
// API DE RECEBIMENTO DAS LOGS DO BOT
// ======================================

app.post('/api/logs', async (req, res) => {
    try {
        if (!segredoValido(req, LOGS_API_SECRET)) {
            return res.status(LOGS_API_SECRET ? 401 : 503).json({
                success: false,
                error: LOGS_API_SECRET
                    ? 'Não autorizado.'
                    : 'LOGS_API_SECRET não configurada.'
            });
        }

        const action = String(req.body.action || '')
            .trim().slice(0, 100);
        const userId = String(req.body.user_id || '')
            .trim().slice(0, 30);
        const username = String(req.body.username || '')
            .trim().slice(0, 100);
        const details = String(req.body.details || '')
            .trim().slice(0, 2000);
        const guildId = String(req.body.guild_id || '')
            .trim().slice(0, 30);
        const channelId = String(req.body.channel_id || '')
            .trim().slice(0, 30);

        if (!action) {
            return res.status(400).json({
                success: false,
                error: 'A ação da log é obrigatória.'
            });
        }

        await pool.query(
            `INSERT INTO site_logs
                (source, action, user_id, username, details,
                 guild_id, channel_id, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
            [
                'bot',
                action,
                userId,
                username,
                details,
                guildId,
                channelId
            ]
        );

        return res.status(201).json({
            success: true
        });
    } catch (erro) {
        console.error('Erro ao receber log do bot:', erro);

        return res.status(500).json({
            success: false,
            error: 'Não foi possível salvar a log.'
        });
    }
});

// ======================================
// PÁGINA INICIAL
// ======================================

app.get('/', (req, res) => {
    const usuario = req.session.usuario;

    const conta = usuario
        ? `<p>Conectado como <strong>${escapar(usuario.username)}</strong>.</p>
           <a href="/verificar">Verificar minha conta</a>
           <a class="secondary" href="/auth/sair">Sair</a>`
        : '<a href="/auth/login">Entrar com Discord</a>';

    res.send(pagina('Início', `
        <section class="card">
            <h2>🛡️ Sistema de verificação</h2>
            <p>Entre com sua conta do Discord para concluir a verificação e receber o cargo.</p>
            ${conta}
        </section>
        <section class="card">
            <h2>Informações</h2>
            <p>A verificação não bloqueia usuários por país nem utiliza sistema AntiVPN.</p>
            <p>O sistema registra informações básicas da conta e da verificação para funcionamento e segurança.</p>
            <p class="small">Nunca informe sua senha do Discord neste site. O login acontece nas páginas oficiais do Discord.</p>
        </section>
    `));
});

// ======================================
// LOGIN DISCORD / OAUTH2
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
            return res.status(400).send(pagina(
                'Login cancelado',
                '<div class="card"><h2>Login cancelado</h2><p>Você não autorizou o login.</p><a href="/">Voltar</a></div>'
            ));
        }

        if (
            typeof state !== 'string' ||
            !req.session.oauthState ||
            state !== req.session.oauthState ||
            typeof code !== 'string'
        ) {
            return res.status(400).send(pagina(
                'Erro de autenticação',
                '<div class="card"><h2>Não foi possível confirmar o login</h2><a href="/">Voltar</a></div>'
            ));
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
                }),
                signal: AbortSignal.timeout(10000)
            }
        );

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok || !tokenData.access_token) {
            console.error('Falha no OAuth do Discord:', tokenData);

            return res.status(401).send(pagina(
                'Erro de login',
                '<div class="card"><h2>Não foi possível entrar</h2><a href="/">Voltar</a></div>'
            ));
        }

        const userResponse = await fetch(
            'https://discord.com/api/v10/users/@me',
            {
                headers: {
                    Authorization: `Bearer ${tokenData.access_token}`
                },
                signal: AbortSignal.timeout(10000)
            }
        );

        const usuario = await userResponse.json();

        if (!userResponse.ok || !usuario.id) {
            return res.status(401).send(pagina(
                'Erro de login',
                '<div class="card"><h2>Não foi possível obter sua conta.</h2><a href="/">Voltar</a></div>'
            ));
        }

        req.session.usuario = {
            id: usuario.id,
            username: usuario.global_name || usuario.username,
            avatar: usuario.avatar || null
        };

        return req.session.save(erro => {
            if (erro) {
                console.error('Erro ao salvar sessão:', erro);

                return res.status(500).send(pagina(
                    'Erro',
                    '<div class="card"><h2>Não foi possível salvar sua sessão.</h2><a href="/">Voltar</a></div>'
                ));
            }

            res.redirect('/verificar');
        });
    } catch (erro) {
        console.error('Erro no login:', erro);

        return res.status(500).send(pagina(
            'Erro',
            '<div class="card"><h2>Erro no login</h2><p>Tente novamente mais tarde.</p><a href="/">Voltar</a></div>'
        ));
    }
});

// ======================================
// VERIFICAÇÃO DA CONTA
// SEM VERIFICAÇÃO DE PAÍS OU ANTIVPN
// ======================================

app.get('/verificar', async (req, res) => {
    if (!req.session.usuario) {
        return res.redirect('/auth/login');
    }

    const usuario = req.session.usuario;
    const ip = obterIp(req);

    try {
        const banPorId = await pool.query(
            `SELECT discord_id
             FROM user_bans
             WHERE discord_id = $1
             LIMIT 1`,
            [usuario.id]
        );

        if (banPorId.rowCount > 0) {
            return res.status(403).send(pagina(
                'Verificação bloqueada',
                '<div class="card"><h2>⛔ Verificação bloqueada</h2><p>Esta conta está banida do sistema de verificação.</p><a href="/">Voltar</a></div>'
            ));
        }

        try {
            await atribuirCargoVerificado(usuario.id);
        } catch (erroCargo) {
            console.error(
                'Falha ao entregar cargo:',
                erroCargo.message
            );

            return res.status(502).send(pagina(
                'Não foi possível entregar o cargo',
                `<section class="card">
                    <h2>⚠️ Não foi possível concluir</h2>
                    <p>O Discord não confirmou a entrega do cargo.</p>
                    <p>${escapar(erroCargo.message)}</p>
                    <p>Confira se você está no servidor correto e tente novamente.</p>
                    <a href="/verificar">Tentar novamente</a>
                </section>`
            ));
        }

        await pool.query(
            `INSERT INTO verified_users
                (discord_id, username, avatar, ip_address, verified_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT (discord_id)
             DO UPDATE SET
                username = EXCLUDED.username,
                avatar = EXCLUDED.avatar,
                ip_address = EXCLUDED.ip_address,
                verified_at = NOW()`,
            [
                usuario.id,
                usuario.username,
                usuario.avatar,
                ip
            ]
        );

        return res.send(pagina('Verificação concluída', `
            <section class="card">
                <h2>✅ Verificação concluída!</h2>
                <p>Conta Discord: <strong>${escapar(usuario.username)}</strong></p>
                <p>Seu cargo de verificado foi entregue com sucesso.</p>
                <p class="small">ID da conta: ${escapar(usuario.id)}</p>
                <a href="/">Voltar à página inicial</a>
            </section>
        `));
    } catch (erro) {
        console.error('Erro ao verificar:', erro);

        return res.status(500).send(pagina(
            'Erro',
            '<div class="card"><h2>Não foi possível concluir</h2><p>Tente novamente mais tarde.</p><a href="/">Voltar</a></div>'
        ));
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
                 ORDER BY verified_at DESC
                 LIMIT 100`,
                [busca, `%${busca}%`]
            );
        } else {
            usuarios = await pool.query(
                `SELECT * FROM verified_users
                 ORDER BY verified_at DESC
                 LIMIT 100`
            );
        }

        const banidos = await pool.query(
            `SELECT * FROM user_bans
             ORDER BY banned_at DESC
             LIMIT 100`
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
                        <label>Motivo do banimento</label>
                        <input name="reason" placeholder="Informe o motivo" required maxlength="300">
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
                <p class="small">Exibindo no máximo 100 usuários e 100 banimentos.</p>
                <a href="/admin/logs">📋 Ver logs do sistema</a>
            </section>

            <section class="card">
                <h2>Usuários verificados</h2>
                <div style="overflow-x:auto">
                    <table>
                        <thead><tr>
                            <th>Nome</th><th>ID</th><th>IP registrado</th><th>Data</th><th>Ação</th>
                        </tr></thead>
                        <tbody>
                            ${linhasUsuarios || '<tr><td colspan="5">Nenhum usuário encontrado.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="card">
                <h2>Usuários banidos</h2>
                <div style="overflow-x:auto">
                    <table>
                        <thead><tr>
                            <th>Nome</th><th>ID</th><th>IP registrado</th><th>Motivo</th><th>Data</th><th>Ação</th>
                        </tr></thead>
                        <tbody>
                            ${linhasBanidos || '<tr><td colspan="6">Nenhum banimento.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </section>

            <a class="secondary" href="/auth/sair">Sair</a>
        `));
    } catch (erro) {
        console.error('Erro no painel:', erro);

        res.status(500).send(pagina(
            'Erro',
            '<div class="card"><h2>Erro ao abrir o painel</h2><a href="/">Voltar</a></div>'
        ));
    }
});

// ======================================
// PÁGINA DE LOGS — SOMENTE ADMIN
// ======================================

app.get('/admin/logs', exigirAdmin, async (req, res) => {
    try {
        const resultado = await pool.query(
            `SELECT id, source, action, user_id, username,
                    details, guild_id, channel_id, created_at
             FROM site_logs
             ORDER BY created_at DESC
             LIMIT 200`
        );

        const linhas = resultado.rows.map(log => `
            <tr>
                <td>${escapar(new Date(log.created_at).toLocaleString('pt-BR'))}</td>
                <td>${escapar(log.source)}</td>
                <td>${escapar(log.action)}</td>
                <td>${escapar(log.username || 'Não informado')}</td>
                <td>${escapar(log.user_id || '—')}</td>
                <td>${escapar(log.details || '—')}</td>
                <td>${escapar(log.guild_id || '—')}</td>
                <td>${escapar(log.channel_id || '—')}</td>
            </tr>
        `).join('');

        return res.send(pagina('Logs do sistema', `
            <section class="card">
                <h2>📋 Logs do sistema</h2>
                <p>Últimos ${resultado.rowCount} registros armazenados no PostgreSQL.</p>
                <p class="small">Máximo de 200 registros, do mais recente para o mais antigo.</p>
                <a href="/admin">Voltar ao painel</a>
                <a class="secondary" href="/admin/logs">Atualizar logs</a>
            </section>

            <section class="card">
                <div style="overflow-x:auto">
                    <table>
                        <thead>
                            <tr>
                                <th>Data</th>
                                <th>Origem</th>
                                <th>Ação</th>
                                <th>Usuário</th>
                                <th>ID</th>
                                <th>Detalhes</th>
                                <th>Servidor</th>
                                <th>Canal</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${linhas || '<tr><td colspan="8">Nenhuma log registrada ainda. Conecte o bot e envie um evento de teste.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </section>
        `));
    } catch (erro) {
        console.error('Erro ao consultar logs:', erro);

        return res.status(500).send(pagina(
            'Erro nas logs',
            '<div class="card"><h2>Não foi possível carregar as logs.</h2><a href="/admin">Voltar</a></div>'
        ));
    }
});

// ======================================
// BANIR PELO PAINEL
// ======================================

app.post('/admin/banir', exigirAdmin, async (req, res) => {
    if (!validarCsrf(req, res)) return;

    const discordId = String(req.body.discord_id || '').trim();
    const username = String(req.body.username || '').slice(0, 100);
    const reason = String(req.body.reason || '').trim().slice(0, 300);

    if (!/^\d{17,20}$/.test(discordId) || !reason) {
        return res.status(400).send(pagina(
            'Dados inválidos',
            '<div class="card"><h2>Dados inválidos</h2><a href="/admin">Voltar</a></div>'
        ));
    }

    try {
        const consulta = await pool.query(
            `SELECT ip_address
             FROM verified_users
             WHERE discord_id = $1
             LIMIT 1`,
            [discordId]
        );

        const ipRegistrado = consulta.rows[0]?.ip_address || '';

        await pool.query(
            `INSERT INTO user_bans
                (discord_id, username, ip_address, reason, banned_by, banned_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             ON CONFLICT (discord_id)
             DO UPDATE SET
                username = EXCLUDED.username,
                ip_address = EXCLUDED.ip_address,
                reason = EXCLUDED.reason,
                banned_by = EXCLUDED.banned_by,
                banned_at = NOW()`,
            [
                discordId,
                username,
                ipRegistrado,
                reason,
                req.session.usuario.id
            ]
        );

        return res.redirect('/admin');
    } catch (erro) {
        console.error('Erro ao banir:', erro);

        return res.status(500).send(pagina(
            'Erro',
            '<div class="card"><h2>Não foi possível banir.</h2><a href="/admin">Voltar</a></div>'
        ));
    }
});

// ======================================
// DESBANIR PELO PAINEL
// ======================================

app.post('/admin/desbanir', exigirAdmin, async (req, res) => {
    if (!validarCsrf(req, res)) return;

    const discordId = String(req.body.discord_id || '').trim();

    if (!/^\d{17,20}$/.test(discordId)) {
        return res.status(400).send(pagina(
            'ID inválido',
            '<div class="card"><h2>ID do Discord inválido.</h2><a href="/admin">Voltar</a></div>'
        ));
    }

    try {
        if (
            !DISCORD_BOT_TOKEN ||
            !/^\d{17,20}$/.test(DISCORD_GUILD_ID || '')
        ) {
            return res.status(503).send(pagina(
                'Configuração necessária',
                '<div class="card"><h2>Desbanimento não configurado</h2><p>Configure DISCORD_BOT_TOKEN e DISCORD_GUILD_ID nas variáveis de ambiente.</p><a href="/admin">Voltar</a></div>'
            ));
        }

        const resposta = await fetch(
            `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/bans/${discordId}`,
            {
                method: 'DELETE',
                headers: {
                    Authorization: `Bot ${DISCORD_BOT_TOKEN}`
                },
                signal: AbortSignal.timeout(10000)
            }
        );

        if (!resposta.ok && resposta.status !== 404) {
            const detalhe = await resposta.text().catch(() => '');

            console.error(
                'Erro no desbanimento do Discord:',
                resposta.status,
                detalhe
            );

            return res.status(502).send(pagina(
                'Falha no desbanimento',
                `<div class="card">
                    <h2>O Discord não permitiu concluir o desbanimento.</h2>
                    <p>Código de resposta: ${resposta.status}.</p>
                    <p>Confira o token, o servidor e as permissões do bot.</p>
                    <p>O registro de banimento do site foi mantido.</p>
                    <a href="/admin">Voltar ao painel</a>
                </div>`
            ));
        }

        await pool.query(
            'DELETE FROM user_bans WHERE discord_id = $1',
            [discordId]
        );

        return res.redirect('/admin');
    } catch (erro) {
        console.error('Erro ao desbanir:', erro);

        return res.status(500).send(pagina(
            'Erro',
            '<div class="card"><h2>Não foi possível concluir o desbanimento.</h2><p>O registro do site foi mantido. Tente novamente.</p><a href="/admin">Voltar</a></div>'
        ));
    }
});

// ======================================
// SAIR
// ======================================

app.get('/auth/sair', (req, res) => {
    req.session.destroy(erro => {
        if (erro) {
            console.error('Erro ao encerrar sessão:', erro);
        }

        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

// ======================================
// TRATAMENTO DE ERROS
// ======================================

app.use((erro, req, res, next) => {
    console.error('Erro não tratado na rota:', erro);

    if (res.headersSent) {
        return next(erro);
    }

    return res.status(500).send(pagina(
        'Erro',
        '<div class="card"><h2>Erro interno</h2><p>Tente novamente mais tarde.</p><a href="/">Voltar</a></div>'
    ));
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
    .catch(erro => {
        console.error('Não foi possível preparar o banco:', erro);
        process.exit(1);
    });
