
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

    await pool.query(`
        CREATE TABLE IF NOT EXISTS vpn_checks (
            id BIGSERIAL PRIMARY KEY,
            discord_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score DOUBLE PRECISION,
            blocked BOOLEAN NOT NULL,
            checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
            '<div class="card"><h2>Solicitação inválida</h2><p>Atualize a página e tente novamente.</p><a href="/">Voltar</a></div>'
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
            '<div class="card"><h2>Solicitação inválida</h2><p>Atualize a página e tente novamente.</p><a href="/">Voltar</a></div>'
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

// ======================================
// ANTI-VPN — IPLOGS
// ======================================

async function verificarIpLogs(ip) {
    const ipLimpo = String(ip || '').trim();

    if (
        !ipLimpo ||
        ipLimpo === 'desconhecido' ||
        ipLimpo === '::1' ||
        ipLimpo === '127.0.0.1'
    ) {
        throw new Error('Não foi possível identificar o IP público.');
    }

    const resposta = await fetch(
        'https://iplogs.com/v1/check',
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ip: ipLimpo
            }),
            signal: AbortSignal.timeout(10000)
        }
    );

    // ALTERAÇÃO: registrar a resposta real do IPLogs
    // para descobrirmos por que a API está retornando erro.
    if (!resposta.ok) {
        const detalhe = await resposta.text().catch(() => '');

        console.error(
            'Erro detalhado do IPLogs:',
            resposta.status,
            detalhe.slice(0, 1500)
        );

        throw new Error(
            `IPLogs respondeu com HTTP ${resposta.status}.`
        );
    }

    const dados = await resposta.json();

    if (
        typeof dados.is_vpn !== 'boolean' ||
        typeof dados.score !== 'number' ||
        typeof dados.verdict !== 'string'
    ) {
        throw new Error('Resposta inválida do IPLogs.');
    }

    const veredito = dados.verdict.toLowerCase();

    const vereditosBloqueados = [
        'vpn',
        'proxy',
        'tor',
        'vpn_likely',
        'vpn-likely'
    ];

    const bloqueado =
        dados.is_vpn === true ||
        dados.score >= 0.5 ||
        vereditosBloqueados.includes(veredito);

    return {
        bloqueado,
        verdict: veredito,
        score: dados.score,
        tipo: String(dados.ip_info?.type || 'desconhecido')
    };
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
                'O usuário ou o cargo não foi encontrado. Confirme se a pessoa está no servidor.'
            );
        }

        if (resposta.status === 403) {
            throw new Error(
                'O bot não tem permissão para entregar o cargo. Confira Gerenciar Cargos e a hierarquia.'
            );
        }

        throw new Error(
            `O Discord recusou a atribuição do cargo (HTTP ${resposta.status}).`
        );
    }
}

// ======================================
// API DE BANIMENTO DO SITE
// ======================================

app.post('/api/ban', async (req, res) => {
    try {
        if (!BAN_API_SECRET) {
            return res.status(503).json({
                success: false,
                error: 'API de banimento não configurada.'
            });
        }

        const authorization = req.get('authorization') || '';
        const prefix = 'Bearer ';

        const chaveRecebida = authorization.startsWith(prefix)
            ? authorization.slice(prefix.length)
            : '';

        const esperada = Buffer.from(BAN_API_SECRET);
        const recebida = Buffer.from(chaveRecebida);

        if (
            recebida.length !== esperada.length ||
            !crypto.timingSafeEqual(recebida, esperada)
        ) {
            return res.status(401).json({
                success: false,
                error: 'Não autorizado.'
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
// PÁGINA INICIAL
// ======================================

app.get('/', (req, res) => {
    const usuario = req.session.usuario;

    const conta = usuario
        ? `<p>Conectado como <strong>${escapar(usuario.username)}</strong>.</p>
           <a href="/verificar">Concluir verificação</a>
           <a class="secondary" href="/auth/sair">Sair</a>`
        : '<a href="/auth/login">Entrar com Discord</a>';

    res.send(pagina('Verificação', `
        <section class="card">
            <h2>🛡️ Verificação de conta</h2>
            <p>Entre com sua conta do Discord para iniciar a verificação.</p>
            ${conta}
        </section>
        <section class="card">
            <h2>🔒 Aviso de privacidade</h2>
            <p>O site registra o identificador público da conta, nome, IP da conexão e data de verificação para segurança e prevenção de abusos.</p>
            <p>Um IP pode ser compartilhado por várias pessoas ou mudar com o tempo. Uma correspondência de IP, isoladamente, não prova que as contas pertencem à mesma pessoa.</p>
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

    const url = new URL(
        'https://discord.com/oauth2/authorize'
    );

    url.searchParams.set('client_id', CLIENT_ID);
    url.searchParams.set(
        'redirect_uri',
        `${SITE_URL}/auth/callback`
    );
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
            console.error('Falha OAuth:', tokenData);

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

        return res.redirect('/verificar');
    } catch (erro) {
        console.error('Erro no login:', erro);

        return res.status(500).send(pagina(
            'Erro',
            '<div class="card"><h2>Erro no login</h2><p>Tente novamente mais tarde.</p><a href="/">Voltar</a></div>'
        ));
    }
});

// ======================================
// VERIFICAÇÃO + ANTI-VPN + CARGO
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
                `<section class="card">
                    <h2>⛔ Verificação bloqueada</h2>
                    <p>Esta conta está banida do sistema de verificação.</p>
                    <p>Se acredita que isso é um erro, entre em contato com a equipe administrativa.</p>
                    <a href="/">Voltar</a>
                </section>`
            ));
        }

        // Consulta o IP do visitante no IPLogs.
        // Se o serviço falhar, a verificação não é concluída.
        let resultadoIp;

        try {
            resultadoIp = await verificarIpLogs(ip);
        } catch (erroIp) {
            console.error(
                'Falha na checagem IPLogs:',
                erroIp.message
            );

            return res.status(503).send(pagina(
                'Verificação indisponível',
                `<section class="card">
                    <h2>⚠️ Não foi possível verificar sua conexão</h2>
                    <p>O serviço de segurança está temporariamente indisponível.</p>
                    <p>Tente novamente em alguns instantes. Seu cargo não foi alterado.</p>
                    <a href="/verificar">Tentar novamente</a>
                    <a class="secondary" href="/">Voltar</a>
                </section>`
            ));
        }

        await pool.query(
            `INSERT INTO vpn_checks
                (discord_id, ip_address, verdict, score, blocked)
             VALUES ($1, $2, $3, $4, $5)`,
            [
                usuario.id,
                ip,
                resultadoIp.verdict,
                resultadoIp.score,
                resultadoIp.bloqueado
            ]
        );

        if (resultadoIp.bloqueado) {
            console.warn(
                `Verificação bloqueada: Discord ${usuario.id}; ` +
                `veredito=${resultadoIp.verdict}; ` +
                `score=${resultadoIp.score}`
            );

            return res.status(403).send(pagina(
                'Conexão bloqueada',
                `<section class="card">
                    <h2>🛡️ Verificação não concluída</h2>
                    <p>A checagem de segurança identificou sinais de VPN, proxy, Tor ou conexão de risco.</p>
                    <p>Se estiver usando uma VPN ou proxy, desative-a e tente novamente.</p>
                    <p>Se acredita que houve um engano, entre em contato com a equipe administrativa.</p>
                    <a href="/">Voltar</a>
                </section>`
            ));
        }

        // Entrega o cargo somente após a checagem do IP.
        // Se falhar, não registra a verificação como concluída.
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
                    <h2>⚠️ Verificação ainda não concluída</h2>
                    <p>Sua conexão passou pela checagem, mas o Discord não confirmou a entrega do cargo.</p>
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
                <p>A checagem de segurança foi concluída e o cargo de verificado foi solicitado ao Discord.</p>
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
        const busca = String(req.query.q || '')
            .trim()
            .slice(0, 100);

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
                `SELECT * FROM verified_users
                 ORDER BY verified_at DESC LIMIT 100`
            );
        }

        const banidos = await pool.query(
            `SELECT * FROM user_bans
             ORDER BY banned_at DESC LIMIT 100`
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

        const checagens = await pool.query(
            `SELECT discord_id, ip_address, verdict, score, blocked, checked_at
             FROM vpn_checks
             ORDER BY checked_at DESC
             LIMIT 50`
        );

        const linhasChecagens = checagens.rows.map(c => `
            <tr>
                <td>${escapar(c.discord_id)}</td>
                <td>${escapar(c.ip_address)}</td>
                <td>${escapar(c.verdict)}</td>
                <td>${escapar(c.score)}</td>
                <td>${c.blocked ? 'Bloqueado' : 'Liberado'}</td>
                <td>${escapar(new Date(c.checked_at).toLocaleString('pt-BR'))}</td>
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
            </section>

            <section class="card">
                <h2>Usuários verificados</h2>
                <div style="overflow-x:auto">
                    <table>
                        <thead><tr>
                            <th>Nome</th><th>ID</th><th>IP</th><th>Data</th><th>Ação</th>
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
                            <th>Nome</th><th>ID</th><th>IP</th><th>Motivo</th><th>Data</th><th>Ação</th>
                        </tr></thead>
                        <tbody>
                            ${linhasBanidos || '<tr><td colspan="6">Nenhum banimento.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="card">
                <h2>🛡️ Registros do anti-VPN</h2>
                <div style="overflow-x:auto">
                    <table>
                        <thead><tr>
                            <th>ID Discord</th><th>IP</th><th>Veredito</th><th>Pontuação</th><th>Resultado</th><th>Data</th>
                        </tr></thead>
                        <tbody>
                            ${linhasChecagens || '<tr><td colspan="6">Nenhuma checagem registrada.</td></tr>'}
                        </tbody>
                    </table>
                </div>
                <p class="small">Os registros contêm dados de conexão; restrinja o acesso ao painel a administradores autorizados.</p>
            </section>

            <a class="secondary" href="/auth/sair">Sair</a>
        `));
    } catch (erro) {
        console.error('Erro no painel:', erro);

        res.status(500).send(pagina(
            'Erro',
            '<div class="card"><h2>Erro ao abrir o painel</h2></div>'
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
                '<div class="card"><h2>Desbanimento não configurado</h2><p>Configure DISCORD_BOT_TOKEN e DISCORD_GUILD_ID nas variáveis de ambiente. Nenhum registro foi removido.</p><a href="/admin">Voltar</a></div>'
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
    req.session.destroy(() => {
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
        console.error(
            'Não foi possível preparar o banco:',
            erro
        );

        process.exit(1);
    });
