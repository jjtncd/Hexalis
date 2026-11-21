const mc = require("minecraft-protocol");
const express = require("express");
const { PNG } = require("pngjs");
const crypto = require("node:crypto");
const net = require("node:net");
const dns = require("node:dns").promises;

const app = express();
const PORT = Number(process.env.PORT || 3000);
app.use(express.json({ limit: "256kb" }));

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------
function chatComponentToText(component) {
    if (component == null) return "";
    if (typeof component === "string" || typeof component === "number") return String(component);
    if (Array.isArray(component)) return component.map(chatComponentToText).join("");
    if (typeof component === "object") {
        let text = typeof component.text === "string" ? component.text : "";
        if (Array.isArray(component.extra)) text += component.extra.map(chatComponentToText).join("");
        if (!text && typeof component.translate === "string") text = component.translate;
        if (Array.isArray(component.with)) text += component.with.map(chatComponentToText).join("");
        return text;
    }
    return "";
}

function chatPacketToText(packet) {
    const raw = packet && packet.message;
    if (typeof raw !== "string") return chatComponentToText(raw);
    try { return chatComponentToText(JSON.parse(raw)); }
    catch { return raw; }
}

async function pingServer(host, port) {
    return mc.ping({ host, port, version: "1.8.8", closeTimeout: 15000, noPongTimeout: 5000 });
}

function faviconToHex(favicon, size = 32) {
    if (typeof favicon !== "string") throw new Error("El servidor no tiene favicon");
    const match = /^data:image\/png;base64,(.+)$/i.exec(favicon);
    if (!match) throw new Error("Favicon PNG inválido");
    const png = PNG.sync.read(Buffer.from(match[1], "base64"));
    if (!png.width || !png.height || png.width > 256 || png.height > 256) {
        throw new Error("Dimensiones de favicon inválidas");
    }
    const pixels = [];
    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            const sx = Math.min(png.width - 1, Math.floor((x + 0.5) * png.width / size));
            const sy = Math.min(png.height - 1, Math.floor((y + 0.5) * png.height / size));
            const i = (sy * png.width + sx) * 4;
            const alpha = png.data[i + 3] / 255;
            const rgb = [0, 1, 2].map(channel =>
                Math.round(png.data[i + channel] * alpha + 18 * (1 - alpha))
            );
            pixels.push(rgb.map(value => value.toString(16).padStart(2, "0")).join("").toUpperCase());
        }
    }
    return pixels;
}

function isPrivateIPv4(host) {
    const parts = host.split(".").map(Number);
    if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    const [a, b] = parts;
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
        (a === 100 && b >= 64 && b <= 127) || a >= 224;
}

function isPrivateAddress(address) {
    const family = net.isIP(address);
    if (family === 4) return isPrivateIPv4(address);
    if (family === 6) {
        const value = address.toLowerCase();
        if (value === "::" || value === "::1" || value.startsWith("fc") || value.startsWith("fd") ||
            value.startsWith("fe8") || value.startsWith("fe9") || value.startsWith("fea") || value.startsWith("feb")) return true;
        const mapped = value.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
        return mapped ? isPrivateIPv4(mapped[1]) : false;
    }
    return true;
}

async function publicDnsError(host) {
    try {
        const records = await dns.lookup(host, { all: true, verbatim: true });
        if (!records.length || records.some(record => isPrivateAddress(record.address))) {
            return "el dominio no apunta exclusivamente a direcciones públicas";
        }
        return null;
    } catch {
        return "no se pudo resolver el dominio";
    }
}

function validateTarget(host, port) {
    if (typeof host !== "string") return "host inválido";
    host = host.trim();
    if (!host || host.length > 253 || !/^[a-zA-Z0-9.-]+$/.test(host)) return "host inválido";
    const lower = host.toLowerCase();
    if (lower === "localhost" || lower.endsWith(".localhost") || lower.endsWith(".local")) {
        return "solo se permiten hosts públicos";
    }
    const ipType = net.isIP(host);
    if (ipType === 4 && isPrivateIPv4(host)) return "solo se permiten hosts públicos";
    if (ipType === 6) return "usa un nombre DNS o una IPv4 pública";
    if (!Number.isInteger(port) || port < 1 || port > 65535) return "puerto inválido";
    return null;
}

function requireBridgeKey(req, res) {
    const configured = String(process.env.JTN_BRIDGE_KEY || "");
    const supplied = String(req.body?.key || "");
    if (!configured) {
        res.status(503).json({ ok: false, error: "JTN_BRIDGE_KEY no está configurada en Render" });
        return false;
    }
    const a = Buffer.from(configured);
    const b = Buffer.from(supplied);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        res.status(401).json({ ok: false, error: "Bridge key inválida" });
        return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// Minecraft status endpoints (existing feature)
// -----------------------------------------------------------------------------
app.get("/ping", async (req, res) => {
    const host = String(req.query.host || "").trim();
    const port = Number.parseInt(req.query.port, 10) || 25565;
    const validation = validateTarget(host, port);
    if (validation) return res.status(400).json({ error: validation });
    const dnsError = await publicDnsError(host);
    if (dnsError) return res.status(400).json({ error: dnsError });
    try {
        const result = await pingServer(host, port);
        res.json({
            motd: chatComponentToText(result.description),
            online: result.players?.online ?? 0,
            max: result.players?.max ?? 0,
            version: result.version?.name ?? "?",
            favicon: result.favicon ?? null,
            latency: result.latency ?? 0
        });
    } catch (error) {
        console.error("[PING ERROR]", host, error.message);
        res.status(502).json({ error: "offline" });
    }
});

app.get("/logo", async (req, res) => {
    const host = String(req.query.host || "mc.hypixel.net").trim();
    const port = Number.parseInt(req.query.port, 10) || 25565;
    const validation = validateTarget(host, port);
    if (validation) return res.status(400).json({ error: validation });
    const dnsError = await publicDnsError(host);
    if (dnsError) return res.status(400).json({ error: dnsError });
    try {
        const result = await pingServer(host, port);
        res.json({ width: 32, height: 32, format: "RGB24-HEX", pixels: faviconToHex(result.favicon, 32) });
    } catch (error) {
        console.error("[LOGO ERROR]", host, error.message);
        res.status(502).json({ error: "No se pudo obtener el logo" });
    }
});

// -----------------------------------------------------------------------------
// Offline-mode Java client bridge
// The bridge is deliberately pinned to 1.8.8, matching JTN MC's current client.
// It only uses offline auth for servers that have disabled online-mode themselves.
// The username is supplied by the Roblox server from the player's own Roblox name.
// -----------------------------------------------------------------------------
const sessions = new Map();
const MAX_ACTIVE_SESSIONS = 4;
const MAX_QUEUED_EVENTS = 120;
const SESSION_IDLE_TTL_MS = 5 * 60 * 1000;
const SESSION_MAX_AGE_MS = 60 * 60 * 1000;

function pushBridgeEvent(session, event) {
    if (!session || session.closed) return;
    session.lastActivity = Date.now();
    session.queue.push({ at: Date.now(), ...event });
    if (session.queue.length > MAX_QUEUED_EVENTS) session.queue.splice(0, session.queue.length - MAX_QUEUED_EVENTS);
    for (const wake of [...session.waiters]) wake();
}

function cleanReason(reason) {
    if (reason == null) return "";
    if (typeof reason === "string") {
        try { return chatComponentToText(JSON.parse(reason)); }
        catch { return reason.slice(0, 500); }
    }
    return chatComponentToText(reason).slice(0, 500);
}

// A server-side verification prompt is not a successful Minecraft login.
// Detect the clear wording used by UniversoCraft and similar servers, then
// send a safe summary instead of forwarding one-time URLs or challenge IDs.
function isVerificationNotice(text) {
    const value = String(text || "");
    return /necesitamos\s+verificar\s+tu\s+conexi[oó]n|verifica(?:r|ci[oó]n).{0,100}(?:conexi[oó]n|navegador)|(?:conexi[oó]n|acceso).{0,100}(?:verificar|verificaci[oó]n)|completa\s+el\s+proceso|complete\s+the\s+verification|verify\s+your\s+connection|anti.?bots?/i.test(value);
}

function markVerificationRequired(session, source) {
    if (!session || session.verificationRequired) return;
    session.verificationRequired = true;
    session.state = "verification_required";
    session.verificationSource = source || "server";
    pushBridgeEvent(session, {
        type: "verification_required",
        message: "El servidor solicitó verificar la conexión antes de permitir el acceso al mundo. JTN MC no abre ni automatiza enlaces externos."
    });
    console.warn(`[BRIDGE] Verification required: ${session.username} @ ${session.host}`);
}

function popcount16(value) {
    let count = 0;
    value = Number(value) & 0xffff;
    while (value) {
        value &= value - 1;
        count++;
    }
    return count;
}

function makeChunkBridgePayload(session, x, z, bitMap, chunkData, groundUp, skyLightSent) {
    const cx = Number(x);
    const cz = Number(z);
    const mask = Number(bitMap) & 0xffff;
    if (!Number.isInteger(cx) || !Number.isInteger(cz)) throw new Error("Coordenadas de chunk inválidas");
    if (!Buffer.isBuffer(chunkData)) chunkData = Buffer.from(chunkData || []);

    const sectionCount = popcount16(mask);
    const blockBytes = sectionCount * 8192;
    const blockLightBytes = sectionCount * 2048;
    const skyLightBytes = skyLightSent ? sectionCount * 2048 : 0;
    const biomeOffset = blockBytes + blockLightBytes + skyLightBytes;
    const required = biomeOffset + (groundUp ? 256 : 0);
    if (chunkData.length < required) {
        throw new Error(`Chunk truncado: recibidos ${chunkData.length}, esperados al menos ${required}`);
    }

    // During initial world transfer retain a 7x7 area at most. Once the server has
    // sent the player's teleport, only accept columns within two chunks of it.
    if (session.positionSeen) {
        const playerChunkX = Math.floor(session.playerX / 16);
        const playerChunkZ = Math.floor(session.playerZ / 16);
        if (Math.max(Math.abs(cx - playerChunkX), Math.abs(cz - playerChunkZ)) > 2) {
            return null;
        }
    }
    const key = `${cx},${cz}`;
    if (!session.chunkKeys.has(key)) {
        if (session.chunkKeys.size >= 49) return null;
        session.chunkKeys.add(key);
    }

    const sections = [];
    let ordinal = 0;
    for (let sy = 0; sy < 16; sy++) {
        if ((mask & (1 << sy)) === 0) continue;
        const blocksStart = ordinal * 8192;
        const blockLightStart = blockBytes + ordinal * 2048;
        const skyLightStart = blockBytes + blockLightBytes + ordinal * 2048;
        sections.push({
            y: sy,
            blocksBase64: chunkData.subarray(blocksStart, blocksStart + 8192).toString("base64"),
            blockLightBase64: chunkData.subarray(blockLightStart, blockLightStart + 2048).toString("base64"),
            skyLightBase64: skyLightSent
                ? chunkData.subarray(skyLightStart, skyLightStart + 2048).toString("base64")
                : null
        });
        ordinal++;
    }

    let biomes = null;
    if (groundUp) {
        biomes = Array.from(chunkData.subarray(biomeOffset, biomeOffset + 256));
    }

    return {
        cx,
        cz,
        packetFormatVersion: 3,
        reset: groundUp === true,
        sections,
        biomes
    };
}

function queueChunkPayload(session, chunkPayload) {
    if (!chunkPayload) return false;
    session.mapChunks++;
    pushBridgeEvent(session, { type: "chunk_data", chunk: chunkPayload });
    return true;
}

function handleMapChunk(session, packet) {
    const skyLightSent = typeof packet.skyLightSent === "boolean"
        ? packet.skyLightSent
        : session.dimension === 0;
    try {
        const chunk = makeChunkBridgePayload(
            session,
            packet.x ?? packet.chunkX,
            packet.z ?? packet.chunkZ,
            packet.bitMap,
            packet.chunkData,
            packet.groundUp === true,
            skyLightSent
        );
        if (chunk) queueChunkPayload(session, chunk);
    } catch (error) {
        console.warn(`[CHUNK DECODE] ${session.host}: ${error.message}`);
        pushBridgeEvent(session, {
            type: "chunk_decode_error",
            x: Number(packet.x) || 0,
            z: Number(packet.z) || 0,
            message: String(error.message || error).slice(0, 200)
        });
    }
}

function handleMapChunkBulk(session, packet) {
    const data = Buffer.isBuffer(packet.data) ? packet.data : Buffer.from(packet.data || []);
    const skyLightSent = packet.skyLightSent === true;
    let offset = 0;
    const meta = Array.isArray(packet.meta) ? packet.meta : [];
    for (const entry of meta) {
        const mask = Number(entry.bitMap) & 0xffff;
        const sectionCount = popcount16(mask);
        const length = sectionCount * (8192 + 2048 + (skyLightSent ? 2048 : 0)) + 256;
        if (offset + length > data.length) {
            console.warn(`[CHUNK BULK] ${session.host}: paquete bulk truncado en ${offset}/${data.length}`);
            pushBridgeEvent(session, { type: "chunk_decode_error", message: "map_chunk_bulk truncado" });
            return;
        }
        const slice = data.subarray(offset, offset + length);
        try {
            const chunk = makeChunkBridgePayload(
                session, entry.x, entry.z, mask, slice, true, skyLightSent
            );
            if (chunk) queueChunkPayload(session, chunk);
        } catch (error) {
            console.warn(`[CHUNK BULK DECODE] ${session.host}: ${error.message}`);
            pushBridgeEvent(session, {
                type: "chunk_decode_error",
                x: Number(entry.x) || 0,
                z: Number(entry.z) || 0,
                message: String(error.message || error).slice(0, 200)
            });
        }
        offset += length;
    }
    if (offset !== data.length) {
        console.warn(`[CHUNK BULK] ${session.host}: ${data.length - offset} bytes sobrantes`);
    }
}

function markSessionJoined(session, source) {
    const wasJoined = session.joined === true;
    // Keep the state monotonic: later login/position packets must not demote a
    // session after playerJoin has already confirmed world entry.
    session.joined = true;
    session.verificationRequired = false;
    session.state = "joined";
    if (wasJoined) return;
    pushBridgeEvent(session, { type: "player_join", username: session.username });
    console.log(`[BRIDGE] LOGIN OK (${source}): ${session.username} @ ${session.host}`);
}

function onMinecraftPacket(session, packet, meta) {
    const name = meta && meta.name;
    if (!name) return;
    session.packetCounts[name] = (session.packetCounts[name] || 0) + 1;
    session.packetsSeen++;

    switch (name) {
        case "login": {
            session.loginPacketSeen = true;
            session.verificationRequired = false;
            // playerJoin can fire before this packet callback. Never overwrite
            // the confirmed joined state with the earlier login_accepted state.
            session.state = session.joined ? "joined" : "login_accepted";
            session.dimension = Number(packet.dimension) || 0;
            session.gameMode = Number(packet.gameMode) || 0;
            pushBridgeEvent(session, {
                type: "login",
                entityId: Number(packet.entityId) || 0,
                gameMode: Number(packet.gameMode) || 0,
                dimension: Number(packet.dimension) || 0,
                difficulty: Number(packet.difficulty) || 0,
                levelType: String(packet.levelType || "")
            });
            break;
        }
        case "position": {
            const position = {
                x: Number(packet.x) || 0,
                y: Number(packet.y) || 0,
                z: Number(packet.z) || 0,
                yaw: Number(packet.yaw) || 0,
                pitch: Number(packet.pitch) || 0,
                flags: Number(packet.flags) || 0
            };
            session.playerX = position.x;
            session.playerY = position.y;
            session.playerZ = position.z;
            session.positionSeen = true;
            // In the 1.8.8 client protocol the server's initial position packet
            // follows the login packet and is the authoritative world-entry signal.
            // Some minecraft-protocol versions do not emit the convenience
            // "playerJoin" event for this client flow, so promote the session here.
            if (session.loginPacketSeen) markSessionJoined(session, "initial position packet");
            pushBridgeEvent(session, { type: "position", ...position });
            break;
        }
        case "spawn_position": {
            const loc = packet.location || {};
            pushBridgeEvent(session, {
                type: "spawn_position",
                x: Number(loc.x) || 0,
                y: Number(loc.y) || 0,
                z: Number(loc.z) || 0
            });
            break;
        }
        case "map_chunk":
            handleMapChunk(session, packet);
            break;
        case "map_chunk_bulk":
            handleMapChunkBulk(session, packet);
            break;
        case "block_change": {
            const location = packet.location || {};
            const state = Number(packet.type) || 0;
            pushBridgeEvent(session, {
                type: "block_change",
                x: Number(location.x) || 0,
                y: Number(location.y) || 0,
                z: Number(location.z) || 0,
                id: state >>> 4,
                meta: state & 15
            });
            break;
        }
        case "multi_block_change": {
            const cx = Number(packet.chunkX) || 0;
            const cz = Number(packet.chunkZ) || 0;
            const blocks = [];
            for (const record of (Array.isArray(packet.records) ? packet.records : [])) {
                const horizontal = Number(record.horizontalPos) & 255;
                const state = Number(record.blockId) || 0;
                blocks.push([
                    cx * 16 + ((horizontal >>> 4) & 15),
                    Number(record.y) & 255,
                    cz * 16 + (horizontal & 15),
                    state >>> 4,
                    state & 15
                ]);
            }
            if (blocks.length) pushBridgeEvent(session, { type: "multi_block_change", blocks });
            break;
        }
        case "unload_chunk": {
            const cx = Number(packet.chunkX ?? packet.x) || 0;
            const cz = Number(packet.chunkZ ?? packet.z) || 0;
            // Let the client receive this column again after it re-enters view distance.
            session.chunkKeys.delete(`${cx},${cz}`);
            pushBridgeEvent(session, { type: "chunk_unload", x: cx, z: cz });
            break;
        }
        case "chat": {
            const text = chatPacketToText(packet).slice(0, 500);
            if (isVerificationNotice(text)) {
                markVerificationRequired(session, "server_chat");
                // Do not pass a one-time verification URL or challenge code to Roblox Output.
            } else {
                pushBridgeEvent(session, { type: "chat", text });
            }
            break;
        }
        case "update_health":
            pushBridgeEvent(session, {
                type: "health",
                health: Number(packet.health) || 0,
                food: Number(packet.food) || 0,
                saturation: Number(packet.foodSaturation) || 0
            });
            break;
        case "respawn":
            session.dimension = Number(packet.dimension) || 0;
            session.gameMode = Number(packet.gamemode) || 0;
            session.positionSeen = false;
            session.chunkKeys.clear();
            pushBridgeEvent(session, {
                type: "respawn",
                dimension: session.dimension,
                gameMode: session.gameMode,
                levelType: String(packet.levelType || "")
            });
            break;
        case "kick_disconnect":
        case "login_disconnect":
        case "disconnect": {
            const reason = cleanReason(packet.reason || packet.message || packet);
            if (isVerificationNotice(reason)) {
                markVerificationRequired(session, "disconnect_reason");
                session.error = "El servidor cerró la conexión después de solicitar una verificación.";
                session.state = "disconnected";
                pushBridgeEvent(session, { type: "disconnect", reason: session.error });
            } else {
                session.error = reason || "El servidor cerró la conexión";
                session.state = "disconnected";
                pushBridgeEvent(session, { type: "disconnect", reason: session.error });
            }
            break;
        }
        default:
            // Count every packet, but send only useful gameplay summaries to Roblox.
            break;
    }
}

function waitForBridgeEvents(session, waitMs) {
    if (session.queue.length || session.closed || waitMs <= 0) return Promise.resolve();
    return new Promise(resolve => {
        let finished = false;
        const finish = () => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            session.waiters.delete(finish);
            resolve();
        };
        const timer = setTimeout(finish, waitMs);
        session.waiters.add(finish);
    });
}

function getSession(sessionId) {
    if (typeof sessionId !== "string" || sessionId.length > 80) return null;
    return sessions.get(sessionId) || null;
}

app.post("/bridge/connect", async (req, res) => {
    if (!requireBridgeKey(req, res)) return;
    const host = String(req.body?.host || "").trim();
    const port = Number(req.body?.port || 25565);
    const username = String(req.body?.username || "");
    const validation = validateTarget(host, port);
    if (validation) return res.status(400).json({ ok: false, error: validation });
    const dnsError = await publicDnsError(host);
    if (dnsError) return res.status(400).json({ ok: false, error: dnsError });
    if (!/^[A-Za-z0-9_]{3,16}$/.test(username)) {
        return res.status(400).json({ ok: false, error: "El nombre debe tener 3-16 letras, números o _" });
    }
    const activeCount = [...sessions.values()].filter(s => !s.closed && !["error", "disconnected"].includes(s.state)).length;
    if (activeCount >= MAX_ACTIVE_SESSIONS) {
        return res.status(429).json({ ok: false, error: "El puente está ocupado; hay demasiadas conexiones activas" });
    }

    const sessionId = crypto.randomUUID();
    const session = {
        id: sessionId,
        host,
        port,
        username,
        state: "connecting",
        error: null,
        queue: [],
        waiters: new Set(),
        packetCounts: {},
        packetsSeen: 0,
        mapChunks: 0,
        chunkKeys: new Set(),
        dimension: 0,
        gameMode: 0,
        positionSeen: false,
        playerX: 0,
        playerY: 0,
        playerZ: 0,
        loginPacketSeen: false,
        joined: false,
        verificationRequired: false,
        verificationSource: null,
        closed: false,
        createdAt: Date.now(),
        lastActivity: Date.now(),
        client: null,
        lastSendAt: 0,
        lastChatAt: 0,
        sendCount: 0
    };
    sessions.set(sessionId, session);

    try {
        console.log(`[BRIDGE] ${username} -> ${host}:${port} (Java 1.8.8, offline auth)`);
        const client = mc.createClient({
            host,
            port,
            username,
            auth: "offline",
            version: "1.8.8",
            hideErrors: true
        });
        session.client = client;

        client.on("connect", () => {
            session.state = "tcp_connected";
            pushBridgeEvent(session, { type: "tcp_connected" });
            console.log(`[BRIDGE] TCP connected: ${session.username} @ ${session.host}`);
        });

        client.on("packet", (packet, meta) => onMinecraftPacket(session, packet, meta));

        client.on("playerJoin", () => {
            markSessionJoined(session, "playerJoin event");
        });

        client.on("state", (newState, oldState) => {
            session.protocolState = String(newState || "");
            pushBridgeEvent(session, { type: "protocol_state", state: session.protocolState, previous: String(oldState || "") });
        });

        client.on("error", error => {
            session.error = session.verificationRequired
                ? "El servidor requiere verificar la conexión antes de entrar."
                : String(error?.message || error || "Error de conexión").slice(0, 500);
            session.state = "error";
            pushBridgeEvent(session, { type: "error", message: session.error });
            console.warn(`[BRIDGE ERROR] ${session.username} @ ${host}: ${session.error}`);
        });

        client.on("end", reason => {
            const endReason = cleanReason(reason);
            if (isVerificationNotice(endReason)) {
                markVerificationRequired(session, "end_reason");
            }
            if (!session.closed && session.state !== "error") {
                session.state = "disconnected";
                session.error = session.verificationRequired
                    ? "El servidor cerró la conexión después de solicitar una verificación."
                    : (endReason || "El servidor cerró la conexión");
            }
            const safeReason = session.verificationRequired
                ? "El servidor cerró la conexión después de solicitar una verificación."
                : (session.error || endReason);
            pushBridgeEvent(session, { type: "end", reason: safeReason });
            console.log(`[BRIDGE] End: ${session.username} @ ${host}`);
        });

        return res.json({ ok: true, sessionId, username, version: "1.8.8", auth: "offline" });
    } catch (error) {
        session.closed = true;
        sessions.delete(sessionId);
        console.error("[BRIDGE START ERROR]", error);
        return res.status(502).json({ ok: false, error: String(error?.message || error).slice(0, 300) });
    }
});

app.post("/bridge/poll", async (req, res) => {
    if (!requireBridgeKey(req, res)) return;
    const session = getSession(req.body?.sessionId);
    if (!session) return res.status(404).json({ ok: false, error: "Sesión no encontrada" });
    session.lastActivity = Date.now();
    const waitMs = Math.max(0, Math.min(1200, Number(req.body?.waitMs) || 0));
    await waitForBridgeEvents(session, waitMs);
    const events = [];
    let chunksInResponse = 0;
    while (session.queue.length && events.length < 12) {
        const next = session.queue[0];
        if (next.type === "chunk_data" && chunksInResponse >= 2) break;
        events.push(session.queue.shift());
        if (next.type === "chunk_data") chunksInResponse++;
    }
    return res.json({
        ok: true,
        state: session.state,
        joined: session.joined,
        verificationRequired: session.verificationRequired === true,
        error: session.error,
        username: session.username,
        version: "1.8.8",
        packetsSeen: session.packetsSeen,
        mapChunks: session.mapChunks,
        protocolState: session.protocolState || "",
        packetCounts: session.packetCounts,
        events
    });
});

// Send only explicitly supported Minecraft 1.8.8 clientbound actions.
// Arbitrary packet names/payloads are never accepted from Roblox.
function finiteNumber(value) {
    return typeof value === "number" && Number.isFinite(value);
}

function validPosition(payload) {
    return finiteNumber(payload.x) && finiteNumber(payload.y) && finiteNumber(payload.z) &&
        Math.abs(payload.x) <= 30_000_000 && Math.abs(payload.z) <= 30_000_000 &&
        payload.y >= -2048 && payload.y <= 4096;
}

function validRotation(payload) {
    return finiteNumber(payload.yaw) && finiteNumber(payload.pitch) &&
        Math.abs(payload.yaw) <= 360_000 && payload.pitch >= -90 && payload.pitch <= 90;
}

app.post("/bridge/send", (req, res) => {
    if (!requireBridgeKey(req, res)) return;
    const session = getSession(req.body?.sessionId);
    if (!session || session.closed || !session.client) {
        return res.status(404).json({ ok: false, error: "Sesión no activa" });
    }
    if (!session.joined) {
        return res.status(409).json({ ok: false, error: "Todavía no has entrado al mundo" });
    }

    const action = String(req.body?.action || "");
    const payload = req.body?.payload && typeof req.body.payload === "object" ? req.body.payload : req.body;
    const now = Date.now();
    const minGap = action === "chat" ? 500 : 45;
    const previous = action === "chat" ? session.lastChatAt : session.lastSendAt;
    if (now - previous < minGap) {
        return res.status(429).json({ ok: false, throttled: true, error: "Acciones demasiado rápidas" });
    }

    try {
        switch (action) {
            case "chat": {
                const text = String(payload.text || "").trim();
                if (!text || text.length > 200) {
                    return res.status(400).json({ ok: false, error: "El mensaje debe tener entre 1 y 200 caracteres" });
                }
                session.client.chat(text);
                session.lastChatAt = now;
                break;
            }
            case "position": {
                if (!validPosition(payload)) {
                    return res.status(400).json({ ok: false, error: "Coordenadas inválidas" });
                }
                session.client.write("position", {
                    x: payload.x, y: payload.y, z: payload.z,
                    onGround: payload.onGround === true
                });
                session.lastSendAt = now;
                break;
            }
            case "look": {
                if (!validRotation(payload)) {
                    return res.status(400).json({ ok: false, error: "Rotación inválida" });
                }
                session.client.write("look", {
                    yaw: payload.yaw, pitch: payload.pitch,
                    onGround: payload.onGround === true
                });
                session.lastSendAt = now;
                break;
            }
            case "position_look": {
                if (!validPosition(payload) || !validRotation(payload)) {
                    return res.status(400).json({ ok: false, error: "Posición o rotación inválida" });
                }
                session.client.write("position_look", {
                    x: payload.x, y: payload.y, z: payload.z,
                    yaw: payload.yaw, pitch: payload.pitch,
                    onGround: payload.onGround === true
                });
                session.lastSendAt = now;
                break;
            }
            case "ground": {
                session.client.write("flying", { onGround: payload.onGround === true });
                session.lastSendAt = now;
                break;
            }
            case "swing": {
                session.client.write("arm_animation", {});
                session.lastSendAt = now;
                break;
            }
            default:
                return res.status(400).json({ ok: false, error: "Acción no permitida" });
        }

        session.lastActivity = now;
        session.sendCount++;
        return res.json({ ok: true, action, sendCount: session.sendCount });
    } catch (error) {
        const message = String(error?.message || error).slice(0, 300);
        session.error = message;
        console.warn(`[BRIDGE SEND ERROR] ${session.username} @ ${session.host}: ${message}`);
        return res.status(502).json({ ok: false, error: message });
    }
});

// Backwards-compatible endpoint for the earlier JTNBridgeChat RemoteFunction.
app.post("/bridge/chat", (req, res) => {
    if (!requireBridgeKey(req, res)) return;
    const session = getSession(req.body?.sessionId);
    if (!session || session.closed || !session.client) {
        return res.status(404).json({ ok: false, error: "Sesión no activa" });
    }
    if (!session.joined) {
        return res.status(409).json({ ok: false, error: "Todavía no has entrado al mundo" });
    }
    const text = String(req.body?.text || "").trim();
    if (!text || text.length > 200) {
        return res.status(400).json({ ok: false, error: "El mensaje debe tener entre 1 y 200 caracteres" });
    }
    const now = Date.now();
    if (now - session.lastChatAt < 500) {
        return res.status(429).json({ ok: false, throttled: true, error: "Mensajes demasiado rápidos" });
    }
    try {
        session.client.chat(text);
        session.lastChatAt = now;
        session.lastActivity = now;
        session.sendCount++;
        return res.json({ ok: true, action: "chat", sendCount: session.sendCount });
    } catch (error) {
        return res.status(502).json({ ok: false, error: String(error?.message || error).slice(0, 300) });
    }
});

app.post("/bridge/disconnect", (req, res) => {
    if (!requireBridgeKey(req, res)) return;
    const session = getSession(req.body?.sessionId);
    if (!session) return res.json({ ok: true, alreadyClosed: true });
    session.closed = true;
    session.state = "disconnected";
    try { session.client?.end("JTN MC disconnect"); } catch {}
    pushBridgeEvent(session, { type: "closed_by_client" });
    sessions.delete(session.id);
    return res.json({ ok: true });
});

setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions) {
        const expired = now - session.lastActivity > SESSION_IDLE_TTL_MS || now - session.createdAt > SESSION_MAX_AGE_MS;
        if (expired) {
            session.closed = true;
            try { session.client?.end("JTN bridge session expired"); } catch {}
            for (const wake of [...session.waiters]) wake();
            sessions.delete(id);
            console.log(`[BRIDGE] Expired session: ${session.username} @ ${session.host}`);
        }
    }
}, 60_000).unref();

app.get("/health", (_req, res) => res.json({ ok: true, service: "JTN Minecraft Relay", bridgeVersion: 1 }));

app.listen(PORT, "0.0.0.0", () => console.log("JTN RELAY + MINECRAFT BRIDGE UP — PORT:", PORT));
