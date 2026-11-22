const mc      = require("minecraft-protocol");
const express = require("express");
const { PNG } = require("pngjs");
const crypto  = require("node:crypto");
const net     = require("node:net");
const dns     = require("node:dns").promises;

const app  = express();
const PORT = Number(process.env.PORT || 3000);
app.use(express.json({ limit: "512kb" }));

// ─────────────────────────────────────────────────────────────────────────────
// Chat component parser
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
// Network / DNS helpers
// ─────────────────────────────────────────────────────────────────────────────
function isPrivateIPv4(host) {
    const parts = host.split(".").map(Number);
    if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    const [a, b] = parts;
    return a === 0 || a === 10 || a === 127 ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 100 && b >= 64 && b <= 127) ||
        a >= 224;
}

function isPrivateAddress(address) {
    const family = net.isIP(address);
    if (family === 4) return isPrivateIPv4(address);
    if (family === 6) {
        const v = address.toLowerCase();
        if (v === "::" || v === "::1" || v.startsWith("fc") || v.startsWith("fd") ||
            v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb")) return true;
        const mapped = v.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
        return mapped ? isPrivateIPv4(mapped[1]) : false;
    }
    return true;
}

async function publicDnsError(host) {
    try {
        const records = await dns.lookup(host, { all: true, verbatim: true });
        if (!records.length || records.some(r => isPrivateAddress(r.address)))
            return "el dominio no apunta exclusivamente a direcciones públicas";
        return null;
    } catch { return "no se pudo resolver el dominio"; }
}

function validateTarget(host, port) {
    if (typeof host !== "string") return "host inválido";
    host = host.trim();
    if (!host || host.length > 253 || !/^[a-zA-Z0-9.\-]+$/.test(host)) return "host inválido";
    const lower = host.toLowerCase();
    if (lower === "localhost" || lower.endsWith(".localhost") || lower.endsWith(".local"))
        return "solo se permiten hosts públicos";
    const ipType = net.isIP(host);
    if (ipType === 4 && isPrivateIPv4(host)) return "solo se permiten hosts públicos";
    if (ipType === 6) return "usa un nombre DNS o una IPv4 pública";
    if (!Number.isInteger(port) || port < 1 || port > 65535) return "puerto inválido";
    return null;
}

function statusError(error) {
    const message = String(error?.message || error || "Unknown error");
    const code = String(error?.code ||
        (message.match(/\b(ETIMEDOUT|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ECONNRESET|EHOSTUNREACH)\b/)?.[1]) ||
        "PING_FAILED");
    return { code, message: message.slice(0, 220) };
}

// ─────────────────────────────────────────────────────────────────────────────
// SRV lookup
// ─────────────────────────────────────────────────────────────────────────────
async function resolveSrvTargets(host, port) {
    const candidates = [];
    const seen = new Set();
    const add = (h, p, route) => {
        const key = `${h.toLowerCase()}:${p}`;
        if (!seen.has(key)) { seen.add(key); candidates.push({ host: h, port: p, route }); }
    };

    const isHostname = net.isIP(host) === 0;

    if (isHostname) {
        const srvNames = [`_minecraft._tcp.${host}`, `_minecraft._tcp.${host.replace(/\.$/, "")}`];
        for (const srvName of srvNames) {
            try {
                const records = await dns.resolveSrv(srvName);
                const ordered = [...records].sort((a, b) => a.priority - b.priority || b.weight - a.weight);
                for (const record of ordered.slice(0, 3)) {
                    const target = String(record.name || "").replace(/\.$/, "");
                    const targetPort = Number(record.port);
                    if (!target || !Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) continue;
                    if (validateTarget(target, targetPort)) continue;
                    const dnsErr = await publicDnsError(target);
                    if (!dnsErr) add(target, targetPort, "srv");
                }
                if (candidates.length) break;
            } catch (e) {
                if (!["ENODATA", "ENOTFOUND", "ESERVFAIL", "EREFUSED"].includes(e?.code)) {
                    console.warn(`[SRV] ${host}: ${e?.code || e?.message}`);
                }
            }
        }
    }

    add(host, port, "direct");

    if (isHostname && port !== 25565 && candidates.length < 3) {
        add(host, 25565, "direct-25565");
    }

    return candidates;
}

async function pingServer(host, port) {
    const candidates = await resolveSrvTargets(host, port);
    const failures = [];

    for (const candidate of candidates) {
        try {
            const result = await mc.ping({
                host: candidate.host,
                port: candidate.port,
                version: "1.8.8",
                closeTimeout: 10000,
                noPongTimeout: 4000,
            });
            result.jtnRoute  = candidate.route;
            result.jtnTarget = `${candidate.host}:${candidate.port}`;
            console.log(`[PING OK] ${host}:${port} via ${candidate.route} -> ${candidate.host}:${candidate.port}`);
            return result;
        } catch (error) {
            const detail = statusError(error);
            failures.push({ ...candidate, ...detail });
            console.warn(`[PING FAIL] ${candidate.route} ${candidate.host}:${candidate.port} ${detail.code}`);
        }
    }

    const last    = failures[failures.length - 1] || { code: "PING_FAILED", message: "Sin respuesta" };
    const combined = new Error(failures.map(f => `${f.route} ${f.host}:${f.port} ${f.code}`).join("; ").slice(0, 500));
    combined.code     = last.code;
    combined.attempts = failures;
    throw combined;
}

// ─────────────────────────────────────────────────────────────────────────────
// Favicon
// ─────────────────────────────────────────────────────────────────────────────
function faviconToHex(favicon, size = 32) {
    if (typeof favicon !== "string") throw new Error("El servidor no tiene favicon");
    const match = /^data:image\/png;base64,(.+)$/i.exec(favicon);
    if (!match) throw new Error("Favicon PNG inválido");
    const png = PNG.sync.read(Buffer.from(match[1], "base64"));
    if (!png.width || !png.height || png.width > 256 || png.height > 256)
        throw new Error("Dimensiones de favicon inválidas");
    const pixels = [];
    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            const sx = Math.min(png.width  - 1, Math.floor((x + 0.5) * png.width  / size));
            const sy = Math.min(png.height - 1, Math.floor((y + 0.5) * png.height / size));
            const i  = (sy * png.width + sx) * 4;
            const alpha = png.data[i + 3] / 255;
            const rgb = [0, 1, 2].map(c => Math.round(png.data[i + c] * alpha + 18 * (1 - alpha)));
            pixels.push(rgb.map(v => v.toString(16).padStart(2, "0")).join("").toUpperCase());
        }
    }
    return pixels;
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth key
// ─────────────────────────────────────────────────────────────────────────────
function requireBridgeKey(req, res) {
    const configured = String(process.env.JTN_BRIDGE_KEY || "");
    const supplied   = String(req.body?.key || "");
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

// ─────────────────────────────────────────────────────────────────────────────
// Ping / logo endpoints
// ─────────────────────────────────────────────────────────────────────────────
app.get("/ping", async (req, res) => {
    const host = String(req.query.host || "").trim();
    const port = Number.parseInt(req.query.port, 10) || 25565;
    const validation = validateTarget(host, port);
    if (validation) return res.status(400).json({ error: validation });
    const dnsError = await publicDnsError(host);
    if (dnsError) return res.status(400).json({ error: dnsError });
    try {
        const result = await pingServer(host, port);
        let pixels = null;
        if (result.favicon) {
            try { pixels = faviconToHex(result.favicon, 32); }
            catch (e) { console.warn("[FAVICON]", host, e.message); }
        }
        res.json({
            ok: true, status: "online",
            motd:    chatComponentToText(result.description),
            online:  result.players?.online ?? 0,
            max:     result.players?.max    ?? 0,
            version: result.version?.name  ?? "?",
            favicon: result.favicon        ?? null,
            pixels,
            latency: result.latency        ?? 0,
            route:   result.jtnRoute       || "direct",
            target:  result.jtnTarget      || `${host}:${port}`
        });
    } catch (error) {
        const detail = statusError(error);
        res.status(502).json({
            ok: false, status: "unreachable",
            error: detail.message || "No se pudo consultar el servidor",
            errorCode: detail.code,
            attempts: Array.isArray(error?.attempts) ? error.attempts : []
        });
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
        res.status(502).json({ error: "No se pudo obtener el logo" });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Entity helpers
// ─────────────────────────────────────────────────────────────────────────────
const MAX_ENTITIES = 150;

// 1.8.8 fixed-point: absolute coords are int32 / 32
function fixedToFloat(v) { return Number(v) / 32; }
// angle byte: 0-255 → 0-360
function angleToYaw(v) { return (Number(v) / 256) * 360; }

const MOB_NAMES = {
    50: "Creeper", 51: "Skeleton", 52: "Spider", 54: "Zombie",
    55: "Slime", 56: "Ghast", 57: "ZombiePigman", 58: "Enderman",
    59: "CaveSpider", 60: "Silverfish", 61: "Blaze", 62: "MagmaCube",
    65: "Bat", 66: "Witch", 67: "Endermite", 68: "Guardian",
    69: "ElderGuardian",
    90: "Pig", 91: "Sheep", 92: "Cow", 93: "Chicken", 94: "Squid",
    95: "Wolf", 96: "Mooshroom", 97: "SnowGolem", 98: "Ocelot",
    99: "IronGolem", 100: "Horse", 101: "Rabbit", 120: "Villager",
};

// ─────────────────────────────────────────────────────────────────────────────
// BRIDGE — sessions
// ─────────────────────────────────────────────────────────────────────────────
const sessions          = new Map();
const MAX_ACTIVE        = 8;
const MAX_QUEUE         = 256;
const IDLE_TTL_MS       = 5 * 60 * 1000;
const MAX_AGE_MS        = 60 * 60 * 1000;
const MAX_CHUNKS_TOTAL  = 225;
const MAX_CHUNKS_RADIUS = 7;

function pushEvent(session, event) {
    if (!session || session.closed) return;
    session.lastActivity = Date.now();
    session.queue.push({ at: Date.now(), ...event });
    if (session.queue.length > MAX_QUEUE) session.queue.splice(0, session.queue.length - MAX_QUEUE);
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

function isVerificationNotice(text) {
    return /necesitamos\s+verificar\s+tu\s+conexi[oó]n|verifica(?:r|ci[oó]n).{0,100}(?:conexi[oó]n|navegador)|completa\s+el\s+proceso|complete\s+the\s+verification|verify\s+your\s+connection|anti.?bots?/i.test(String(text || ""));
}

function markVerificationRequired(session, source) {
    if (!session || session.verificationRequired) return;
    session.verificationRequired = true;
    session.state = "verification_required";
    pushEvent(session, {
        type: "verification_required",
        message: "El servidor solicitó verificación. JTN MC no automatiza enlaces externos."
    });
    console.warn(`[BRIDGE] Verification required: ${session.username} @ ${session.host}`);
}

function popcount16(v) {
    let c = 0; v = Number(v) & 0xffff;
    while (v) { v &= v - 1; c++; }
    return c;
}

function makeChunkPayload(session, x, z, bitMap, chunkData, groundUp, skyLightSent) {
    const cx   = Number(x);
    const cz   = Number(z);
    const mask = Number(bitMap) & 0xffff;
    if (!Number.isInteger(cx) || !Number.isInteger(cz)) throw new Error("Coordenadas inválidas");
    if (!Buffer.isBuffer(chunkData)) chunkData = Buffer.from(chunkData || []);

    const sectionCount = popcount16(mask);
    // Minecraft 1.8.x serializes each section as one contiguous record:
    // Blocks (8192), BlockLight (2048), then SkyLight (2048 in dimensions
    // with sky). The old decoder incorrectly treated these as three global
    // arrays, so section 1+ read lighting bytes as block IDs after respawn.
    const sectionBytes = 8192 + 2048 + (skyLightSent ? 2048 : 0);
    const biomeOffset = sectionCount * sectionBytes;
    const required = biomeOffset + (groundUp ? 256 : 0);
    if (chunkData.length < required)
        throw new Error(`Chunk truncado: ${chunkData.length} < ${required}`);

    if (session.positionSeen) {
        const pcx = Math.floor(session.playerX / 16);
        const pcz = Math.floor(session.playerZ / 16);
        if (Math.max(Math.abs(cx - pcx), Math.abs(cz - pcz)) > MAX_CHUNKS_RADIUS) return null;
    }

    const key = `${cx},${cz}`;
    if (!session.chunkKeys.has(key)) {
        if (session.chunkKeys.size >= MAX_CHUNKS_TOTAL) return null;
        session.chunkKeys.add(key);
    }

    const sections = [];
    let offset = 0;
    for (let sy = 0; sy < 16; sy++) {
        if ((mask & (1 << sy)) === 0) continue;

        const bStart = offset;
        offset += 8192;
        const blStart = offset;
        offset += 2048;
        const slStart = skyLightSent ? offset : null;
        if (skyLightSent) offset += 2048;

        sections.push({
            y: sy,
            blocksBase64: chunkData.subarray(bStart, bStart + 8192).toString("base64"),
            blockLightBase64: chunkData.subarray(blStart, blStart + 2048).toString("base64"),
            skyLightBase64: skyLightSent
                ? chunkData.subarray(slStart, slStart + 2048).toString("base64")
                : null
        });
    }

    return {
        cx, cz,
        packetFormatVersion: 3,
        reset:    groundUp === true,
        sections,
        biomes:   groundUp ? Array.from(chunkData.subarray(biomeOffset, biomeOffset + 256)) : null
    };
}

function handleMapChunk(session, packet) {
    const skyLightSent = typeof packet.skyLightSent === "boolean" ? packet.skyLightSent : session.dimension === 0;
    try {
        const chunk = makeChunkPayload(session, packet.x ?? packet.chunkX, packet.z ?? packet.chunkZ,
            packet.bitMap, packet.chunkData, packet.groundUp === true, skyLightSent);
        if (chunk) {
            session.mapChunks++;
            pushEvent(session, { type: "chunk_data", chunk });
        }
    } catch (e) {
        console.warn(`[CHUNK] ${session.host}: ${e.message}`);
        pushEvent(session, { type: "chunk_decode_error", x: Number(packet.x) || 0, z: Number(packet.z) || 0, message: e.message.slice(0, 200) });
    }
}

function handleMapChunkBulk(session, packet) {
    const data = Buffer.isBuffer(packet.data) ? packet.data : Buffer.from(packet.data || []);
    const skyLightSent = packet.skyLightSent === true;
    let offset = 0;
    for (const entry of (Array.isArray(packet.meta) ? packet.meta : [])) {
        const mask    = Number(entry.bitMap) & 0xffff;
        const sc      = popcount16(mask);
        const length  = sc * (8192 + 2048 + (skyLightSent ? 2048 : 0)) + 256;
        if (offset + length > data.length) break;
        try {
            const chunk = makeChunkPayload(session, entry.x, entry.z, mask,
                data.subarray(offset, offset + length), true, skyLightSent);
            if (chunk) { session.mapChunks++; pushEvent(session, { type: "chunk_data", chunk }); }
        } catch (e) {
            pushEvent(session, { type: "chunk_decode_error", x: Number(entry.x) || 0, z: Number(entry.z) || 0, message: e.message.slice(0, 200) });
        }
        offset += length;
    }
}

function markSessionJoined(session, source) {
    const was = session.joined === true;
    session.joined = true;
    session.verificationRequired = false;
    session.state = "joined";
    if (was) return;
    pushEvent(session, { type: "player_join", username: session.username });
    console.log(`[BRIDGE] LOGIN OK (${source}): ${session.username} @ ${session.host}`);
}

function onPacket(session, packet, meta) {
    const name = meta && meta.name;
    if (!name) return;
    session.packetCounts[name] = (session.packetCounts[name] || 0) + 1;
    session.packetsSeen++;

    switch (name) {
        case "login":
            session.loginPacketSeen = true;
            session.verificationRequired = false;
            session.state   = session.joined ? "joined" : "login_accepted";
            session.dimension = Number(packet.dimension) || 0;
            session.gameMode  = Number(packet.gameMode)  || 0;
            pushEvent(session, {
                type: "login",
                entityId:  Number(packet.entityId)  || 0,
                gameMode:  Number(packet.gameMode)   || 0,
                dimension: Number(packet.dimension)  || 0,
                difficulty: Number(packet.difficulty) || 0,
                levelType: String(packet.levelType || "")
            });
            break;

        case "position": {
            const pos = {
                x: Number(packet.x) || 0, y: Number(packet.y) || 0, z: Number(packet.z) || 0,
                yaw: Number(packet.yaw) || 0, pitch: Number(packet.pitch) || 0,
                flags: Number(packet.flags) || 0
            };
            session.playerX = pos.x; session.playerY = pos.y; session.playerZ = pos.z;
            session.positionSeen = true;
            session.awaitingSpawnPosition = false;
            if (session.loginPacketSeen) markSessionJoined(session, "initial position");

            if (session.client && !session.closed) {
                try {
                    session.client.write("position_look", {
                        x: pos.x, y: pos.y, z: pos.z,
                        yaw: pos.yaw, pitch: pos.pitch,
                        onGround: true
                    });
                } catch (e) { /* ignorar */ }
            }

            pushEvent(session, { type: "position", ...pos });
            break;
        }

        case "spawn_position": {
            const loc = packet.location || {};
            pushEvent(session, { type: "spawn_position",
                x: Number(loc.x) || 0, y: Number(loc.y) || 0, z: Number(loc.z) || 0 });
            break;
        }

        case "map_chunk":      handleMapChunk(session, packet);     break;
        case "map_chunk_bulk": handleMapChunkBulk(session, packet); break;

        case "block_change": {
            const loc = packet.location || {};
            const state = Number(packet.type) || 0;
            pushEvent(session, { type: "block_change",
                x: Number(loc.x) || 0, y: Number(loc.y) || 0, z: Number(loc.z) || 0,
                id: state >>> 4, meta: state & 15 });
            break;
        }

        case "multi_block_change": {
            const cx = Number(packet.chunkX) || 0;
            const cz = Number(packet.chunkZ) || 0;
            const blocks = [];
            for (const r of (Array.isArray(packet.records) ? packet.records : [])) {
                const h = Number(r.horizontalPos) & 255;
                const s = Number(r.blockId) || 0;
                blocks.push([cx * 16 + ((h >>> 4) & 15), Number(r.y) & 255, cz * 16 + (h & 15), s >>> 4, s & 15]);
            }
            if (blocks.length) pushEvent(session, { type: "multi_block_change", blocks });
            break;
        }

        case "unload_chunk": {
            const cx = Number(packet.chunkX ?? packet.x) || 0;
            const cz = Number(packet.chunkZ ?? packet.z) || 0;
            session.chunkKeys.delete(`${cx},${cz}`);
            pushEvent(session, { type: "chunk_unload", x: cx, z: cz });
            break;
        }

        case "chat": {
            const text = chatPacketToText(packet).slice(0, 500);
            if (isVerificationNotice(text)) markVerificationRequired(session, "server_chat");
            else pushEvent(session, { type: "chat", text });
            break;
        }

        case "update_health": {
            const hpRaw = packet.health ?? packet.hp ?? packet.healthValue;
            const foodRaw = packet.food ?? packet.foodLevel ?? packet.foods;
            const satRaw = packet.foodSaturation ?? packet.saturation ?? packet.foodSaturationLevel;
            const hp = Number(hpRaw);
            const food = Number(foodRaw);
            const sat = Number(satRaw);
            const health = Number.isFinite(hp) ? hp : 20;
            const foodVal = Number.isFinite(food) ? food : 0;
            const satVal = Number.isFinite(sat) ? sat : 0;
            const wasDead = session.dead === true;
            // A positive health packet alone must not unlock a player who has died.
            // In 1.8.8, the clientbound Respawn packet is the authoritative transition.
            if (!wasDead && health <= 0) session.dead = true;
            session.lastHealth = health;
            session.lastFood = foodVal;
            // Always push health; the transition revision preserves death/respawn ordering.
            if (session.dead !== wasDead) session.healthRevision = (session.healthRevision || 0) + 1;
            pushEvent(session, {
                type: "health",
                health,
                food: foodVal,
                saturation: satVal,
                dead: session.dead === true,
                revision: session.healthRevision || 0,
            });
            if (session.dead && !wasDead) {
                console.log(`[HEALTH] DEATH ${session.username} hp=${health} rev=${session.healthRevision}`);
                pushEvent(session, {
                    type: "death",
                    health: 0,
                    food: foodVal,
                    saturation: satVal,
                    dead: true,
                    revision: session.healthRevision || 0,
                });
            }
            break;
        }

        case "respawn":
            session.dimension = Number(packet.dimension) || 0;
            session.gameMode  = Number(packet.gamemode)  || 0;
            session.positionSeen = false;
            session.awaitingSpawnPosition = true;
            session.chunkKeys.clear();
            session.entities.clear();
            // A long-poll queue may still contain pre-death coordinates/chunks.
            // Drop them so they cannot be mistaken for the new spawn handoff.
            const staleWorldEvents = new Set([
                "position", "spawn_position", "chunk_data", "chunk_unload",
                "block_change", "entity_spawn", "entity_move", "entity_destroy",
            ]);
            session.queue = session.queue.filter(ev => !staleWorldEvents.has(ev.type));
            session.dead = false; // Only the server's respawn packet releases the death lock.
            session.lastRespawnAt = 0;
            session.healthRevision = (session.healthRevision || 0) + 1;
            pushEvent(session, {
                type: "respawn",
                dimension: session.dimension,
                gameMode: session.gameMode,
                levelType: String(packet.levelType || ""),
                health: session.lastHealth > 0 ? session.lastHealth : 20,
                dead: false,
                respawned: true,
                revision: session.healthRevision,
            });
            break;

        // ── ENTITIES ──────────────────────────────────────────────────────────

        case "named_entity_spawn": {
            if (session.entities.size >= MAX_ENTITIES) break;
            const eid  = Number(packet.entityId);
            const ex   = fixedToFloat(packet.x);
            const ey   = fixedToFloat(packet.y);
            const ez   = fixedToFloat(packet.z);
            const eyaw = angleToYaw(packet.yaw);
            const ename = String(packet.playerName || packet.name || "Player").slice(0, 32);
            session.entities.set(eid, { x: ex, y: ey, z: ez, yaw: eyaw, kind: "player", name: ename });
            pushEvent(session, { type: "entity_spawn", entityId: eid, kind: "player", name: ename, x: ex, y: ey, z: ez, yaw: eyaw });
            break;
        }

        case "spawn_mob": {
            if (session.entities.size >= MAX_ENTITIES) break;
            const eid     = Number(packet.entityId);
            const ex      = fixedToFloat(packet.x);
            const ey      = fixedToFloat(packet.y);
            const ez      = fixedToFloat(packet.z);
            const eyaw    = angleToYaw(packet.yaw);
            const mobType = Number(packet.type) || 0;
            const mobName = MOB_NAMES[mobType] || `Mob${mobType}`;
            session.entities.set(eid, { x: ex, y: ey, z: ez, yaw: eyaw, kind: "mob", mobType, name: mobName });
            pushEvent(session, { type: "entity_spawn", entityId: eid, kind: "mob", mobType, name: mobName, x: ex, y: ey, z: ez, yaw: eyaw });
            break;
        }

        case "rel_entity_move": {
            const eid = Number(packet.entityId);
            const e   = session.entities.get(eid);
            if (!e) break;
            e.x += fixedToFloat(packet.dX);
            e.y += fixedToFloat(packet.dY);
            e.z += fixedToFloat(packet.dZ);
            pushEvent(session, { type: "entity_move", entityId: eid, x: e.x, y: e.y, z: e.z, yaw: e.yaw });
            break;
        }

        case "entity_look": {
            const eid = Number(packet.entityId);
            const e   = session.entities.get(eid);
            if (!e) break;
            e.yaw = angleToYaw(packet.yaw);
            pushEvent(session, { type: "entity_move", entityId: eid, x: e.x, y: e.y, z: e.z, yaw: e.yaw });
            break;
        }

        case "entity_move_look": {
            const eid = Number(packet.entityId);
            const e   = session.entities.get(eid);
            if (!e) break;
            e.x  += fixedToFloat(packet.dX);
            e.y  += fixedToFloat(packet.dY);
            e.z  += fixedToFloat(packet.dZ);
            e.yaw = angleToYaw(packet.yaw);
            pushEvent(session, { type: "entity_move", entityId: eid, x: e.x, y: e.y, z: e.z, yaw: e.yaw });
            break;
        }

        case "entity_teleport": {
            const eid = Number(packet.entityId);
            const e   = session.entities.get(eid);
            if (!e) break;
            e.x   = fixedToFloat(packet.x);
            e.y   = fixedToFloat(packet.y);
            e.z   = fixedToFloat(packet.z);
            e.yaw = angleToYaw(packet.yaw);
            pushEvent(session, { type: "entity_move", entityId: eid, x: e.x, y: e.y, z: e.z, yaw: e.yaw });
            break;
        }

        case "entity_destroy": {
            const ids = Array.isArray(packet.entityIds) ? packet.entityIds.map(Number) : [];
            if (!ids.length) break;
            for (const eid of ids) session.entities.delete(eid);
            pushEvent(session, { type: "entity_destroy", entityIds: ids });
            break;
        }

        case "kick_disconnect":
        case "login_disconnect":
        case "disconnect": {
            const reason = cleanReason(packet.reason || packet.message || packet);
            if (isVerificationNotice(reason)) {
                markVerificationRequired(session, "disconnect_reason");
                session.error = "El servidor cerró la conexión después de solicitar una verificación.";
            } else {
                session.error = reason || "El servidor cerró la conexión";
            }
            session.state = "disconnected";
            pushEvent(session, { type: "disconnect", reason: session.error });
            break;
        }
    }
}

function waitForEvents(session, waitMs) {
    if (session.queue.length || session.closed || waitMs <= 0) return Promise.resolve();
    return new Promise(resolve => {
        let done = false;
        const finish = () => {
            if (done) return; done = true;
            clearTimeout(timer); session.waiters.delete(finish); resolve();
        };
        const timer = setTimeout(finish, waitMs);
        session.waiters.add(finish);
    });
}

function getSession(id) {
    if (typeof id !== "string" || id.length > 80) return null;
    return sessions.get(id) || null;
}

function startKeepAlive(session) {
    if (session._keepAlive) return;
    session._keepAlive = setInterval(() => {
        if (session.closed || !session.client || !session.joined
            || session.dead === true || session.awaitingSpawnPosition === true) return;
        const now = Date.now();
        if (now - session.lastSendAt > 8000) {
            try {
                session.client.write("position_look", {
                    x: session.playerX, y: session.playerY, z: session.playerZ,
                    yaw: 0, pitch: 0, onGround: true
                });
            } catch (e) { /* ignorar */ }
        }
    }, 5000).unref();
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge endpoints
// ─────────────────────────────────────────────────────────────────────────────
app.post("/bridge/connect", async (req, res) => {
    if (!requireBridgeKey(req, res)) return;

    const host     = String(req.body?.host     || "").trim();
    const port     = Number(req.body?.port     || 25565);
    const username = String(req.body?.username || "");

    const validation = validateTarget(host, port);
    if (validation) return res.status(400).json({ ok: false, error: validation });
    const dnsError = await publicDnsError(host);
    if (dnsError) return res.status(400).json({ ok: false, error: dnsError });
    if (!/^[A-Za-z0-9_]{3,16}$/.test(username))
        return res.status(400).json({ ok: false, error: "Nombre: 3-16 letras, números o _" });

    const active = [...sessions.values()].filter(s => !s.closed && !["error", "disconnected"].includes(s.state)).length;
    if (active >= MAX_ACTIVE)
        return res.status(429).json({ ok: false, error: "Demasiadas conexiones activas" });

    const sessionId = crypto.randomUUID();
    const session = {
        id: sessionId, host, port, username,
        state: "connecting", error: null,
        queue: [], waiters: new Set(),
        packetCounts: {}, packetsSeen: 0, mapChunks: 0,
        chunkKeys: new Set(),
        entities: new Map(),           // ← entity tracking
        dimension: 0, gameMode: 0,
        positionSeen: false,
        awaitingSpawnPosition: false,
        playerX: 0, playerY: 64, playerZ: 0,
        loginPacketSeen: false,
        joined: false,
        dead: false,
        lastHealth: 20,
        lastFood: 20,
        healthRevision: 0,
        lastRespawnAt: 0,
        verificationRequired: false, verificationSource: null,
        closed: false,
        createdAt: Date.now(), lastActivity: Date.now(),
        client: null, lastSendAt: 0, lastChatAt: 0, sendCount: 0,
        _keepAlive: null
    };
    sessions.set(sessionId, session);

    try {
        const candidates = await resolveSrvTargets(host, port);
        const target = candidates[0];

        console.log(`[BRIDGE] ${username} -> ${target.host}:${target.port} via ${target.route} (1.8.8 offline)`);

        const client = mc.createClient({
            host:       target.host,
            port:       target.port,
            username,
            auth:       "offline",
            version:    "1.8.8",
            hideErrors: true,
        });
        session.client = client;

        client.on("connect", () => {
            session.state = "tcp_connected";
            pushEvent(session, { type: "tcp_connected" });
            console.log(`[BRIDGE] TCP OK: ${username} @ ${target.host}:${target.port}`);
        });

        client.on("packet", (packet, meta) => onPacket(session, packet, meta));

        client.on("playerJoin", () => {
            markSessionJoined(session, "playerJoin");
            startKeepAlive(session);
        });

        client.on("state", (newState, oldState) => {
            session.protocolState = String(newState || "");
            pushEvent(session, { type: "protocol_state", state: session.protocolState, previous: String(oldState || "") });
        });

        client.on("error", error => {
            session.error = session.verificationRequired
                ? "El servidor requiere verificación antes de entrar."
                : String(error?.message || error || "Error de conexión").slice(0, 500);
            session.state = "error";
            pushEvent(session, { type: "error", message: session.error });
            console.warn(`[BRIDGE ERROR] ${username} @ ${target.host}: ${session.error}`);
        });

        client.on("end", reason => {
            const r = cleanReason(reason);
            if (isVerificationNotice(r)) markVerificationRequired(session, "end_reason");
            if (!session.closed && session.state !== "error") {
                session.state = "disconnected";
                session.error = session.verificationRequired
                    ? "El servidor cerró la conexión después de solicitar verificación."
                    : (r || "El servidor cerró la conexión");
            }
            pushEvent(session, { type: "end", reason: session.error || r });
            if (session._keepAlive) { clearInterval(session._keepAlive); session._keepAlive = null; }
            console.log(`[BRIDGE] End: ${username} @ ${target.host}`);
        });

        return res.json({ ok: true, sessionId, username, version: "1.8.8", auth: "offline",
            resolvedHost: target.host, resolvedPort: target.port, route: target.route });
    } catch (error) {
        session.closed = true;
        sessions.delete(sessionId);
        return res.status(502).json({ ok: false, error: String(error?.message || error).slice(0, 300) });
    }
});

// poll — deduplicates entity_move per entityId before sending
app.post("/bridge/poll", async (req, res) => {
    if (!requireBridgeKey(req, res)) return;
    const session = getSession(req.body?.sessionId);
    if (!session) return res.status(404).json({ ok: false, error: "Sesión no encontrada" });
    session.lastActivity = Date.now();
    const waitMs = Math.max(0, Math.min(1500, Number(req.body?.waitMs) || 0));
    await waitForEvents(session, waitMs);

    // Deduplicate entity_move: for the same entityId keep only the latest
    const latestMove = new Map();
    for (const ev of session.queue) {
        if (ev.type === "entity_move") latestMove.set(ev.entityId, ev);
    }

    // Pull critical events first so death/health never starve behind chunks
    const critical = [];
    const rest = [];
    for (const ev of session.queue) {
        if (ev && (ev.type === "health" || ev.type === "death" || ev.type === "respawn" || ev.type === "disconnect" || ev.type === "end")) {
            critical.push(ev);
        } else {
            rest.push(ev);
        }
    }
    session.queue = rest;

    const events = [...critical];
    let chunksInResponse = 0;
    while (session.queue.length && events.length < 40) {
        const next = session.queue[0];
        if (next.type === "chunk_data" && chunksInResponse >= 6) break;
        if (next.type === "entity_move" && latestMove.get(next.entityId) !== next) {
            session.queue.shift();
            continue;
        }
        events.push(session.queue.shift());
        if (next.type === "chunk_data") chunksInResponse++;
    }

    return res.json({
        ok: true, state: session.state,
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

function finiteNumber(v) { return typeof v === "number" && Number.isFinite(v); }
function validPos(p) {
    return finiteNumber(p.x) && finiteNumber(p.y) && finiteNumber(p.z) &&
        Math.abs(p.x) <= 30_000_000 && Math.abs(p.z) <= 30_000_000 &&
        p.y >= -2048 && p.y <= 4096;
}
function validRot(p) {
    return finiteNumber(p.yaw) && finiteNumber(p.pitch) &&
        Math.abs(p.yaw) <= 360_000 && p.pitch >= -90 && p.pitch <= 90;
}

app.post("/bridge/send", (req, res) => {
    if (!requireBridgeKey(req, res)) return;
    const session = getSession(req.body?.sessionId);
    if (!session || session.closed || !session.client)
        return res.status(404).json({ ok: false, error: "Sesión no activa" });
    if (!session.joined)
        return res.status(409).json({ ok: false, error: "Todavía no entraste al mundo" });

    const action  = String(req.body?.action || "");
    const payload = req.body?.payload && typeof req.body.payload === "object" ? req.body.payload : req.body;
    const now     = Date.now();

    // Do not accept client movement while the Java server reports zero health.
    // Chat and the respawn request remain available from the death screen.
    const movementActions = new Set(["position", "look", "position_look", "ground", "swing"]);
    if ((session.dead || session.awaitingSpawnPosition) && movementActions.has(action)) {
        return res.status(409).json({
            ok: false,
            dead: session.dead === true,
            awaitingSpawn: session.awaitingSpawnPosition === true,
            error: "Movimiento bloqueado hasta que el servidor confirme el nuevo spawn.",
        });
    }
    if (action === "respawn") {
        if (now - (session.lastRespawnAt || 0) < 1000) {
            return res.status(429).json({ ok: false, throttled: true, error: "Respawn ya solicitado; esperando al servidor." });
        }
        session.lastRespawnAt = now;
    }

    const minGap  = action === "chat" ? 500 : 25;
    const prev    = action === "chat" ? session.lastChatAt : session.lastSendAt;
    if (now - prev < minGap)
        return res.status(429).json({ ok: false, throttled: true, error: "Acciones muy rápidas" });

    try {
        switch (action) {
            case "chat": {
                const text = String(payload.text || "").trim();
                if (!text || text.length > 200)
                    return res.status(400).json({ ok: false, error: "Mensaje: 1-200 caracteres" });
                session.client.chat(text);
                session.lastChatAt = now;
                break;
            }
            case "position": {
                if (!validPos(payload))
                    return res.status(400).json({ ok: false, error: "Coordenadas inválidas" });
                session.client.write("position", {
                    x: payload.x, y: payload.y, z: payload.z,
                    onGround: payload.onGround === true
                });
                session.playerX = payload.x;
                session.playerY = payload.y;
                session.playerZ = payload.z;
                session.lastSendAt = now;
                break;
            }
            case "look": {
                if (!validRot(payload))
                    return res.status(400).json({ ok: false, error: "Rotación inválida" });
                session.client.write("look", {
                    yaw: payload.yaw, pitch: payload.pitch,
                    onGround: payload.onGround === true
                });
                session.lastSendAt = now;
                break;
            }
            case "position_look": {
                if (!validPos(payload) || !validRot(payload))
                    return res.status(400).json({ ok: false, error: "Posición o rotación inválida" });
                session.client.write("position_look", {
                    x: payload.x, y: payload.y, z: payload.z,
                    yaw: payload.yaw, pitch: payload.pitch,
                    onGround: payload.onGround === true
                });
                session.playerX = payload.x;
                session.playerY = payload.y;
                session.playerZ = payload.z;
                session.lastSendAt = now;
                break;
            }
            case "ground":
                session.client.write("flying", { onGround: payload.onGround === true });
                session.lastSendAt = now;
                break;
            case "swing":
                session.client.write("arm_animation", {});
                session.lastSendAt = now;
                break;
            case "respawn":
                // 1.8.8 client_command payload 0 = "perform respawn"
                session.client.write("client_command", { payload: 0 });
                session.lastSendAt = now;
                break;
            default:
                return res.status(400).json({ ok: false, error: "Acción no permitida" });
        }
        session.lastActivity = now;
        session.sendCount++;
        return res.json({
            ok: true,
            action,
            sendCount: session.sendCount,
            ...(action === "respawn" ? { pending: true, serverConfirmed: false } : {}),
        });
    } catch (error) {
        const message = String(error?.message || error).slice(0, 300);
        session.error = message;
        return res.status(502).json({ ok: false, error: message });
    }
});

app.post("/bridge/chat", (req, res) => {
    if (!requireBridgeKey(req, res)) return;
    const session = getSession(req.body?.sessionId);
    if (!session || session.closed || !session.client)
        return res.status(404).json({ ok: false, error: "Sesión no activa" });
    if (!session.joined)
        return res.status(409).json({ ok: false, error: "Todavía no entraste al mundo" });
    const text = String(req.body?.text || "").trim();
    if (!text || text.length > 200)
        return res.status(400).json({ ok: false, error: "Mensaje: 1-200 caracteres" });
    const now = Date.now();
    if (now - session.lastChatAt < 500)
        return res.status(429).json({ ok: false, throttled: true, error: "Mensajes muy rápidos" });
    try {
        session.client.chat(text);
        session.lastChatAt = now; session.lastActivity = now; session.sendCount++;
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
    session.state  = "disconnected";
    if (session._keepAlive) { clearInterval(session._keepAlive); session._keepAlive = null; }
    try { session.client?.end("JTN MC disconnect"); } catch {}
    pushEvent(session, { type: "closed_by_client" });
    sessions.delete(session.id);
    return res.json({ ok: true });
});

setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions) {
        if (now - session.lastActivity > IDLE_TTL_MS || now - session.createdAt > MAX_AGE_MS) {
            session.closed = true;
            if (session._keepAlive) { clearInterval(session._keepAlive); session._keepAlive = null; }
            try { session.client?.end("JTN bridge expired"); } catch {}
            for (const wake of [...session.waiters]) wake();
            sessions.delete(id);
            console.log(`[BRIDGE] Expired: ${session.username} @ ${session.host}`);
        }
    }
}, 60_000).unref();

app.get("/health", (_req, res) => res.json({ ok: true, service: "JTN Minecraft Relay", bridgeVersion: 3 }));

app.listen(PORT, "0.0.0.0", () => console.log("JTN RELAY v3 + BRIDGE (entities+chat) — PORT:", PORT));