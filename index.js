
const mc = require("minecraft-protocol");
const express = require("express");
const { PNG } = require("pngjs");

const app = express();

const PORT = process.env.PORT || 3000;

// Consulta Minecraft
async function pingServer(host, port) {
    return await mc.ping({
        host,
        port,
        version: false,
        closeTimeout: 5000
    });
}

// Convierte favicon PNG a píxeles RGB hexadecimales
function faviconToHex(favicon, size = 32) {
    if (!favicon) {
        throw new Error("El servidor no tiene favicon");
    }

    const match = /^data:image\/png;base64,(.+)$/i.exec(favicon);

    if (!match) {
        throw new Error("Favicon PNG inválido");
    }

    const buffer = Buffer.from(match[1], "base64");
    const png = PNG.sync.read(buffer);

    if (
        png.width < 1 || png.height < 1 ||
        png.width > 256 || png.height > 256
    ) {
        throw new Error("Dimensiones de imagen inválidas");
    }

    const pixels = [];

    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            const sx = Math.min(
                png.width - 1,
                Math.floor((x + 0.5) * png.width / size)
            );

            const sy = Math.min(
                png.height - 1,
                Math.floor((y + 0.5) * png.height / size)
            );

            const i = (sy * png.width + sx) * 4;
            const alpha = png.data[i + 3] / 255;

            const rgb = [0, 1, 2].map(channel => {
                return Math.round(
                    png.data[i + channel] * alpha +
                    18 * (1 - alpha)
                );
            });

            const hex = rgb
                .map(value => value.toString(16).padStart(2, "0"))
                .join("")
                .toUpperCase();

            pixels.push(hex);
        }
    }

    return pixels;
}

// Endpoint PING
app.get("/ping", async (req, res) => {
    const host = req.query.host;
    const port = parseInt(req.query.port, 10) || 25565;

    if (!host) {
        return res.status(400).json({ error: "falta host" });
    }

    try {
        const r = await pingServer(host, port);

        const motd = typeof r.description === "string"
            ? r.description
            : (r.description?.text || JSON.stringify(r.description));

        res.json({
            motd,
            online: r.players?.online ?? 0,
            max: r.players?.max ?? 0,
            version: r.version?.name ?? "?",
            favicon: r.favicon ?? null,
            latency: r.latency ?? 0
        });

    } catch (e) {
        console.error("[PING ERROR]", e.message);
        res.status(502).json({ error: "offline" });
    }
});

// Endpoint LOGO
app.get("/logo", async (req, res) => {
    const host = req.query.host || "mc.hypixel.net";
    const port = parseInt(req.query.port, 10) || 25565;

    try {
        console.log("[LOGO] Consultando:", host, port);

        const result = await pingServer(host, port);

        const pixels = faviconToHex(result.favicon, 32);

        console.log("[LOGO] Convertidos:", pixels.length, "pixeles");

        res.json({
            width: 32,
            height: 32,
            format: "RGB24-HEX",
            pixels
        });

    } catch (e) {
        console.error("[LOGO ERROR]", e.message);

        res.status(502).json({
            error: "No se pudo obtener el logo",
            detail: e.message
        });
    }
});

app.listen(PORT, () => {
    console.log("JTN RELAY UP — PORT:", PORT);
});
