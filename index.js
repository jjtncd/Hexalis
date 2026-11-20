
const mc = require("minecraft-protocol");
const express = require("express");
const { PNG } = require("pngjs");

const app = express();
const PORT = process.env.PORT || 3000;

// Convierte componentes Minecraft a texto legible
function flattenMotd(component) {
    if (component == null) return "";

    if (typeof component === "string") {
        return component;
    }

    if (Array.isArray(component)) {
        return component.map(flattenMotd).join("");
    }

    if (typeof component !== "object") {
        return "";
    }

    let text = "";

    if (component.text) {
        text += component.text;
    } else if (component.translate) {
        text += component.translate;
    }

    if (component.with) {
        text += component.with.map(flattenMotd).join("");
    }

    if (component.extra) {
        text += component.extra.map(flattenMotd).join("");
    }

    return text;
}

// Consulta Minecraft
async function pingServer(host, port) {
    return mc.ping({
        host,
        port,
        version: false,
        closeTimeout: 5000
    });
}

// PNG -> HEX RGB, resolución 64x64
function faviconToHex(favicon) {
    if (!favicon) {
        throw new Error("Servidor sin favicon");
    }

    const match = /^data:image\/png;base64,(.+)$/i.exec(favicon);

    if (!match) {
        throw new Error("Favicon inválido");
    }

    const png = PNG.sync.read(
        Buffer.from(match[1], "base64")
    );

    if (
        png.width < 1 || png.height < 1 ||
        png.width > 256 || png.height > 256
    ) {
        throw new Error("Dimensiones inválidas");
    }

    const size = 64;
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

            pixels.push(
                rgb.map(v =>
                    v.toString(16).padStart(2, "0")
                ).join("").toUpperCase()
            );
        }
    }

    return pixels;
}

// PING
app.get("/ping", async (req, res) => {
    const host = req.query.host;
    const port = parseInt(req.query.port, 10) || 25565;

    if (!host) {
        return res.status(400).json({
            error: "falta host"
        });
    }

    try {
        const r = await pingServer(host, port);

        res.json({
            motd: flattenMotd(r.description),
            online: r.players?.online ?? 0,
            max: r.players?.max ?? 0,
            version: r.version?.name ?? "?",
            favicon: r.favicon ?? null,
            latency: r.latency ?? 0
        });

    } catch (e) {
        console.error("[PING ERROR]", e.message);

        res.status(502).json({
            error: "offline"
        });
    }
});

// LOGO
app.get("/logo", async (req, res) => {
    const host = req.query.host || "mc.hypixel.net";
    const port = parseInt(req.query.port, 10) || 25565;

    try {
        console.log("[JTN LOGO] Consultando:", host);

        const r = await pingServer(host, port);
        const pixels = faviconToHex(r.favicon);

        console.log("[JTN LOGO] HEX:", pixels.length);

        res.json({
            width: 64,
            height: 64,
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
