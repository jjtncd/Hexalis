const mc      = require("minecraft-protocol")
const express = require("express")
const app     = express()

app.get("/ping", async (req, res) => {
    const host = req.query.host
    const port = parseInt(req.query.port) || 25565
    if (!host) return res.json({ error: "falta host" })

    try {
        const r = await mc.ping({ host, port, version: false, closeTimeout: 5000 })

        const motd = typeof r.description === "string"
            ? r.description
            : (r.description?.text || JSON.stringify(r.description))

        res.json({
            motd:    motd,
            online:  r.players?.online  ?? 0,
            max:     r.players?.max     ?? 0,
            version: r.version?.name    ?? "?",
            favicon: r.favicon          ?? null,
            latency: r.latency          ?? 0,
        })
    } catch (e) {
        res.json({ error: "offline" })
    }
})

app.listen(process.env.PORT || 3000, () => console.log("relay up"))