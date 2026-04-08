// =============================================================================
// proxy.pac — Cloudflare WARP + DoH (HTTPS)
// Generat automat de: generate-proxy-pac.ps1
// Host: https://raw.githubusercontent.com/<USER>/<REPO>/main/proxy.pac
// Ultima actualizare: @@GENERATED_DATE@@
// =============================================================================

// -----------------------------------------------------------------------
// CONFIGURATIE WARP
// Cloudflare WARP ruleaza local ca HTTPS proxy pe portul 40000
// Activeaza "Proxy Mode" in WARP client: Settings > Preferences > Proxy
// -----------------------------------------------------------------------
var WARP_PROXY    = "HTTPS 127.0.0.1:40000";
var WARP_SOCKS    = "SOCKS5 127.0.0.1:40000";   // fallback SOCKS5
var DIRECT        = "DIRECT";

// -----------------------------------------------------------------------
// IP-URI CLOUDFLARE WARP / WARP+
// Endpoint-uri anycast Cloudflare (WireGuard UDP 2408)
// Folosite pentru detectie: daca esti deja pe WARP, nu mai proxiezi
// -----------------------------------------------------------------------
var WARP_ENDPOINTS = [
    "162.159.192.1",
    "162.159.193.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
    "162.159.204.1",
    "162.159.205.1"
];

// -----------------------------------------------------------------------
// DOMENII RUTATE PRIN WARP (adauga ce ai nevoie)
// -----------------------------------------------------------------------
var WARP_DOMAINS = [
    // Cloudflare DoH
    "cloudflare-dns.com",
    "1.1.1.1",
    "1.0.0.1",

    // Servicii cu geo-blocking / protectie extra
    "discord.com",
    "discordapp.com",
    "discord.gg",

    // Adauga domeniile tale:
    // "exemplu.com",
];

// -----------------------------------------------------------------------
// DOMENII MEREU DIRECTE (bypass complet)
// -----------------------------------------------------------------------
var DIRECT_DOMAINS = [
    "localhost",
    "127.0.0.1",
    "*.local",
    "*.lan",
    "*.internal",
    "10.*",
    "192.168.*",
    "172.16.*",
    "169.254.*",        // link-local

    // Adauga retele interne:
    // "corp.exemplu.ro",
];

// -----------------------------------------------------------------------
// SUBNETS CLOUDFLARE (trafic deja pe Cloudflare -> DIRECT)
// -----------------------------------------------------------------------
var CF_SUBNETS = [
    { net: "103.21.244.0",  mask: "255.255.252.0" },
    { net: "103.22.200.0",  mask: "255.255.252.0" },
    { net: "103.31.4.0",    mask: "255.255.252.0" },
    { net: "104.16.0.0",    mask: "255.240.0.0"   },
    { net: "104.24.0.0",    mask: "255.252.0.0"   },
    { net: "162.158.0.0",   mask: "255.254.0.0"   },
    { net: "162.159.0.0",   mask: "255.255.0.0"   },
    { net: "172.64.0.0",    mask: "255.252.0.0"   },
    { net: "188.114.96.0",  mask: "255.255.240.0" },
    { net: "190.93.240.0",  mask: "255.255.240.0" },
    { net: "197.234.240.0", mask: "255.255.252.0" },
    { net: "198.41.128.0",  mask: "255.255.128.0" }
];

// =============================================================================
// FUNCTII HELPER
// =============================================================================

function isDirect(host) {
    for (var i = 0; i < DIRECT_DOMAINS.length; i++) {
        var d = DIRECT_DOMAINS[i];
        if (d.indexOf("*") === 0) {
            if (dnsDomainIs(host, d.substring(1))) return true;
        } else if (d.indexOf("*") > 0) {
            // wildcard la mijloc — simplu shExpMatch
            if (shExpMatch(host, d)) return true;
        } else {
            if (host === d || dnsDomainIs(host, "." + d)) return true;
        }
    }
    return false;
}

function isWarpDomain(host) {
    for (var i = 0; i < WARP_DOMAINS.length; i++) {
        if (host === WARP_DOMAINS[i] || dnsDomainIs(host, "." + WARP_DOMAINS[i])) {
            return true;
        }
    }
    return false;
}

function isCloudflareIP(ip) {
    if (!isValidIP(ip)) return false;
    for (var i = 0; i < CF_SUBNETS.length; i++) {
        if (isInNet(ip, CF_SUBNETS[i].net, CF_SUBNETS[i].mask)) return true;
    }
    return false;
}

function isValidIP(str) {
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(str);
}

function isPrivateIP(ip) {
    return isInNet(ip, "10.0.0.0",     "255.0.0.0")
        || isInNet(ip, "172.16.0.0",   "255.240.0.0")
        || isInNet(ip, "192.168.0.0",  "255.255.0.0")
        || isInNet(ip, "127.0.0.0",    "255.0.0.0")
        || isInNet(ip, "169.254.0.0",  "255.255.0.0");
}

// =============================================================================
// ENTRY POINT — FindProxyForURL
// =============================================================================
function FindProxyForURL(url, host) {

    // 1. Protocol file:// — intotdeauna direct
    if (url.substring(0, 5) === "file:") {
        return DIRECT;
    }

    // 2. Domenii locale / bypass explicit
    if (isDirect(host)) {
        return DIRECT;
    }

    // 3. Host este IP explicit
    if (isValidIP(host)) {
        if (isPrivateIP(host))    return DIRECT;
        if (isCloudflareIP(host)) return DIRECT;    // deja pe CF infra
        return WARP_PROXY;
    }

    // 4. DoH — forteaza prin WARP (HTTPS proxy)
    //    Browserul face cereri DoH catre 1.1.1.1 / cloudflare-dns.com
    if (host === "1.1.1.1" || host === "1.0.0.1" ||
        dnsDomainIs(host, ".cloudflare-dns.com") ||
        dnsDomainIs(host, ".mozilla.cloudflare-dns.com")) {
        return WARP_PROXY;
    }

    // 5. Domenii configurate explicit pentru WARP
    if (isWarpDomain(host)) {
        return WARP_PROXY;
    }

    // 6. Rezolva IP si decide
    var ip = dnsResolve(host);
    if (ip) {
        if (isPrivateIP(ip))    return DIRECT;
        if (isCloudflareIP(ip)) return DIRECT;
    }

    // 7. Default: DIRECT (schimba in WARP_PROXY pentru full-tunnel)
    return DIRECT;
}
