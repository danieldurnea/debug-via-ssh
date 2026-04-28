// ============================================================================
// proxy.pac — Mobile Tracking Blocker (Meta/Google/Tracking) for GrapheneOS
// ----------------------------------------------------------------------------
// Compatible with: Cloudflare WARP (WireGuard), GrapheneOS, Android 13+
//                  iOS (Settings → Wi-Fi → Configure Proxy → Automatic)
//                  Firefox/Chromium desktop
//
// Strategy:
//   - tracking/ad/telemetry domains  → PROXY 0.0.0.0:1  (= effectively blocked)
//   - everything else                → DIRECT           (passes through WARP)
//
// Why "PROXY 0.0.0.0:1"?
//   PAC has no native block verb. Routing to an unreachable proxy is the
//   standard pattern — the connection fails fast (1-3 sec) instead of timing
//   out for 60+ sec. Apps treat this as "no network", which is the goal.
//
// What it WILL break (acceptable trade-offs):
//   - Facebook/Instagram in-feed ads (good — that's the point)
//   - "Sponsored" stories (good)
//   - Pixel-based conversion tracking on websites
//   - Some embedded Like/Share buttons on third-party sites
//   - Google Analytics, gtag, GA4
//
// What it WON'T break:
//   - WhatsApp messages, calls, voice notes, media transfer
//   - Facebook/Instagram timeline content, DMs, Stories
//   - Login flows
//
// What it CAN'T do (PAC limitations):
//   - Block intra-app QUIC/UDP (FB Messenger calls, WhatsApp media on UDP)
//   - Block on mobile data — PAC works only on Wi-Fi
//   - Block trackers loaded from same-origin as app (Meta SDKs)
//
// For complete protection, combine with:
//   - NextDNS profile (recommended)  https://my.nextdns.io/start
//   - RethinkDNS app (per-app firewall)
//   - GrapheneOS "Sensors permission" disabled by default
//
// Maintenance: review every 3 months. Tracking domains rotate.
// Last updated: 2026-04
// ============================================================================

function FindProxyForURL(url, host) {
    // Lowercase host once (called many times per session)
    var h = host.toLowerCase();

    // ─────────────────────────────────────────────────────────────────────
    // FAST-PATH: ALLOW localhost / LAN / private ranges
    // (your own services, router, NAS, GrapheneOS Owncloud, etc.)
    // ─────────────────────────────────────────────────────────────────────
    if (isPlainHostName(h)
        || dnsDomainIs(h, ".local")
        || isInNet(dnsResolve(h), "10.0.0.0",   "255.0.0.0")
        || isInNet(dnsResolve(h), "172.16.0.0", "255.240.0.0")
        || isInNet(dnsResolve(h), "192.168.0.0","255.255.0.0")
        || isInNet(dnsResolve(h), "127.0.0.0",  "255.0.0.0")) {
        return "DIRECT";
    }

    // ─────────────────────────────────────────────────────────────────────
    // META TRACKING & AD INFRASTRUCTURE — blocked
    // (NOT the core domains needed for messaging)
    // ─────────────────────────────────────────────────────────────────────

    // Facebook tracking pixels & ad networks
    if (dnsDomainIs(h, "connect.facebook.net")          // Pixel SDK loader
     || dnsDomainIs(h, "graph.facebook.com")            // analytics endpoint
     || dnsDomainIs(h, "edge-chat-latest.facebook.com") // typing indicators (telemetry)
     || dnsDomainIs(h, ".analytics.facebook.com")
     || dnsDomainIs(h, ".ads.facebook.com")
     || dnsDomainIs(h, "an.facebook.com")               // Audience Network
     || dnsDomainIs(h, ".audience-network.com")
     || dnsDomainIs(h, "pixel.facebook.com")
     || dnsDomainIs(h, "metrics.facebook.com")
     || dnsDomainIs(h, "dpm.demdex.net")                // Adobe (used by FB)
     || dnsDomainIs(h, "atdmt.com")                     // FB-owned ad serving
     || dnsDomainIs(h, ".fbsbx.com")                    // FB ad sandbox
     || dnsDomainIs(h, ".fbcdn.net") && /\/ads?\//.test(url)  // ad-only CDN paths
     || dnsDomainIs(h, "graph.instagram.com") && /\/(insights|ads)/.test(url)
     || dnsDomainIs(h, "i.instagram.com") && /\/logging\//.test(url)
     || dnsDomainIs(h, "rupload.facebook.com")          // ad creative upload
        ) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // META APP TELEMETRY (specific endpoints — leave core working)
    // ─────────────────────────────────────────────────────────────────────
    if (dnsDomainIs(h, ".facebook.com") && (
            /\/ajax\/bz/.test(url)             // crash reports
         || /\/x_logging/.test(url)            // session logging
         || /\/falco_/.test(url)               // event tracking
         || /\/data\/manifest/.test(url) && /tracking/.test(url)
        )) {
        return "PROXY 0.0.0.0:1";
    }

    // WhatsApp telemetry (NOT messages — those go through e2e endpoints)
    if (dnsDomainIs(h, "crashlogs.whatsapp.net")
     || dnsDomainIs(h, "log.whatsapp.com")
     || dnsDomainIs(h, "static.whatsapp.net") && /\/log/.test(url)) {
        return "PROXY 0.0.0.0:1";
    }

    // Instagram tracking
    if (dnsDomainIs(h, ".cdninstagram.com") && /\/log/.test(url)
     || dnsDomainIs(h, "graph.instagram.com") && /\/logging/.test(url)) {
        return "PROXY 0.0.0.0:1";
    }

    // Messenger telemetry
    if (dnsDomainIs(h, ".messenger.com") && (
            /\/intern\//.test(url)
         || /\/falco/.test(url)
         || /\/logging/.test(url)
        )) {
        return "PROXY 0.0.0.0:1";
    }

    // Threads telemetry
    if (dnsDomainIs(h, ".threads.net") && /\/log/.test(url)) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // GOOGLE TRACKING & ADS
    // ─────────────────────────────────────────────────────────────────────
    if (dnsDomainIs(h, "google-analytics.com")
     || dnsDomainIs(h, "ssl.google-analytics.com")
     || dnsDomainIs(h, "www.google-analytics.com")
     || dnsDomainIs(h, "analytics.google.com")
     || dnsDomainIs(h, "googletagmanager.com")
     || dnsDomainIs(h, "googletagservices.com")
     || dnsDomainIs(h, "googlesyndication.com")
     || dnsDomainIs(h, "googleadservices.com")
     || dnsDomainIs(h, "doubleclick.net")
     || dnsDomainIs(h, "adservice.google.com")
     || dnsDomainIs(h, "stats.g.doubleclick.net")
     || dnsDomainIs(h, "pagead2.googlesyndication.com")
     || dnsDomainIs(h, "googleads.g.doubleclick.net")
     || dnsDomainIs(h, "ad.doubleclick.net")
     || dnsDomainIs(h, "adwords.google.com")
     || dnsDomainIs(h, "ads.google.com")
     || dnsDomainIs(h, "app-measurement.com")        // Firebase Analytics
     || dnsDomainIs(h, "crashlytics.com")
     || dnsDomainIs(h, "firebase-settings.crashlytics.com")) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // MAJOR TRACKING / ANALYTICS PLATFORMS
    // ─────────────────────────────────────────────────────────────────────
    if (dnsDomainIs(h, "scorecardresearch.com")      // ComScore
     || dnsDomainIs(h, "quantserve.com")
     || dnsDomainIs(h, "hotjar.com")
     || dnsDomainIs(h, "mouseflow.com")
     || dnsDomainIs(h, "fullstory.com")
     || dnsDomainIs(h, "segment.io")
     || dnsDomainIs(h, "segment.com")
     || dnsDomainIs(h, "mixpanel.com")
     || dnsDomainIs(h, "amplitude.com")
     || dnsDomainIs(h, "branch.io")
     || dnsDomainIs(h, "appsflyer.com")
     || dnsDomainIs(h, "adjust.com")
     || dnsDomainIs(h, "kochava.com")
     || dnsDomainIs(h, "tapad.com")
     || dnsDomainIs(h, "moat.com")
     || dnsDomainIs(h, "moatads.com")
     || dnsDomainIs(h, "criteo.com")
     || dnsDomainIs(h, "criteo.net")
     || dnsDomainIs(h, "outbrain.com")
     || dnsDomainIs(h, "taboola.com")
     || dnsDomainIs(h, "taboola.net")
     || dnsDomainIs(h, "rubiconproject.com")
     || dnsDomainIs(h, "openx.net")
     || dnsDomainIs(h, "pubmatic.com")
     || dnsDomainIs(h, "casalemedia.com")
     || dnsDomainIs(h, "adsrvr.org")               // Trade Desk
     || dnsDomainIs(h, "adnxs.com")                 // AppNexus / Xandr
     || dnsDomainIs(h, "rlcdn.com")
     || dnsDomainIs(h, "mathtag.com")
     || dnsDomainIs(h, "agkn.com")
     || dnsDomainIs(h, "bidswitch.net")) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // AMAZON / TIKTOK / SOCIAL TRACKING
    // ─────────────────────────────────────────────────────────────────────
    if (dnsDomainIs(h, "amazon-adsystem.com")
     || dnsDomainIs(h, "amazon-ads.com")
     || dnsDomainIs(h, "assoc-amazon.com")
     || dnsDomainIs(h, "analytics.tiktok.com")
     || dnsDomainIs(h, "ads.tiktok.com")
     || dnsDomainIs(h, "log.byteoversea.com")     // TikTok telemetry
     || dnsDomainIs(h, "log.tiktokv.com")
     || dnsDomainIs(h, "mssdk.tiktokv.com")
     || dnsDomainIs(h, "ads.twitter.com")
     || dnsDomainIs(h, "analytics.twitter.com")
     || dnsDomainIs(h, "ads-api.twitter.com")
     || dnsDomainIs(h, "ads.linkedin.com")
     || dnsDomainIs(h, "px.ads.linkedin.com")
     || dnsDomainIs(h, "ads.pinterest.com")
     || dnsDomainIs(h, "log.pinterest.com")
     || dnsDomainIs(h, "ads.snapchat.com")
     || dnsDomainIs(h, "tr.snapchat.com")) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // MICROSOFT / APPLE / SAMSUNG TELEMETRY
    // ─────────────────────────────────────────────────────────────────────
    if (dnsDomainIs(h, "vortex.data.microsoft.com")
     || dnsDomainIs(h, "telemetry.microsoft.com")
     || dnsDomainIs(h, "data.microsoft.com")
     || dnsDomainIs(h, "watson.telemetry.microsoft.com")
     || dnsDomainIs(h, "settings-win.data.microsoft.com")
     || dnsDomainIs(h, "events.data.microsoft.com")
     || dnsDomainIs(h, "ads.msn.com")
     || dnsDomainIs(h, "rad.msn.com")
     || dnsDomainIs(h, "samsungcloudsolution.com") && /\/log/.test(url)
     || dnsDomainIs(h, "samsungrm.net")
     || dnsDomainIs(h, "iadsdk.apple.com")
     || dnsDomainIs(h, "metrics.apple.com")
     || dnsDomainIs(h, "metrics.icloud.com")) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // CRASH/ERROR REPORTING (often used as tracking vector)
    // ─────────────────────────────────────────────────────────────────────
    if (dnsDomainIs(h, "sentry.io") && /\/api\/.*\/store/.test(url)
     || dnsDomainIs(h, "bugsnag.com")
     || dnsDomainIs(h, "raygun.io")
     || dnsDomainIs(h, "rollbar.com")
     || dnsDomainIs(h, "newrelic.com") && /\/log/.test(url)
     || dnsDomainIs(h, "datadoghq.com") && /\/intake/.test(url)) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // FINGERPRINTING / DEVICE ID PROVIDERS
    // ─────────────────────────────────────────────────────────────────────
    if (dnsDomainIs(h, "fingerprintjs.com")
     || dnsDomainIs(h, "fpjs.io")
     || dnsDomainIs(h, "iovation.com")
     || dnsDomainIs(h, "perimeterx.net")
     || dnsDomainIs(h, "imrworldwide.com")     // Nielsen
     || dnsDomainIs(h, "demdex.net")            // Adobe Audience
     || dnsDomainIs(h, "everesttech.net")
     || dnsDomainIs(h, "omtrdc.net")             // Adobe Analytics
     || dnsDomainIs(h, "2o7.net")                // Adobe SiteCatalyst
     || dnsDomainIs(h, "247-inc.net")
     || dnsDomainIs(h, "tealiumiq.com")) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // ROMANIAN-SPECIFIC TRACKERS (relevant for RO users)
    // ─────────────────────────────────────────────────────────────────────
    if (dnsDomainIs(h, "trafic.ro")
     || dnsDomainIs(h, "gemius.pl")
     || dnsDomainIs(h, "gemius.ro")
     || dnsDomainIs(h, "sati.ro")
     || dnsDomainIs(h, "monitor.ro") && /\/track/.test(url)
     || dnsDomainIs(h, "digitalvelocity.ro") && /\/log/.test(url)) {
        return "PROXY 0.0.0.0:1";
    }

    // ─────────────────────────────────────────────────────────────────────
    // DEFAULT: pass through to WARP (DIRECT — no proxy)
    // WireGuard will handle DNS resolution via 1.1.1.1/1.0.0.1
    // ─────────────────────────────────────────────────────────────────────
    return "DIRECT";
}
