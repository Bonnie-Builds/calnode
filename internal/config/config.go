package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port           string
	DatabaseURL    string
	EncryptionKey  string // platform secret (KEK input); vault derives the real AES key
	RecoverySecret string // CALNODE_RECOVERY_SECRET — escrow key stored in keystore
	BaseURL        string // identity host: OAuth callbacks, admin UI, team invites
	PublicBaseURL  string // booker-facing host: booking links, emails; defaults to BaseURL
	LogLevel       slog.Level

	// Email / SMTP
	SMTPHost          string
	SMTPPort          string
	SMTPUser          string
	SMTPPass          string
	SMTPTLS           bool // implicit TLS (port 465)
	SMTPStartTLS      bool // STARTTLS (port 587)
	EmailFrom         string
	EmailFromName     string
	EmailProvider     string // "resend" for the deployment preset; otherwise "smtp"
	EmailManagedByEnv bool   // true when deployment env owns email configuration

	// Google OAuth (calendar + sign-in)
	GoogleClientID     string
	GoogleClientSecret string
	// BonnieManagedMode disables Calnode's browser calendar-consent flow and
	// enables Bonnie-managed identity and scheduling surfaces.
	BonnieManagedMode bool

	// Microsoft 365 / Outlook (calendar) — env-only; tenant defaults to "common".
	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftTenant       string

	// Zoom OAuth app (per-host meeting links) — DB settings take priority over these.
	ZoomClientID     string
	ZoomClientSecret string

	// CookieSecure sets the Secure flag on session cookies. Defaults to true
	// when BASE_URL starts with https://, but can be overridden explicitly via
	// COOKIE_SECURE=false for HTTPS-terminated-at-proxy setups where the binary
	// itself listens on plain HTTP and BASE_URL is set correctly.
	CookieSecure bool

	// EmbedAllowedOrigins lists the origins permitted to call the public booking
	// endpoints cross-origin (for the embeddable widget). Empty ⇒ allow any origin
	// (`*`). CORS only constrains browsers; it is not an access-control boundary —
	// the public endpoints are rate-limited regardless. Comma-separated.
	EmbedAllowedOrigins []string

	// DemoMode turns this instance into a public, self-resetting demo: seeds sample
	// data on every boot (there's no persistent volume, so every boot is a fresh DB),
	// disables calendar/Zoom connect, serves a disallow-all robots.txt, and exposes
	// demo_mode/next_reset_at via the public auth-status endpoint so the frontend can
	// show the reset banner. Never set this on a real deployment.
	DemoMode bool
	// DemoResetInterval is how often DemoMode wipes and re-seeds the DB. Configurable
	// (not hardcoded to 30m) so local verification doesn't require waiting half an hour.
	DemoResetInterval time.Duration

	// Bonnie-managed identity contract (BONNIE_MANAGED_MODE).
	//
	BonnieManagedIssuer string
	// BonnieManagedCompany is the exact canonical Bonnie company ref accepted in the assertion.
	BonnieManagedCompany string
	// BonnieManagedJWKSURL is a URL the fork fetches to obtain Bonnie's versioned
	// public JWKS (Ed25519 verification keys). Mutually exclusive with a static
	// inline document.
	BonnieManagedJWKSURL string
	// BonnieManagedJWKS is an inline JSON JWKS document (public keys only).
	BonnieManagedJWKS string
	// BonnieManagedAllowedKids is the allowlist of accepted `kid` values (comma-separated).
	BonnieManagedAllowedKids []string
	// BonnieManagedOperatorKey is the secret shared with Bonbon's operator for the
	// managed member ensure/archive/reactivate endpoints. Never an API key or session.
	BonnieManagedOperatorKey string
	// BonnieManagedEntryPath is the allowlisted 303 target after a successful exchange.
	BonnieManagedEntryPath string
	// BonnieManagedLoginRedirect is where an unauthenticated managed-mode browser is
	// sent when it reaches the scheduler root without a session.
	BonnieManagedLoginRedirect string
	// BonnieManagedSessionTTL bounds managed browser sessions (default 1h).
	BonnieManagedSessionTTL time.Duration
	// BonnieManagedSiteDomain is the deployment-owned registrable site suffix
	// shared by Bonnie and this Calnode instance (for example, example.com).
	BonnieManagedSiteDomain string
	// BonnieManagedFrameAncestors is the exact comma-separated Bonnie app origin
	// allowlist for the managed personal-calendar iframe. Empty keeps embed dark.
	BonnieManagedFrameAncestors []string
	// BonnieManagedBookingFrameAncestors is the exact comma-separated Bonnie app
	// origin allowlist for public booking pages. Empty keeps booking-page framing
	// disabled and preserves the default DENY policy.
	BonnieManagedBookingFrameAncestors []string

	// Bonbon custody transport (Phase 3): when CustodyTransportURL is set, the
	// Google calendar effects ride Bonbon's operation-shaped custody boundary
	// instead of direct Google API calls. No credential material or
	// credential-kind selection ever passes through Calnode.
	CustodyTransportURL string
	// CustodyCompanyRef defaults to BonnieManagedCompany (the canonical company ref).
	CustodyCompanyRef string
	// CustodyInstanceRef pins this deployment's instance reference (required with a URL).
	CustodyInstanceRef string
	// CustodyAuthHeader is optional deployment-boundary caller auth (NOT a calendar credential).
	CustodyAuthHeader string
}

func Load() *Config {
	resendKey := strings.TrimSpace(os.Getenv("RESEND_API_KEY"))
	smtpHost := getEnv("EMAIL_SMTP_HOST", "")
	smtpPort := getEnv("EMAIL_SMTP_PORT", "587")
	smtpUser := getEnv("EMAIL_SMTP_USER", "")
	smtpPass := getEnv("EMAIL_SMTP_PASS", "")
	smtpTLS := getBool("EMAIL_SMTP_TLS", false)
	smtpStartTLS := getBool("EMAIL_SMTP_STARTTLS", false)
	emailProvider := "smtp"
	emailManagedByEnv := smtpHost != ""
	if smtpHost == "" && resendKey != "" {
		smtpHost = "smtp.resend.com"
		smtpPort = "587"
		smtpUser = "resend"
		smtpPass = resendKey
		smtpTLS = false
		smtpStartTLS = true
		emailProvider = "resend"
		emailManagedByEnv = true
	} else if strings.EqualFold(smtpHost, "smtp.resend.com") {
		emailProvider = "resend"
	}

	cfg := &Config{
		Port:        getEnv("PORT", "3000"),
		DatabaseURL: getEnv("DATABASE_URL", "sqlite://./data/calnode.db"),
		BaseURL:     getEnv("BASE_URL", "http://localhost:3000"),

		SMTPHost:          smtpHost,
		SMTPPort:          smtpPort,
		SMTPUser:          smtpUser,
		SMTPPass:          smtpPass,
		SMTPTLS:           smtpTLS,
		SMTPStartTLS:      smtpStartTLS,
		EmailFrom:         getEnv("EMAIL_FROM_ADDRESS", "bookings@localhost"),
		EmailFromName:     getEnv("EMAIL_FROM_NAME", "Bonnie"),
		EmailProvider:     emailProvider,
		EmailManagedByEnv: emailManagedByEnv,

		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),

		MicrosoftClientID:     getEnv("MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret: getEnv("MICROSOFT_CLIENT_SECRET", ""),
		MicrosoftTenant:       getEnv("MICROSOFT_TENANT", "common"),

		ZoomClientID:     getEnv("ZOOM_CLIENT_ID", ""),
		ZoomClientSecret: getEnv("ZOOM_CLIENT_SECRET", ""),

		EmbedAllowedOrigins: splitCSV(getEnv("EMBED_ALLOWED_ORIGINS", "")),
	}

	cfg.EncryptionKey = os.Getenv("CALNODE_ENCRYPTION_KEY")
	cfg.RecoverySecret = os.Getenv("CALNODE_RECOVERY_SECRET")
	// PUBLIC_BASE_URL overrides the booker-facing host (custom/vanity domain).
	// Unset → inherits BASE_URL, so single-domain deploys need only set BASE_URL.
	cfg.PublicBaseURL = getEnv("PUBLIC_BASE_URL", cfg.BaseURL)
	cfg.LogLevel = parseLogLevel(getEnv("LOG_LEVEL", "info"))
	cfg.CookieSecure = getBool("COOKIE_SECURE", strings.HasPrefix(cfg.BaseURL, "https://"))
	cfg.DemoMode = getBool("DEMO_MODE", false)
	cfg.BonnieManagedMode = getBool("BONNIE_MANAGED_MODE", false)
	cfg.BonnieManagedIssuer = strings.TrimSpace(os.Getenv("BONNIE_MANAGED_ISSUER"))
	cfg.BonnieManagedCompany = strings.TrimSpace(os.Getenv("BONNIE_MANAGED_COMPANY"))
	cfg.BonnieManagedJWKSURL = strings.TrimSpace(os.Getenv("BONNIE_MANAGED_JWKS_URL"))
	cfg.BonnieManagedJWKS = strings.TrimSpace(os.Getenv("BONNIE_MANAGED_JWKS"))
	cfg.BonnieManagedAllowedKids = splitCSV(os.Getenv("BONNIE_MANAGED_ALLOWED_KIDS"))
	cfg.BonnieManagedOperatorKey = os.Getenv("BONNIE_MANAGED_OPERATOR_KEY")
	cfg.BonnieManagedEntryPath = getEnv("BONNIE_MANAGED_ENTRY_PATH", "/")
	cfg.BonnieManagedLoginRedirect = strings.TrimSpace(os.Getenv("BONNIE_MANAGED_LOGIN_REDIRECT"))
	cfg.BonnieManagedSessionTTL = getDuration("BONNIE_MANAGED_SESSION_TTL", time.Hour)
	cfg.BonnieManagedSiteDomain = strings.ToLower(strings.TrimSpace(os.Getenv("BONNIE_MANAGED_SITE_DOMAIN")))
	cfg.BonnieManagedFrameAncestors = splitCSV(os.Getenv("BONNIE_MANAGED_FRAME_ANCESTORS"))
	cfg.BonnieManagedBookingFrameAncestors = splitCSV(os.Getenv("BONNIE_MANAGED_BOOKING_FRAME_ANCESTORS"))
	cfg.CustodyTransportURL = strings.TrimSpace(os.Getenv("BONNIE_CUSTODY_TRANSPORT_URL"))
	cfg.CustodyCompanyRef = strings.TrimSpace(os.Getenv("BONNIE_CUSTODY_COMPANY_REF"))
	cfg.CustodyInstanceRef = strings.TrimSpace(os.Getenv("BONNIE_CUSTODY_INSTANCE_REF"))
	if cfg.CustodyCompanyRef == "" {
		cfg.CustodyCompanyRef = cfg.BonnieManagedCompany
	}
	cfg.CustodyAuthHeader = os.Getenv("BONNIE_CUSTODY_AUTH_HEADER")
	cfg.DemoResetInterval = getDuration("DEMO_RESET_INTERVAL", 30*time.Minute)

	return cfg
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// splitCSV parses a comma-separated value into trimmed, non-empty entries.
// Returns nil for an empty string.
func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
