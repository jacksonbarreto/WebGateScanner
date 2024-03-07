package secureTransport

// TODO: Confirm if this is the correct struct from the DB

type Assessment struct {
	AssessmentId       string
	ResultRaw          string
	Host               string
	EngineVersion      string
	CriteriaVersion    string
	DigitalCertificate DigitalCertificate
	Endpoint           []Endpoint
}

type DigitalCertificate struct {
	NotBefore              int64
	NotAfter               int64
	DnsCaa                 bool
	MustStaple             bool
	Sgc                    int
	Issues                 int
	Sct                    bool
	KeyAlg                 string
	KeySize                int
	KeyStrength            int
	KeyKnownDebianInsecure bool
	Raw                    string
	IssuerSubject          string
	Subject                string
	RevocationInfo         int
	RevocationStatus       int
	CrlRevocationStatus    int
	OcspRevocationStatus   int
	SigAlg                 string
}

type Endpoint struct {
	IpAddress           string
	Protocols           []SecurityProtocol
	Grade               string
	GradeTrustIgnored   string
	HasWarnings         bool
	IsExceptional       bool
	ServerSignature     string
	PrefixDelegation    bool
	NonPrefixDelegation bool
	VulnBeast           bool
	RenegSupport        int
	SessionResumption   int
	CompressionMethods  int
	SupportsNpn         bool
	SupportsAlpn        bool
	AlpnProtocols       string
	NpnProtocols        string
	SessionTickets      int
	OcspStapling        bool
	SniRequired         bool
	HttpStatusCode      int
	SupportsRc4         bool
	Rc4WithModern       bool
	Rc4Only             bool
	ForwardSecrecy      int

	ProtocolIntolerance   int
	MiscIntolerance       int
	Heartbleed            bool
	Heartbeat             bool
	OpenSslCcs            int
	OpenSSLLuckyMinus20   int
	Ticketbleed           int
	Bleichenbacher        int
	Poodle                bool
	PoodleTLS             int
	FallbackScsv          bool
	Freak                 bool
	HasSct                int
	DhUsesKnownPrimes     int
	DhYsReuse             bool
	EcdhParameterReuse    bool
	Logjam                bool
	ResponseRawHeader     string
	HttpVersion           string
	DrownErrors           bool
	DrownVulnerable       bool
	StaticPkpPolicyStatus string
	HpkpPolicyStatus      string
	HpkpRoPolicyStatus    string
	HstsPolicyStatus      string
}

type SecurityProtocol struct {
	Name       string
	ProtocolId string
	Version    string
}
