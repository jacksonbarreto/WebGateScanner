package models

type TestSSLResponse struct {
	ClientProblem1 []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Finding  string `json:"finding"`
	} `json:"clientProblem1"`
	Invocation string `json:"Invocation"`
	At         string `json:"at"`
	Version    string `json:"version"`
	Openssl    string `json:"openssl"`
	StartTime  string `json:"startTime"`
	ScanResult []struct {
		TargetHost string `json:"targetHost"`
		IP         string `json:"ip"`
		Port       string `json:"port"`
		RDNS       string `json:"rDNS"`
		Service    string `json:"service"`
		Pretest    []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
		} `json:"pretest"`
		Protocols []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
		} `json:"protocols"`
		Grease  []any `json:"grease"`
		Ciphers []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Cwe      string `json:"cwe,omitempty"`
			Finding  string `json:"finding"`
		} `json:"ciphers"`
		Pfs []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
		} `json:"pfs"`
		ServerPreferences []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
		} `json:"serverPreferences"`
		ServerDefaults []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
		} `json:"serverDefaults"`
		HeaderResponse []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
			Cwe      string `json:"cwe,omitempty"`
		} `json:"headerResponse"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Cve      string `json:"cve,omitempty"`
			Cwe      string `json:"cwe,omitempty"`
			Finding  string `json:"finding"`
		} `json:"vulnerabilities"`
		CipherTests []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
		} `json:"cipherTests"`
		BrowserSimulations []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
		} `json:"browserSimulations"`
	} `json:"scanResult"`
	ScanTime int `json:"scanTime"`
}
