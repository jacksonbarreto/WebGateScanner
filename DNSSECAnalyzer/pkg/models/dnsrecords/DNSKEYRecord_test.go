package dnsrecords

import (
	"strings"
	"testing"
)

func TestNewDNSKEYRecordOK(t *testing.T) {
	response := goodDNSKeyResponse
	expected := &DNSKEYResponse{
		Records: []DNSKEYRecord{
			{
				Flags:         256,
				Protocol:      3,
				Algorithm:     7,
				PublicKey:     "AwEAAbQIht7R2chVP06KG0T+2qFPl88bDNh5ZVQZ/D14jjaTd2ZG/pd4Be75jEpKKPwFGgi87e2Ii86FcKYgBSZmkJs7q9ai0kdHi/fGVXmthcnpV2PXp2W6QT5tYs/0UsjaIxRMOzsfBv52KEg5DrU33sLEUe72odKLBLbOM9aYnu1P",
				KeyType:       "ZSK",
				AlgorithmName: "NSEC3RSASHA1",
				KeyID:         45269,
			},
			{
				Flags:         257,
				Protocol:      3,
				Algorithm:     7,
				PublicKey:     "AwEAAa2iPQ5BhbTgLBIvK2Jx4qj6biGM1VueETFd4XILxdiXeFfK/ZQZhm1Xt8THcw+aOoalBlKp4nJwT8Cy0Ts+fEGJirOmd3XcGMgTn0YpzmAFC8KyvAGGuEB24dkltXEP8DYICdJiOwaNbZJbluF1/cIGQp+N+A94QpzxWnzTJmPce0SZaGB2eV9Z4lMGsjlULlRs6QbBSwykPKM/E5nQr0lP+Yhmdvuja+3nEbkSBFSHnzZPjrqCcJYAvKPB9U3PIpn+tyU/AKHjypoNYJT8f9euee1sbmhEYVjHIF3ECTMMk6T8F8mDOlMYjdEI5OL2EFLZPxxuUXZLKXV+AC5WofE=",
				KeyType:       "KSK",
				AlgorithmName: "NSEC3RSASHA1",
				KeyID:         4410,
			},
		},
		Validated: true,
		RRSIG: &RRSIGRecord{
			TypeCovered: "DNSKEY",
			Algorithm:   7,
			Labels:      2,
			OriginalTTL: 86400,
			Expiration:  1704326400,
			Inception:   1702512000,
			KeyTag:      4410,
			SignerName:  "ipb.pt",
			Signature:   "D8Rtw6kkAXMQpUjwwjFp7s5zx+4ocz8+0D7natTPc7yxsZIaE+k4Eud3iqL4o8jRGgyqGRDsbxRUQx1dB4ivbxyrQe+TnYMm1lOZPQIt9zKfTt/3UegBL2hWVa+5StWMtsfDTFTuhQI4kkJ01aIKpVi7++B4dXVjOQA8ydMNgNzErUMFe+NNpdE5ddrTWRWS9aH6jewKohhf1lNU0WkR8NjWtCIQqFdkcDd5AIHXJ5yKjyOjC/2A+9ZxELqRSTPo3SKnSMRCQO9yR5v5EJh7k7GYm0rFzN2D2EkIlqi19MPHBwzBHf/GBLCL5tiQjxo+ZqxOPUv3Dp4Bm5LHNVt3cg==",
		},
		RawResponse: response,
	}
	r := &DNSKEYResponse{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse DNSKEY record: %v", err)
	}
	dnsKeyRecord, ok := result.(*DNSKEYResponse)
	if !ok {
		t.Fatalf("Result is not a *DNSKEYResponse")
	}

	if !dnsKeyRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", dnsKeyRecord, expected)
	}

}

func TestNewDNSKEYRecordNoDNSSEC(t *testing.T) {
	response := badDNSKeyResponse

	r := &DNSKEYResponse{}
	dnsKeyRecord, err := r.Parse(response)

	if dnsKeyRecord != nil {
		t.Fatalf("Expected nil DNSKEY response, got %+v", dnsKeyRecord)
	}

	if !strings.Contains(err.Error(), "resolution failed") {
		t.Errorf("Expected error to contain 'resolution failed', got: %v", err)
	}
}

const goodDNSKeyResponse = `; fully validated
ipb.pt.                 21600   IN      DNSKEY  256 3 7 AwEAAbQIht7R2chVP06KG0T+2qFPl88bDNh5ZVQZ/D14jjaTd2ZG/pd4 Be75jEpKKPwFGgi87e2Ii86FcKYgBSZmkJs7q9ai0kdHi/fGVXmthcnp V2PXp2W6QT5tYs/0UsjaIxRMOzsfBv52KEg5DrU33sLEUe72odKLBLbO M9aYnu1P  ; ZSK; alg = NSEC3RSASHA1 ; key id = 45269
ipb.pt.                 21600   IN      DNSKEY  257 3 7 AwEAAa2iPQ5BhbTgLBIvK2Jx4qj6biGM1VueETFd4XILxdiXeFfK/ZQZ hm1Xt8THcw+aOoalBlKp4nJwT8Cy0Ts+fEGJirOmd3XcGMgTn0YpzmAF C8KyvAGGuEB24dkltXEP8DYICdJiOwaNbZJbluF1/cIGQp+N+A94Qpzx WnzTJmPce0SZaGB2eV9Z4lMGsjlULlRs6QbBSwykPKM/E5nQr0lP+Yhm dvuja+3nEbkSBFSHnzZPjrqCcJYAvKPB9U3PIpn+tyU/AKHjypoNYJT8 f9euee1sbmhEYVjHIF3ECTMMk6T8F8mDOlMYjdEI5OL2EFLZPxxuUXZL KXV+AC5WofE=  ; KSK; alg = NSEC3RSASHA1 ; key id = 4410
ipb.pt.                 21600   IN      RRSIG   DNSKEY 7 2 86400 20240104000000 20231214000000 4410 ipb.pt. D8Rtw6kkAXMQpUjwwjFp7s5zx+4ocz8+0D7natTPc7yxsZIaE+k4Eud3 iqL4o8jRGgyqGRDsbxRUQx1dB4ivbxyrQe+TnYMm1lOZPQIt9zKfTt/3 UegBL2hWVa+5StWMtsfDTFTuhQI4kkJ01aIKpVi7++B4dXVjOQA8ydMN gNzErUMFe+NNpdE5ddrTWRWS9aH6jewKohhf1lNU0WkR8NjWtCIQqFdk cDd5AIHXJ5yKjyOjC/2A+9ZxELqRSTPo3SKnSMRCQO9yR5v5EJh7k7GY m0rFzN2D2EkIlqi19MPHBwzBHf/GBLCL5tiQjxo+ZqxOPUv3Dp4Bm5LH NVt3cg==`

const badDNSKeyResponse = `;; resolution failed: ncache nxrrset
; negative response, unsigned answer
; ipp.pt.                       600     IN      \-DNSKEY ;-$NXRRSET
; ipp.pt. SOA dns1.ipp.pt. core.ipp.pt. 2023112101 7200 7200 1209600 86400`
