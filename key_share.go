package reality

import "crypto/mlkem"

func hasKeyShare(keyShares []keyShare, group CurveID) bool {
	for _, ks := range keyShares {
		if ks.group == group {
			return true
		}
	}
	return false
}

// legacyPeerPub restores the key selection used before REALITY v26.9.8.
// Authentication and ECDH validation remain the caller's responsibility.
func legacyPeerPub(keyShares []keyShare) []byte {
	for _, ks := range keyShares {
		if ks.group == X25519 && len(ks.data) == 32 {
			return ks.data
		}
	}
	for _, ks := range keyShares {
		if ks.group == X25519MLKEM768 && len(ks.data) == mlkem.EncapsulationKeySize768+32 {
			return ks.data[mlkem.EncapsulationKeySize768:]
		}
	}
	return nil
}
