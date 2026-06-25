package zeek

import "crypto/rand"

const uidAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// uidLength is the number of base62 characters following the "C" prefix.
// Zeek's default connection UID encodes 96 bits of randomness, which is about
// 17 base62 characters, so we match that here.
const uidLength = 17

// NewUID returns a Zeek-style connection identifier: the letter "C" followed
// by uidLength random base62 characters (e.g. "CsRwjF2hdSqJ7zUbcd").
//
// Sysmon events carry no flow-correlation identity, so each emitted row gets
// its own UID. This matches Zeek's own behavior of generating random UIDs and
// keeps the output recognizable to downstream consumers such as RITA.
func NewUID() string {
	buf := make([]byte, uidLength)
	// crypto/rand.Read does not fail on supported platforms; if it ever did,
	// we degrade to the zeroed buffer rather than failing a log write.
	_, _ = rand.Read(buf)

	// Map each random byte onto a base62 character in place. The slight modulo
	// bias (256 is not a multiple of 62) is irrelevant for an opaque ID.
	for i, b := range buf {
		buf[i] = uidAlphabet[int(b)%len(uidAlphabet)]
	}
	return "C" + string(buf)
}
