// Package listener is the TLS listener of the sensor.
//
// It holds the certificate cache and the configuration of the ACME client
// (FR-01, SEC-21), which NewACME builds from ACMEParams. It also holds the core
// of the decoy listener. This is an HTTP/1.1 server over TLS with bounds on
// connections, headers and time (SEC-02, SEC-22).
//
// Of SEC-02, the package enforces the connection cap, the size of the request
// head and the number of header values. The body cap, the path cap and the
// per-IP token bucket are not in this package.
//
// The package keeps a copy of the first ClientHello of each connection (FR-05).
// The copy has an array with a cap for each list and the first ALPN value. So
// its size is fixed. The error log counts lines and keeps no client data
// (SEC-22).
package listener
