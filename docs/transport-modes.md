# Transport modes

Standard wireguard only supports UDP transport over IPv4 or IPv6. This works fine over most networks however there are many cases where
1. You do not have the ability to expose a Wireguard port directly, but you can accept incomming connections through web connections
2. You need a proxy to connect to the internet/network you want to run Wireguard over
3. Or you need a small relay to proxy Wireguard to your machine seamlessly 
4. Or you are on a network that blocks VPNs because it does not support UDP or has MTU issues, even if the network is not actively blocking vpns
5. Or you want to make sure your VPN traffic does not look like a VPN

All five are legitemate cases where you want to use transport modes to carry Wireguard traffic.

`uwgsocks` support all useful transport modes that works on all networks you can think off, you can tunnel Wireguard. The following transport modes are supported:

* UDP
* TCP
* HTTP
* HTTPS
* QUIC (HTTP/3)
* TLS
* DTLS (UDP)
* TURN

Those can then be carried over a proxy of SOCKS5 or HTTP(S).

Connection-oriented transports like TLS/TCP/HTTP/HTTPS/QUIC support full roaming like normal UDP. Connections are automatically re-attempted from 
scratch whenever Wireguard wants to start a new handshake because of a failed handshake or session.

The transport security (like HTTP vs HTTPS or DTLS vs UDP) does NOT have any relevance for the security of your Wireguard tunnel data, as data is always encrypted and authenticated by Wireguard.

## UDP

UDP is the default transport mode. UDP has both listen and connect mode.

1. UDP in connect mode choses a random UDP source port per Wireguard peer. This mode cannot receive incomming wireguard connections.
2. UDP in listen mode can both receive and send UDP packets to existing/new wireguard peers. If ListenPort is specified in the config this mode is used. All UDP packets will have the same UDP source port.

```yaml
transports:
  - name: standard-wireguard
    base: udp
    listen: true
    listen_port: 51820
```

## TCP

TCP is used when you are on a network that does not support UDP or has MTU issue with Wireguard. TCP is connection oriented, in that for every peer a conenction must be established when the session is active. 

TCP has both listen and connect mode:
1. TCP in connect mode connects to another peer when it becomes active (e.g data is queued or PersistentKeepAlive). The connection remains alive as long as the default 'UDP' timeout. Reconnections happen automatically on handshake/session failures, always within 10 seconds (as by default in Wireguard)
2. TCP in listen mode can receive TCP clients on a port. When connected, packets send to that peer will re-use the TCP connection.

TCP tunnels Wireguard by prefixing a 2 byte big-endian header that tells how long the wireguard packet is that follows, send in a transport stream. 

```yaml
transports:
  - name: wireguard-tcp
    base: tcp
    listen: true
    listen_port: 51820
```

## TLS

TLS is TCP wireguard send over a TLS stream. This can be useful to make it look like HTTPS web traffic. by default the client does not validate server certificates since Wireguard is already encrypted, and the server by default just serves a random in-memory self-signed certificate.

In most cases this mode is not useful, unless you really want to conceal your traffic for deep inspection firewalls. TCP transport usually solves the issue for most use cases with UDP and if you want/must use a reverse proxy to expose your application then HTTP/HTTPS will do the job for you.

```yaml
transports:
  - name: wireguard-tls
    base: tcp
    listen: true
    listen_port: 8443
```


## HTTP/HTTPS

HTTP/HTTPS tunnel wireguad over Websocket frames, each frame is a Websocket binary frame containing a Wireguard packet

The semantics are the same as TCP, only the connection is bootstrapped with Websocket. The main advantage is that with HTTP you can put Wireguard behidn a reverse proxy like cloudflare/CDN accelerator and just connect using a URL, without that reverse proxy being able to inspect traffic. It also works over networks that actively MITM HTTPS connections as part of a corperate firewall.

In addition a raw HTTP upgrade to regular TCP transport is also supported, compatible with [https://codeberg.org/eduVPN/proxyguard/](https://codeberg.org/eduVPN/proxyguard/). This can be useful when:

1. Some internet proxies do not support backpressure on their websockets. If you notice that whenever you try to saturate your internet connection that it gets killed or becomes horrible, switching to a raw upgrade protocol might help. However most proxies will support backpressure fine as they just forward streams.
2. If you need to connect to a server that requires ProxyGuard

Its more common that a raw connection upgrade is blocked by reverse proxies than proxies seeing Websocket not having a backpressure, which is why its not set to the default.

```yaml
transports:
  - name: wireguard-http
    base: http
    #websocket (default) or proxyguard. For inbound connections on listen mode both are supported regardless of this value
    upgrade_mode: websocket 
    listen: true
    listen_port: 80
  - name: wireguard-https
    upgrade_mode: websocket
    base: https
    listen: true
    listen_port: 443

    # Configuration below is completely optional, by default a random self-generated cert is used
    # and since clients do not validate certs, clients can just connect without this 'tls' section
    tls:
      cert_file: /etc/letsencrypt/live/vpn/fullchain.pem
      key_file: /etc/letsencrypt/live/vpn/privkey.pem
      verify_peer: false
      reload_interval: 60s
      ca_file: ""
      server_sni: vpn.example.com
```

## QUIC (HTTP/3)

QUIC is added to expose Wireguard behind HTTP/3 capable reverse proxies to improve performance. it uses QUIC WebTransport [https://developer.mozilla.org/en-US/docs/Web/API/WebTransport](https://developer.mozilla.org/en-US/docs/Web/API/WebTransport), which is a valid web standard specifically for HTTP/3 making it most likely to be forwarded over reverse proxies just like WebSocket.

The above modes all require sending wireguard over TCP which has the TCP meltdown problem and degrades performance compared to UDP. By using HTTP/3 which itself is over UDP port 443, we can establish unreliable transport stream. This allows Wireguard to be hosted behind a global reverse proxy/TURN allowing you to easily expose Wireguard on machines where you do not have a port available to port forward and not have the ability/will to host a small TURN relay server on a VPS or want to benefit from the improved IP routing of global CDN networks.

In addition to WebTransport, WebSocket over QUIC is also supported. This makes it possible to connect through WebSocket over HTTP to the reverse proxy and let the reverse proxy still tunnel the traffic over QUIC to your Wireguard server, allowing one URL to both terminate HTTP Websocket TCP and QUIC UDP.


```yaml
transports:
  - name: wireguard-quic
    base: quic
    listen: true
    listen_port: 443

    # Configuration below is completely optional, by default a random self-generated cert is used
    # and since clients do not validate certs, clients can just connect without this 'tls' section
    tls:
      cert_file: /etc/letsencrypt/live/vpn/fullchain.pem
      key_file: /etc/letsencrypt/live/vpn/privkey.pem
      verify_peer: false
      reload_interval: 60s
      ca_file: ""
      server_sni: vpn.example.com
```

## DTLS

DTLS is added to make your Wireguard traffic look like legitemate WebRTC traffic. This has the advantage over TLS in that its still UDP and unreliable transport meaning you won't have the TCP meltdown problem.

```yaml
transports:
  - name: wireguard-quic
    base: dtls
    listen: true
    listen_port: 52201
```

# TURN

TURN is supported to use a small TURN server on a linux server (like VPS) to forward incomming connections to your Wireguard server if it does not have the ability to port forward a port.

The TURN relay can also be used to let Wireguard clients connect through TURN over TCP/DTLS when normal Wireguard UDP fails and your target server cannot port forward ports.

TURN supports the following transport modes:

* TURN UDP
* TURN TCP
* TURN TLS
* TURN DTLS

TURN is also used by WebRTC so TURN traffic is very unlikely to be blocked/affected by firewalls as many web applications and apps legitemately use this for multimedia streaming, even the normal TURN UDP which does not use any kind of concealing/obfuscation.

```yaml
transports:
  - name: turn
    base: turn
    listen: true
    turn:
      server: turn.example.com:3478
      username: wg
      password: secret # password is not sent over clear in turn, but used to authenticate the connection with a hash
      realm: example
      protocol: udp # udp, tcp, tls, dtls
      no_create_permission: false
      include_wg_public_key: false
      permissions: [198.51.100.10/32]
      
      # a TLS section can be put for TURN as well
```

# Proxy

When you need/want to use a proxy to connect to the Wireguard server, then the above 'base' transports can be routed over it. uwgsocks supports connecting to SOCKS5 and HTTP/HTTPS proxies. Only socks5 proxies support 'UDP' transports like UDP, TURN UDP and DTLS, otherwise you must use a TCP-based transport.

SOCKS5/HTTP proxies is mostly supported to let Wireguard connect to local applications like Tor or a corperate zero-trust network app that exposes a proxy on loopback, instead of global HTTP/SOCKS5 proxies.

For anonymous HTTPS proxies by default the server certificate is not validated as Wireguard inside the proxy is already encrypted and authenticated. However if you provide a username/password for the proxy, then the uwgsocks will validate the server certificate to prevent exposing your proxy credentials in the clear. This flag is overridable in the config.

The idea why TLS certificates for transports are not validated is to have a higher success rate and ease of use since you do not have to do proper certificate maintenance on client/server keeping the authentication to just Wireguard public/private keys and has a higher success rate when there are misconfigurations.

```yaml
proxy:
  type: socks5 #http, https or socks5
  socks5:
    server: 127.0.0.1:1080
    username: ""
    password: ""
  http:
    server: proxy.example.com:443
    username: ""
    password: ""

    # tls config can also be put here if type is https
```