# mcconnect

A lightweight, protocol-level Minecraft server implementation for Node.js. Designed for authentication services, proxy backends, protocol analysis tools, and minimal custom servers.

## Overview

`mcconnect` provides a clean, fast, and dependency-free implementation of the Minecraft protocol (1.7+ → latest). It handles handshake, status, ping, login, authentication, and server transfer workflows without simulating gameplay.

## Features

- Full Minecraft protocol coverage (1.7+)
- Asynchronous, event-driven architecture
- Customizable MOTD and JSON text components
- Mojang session authentication and encryption
- Server transfer / redirect support
- Configurable ping modes
- Graceful disconnection handling
- Zero external dependencies (Node.js core only)

## Installation

```bash
npm install mcconnect
```

## Basic Usage

```javascript
import MCConnect from 'mcconnect';

const server = new MCConnect(25565)
  .onMOTD((protocol) => ({
    version: { name: "1.21", protocol },
    players: {
      max: 100,
      online: 42,
      sample: [
        { name: "Notch", id: "069a79f4-44e9-4726-a5be-fca90e38aaf5" }
      ]
    },
    description: {
      text: "",
      extra: [
        { text: "Custom Minecraft Server", color: "gold" },
        { text: "\nRunning on ", color: "gray" },
        { text: "MCConnect", color: "aqua", bold: true }
      ]
    }
  }))
  .onConnect((profile, protocol) => {
    console.log(`Connection: ${profile.name} (${profile.id})`);
    return { text: "Server is in maintenance mode", color: "red" };
  });

console.log("Server listening on port 25565");
```

---

## API Reference

### Constructor

### `new MCConnect([port = 25565])`

Creates a new protocol-level Minecraft server.

```javascript
const server = new MCConnect();       // Default port (25565)
const server = new MCConnect(25570);  // Custom port
```

---

## Methods

### `.onMOTD(handler)`

Sets the handler for server list status responses.

**Signature**
```js
(protocolVersion) => statusObject
```

**Status Object**
```javascript
{
  version: { name: "1.21", protocol: 763 },
  players: {
    max: 100,
    online: 42,
    sample: [{ name: "Player1", id: "uuid" }]
  },
  description: {
    text: "",
    extra: [
      { text: "Server MOTD", color: "gold", bold: true }
    ]
  },
  favicon: "data:image/png;base64,..."  // optional
}
```

---

### `.onConnect(handler)`

Called after successful login and Mojang session validation. Return a text component to disconnect the client with a custom message.

**Signature**
```js
(profile, protocolVersion) => textComponent | void
```

**Profile Object**
```javascript
{
  id: "uuid",
  name: "Player",
  properties: [
    { name: "textures", value: "base64...", signature: "..." }
  ]
}
```

---

### `.onRedirect(handler)`

Called after successful authentication. If the handler returns a `{ host, port }` object, the client is transferred to that server using Minecraft's native transfer packet (requires 1.20.5+ / protocol 766+). Return `null` or `undefined` to fall through to the `onConnect` handler instead.

**Signature**
```js
(profile, protocolVersion) => { host: string, port: number } | null
```

**Example**
```javascript
server.onRedirect((profile, protocol) => {
  if (profile.name === "Notch") {
    return { host: "vip.example.com", port: 25565 };
  }
  return null; // fall through to onConnect
});
```

> **Note:** Server transfers require the client to have the `transfersAllowed` option enabled (on by default in vanilla 1.20.5+). Clients on older protocol versions will not support this feature.

---

### `.setPingMode(mode)`

Sets the default ping response behavior.

```javascript
server.setPingMode('online');   // Respond immediately (default)
server.setPingMode('pinging');  // Simulate a 3–5s delay
```

---

### `.onPing(handler)`

Sets a custom ping handler for fine-grained control over ping responses.

**Signature**
```js
(payload, protocolVersion) => 'online' | 'pinging'
```

---

### `.close()`

Stops the server and closes the listening socket.

```javascript
await server.close();
```

---

## Examples

### Authentication Server

```javascript
import MCConnect from 'mcconnect';

new MCConnect(25565)
  .onMOTD(() => ({
    version: { name: "Auth", protocol: 763 },
    players: { max: 0, online: 0 },
    description: {
      text: "",
      extra: [{ text: "Authentication Portal", color: "gold", bold: true }]
    }
  }))
  .onConnect((profile) => {
    console.log(`Authenticated: ${profile.name}`);
    return { text: "Authentication successful!", color: "green" };
  });
```

---

### Redirect / Proxy Gateway

```javascript
import MCConnect from 'mcconnect';

new MCConnect(25565)
  .onMOTD(() => ({
    version: { name: "Gateway", protocol: 766 },
    players: { max: 0, online: 0 },
    description: { text: "Login Gateway", color: "gold" }
  }))
  .onRedirect((profile, protocol) => {
    console.log(`Redirecting ${profile.name} to lobby`);
    return { host: "lobby.example.com", port: 25565 };
  });
```

---

### Maintenance Mode

```javascript
import MCConnect from 'mcconnect';

new MCConnect(25565)
  .onMOTD(() => ({
    version: { name: "Maintenance", protocol: 763 },
    players: { max: 0, online: 0 },
    description: {
      text: "",
      extra: [
        { text: "Server Maintenance", color: "gold", bold: true },
        { text: "\nBack soon!", color: "gray" }
      ]
    }
  }))
  .onConnect(() => ({
    text: "Server is offline for maintenance.",
    color: "red"
  }));
```

---

### Protocol Test Server

```javascript
import MCConnect from 'mcconnect';

new MCConnect(25566)
  .onMOTD((protocol) => ({
    version: { name: "Test", protocol },
    players: { max: 20, online: 0 },
    description: {
      text: "",
      extra: [
        { text: "Protocol: ", color: "gray" },
        { text: `${protocol}`, color: "green", bold: true }
      ]
    }
  }))
  .onConnect((profile, protocol) => {
    console.log(`${profile.name} connected (v${protocol})`);
    return { text: `Protocol: ${protocol}`, color: "gray" };
  });
```

---

## Protocol Support

| Feature              | Details                     |
|----------------------|-----------------------------|
| Protocol versions    | 1.7.2 → Latest              |
| Encoding             | VarInt, UTF-8 strings       |
| Key exchange         | RSA-1024                    |
| Stream encryption    | AES-128-CFB8                |
| Authentication       | Mojang session verification |
| Server transfers     | Protocol 766+ (1.20.5+)     |

---

## Security

- Mojang session validation is mandatory for all connecting players
- All sessions are encrypted using RSA key exchange + AES-128-CFB8
- Malformed or invalid packets result in a graceful disconnect

**Recommended production safeguards:**
- Connection rate limiting
- Status ping throttling
- Session caching

---

## Limitations

- Not a gameplay server — protocol handling only
- No plugin or extension system
- Single-process by design
- Requires internet access for Mojang session authentication
- Server transfers require client protocol 766+ (Minecraft 1.20.5+)

---

## Building From Source

```bash
git clone https://github.com/Voxxin/mcconnect.git
cd mcconnect
npm install
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for your changes
4. Ensure all tests pass
5. Open a pull request

---

## License

ISC License — see `LICENSE` for details.