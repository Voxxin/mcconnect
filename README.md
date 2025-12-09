# mcconnect

A lightweight, protocol-level Minecraft server implementation for Node.js.
Designed for authentication services, proxy backends, protocol analysis tools, and minimal custom servers.

## Overview

`mcconnect` provides a clean, fast, and dependency-free implementation of the Minecraft protocol (1.7+ → latest).
It focuses on handshake, status, ping, login, and authentication workflows without simulating gameplay.

## Features

* Full Minecraft protocol coverage (1.7+)
* Asynchronous, event-driven architecture
* Customizable MOTD and JSON text components
* Mojang session authentication and encryption
* Configurable ping modes
* Graceful disconnection handling
* Zero external dependencies (Node.js core only)

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
        { name: "Notch", id: "069a79f4-44e9-4726-a5be-fca90e38aaf5" },
        { name: "Alex", id: "069a79f4-44e9-4726-a5be-fca90e38aaf6" }
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

### `new mcconnect([port = 25565])`

Creates a new protocol-level Minecraft server.

```javascript
const server = new mcconnect();      // Default port
const server2 = new mcconnect(25570); // Custom port
```

---

## Server Methods

### `.onMOTD(handler)`

Sets the handler for status responses.

**Handler Signature**

```js
(protocolVersion) => statusObject
```

**Status Format**

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
  favicon: "data:image/png;base64,..."
}
```

---

### `.onConnect(handler)`

Called after successful login + session validation.

**Signature**

```js
(profile, protocolVersion) => object | void
```

Return a text component object to disconnect the client with that message.

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

### `.setPingMode(mode)`

Sets default ping handling behavior.

```javascript
server.setPingMode('online');  // instant (default)
server.setPingMode('pinging'); // simulated delay
```

---

### `.onPing(handler)`

Custom ping handler for advanced control.

```js
(payload, protocolVersion) => 'online' | 'pinging' | other
```

---

## Examples

### Authentication Server

```javascript
import MCConnect from 'mcconnect';

const auth = new MCConnect(25565)
  .onMOTD(() => ({
    version: { name: "Auth", protocol: 763 },
    players: { max: 0, online: 0 },
    description: {
      text: "",
      extra: [
        { text: "Authentication Portal", color: "gold", bold: true }
      ]
    }
  }))
  .onConnect((profile) => {
    console.log(`Authenticated: ${profile.name}`);
    return { text: "Authentication successful", color: "green" };
  });
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
        { text: "Testing protocol ", color: "gray" },
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

### Maintenance Proxy

```javascript
import MCConnect from 'mcconnect';

new MCConnect(25565)
  .onMOTD(() => ({
    version: { name: "MAINTENANCE", protocol: 763 },
    players: { max: 0, online: 0 },
    description: {
      text: "",
      extra: [
        { text: "Server Maintenance", color: "gold", bold: true },
        { text: "\nReturning shortly", color: "gray" }
      ]
    }
  }))
  .onConnect(() => ({
    text: "Server offline for maintenance",
    color: "red"
  }));
```

---

## Protocol Support

* Protocol versions: **1.7.2 → Latest**
* Variable-length integers (VarInt)
* UTF-8 strings
* RSA (1024-bit) key exchange
* AES-128-CFB8 encrypted streams
* Mojang session verification
* Status, ping, login, disconnect flows

---

## Security

* Mojang session validation is mandatory
* Encrypted sessions using RSA + AES
* Graceful disconnect on malformed or invalid packets
* Recommended production safeguards:

  * Connection rate limiting
  * Status ping throttling
  * Session caching

---

## Performance

* Low memory usage (2–5 KB idle per connection)
* Handles thousands of simultaneous status requests
* Minimal allocations, buffer reuse where possible

---

## Limitations

1. Not a gameplay server — protocol only
2. No plugin/extension system
3. Single-process by design
4. Requires internet access for Mojang session authentication

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
3. Add tests
4. Ensure tests pass
5. Open a pull request

---

## License

ISC License — see `LICENSE` for details.
