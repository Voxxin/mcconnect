import net from "node:net";
import crypto from "node:crypto";

// --- VarInt ---

class VarInt {
  static read(buffer, offset = 0) {
    let result = 0,
      shift = 0;
    do {
      const byte = buffer[offset + shift];
      result |= (byte & 0x7f) << (7 * shift++);
      if (shift > 5) throw new Error("VarInt too big");
      if (!(byte & 0x80)) break;
    } while (true);
    return { v: result, s: shift };
  }

  static write(value) {
    const bytes = [];
    do {
      let temp = value & 0x7f;
      value >>>= 7;
      if (value) temp |= 0x80;
      bytes.push(temp);
    } while (value);
    return Buffer.from(bytes);
  }
}

// --- PacketParser ---

class PacketParser {
  static readString(buffer, offset) {
    const { v: length, s: size } = VarInt.read(buffer, offset);
    return {
      v: buffer.toString("utf8", offset + size, offset + size + length),
      s: size + length,
    };
  }

  static readByteArray(buffer, offset) {
    const { v: length, s: size } = VarInt.read(buffer, offset);
    return {
      v: buffer.slice(offset + size, offset + size + length),
      s: size + length,
    };
  }

  static writeString(str) {
    const buf = Buffer.from(str, "utf8");
    return Buffer.concat([VarInt.write(buf.length), buf]);
  }

  static writeByteArray(data) {
    return Buffer.concat([VarInt.write(data.length), data]);
  }

  static writeUUID(uuid) {
    return Buffer.from(uuid.replace(/-/g, ""), "hex");
  }

  /**
   * Encodes a Mojang Game Profile for the Login Success packet.
   * Format changed in protocol 776 (26.2): added `strict_error_handling` boolean.
   */
  static writeGameProfile(profile, protocolVersion) {
    const parts = [
      PacketParser.writeUUID(profile.id),
      PacketParser.writeString(profile.name),
      VarInt.write(profile.properties?.length ?? 0),
    ];

    for (const prop of profile.properties ?? []) {
      parts.push(PacketParser.writeString(prop.name));
      parts.push(PacketParser.writeString(prop.value));
      if (prop.signature) {
        parts.push(Buffer.from([0x01]));
        parts.push(PacketParser.writeString(prop.signature));
      } else {
        parts.push(Buffer.from([0x00]));
      }
    }

    // Protocol 776 (26.2) appended a random session UUID to login_finished
    if (protocolVersion >= 776) {
      parts.push(crypto.randomBytes(16));
    }

    return Buffer.concat(parts);
  }
}

// --- Connection ---

class Connection {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.state = "handshake"; // handshake | status | login | configuration
    this.protocolVersion = 0;
    this.serverAddress = '';
    this.verificationToken = null;
    this.sharedSecret = null;
    this.username = null;
    this.gameProfile = null;
    this.cipher = null;
    this.decipher = null;
    this.redirectTarget = null;
  }

  append(data) {
    if (this.decipher) data = this.decipher.update(data);
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  consume(size) {
    this.buffer = this.buffer.slice(size);
  }

  write(data) {
    if (this.cipher) data = this.cipher.update(data);
    this.socket.write(data);
  }
}

// --- MCConnect ---

/**
 * Lightweight Minecraft protocol server (1.7+ → latest).
 *
 * Handles handshake, status/ping, login, Mojang authentication,
 * encryption, and server transfers. Does not simulate gameplay.
 *
 * @example
 * const server = new MCConnect(25565)
 *   .onMOTD((protocol) => ({
 *     version: { name: "1.21", protocol },
 *     players: { max: 100, online: 0 },
 *     description: { text: "Hello world" },
 *   }))
 *   .onConnect((profile) => {
 *     console.log(`${profile.name} connected`);
 *     return "Server under maintenance.";
 *   });
 */
export default class MCConnect {
  #keys;
  #server;
  #motdHandler = null;
  #connectHandler = null;
  #redirectHandler = null;
  #pingMode = "online";
  #pingHandler = null;

  /** @param {number} [port=25565] */
  constructor(port = 25565) {
    this.#keys = crypto.generateKeyPairSync("rsa", {
      modulusLength: 1024,
      publicExponent: 65537,
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    this.#server = net.createServer((socket) => this.#handleConnection(socket));
    this.#server.listen(port);
  }

  // --- Public API ---

  /**
   * Sets the server list status/MOTD handler.
   * @param {(protocolVersion: number) => object} handler
   * @returns {this}
   */
  onMOTD(handler) {
    this.#motdHandler = handler;
    return this;
  }

  /**
   * Called after successful Mojang authentication. Return a text component
   * to disconnect the client with a custom message.
   * @param {(profile: object, protocolVersion: number, serverAddress: string) => object|string|null} handler
   * @returns {this}
   */
  onConnect(handler) {
    this.#connectHandler = handler;
    return this;
  }

  /**
   * Called after authentication. Return `{ host, port }` to transfer the
   * client to another server (requires client protocol 766+), or `null`
   * to fall through to `onConnect`.
   * @param {(profile: object, protocolVersion: number, serverAddress: string) => {host: string, port: number, serverAddress: string}|null} handler
   * @returns {this}
   */
  onRedirect(handler) {
    this.#redirectHandler = handler;
    return this;
  }

  /**
   * @param {"online"|"pinging"} mode  `online` = immediate, `pinging` = 3–5s delay
   * @returns {this}
   */
  setPingMode(mode) {
    if (mode !== "online" && mode !== "pinging")
      throw new Error('Ping mode must be "online" or "pinging"');
    this.#pingMode = mode;
    return this;
  }

  /**
   * Custom ping handler. Return `"online"` or `"pinging"`.
   * @param {(payload: Buffer, protocolVersion: number, serverAddress: string) => "online"|"pinging"} handler
   * @returns {this}
   */
  onPing(handler) {
    this.#pingHandler = handler;
    return this;
  }

  /** @returns {Promise<void>} */
  close() {
    return new Promise((resolve) => this.#server.close(resolve));
  }

  // --- Connection handling ---

  #handleConnection(socket) {
    const connection = new Connection(socket);

    socket.on("data", async (data) => {
      connection.append(data);
      await this.#process(connection);
    });

    socket.on("error", (err) => {
      if (
        !err.message.includes("ECONNRESET") &&
        !err.message.includes("socket")
      ) {
        console.error("Connection error:", err);
      }
    });
  }

  async #process(connection) {
    while (connection.buffer.length > 0) {
      try {
        const { done, packet } = this.#parse(connection);
        if (!done) break;
        await this.#handle(packet, connection);
        connection.consume(packet.totalSize);
      } catch (err) {
        if (err.message.includes("Incomplete")) break;
        console.error("Packet error:", err);
        this.#disconnect(connection, "Internal error");
        break;
      }
    }
  }

  #parse(connection) {
    if (connection.buffer.length < 1) return { done: false };
    const { v: length, s: lengthSize } = VarInt.read(connection.buffer, 0);
    const totalSize = lengthSize + length;
    if (connection.buffer.length < totalSize) throw new Error("Incomplete");
    const data = connection.buffer.slice(lengthSize, totalSize);
    const { v: id } = VarInt.read(data, 0);
    return { done: true, packet: { id, length, data, totalSize } };
  }

  async #handle(packet, connection) {
    switch (connection.state) {
      case "handshake":
        return this.#handshake(packet, connection);
      case "status":
        return this.#status(packet, connection);
      case "login":
        return this.#login(packet, connection);
      case "configuration":
        return; // nothing to handle before transfer/disconnect
    }
  }

  // --- Handshake ---

  async #handshake(packet, connection) {
    if (packet.id !== 0x00) return;
    const { protocolVersion, serverAddress, nextState } = this.#parseHandshake(packet.data);
    connection.protocolVersion = protocolVersion;
    connection.serverAddress = serverAddress;
    if (nextState === 1) connection.state = "status";
    else if (nextState === 2 || nextState === 3) connection.state = "login";
    else this.#disconnect(connection, "Bad handshake");
  }

  #parseHandshake(buffer) {
    let offset = VarInt.read(buffer, 0).s;
    const protocolVersion = VarInt.read(buffer, offset);
    offset += protocolVersion.s;
    const serverAddress = PacketParser.readString(buffer, offset);
    offset += serverAddress.s;
    offset += 2; // port (UInt16BE)
    const nextState = VarInt.read(buffer, offset);
    return { protocolVersion: protocolVersion.v, serverAddress: serverAddress.v, nextState: nextState.v };
  }

  // --- Status ---

  async #status(packet, connection) {
    if (packet.id === 0x00) this.#sendStatus(connection);
    else if (packet.id === 0x01) await this.#ping(packet.data, connection);
  }

  #sendStatus(connection) {
    const response = {
      version: { name: "1.21", protocol: connection.protocolVersion },
      players: { max: 0, online: 0, sample: [] },
      description: { text: "Minecraft Server" },
      ...(this.#motdHandler?.(connection.protocolVersion) ?? {}),
    };
    response.description = this.#normalizeDescription(response.description);

    const json = Buffer.from(JSON.stringify(response), "utf8");
    this.#send(
      connection,
      Buffer.concat([VarInt.write(0x00), VarInt.write(json.length), json]),
    );
  }

  async #ping(packetData, connection) {
    const payload = packetData.slice(VarInt.read(packetData, 0).s);
    let mode = this.#pingMode;
    if (this.#pingHandler) {
      try {
        mode = this.#pingHandler(payload, connection.protocolVersion, connection.serverAddress);
      } catch (e) {
        console.error("Ping handler error:", e);
      }
    }
    mode === "online"
      ? this.#send(connection, Buffer.concat([VarInt.write(0x01), payload]))
      : setTimeout(
        () => {
          if (!connection.socket.destroyed)
            this.#send(
              connection,
              Buffer.concat([VarInt.write(0x01), Buffer.alloc(8)]),
            );
        },
        3000 + Math.random() * 2000,
      );
  }

  // --- Login ---

  async #login(packet, connection) {
    if (packet.id === 0x00) await this.#loginStart(packet.data, connection);
    else if (packet.id === 0x01)
      await this.#encryptionResponse(packet.data, connection);
    else if (packet.id === 0x03) await this.#loginAcknowledged(connection);
  }

  async #loginStart(buffer, connection) {
    connection.username = PacketParser.readString(
      buffer,
      VarInt.read(buffer, 0).s,
    ).v;
    this.#sendEncryptionRequest(connection);
  }

  #sendEncryptionRequest(connection) {
    connection.verificationToken = crypto.randomBytes(4);

    // Encryption Request format changed at protocol 764
    const packet =
      connection.protocolVersion > 763
        ? Buffer.concat([
          VarInt.write(0x01),
          PacketParser.writeString(""),
          PacketParser.writeByteArray(this.#keys.publicKey),
          PacketParser.writeByteArray(connection.verificationToken),
          Buffer.from([0x01]), // should_authenticate = true
        ])
        : Buffer.concat([
          VarInt.write(0x01),
          PacketParser.writeString(""),
          VarInt.write(this.#keys.publicKey.length),
          this.#keys.publicKey,
          VarInt.write(4),
          connection.verificationToken,
        ]);

    this.#send(connection, packet);
  }

  async #encryptionResponse(buffer, connection) {
    const { decryptedSecret, decryptedToken } =
      this.#parseEncryptionResponse(buffer);

    if (
      decryptedToken.length > 0 &&
      !decryptedToken.equals(connection.verificationToken)
    ) {
      return this.#disconnect(connection, "Bad token");
    }

    connection.sharedSecret = decryptedSecret;

    try {
      connection.gameProfile = await this.#authenticate(
        connection.username,
        this.#hash(decryptedSecret),
      );
    } catch {
      return this.#disconnect(connection, "Authentication failed");
    }

    this.#enableEncryption(connection);

    // Check for redirect first
    if (this.#redirectHandler) {
      try {
        const target = this.#redirectHandler(
          connection.gameProfile,
          connection.protocolVersion,
          connection.serverAddress,
        );
        if (target?.host && typeof target.port === "number") {
          connection.redirectTarget = target;
          this.#sendLoginSuccess(connection);
          return;
        }
      } catch (e) {
        console.error("Redirect handler error:", e);
      }
    }

    // Otherwise disconnect with custom or default message
    let message = "Disconnected.";
    if (this.#connectHandler) {
      try {
        const result = this.#connectHandler(
          connection.gameProfile,
          connection.protocolVersion,
          connection.serverAddress,
        );
        if (result != null) message = result;
      } catch (e) {
        console.error("Connect handler error:", e);
      }
    }
    this.#disconnect(connection, message);
  }

  #sendLoginSuccess(connection) {
    const profileData = PacketParser.writeGameProfile(
      connection.gameProfile,
      connection.protocolVersion,
    );
    const packet = Buffer.concat([VarInt.write(0x02), profileData]);
    this.#send(connection, packet);
  }

  async #loginAcknowledged(connection) {
    connection.state = "configuration";
    if (connection.redirectTarget) this.#sendTransfer(connection);
  }

  #sendTransfer(connection) {
    this.#send(
      connection,
      Buffer.concat([
        VarInt.write(0x0b),
        PacketParser.writeString(connection.redirectTarget.host),
        VarInt.write(connection.redirectTarget.port),
      ]),
    );
    setTimeout(() => connection.socket.end(), 100);
  }

  // --- Crypto ---

  #parseEncryptionResponse(buffer) {
    let offset = VarInt.read(buffer, 0).s;
    const encryptedSecret = PacketParser.readByteArray(buffer, offset);
    offset += encryptedSecret.s;
    const encryptedToken =
      offset < buffer.length
        ? PacketParser.readByteArray(buffer, offset).v
        : Buffer.alloc(0);

    const decrypt = (data) =>
      crypto.privateDecrypt(
        {
          key: this.#keys.privateKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        data,
      );

    return {
      decryptedSecret: decrypt(encryptedSecret.v),
      decryptedToken:
        encryptedToken.length > 0 ? decrypt(encryptedToken) : encryptedToken,
    };
  }

  #hash(sharedSecret) {
    const hash = crypto.createHash("sha1");
    hash.update(Buffer.alloc(0));
    hash.update(sharedSecret);
    hash.update(this.#keys.publicKey);
    const hex = hash.digest("hex");
    const big = BigInt("0x" + hex);
    return (big >= 1n << 159n ? big - (1n << 160n) : big).toString(16);
  }

  async #authenticate(username, serverHash) {
    const url = `https://sessionserver.mojang.com/session/minecraft/hasJoined?username=${encodeURIComponent(username)}&serverId=${serverHash}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Mojang API error: ${res.status}`);
    return res.json();
  }

  #enableEncryption(connection) {
    connection.cipher = crypto.createCipheriv(
      "aes-128-cfb8",
      connection.sharedSecret,
      connection.sharedSecret,
    );
    connection.decipher = crypto.createDecipheriv(
      "aes-128-cfb8",
      connection.sharedSecret,
      connection.sharedSecret,
    );
  }

  // --- Send / Disconnect ---

  #send(connection, data) {
    connection.write(Buffer.concat([VarInt.write(data.length), data]));
  }

  #disconnect(connection, reason) {
    const normalized = this.#normalizeDescription(reason);
    const body = Buffer.from(JSON.stringify(normalized), "utf8");
    this.#send(
      connection,
      Buffer.concat([VarInt.write(0x00), VarInt.write(body.length), body]),
    );
    setTimeout(() => connection.socket.end(), 100);
  }

  // --- Description normalization ---

  #normalizeDescription(description) {
    if (!description) return { text: "Minecraft Server" };
    if (typeof description === "string")
      return this.#parseColorCodes(description);

    const normalized = { text: "", ...description };

    if (
      normalized.color?.startsWith?.("#") &&
      !/^#[0-9A-Fa-f]{6}$/.test(normalized.color)
    ) {
      normalized.color = "white";
    }

    if (this.#countNewlines(normalized) > 1)
      return this.#limitNewlines(normalized, true);
    return normalized;
  }

  #parseColorCodes(string) {
    const COLOR_MAP = {
      0: "black",
      1: "dark_blue",
      2: "dark_green",
      3: "dark_aqua",
      4: "dark_red",
      5: "dark_purple",
      6: "gold",
      7: "gray",
      8: "dark_gray",
      9: "blue",
      a: "green",
      b: "aqua",
      c: "red",
      d: "light_purple",
      e: "yellow",
      f: "white",
    };

    const parts = [];
    let current = { text: "" };

    for (let i = 0; i < string.length; i++) {
      if (string[i] === "§" && i + 1 < string.length) {
        if (current.text) parts.push(current);
        const code = string[++i].toLowerCase();
        current =
          code === "r"
            ? { text: "" }
            : {
              text: "",
              ...(COLOR_MAP[code] ? { color: COLOR_MAP[code] } : {}),
            };
      } else {
        current.text += string[i];
      }
    }

    if (current.text) parts.push(current);
    return parts.length === 1 ? parts[0] : { text: "", extra: parts };
  }

  #countNewlines(component) {
    if (typeof component === "string")
      return (component.match(/\n/g) ?? []).length;
    let count = (component.text?.match?.(/\n/g) ?? []).length;
    if (Array.isArray(component.extra))
      count += component.extra.reduce((n, c) => n + this.#countNewlines(c), 0);
    return count;
  }

  #limitNewlines(component, allowFirst = true) {
    if (typeof component === "string") {
      if (!allowFirst) return component.replace(/\n/g, " ");
      const parts = component.split("\n");
      return parts.length <= 2
        ? component
        : `${parts[0]}\n${parts.slice(1).join(" ")}`;
    }
    const result = { ...component };
    if (result.text) {
      result.text = this.#limitNewlines(result.text, allowFirst);
      if (result.text.includes("\n")) allowFirst = false;
    }
    if (Array.isArray(result.extra))
      result.extra = result.extra.map((c) =>
        this.#limitNewlines(c, allowFirst),
      );
    return result;
  }
}
