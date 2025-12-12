import net from "node:net";
import crypto from "node:crypto";

// --- PRIVATE HELPER CLASSES (Internal use only) ---

/**
 * Variable Integer (VarInt) encoder/decoder for Minecraft protocol
 * Handles the variable-length integer format used in Minecraft packets
 * @private
 */
class VarInt {
  /**
   * Reads a VarInt from buffer starting at given offset
   * @param {Buffer} buffer - Buffer containing VarInt data
   * @param {number} [offset=0] - Starting offset in buffer
   * @returns {Object} Object containing value and size {v: number, s: number}
   * @throws {Error} If VarInt exceeds maximum size (5 bytes)
   */
  static read(buffer, offset = 0) {
    let result = 0,
      shift = 0;
    do {
      const byteValue = buffer[offset + shift];
      result |= (byteValue & 0x7f) << (7 * shift++);
      if (shift > 5) throw new Error("VarInt too big");
      if (!(byteValue & 0x80)) break;
    } while (true);
    return { v: result, s: shift };
  }

  /**
   * Writes a VarInt to buffer
   * @param {number} value - Value to encode as VarInt
   * @returns {Buffer} Buffer containing encoded VarInt
   */
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

/**
 * Packet parser for Minecraft protocol data types
 * Handles string and byte array serialization/deserialization
 * @private
 */
class PacketParser {
  /**
   * Reads a length-prefixed UTF-8 string from buffer
   * @param {Buffer} buffer - Input buffer
   * @param {number} offset - Starting offset
   * @returns {Object} Object containing string value and bytes read {v: string, s: number}
   */
  static readString(buffer, offset) {
    const { v: length, s: size1 } = VarInt.read(buffer, offset);
    return {
      v: buffer.toString("utf8", offset + size1, offset + size1 + length),
      s: size1 + length,
    };
  }

  /**
   * Reads a length-prefixed byte array from buffer
   * @param {Buffer} buffer - Input buffer
   * @param {number} offset - Starting offset
   * @returns {Object} Object containing byte array and bytes read {v: Buffer, s: number}
   */
  static readByteArray(buffer, offset) {
    const { v: length, s: size1 } = VarInt.read(buffer, offset);
    return {
      v: buffer.slice(offset + size1, offset + size1 + length),
      s: size1 + length,
    };
  }

  /**
   * Encodes a string to Minecraft protocol format (length-prefixed UTF-8)
   * @param {string} str - String to encode
   * @returns {Buffer} Encoded string buffer
   */
  static writeString(str) {
    const stringBuffer = Buffer.from(str, "utf8");
    return Buffer.concat([VarInt.write(stringBuffer.length), stringBuffer]);
  }

  /**
   * Encodes a byte array to Minecraft protocol format (length-prefixed)
   * @param {Buffer} data - Data to encode
   * @returns {Buffer} Encoded data buffer
   */
  static writeByteArray(data) {
    return Buffer.concat([VarInt.write(data.length), data]);
  }
}

/**
 * Connection state manager for individual client connections
 * Tracks connection state, encryption, and buffers
 * @private
 */
class Connection {
  /**
   * Creates a new connection handler
   * @param {net.Socket} socket - TCP socket for the connection
   */
  constructor(socket) {
    this.socket = socket; // TCP socket
    this.buffer = Buffer.alloc(0); // Accumulated buffer
    this.state = "handshake"; // Connection state: 'handshake' | 'status' | 'login'
    this.protocolVersion = 0; // Protocol version
    this.verificationToken = null; // Verification token
    this.sharedSecret = null; // Shared secret for encryption
    this.username = null; // Username
    this.gameProfile = null; // Game profile (after authentication)
    this.cipher = null; // Cipher for outgoing data
    this.decipher = null; // Decipher for incoming data
  }

  /**
   * Appends incoming data to buffer, decrypting if encryption is enabled
   * @param {Buffer} data - Incoming data
   */
  append(data) {
    if (this.decipher) data = this.decipher.update(data);
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  /**
   * Consumes bytes from the beginning of the buffer
   * @param {number} size - Number of bytes to consume
   */
  consume(size) {
    this.buffer = this.buffer.slice(size);
  }

  /**
   * Writes data to socket, encrypting if encryption is enabled
   * @param {Buffer} data - Data to send
   */
  write(data) {
    if (this.cipher) data = this.cipher.update(data);
    this.socket.write(data);
  }
}

// --- MAIN EXPORTED CLASS ---

/**
 * Minecraft Protocol Server - Lightweight Minecraft server implementation
 *
 * A minimal, configurable Minecraft server that handles protocol-level communication,
 * including server list ping, player authentication, and connection management.
 *
 * Features:
 * - Full Minecraft protocol compliance (1.7+)
 * - Asynchronous event-driven architecture
 * - Customizable MOTD and ping responses
 * - Player authentication with Mojang sessions
 * - Encryption support
 * - Clean disconnect handling
 *
 * @class MCConnect
 * @example
 * const MCConnect = require('mcconnect');
 *
 * const server = new MCConnect(25565)
 *   .onMOTD((protocolVersion) => ({
 *     version: { name: "1.21", protocol: protocolVersion },
 *     players: { max: 100, online: 42, sample: [] },
 *     description: "§6Awesome Server §e[v1.21]",
 *     favicon: "data:image/png;base64,..."
 *   }))
 *   .onPing((payload, protocolVersion) => 'online')
 *   .onConnect((profile, protocolVersion) => {
 *     console.log(`${profile.name} (${profile.id}) attempted to connect`);
 *     return "§cServer is currently closed for maintenance";
 *   });
 */
export default class MCConnect {
  /**
   * Creates a new Minecraft protocol server
   * @param {number} [port=25565] - Port to listen on (default: 25565)
   */
  constructor(port = 25565) {
    // Generate RSA key pair for encryption
    this.#keys = crypto.generateKeyPairSync("rsa", {
      modulusLength: 1024, // 1024-bit RSA key (Minecraft requirement)
      publicExponent: 65537,
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    // Create TCP server
    this.#server = net.createServer((socket) => this.#handleConnection(socket));
    this.#server.listen(port);

    // Event handlers (initially null)
    this.#motdHandler = null; // MOTD (status) handler
    this.#connectHandler = null; // Connection handler
    this.#pingMode = "online"; // Default ping mode
    this.#pingHandler = null; // Custom ping handler
  }

  // Private fields
  #keys;
  #server;
  #motdHandler;
  #connectHandler;
  #pingMode;
  #pingHandler;

  /**
   * @callback MOTDHandler
   * @param {number} protocolVersion - The Minecraft protocol version number
   * @returns {Object} Server status response object
   * @returns {Object} return.version - Server version info
   * @returns {string} return.version.name - Human-readable version name (e.g., "1.21")
   * @returns {number} return.version.protocol - Protocol version number
   * @returns {Object} return.players - Player information
   * @returns {number} return.players.max - Maximum player capacity
   * @returns {number} return.players.online - Current online players
   * @returns {Array} return.players.sample - Sample player list (optional)
   * @returns {string|Object} return.description - Server MOTD/description (supports color codes)
   * @returns {string} [return.favicon] - Base64-encoded server icon (data:image/png;base64,...)
   */

  /**
   * Sets the MOTD (Server List Ping) handler
   * @param {MOTDHandler} handler - Function receiving protocol version and returning server status object
   * @returns {MCConnect} Returns self for chaining
   */
  onMOTD(handler) {
    this.#motdHandler = handler;
    return this;
  }

  /**
   * @callback ConnectHandler
   * @param {Object} gameProfile - Authenticated player profile from Mojang
   * @param {string} gameProfile.id - Player's unique Mojang ID (UUID)
   * @param {string} gameProfile.name - Player's username
   * @param {Object[]} [gameProfile.properties] - Additional player properties (textures, etc.)
   * @param {number} protocolVersion - The Minecraft protocol version number
   * @returns {string|null|undefined} Custom disconnect message, or null/undefined for default message
   */

  /**
   * Sets the player connection handler (called when player tries to join)
   * @param {ConnectHandler} handler - Function receiving game profile and protocol version
   * @returns {MCConnect} Returns self for chaining
   */
  onConnect(handler) {
    this.#connectHandler = handler;
    return this;
  }

  /**
   * Sets the ping response mode
   * @param {"online"|"pinging"} mode - 'online' (immediate response) or 'pinging' (delayed response, 3-5s)
   * @returns {MCConnect} Returns self for chaining
   */
  setPingMode(mode) {
    if (mode !== "online" && mode !== "pinging") {
      throw new Error('Ping mode must be either "online" or "pinging"');
    }
    this.#pingMode = mode;
    return this;
  }

  /**
   * @callback PingHandler
   * @param {Buffer} payload - The ping payload (8-byte timestamp)
   * @param {number} protocolVersion - The Minecraft protocol version number
   * @returns {"online"|"pinging"} Response mode: 'online' for immediate response, 'pinging' for delayed
   */

  /**
   * Sets a custom ping handler
   * @param {PingHandler} handler - Function receiving ping payload and protocol version
   * @returns {MCConnect} Returns self for chaining
   */
  onPing(handler) {
    this.#pingHandler = handler;
    return this;
  }

  /**
   * Closes the server and stops listening for connections
   * @returns {Promise<void>} Promise that resolves when server is closed
   */
  close() {
    return new Promise((resolve) => {
      this.#server.close(() => resolve());
    });
  }

  // --- PRIVATE METHODS ---

  /**
   * Handles new TCP connections
   * @private
   */
  #handleConnection(socket) {
    const connection = new Connection(socket);
    socket.on("data", async (data) => {
      connection.append(data);
      await this.#process(connection);
    });
    socket.on("error", (error) => {
      // Suppress common connection reset errors
      if (
        !error.message.includes("ECONNRESET") &&
        !error.message.includes("socket")
      ) {
        console.error("Connection error:", error);
      }
    });
  }

  /**
   * Processes incoming data from connection buffer
   * @private
   */
  async #process(connection) {
    while (connection.buffer.length > 0) {
      try {
        const { done, packet } = this.#parse(connection);
        if (!done) break;
        await this.#handle(packet, connection);
        connection.consume(packet.totalSize);
      } catch (error) {
        if (error.message.includes("Incomplete")) break;
        console.error("Packet processing error:", error);
        this.#disconnect(connection, "Internal error");
        break;
      }
    }
  }

  /**
   * Parses next packet from buffer
   * @private
   */
  #parse(connection) {
    if (connection.buffer.length < 1) return { done: false };
    const { v: length, s: lengthSize } = VarInt.read(connection.buffer, 0); // Read packet length
    const totalSize = lengthSize + length; // Total packet size
    if (connection.buffer.length < totalSize) throw new Error("Incomplete");
    const packetData = connection.buffer.slice(lengthSize, totalSize); // Packet data (without length)
    const { v: packetId } = VarInt.read(packetData, 0); // Packet ID
    return {
      done: true,
      packet: { id: packetId, length, data: packetData, totalSize },
    };
  }

  /**
   * Routes packet to appropriate handler based on connection state
   * @private
   */
  async #handle(packet, connection) {
    switch (connection.state) {
      case "handshake":
        await this.#handshake(packet, connection);
        break;
      case "status":
        await this.#status(packet, connection);
        break;
      case "login":
        await this.#login(packet, connection);
        break;
    }
  }

  /**
   * Handles handshake packet (first packet from client)
   * @private
   */
  async #handshake(packet, connection) {
    if (packet.id !== 0x00) return; // Only accept handshake packet
    const handshake = this.#parseHandshake(packet.data);
    connection.protocolVersion = handshake.protocolVersion; // Store protocol version

    // Switch to next state based on requested next state
    switch (handshake.nextState) {
      case 1:
        connection.state = "status";
        break; // Status request
      case 2:
        connection.state = "login";
        break; // Login request
      default:
        this.#disconnect(connection, "Bad handshake");
    }
  }

  /**
   * Parses handshake packet data
   * @private
   */
  #parseHandshake(buffer) {
    let offset = VarInt.read(buffer, 0).s; // Skip packet ID
    const protocolVersion = VarInt.read(buffer, offset); // Protocol version
    offset += protocolVersion.s;
    const serverAddress = PacketParser.readString(buffer, offset); // Server address
    offset += serverAddress.s;
    const serverPort = buffer.readUInt16BE(offset); // Server port
    offset += 2;
    const nextState = VarInt.read(buffer, offset); // Next state (1=status, 2=login)
    return {
      protocolVersion: protocolVersion.v,
      serverAddress: serverAddress.v,
      serverPort,
      nextState: nextState.v,
    };
  }

  /**
   * Handles status request packets
   * @private
   */
  async #status(packet, connection) {
    if (packet.id === 0x00) this.#sendStatus(connection); // Status request
    else if (packet.id === 0x01) await this.#ping(packet.data, connection); // Ping request
  }

  /**
   * Sends server status/MOTD response
   * @private
   */
  #sendStatus(connection) {
    // Get MOTD from handler or use default
    let response = this.#motdHandler
      ? this.#motdHandler(connection.protocolVersion)
      : {
          version: { name: "1.21", protocol: connection.protocolVersion },
          players: { max: 0, online: 0, sample: [] },
          description: { text: "Minecraft Server" },
        };

    // Ensure required fields exist
    response = {
      version: response.version || {
        name: "1.21",
        protocol: connection.protocolVersion,
      },
      players: response.players || { max: 0, online: 0, sample: [] },
      ...response,
    };

    // Normalize description (handle color codes, newlines, etc.)
    response.description = this.#normalizeDescription(response.description);

    // Build and send response packet
    const jsonBuffer = Buffer.from(JSON.stringify(response), "utf8");
    const packet = Buffer.concat([
      VarInt.write(0x00),
      VarInt.write(jsonBuffer.length),
      jsonBuffer,
    ]);
    this.#send(connection, packet);
  }

  /**
   * Normalizes description to prevent chat spam and ensure valid formatting
   * @private
   */
  #normalizeDescription(description) {
    if (!description) return { text: "Minecraft Server" };

    // Handle string descriptions with color codes
    if (typeof description === "string") {
      return this.#parseColorCodes(description);
    }

    // Handle object descriptions
    const normalized = { ...description };
    if (!normalized.hasOwnProperty("text")) normalized.text = "";

    // Validate color format
    if (normalized.color && typeof normalized.color === "string") {
      normalized.color = normalized.color.toLowerCase();
      if (
        normalized.color.startsWith("#") &&
        !/^[0-9A-Fa-f]{6}$/.test(normalized.color.slice(1))
      ) {
        normalized.color = "white"; // Fallback to white for invalid hex
      }
    }

    // Limit newlines to prevent chat spam
    const newlineCount = this.#countNewlines(normalized);
    if (newlineCount > 1) {
      return this.#limitNewlines(normalized, true);
    }

    return normalized;
  }

  /**
   * Parses Minecraft color codes (§) into JSON text components
   * @private
   */
  #parseColorCodes(string) {
    const parts = [];
    let current = { text: "" };
    let i = 0;

    while (i < string.length) {
      if (string[i] === "§" && i + 1 < string.length) {
        const code = string[i + 1].toLowerCase();
        if (current.text) parts.push(current);

        if (code === "r") {
          current = { text: "" }; // Reset formatting
        } else if ("0123456789abcdefklmnor".includes(code)) {
          const colorMap = {
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
          if (colorMap[code]) {
            current = { text: "", color: colorMap[code] };
          } else {
            current = { text: "" }; // Formatting codes not supported
          }
        }
        i += 2;
      } else {
        current.text += string[i];
        i++;
      }
    }

    if (current.text) parts.push(current);

    if (parts.length === 1) return parts[0];
    return { text: "", extra: parts };
  }

  /**
   * Counts newlines in text component (recursive)
   * @private
   */
  #countNewlines(component) {
    if (typeof component === "string") {
      return (component.match(/\n/g) || []).length;
    }
    let count = 0;
    if (component.text) count += (component.text.match(/\n/g) || []).length;
    if (Array.isArray(component.extra)) {
      for (const item of component.extra) count += this.#countNewlines(item);
    }
    return count;
  }

  /**
   * Limits newlines to prevent excessive chat spam
   * @private
   */
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
    if (Array.isArray(result.extra)) {
      result.extra = result.extra.map((item) =>
        this.#limitNewlines(item, allowFirst)
      );
    }
    return result;
  }

  /**
   * Handles ping request (immediate or delayed response)
   * @private
   */
  async #ping(packetData, connection) {
    const payload = packetData.slice(VarInt.read(packetData, 0).s); // Payload after packet ID

    // Use custom handler if set
    if (this.#pingHandler) {
      try {
        const response = this.#pingHandler(payload, connection.protocolVersion);
        if (response === "online") this.#pong(payload, connection);
        else if (response === "pinging") this.#simulatePing(connection);
        return;
      } catch (error) {
        console.error("Ping handler error:", error);
      }
    }

    // Use default mode
    this.#pingMode === "online"
      ? this.#pong(payload, connection)
      : this.#simulatePing(connection);
  }

  /**
   * Sends immediate pong response
   * @private
   */
  #pong(payload, connection) {
    this.#send(connection, Buffer.concat([VarInt.write(0x01), payload]));
  }

  /**
   * Simulates delayed ping response (3-5 seconds)
   * @private
   */
  #simulatePing(connection) {
    setTimeout(() => {
      if (!connection.socket.destroyed)
        this.#send(
          connection,
          Buffer.concat([VarInt.write(0x01), Buffer.alloc(8)])
        );
    }, 3000 + Math.random() * 2000);
  }

  /**
   * Handles login phase packets
   * @private
   */
  async #login(packet, connection) {
    if (packet.id === 0x00) await this.#loginStart(packet.data, connection); // Login start
    else if (packet.id === 0x01)
      await this.#encryptionResponse(packet.data, connection); // Encryption response
  }

  /**
   * Handles initial login packet (username)
   * @private
   */
  async #loginStart(buffer, connection) {
    const username = PacketParser.readString(buffer, VarInt.read(buffer, 0).s);
    connection.username = username.v;
    this.#sendEncryptionRequest(connection); // Start encryption handshake
  }

  /**
   * Sends encryption request to client
   * @private
   */
  #sendEncryptionRequest(connection) {
    connection.verificationToken = crypto.randomBytes(4); // 4-byte verification token

    let packet;
    // Different packet format for newer protocol versions
    if (connection.protocolVersion > 763) {
      packet = Buffer.concat([
        VarInt.write(0x01),
        PacketParser.writeString(""),
        PacketParser.writeByteArray(this.#keys.publicKey),
        PacketParser.writeByteArray(connection.verificationToken),
        Buffer.from([0x01]), // Enable encryption flag
      ]);
    } else {
      packet = Buffer.concat([
        VarInt.write(0x01),
        PacketParser.writeString(""),
        VarInt.write(this.#keys.publicKey.length),
        this.#keys.publicKey,
        VarInt.write(4),
        connection.verificationToken,
      ]);
    }
    this.#send(connection, packet);
  }

  /**
   * Handles encryption response from client
   * @private
   */
  async #encryptionResponse(buffer, connection) {
    const response = this.#parseEncryptionResponse(buffer);

    // Verify token matches
    if (response.decryptedToken.length > 0 && !response.decryptedToken.equals(connection.verificationToken)) {
      this.#disconnect(connection, "Bad token");
      return;
    }

    connection.sharedSecret = response.decryptedSecret; // Store shared secret
    const serverHash = this.#hash(connection.sharedSecret); // Compute server hash for authentication

    try {
      // Authenticate with Mojang session server
      connection.gameProfile = await this.#authenticate(connection.username, serverHash);
      this.#enableEncryption(connection); // Enable encryption

      // Call connection handler for custom disconnect message
      let message = "Disconnected.";
      if (this.#connectHandler) {
        const handlerResult = this.#connectHandler(connection.gameProfile, connection.protocolVersion);
        if (handlerResult !== undefined && handlerResult !== null) message = handlerResult;
      }
      this.#disconnect(connection, message);
    } catch (error) {
      this.#disconnect(connection, "Authentication failed");
    }
  }

  /**
   * Parses encryption response packet
   * @private
   */
  #parseEncryptionResponse(buffer) {
    let offset = VarInt.read(buffer, 0).s;
    const encryptedSecret = PacketParser.readByteArray(buffer, offset); // Encrypted shared secret
    offset += encryptedSecret.s;

    let encryptedToken = Buffer.alloc(0);
    if (offset < buffer.length) {
      const tokenResult = PacketParser.readByteArray(buffer, offset); // Encrypted verification token
      encryptedToken = tokenResult.v;
    }

    // Decrypt with private key
    const decrypt = (data) =>
      crypto.privateDecrypt(
        {
          key: this.#keys.privateKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        data
      );

    return {
      decryptedSecret: decrypt(encryptedSecret.v),
      decryptedToken: encryptedToken.length > 0 ? decrypt(encryptedToken) : encryptedToken,
    };
  }

  /**
   * Computes Minecraft authentication hash
   * @private
   */
  #hash(sharedSecret) {
    const hash = crypto.createHash("sha1");
    hash.update(Buffer.alloc(0)); // Server ID (empty for offline mode)
    hash.update(sharedSecret); // Shared secret
    hash.update(this.#keys.publicKey); // Server public key
    const hex = hash.digest("hex");

    // Convert to signed hex (Minecraft-specific format)
    const bigInt = BigInt("0x" + hex);
    return bigInt >= 1n << 159n
      ? (bigInt - (1n << 160n)).toString(16)
      : bigInt.toString(16);
  }

  /**
   * Authenticates player with Mojang session server
   * @private
   */
  async #authenticate(username, serverHash) {
    const response = await fetch(
      `https://sessionserver.mojang.com/session/minecraft/hasJoined?username=${encodeURIComponent(
        username
      )}&serverId=${serverHash}`
    );
    if (!response.ok) throw new Error(`Mojang API failure: ${response.status}`);
    return response.json();
  }

  /**
   * Enables AES encryption on the connection
   * @private
   */
  #enableEncryption(connection) {
    // Use shared secret as both key and IV for AES-128-CFB8
    connection.cipher = crypto.createCipheriv("aes-128-cfb8", connection.sharedSecret, connection.sharedSecret);
    connection.decipher = crypto.createDecipheriv("aes-128-cfb8", connection.sharedSecret, connection.sharedSecret);
  }

  /**
   * Sends packet to client (with length prefix)
   * @private
   */
  #send(connection, data) {
    const length = VarInt.write(data.length); // Packet length prefix
    connection.write(Buffer.concat([length, data]));
  }

  /**
   * Disconnects client with formatted message
   * @private
   */
  #disconnect(connection, reason) {
    // Normalize disconnect message
    const normalizedReason = this.#normalizeDescription(reason);
    const reasonBuffer = Buffer.from(JSON.stringify(normalizedReason), "utf8");
    const packet = Buffer.concat([
      VarInt.write(0x00),
      VarInt.write(reasonBuffer.length),
      reasonBuffer,
    ]);
    this.#send(connection, packet);

    // Close connection after brief delay
    setTimeout(() => connection.socket.end(), 100);
  }
}