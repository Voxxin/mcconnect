import net from 'node:net';
import crypto from 'node:crypto';

// --- PRIVATE HELPER CLASSES (Internal use only) ---

/**
 * Variable Integer (VarInt) encoder/decoder for Minecraft protocol
 * Handles the variable-length integer format used in Minecraft packets
 * @private
 */
class VarInt {
    /**
     * Reads a VarInt from buffer starting at given offset
     * @param {Buffer} b - Buffer containing VarInt data
     * @param {number} [o=0] - Starting offset in buffer
     * @returns {Object} Object containing value and size {v: number, s: number}
     * @throws {Error} If VarInt exceeds maximum size (5 bytes)
     */
    static read(b, o = 0) {
        let r = 0, s = 0;
        do {
            const bv = b[o + s];
            r |= (bv & 0x7F) << (7 * s++);
            if (s > 5) throw new Error("VarInt too big");
            if (!(bv & 0x80)) break;
        } while (true);
        return { v: r, s };
    }

    /**
     * Writes a VarInt to buffer
     * @param {number} v - Value to encode as VarInt
     * @returns {Buffer} Buffer containing encoded VarInt
     */
    static write(v) {
        const b = [];
        do {
            let t = v & 0x7F;
            v >>>= 7;
            if (v) t |= 0x80;
            b.push(t);
        } while (v);
        return Buffer.from(b);
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
     * @param {Buffer} b - Input buffer
     * @param {number} o - Starting offset
     * @returns {Object} Object containing string value and bytes read {v: string, s: number}
     */
    static readString(b, o) {
        const { v: l, s: s1 } = VarInt.read(b, o);
        return { v: b.toString('utf8', o + s1, o + s1 + l), s: s1 + l };
    }

    /**
     * Reads a length-prefixed byte array from buffer
     * @param {Buffer} b - Input buffer
     * @param {number} o - Starting offset
     * @returns {Object} Object containing byte array and bytes read {v: Buffer, s: number}
     */
    static readByteArray(b, o) {
        const { v: l, s: s1 } = VarInt.read(b, o);
        return { v: b.slice(o + s1, o + s1 + l), s: s1 + l };
    }

    /**
     * Encodes a string to Minecraft protocol format (length-prefixed UTF-8)
     * @param {string} s - String to encode
     * @returns {Buffer} Encoded string buffer
     */
    static writeString(s) {
        const sb = Buffer.from(s, 'utf8');
        return Buffer.concat([VarInt.write(sb.length), sb]);
    }

    /**
     * Encodes a byte array to Minecraft protocol format (length-prefixed)
     * @param {Buffer} d - Data to encode
     * @returns {Buffer} Encoded data buffer
     */
    static writeByteArray(d) {
        return Buffer.concat([VarInt.write(d.length), d]);
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
     * @param {net.Socket} c - TCP socket for the connection
     */
    constructor(c) {
        this.c = c;                    // TCP socket
        this.b = Buffer.alloc(0);      // Accumulated buffer
        this.s = 'handshake';          // Connection state: 'handshake' | 'status' | 'login'
        this.pv = 0;                   // Protocol version
        this.vt = null;                // Verification token
        this.ss = null;                // Shared secret for encryption
        this.un = null;                // Username
        this.gp = null;                // Game profile (after authentication)
        this.cph = null;               // Cipher for outgoing data
        this.dcph = null;              // Decipher for incoming data
    }

    /**
     * Appends incoming data to buffer, decrypting if encryption is enabled
     * @param {Buffer} d - Incoming data
     */
    append(d) {
        if (this.dcph) d = this.dcph.update(d);
        this.b = Buffer.concat([this.b, d]);
    }

    /**
     * Consumes bytes from the beginning of the buffer
     * @param {number} sz - Number of bytes to consume
     */
    consume(sz) {
        this.b = this.b.slice(sz);
    }

    /**
     * Writes data to socket, encrypting if encryption is enabled
     * @param {Buffer} d - Data to send
     */
    write(d) {
        if (this.cph) d = this.cph.update(d);
        this.c.write(d);
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
 * @class mcconnect
 * @example
 * const mcconnect = require('mcconnect');
 * 
 * const server = new mcconnect(25565)
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
    constructor(p = 25565) {
        // Generate RSA key pair for encryption
        this.keys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 1024,              // 1024-bit RSA key (Minecraft requirement)
            publicExponent: 65537,
            publicKeyEncoding: { type: 'spki', format: 'der' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        // Create TCP server
        this.srv = net.createServer(c => this._handleConn(c));
        this.srv.listen(p);

        // Event handlers (initially null)
        this.motdH = null;    // MOTD (status) handler
        this.connH = null;    // Connection handler
        this.pingM = 'online'; // Default ping mode
        this.pingH = null;    // Custom ping handler
    }

    /**
     * Sets the MOTD (Server List Ping) handler
     * @param {Function} handler - Function returning server status object
     * @returns {mcconnect} Returns self for chaining
     */
    onMOTD(h) { this.motdH = h; return this; }

    /**
     * Sets the player connection handler (called when player tries to join)
     * @param {Function} handler - Function processing connection attempts
     * @returns {mcconnect} Returns self for chaining
     */
    onConnect(h) { this.connH = h; return this; }

    /**
     * Sets the ping response mode
     * @param {string} mode - 'online' (immediate) or 'pinging' (delayed)
     * @returns {mcconnect} Returns self for chaining
     */
    setPingMode(m) { this.pingM = m; return this; }

    /**
     * Sets a custom ping handler
     * @param {Function} handler - Custom ping handler function
     * @returns {mcconnect} Returns self for chaining
     */
    onPing(h) { this.pingH = h; return this; }

    // --- PRIVATE METHODS ---

    /**
     * Handles new TCP connections
     * @private
     */
    async _handleConn(c) {
        const s = new Connection(c);
        c.on('data', async d => {
            s.append(d);
            await this._process(s);
        });
        c.on('error', e => {
            // Suppress common connection reset errors
            if (!e.message.includes('ECONNRESET') && !e.message.includes('socket')) {
                console.error('Conn error:', e);
            }
        });
    }

    /**
     * Processes incoming data from connection buffer
     * @private
     */
    async _process(s) {
        while (s.b.length > 0) {
            try {
                const { done, pkt } = this._parse(s);
                if (!done) break;
                await this._handle(pkt, s);
                s.consume(pkt.ts);
            } catch (e) {
                if (e.message.includes("Incomplete")) break;
                console.error('Pkt error:', e);
                this._dc(s, 'Internal error');
                break;
            }
        }
    }

    /**
     * Parses next packet from buffer
     * @private
     */
    _parse(s) {
        if (s.b.length < 1) return { done: false };
        const { v: l, s: ls } = VarInt.read(s.b, 0); // Read packet length
        const ts = ls + l; // Total packet size
        if (s.b.length < ts) throw new Error("Incomplete");
        const pd = s.b.slice(ls, ts); // Packet data (without length)
        const { v: pid } = VarInt.read(pd, 0); // Packet ID
        return { done: true, pkt: { id: pid, l, d: pd, ts } };
    }

    /**
     * Routes packet to appropriate handler based on connection state
     * @private
     */
    async _handle(p, s) {
        switch (s.s) {
            case 'handshake': await this._handshake(p, s); break;
            case 'status': await this._status(p, s); break;
            case 'login': await this._login(p, s); break;
        }
    }

    /**
     * Handles handshake packet (first packet from client)
     * @private
     */
    async _handshake(p, s) {
        if (p.id !== 0x00) return; // Only accept handshake packet
        const hs = this._parseHS(p.d);
        s.pv = hs.pv; // Store protocol version
        
        // Switch to next state based on requested next state
        switch (hs.ns) {
            case 1: s.s = 'status'; break; // Status request
            case 2: s.s = 'login'; break;  // Login request
            default: this._dc(s, 'Bad handshake');
        }
    }

    /**
     * Parses handshake packet data
     * @private
     */
    _parseHS(b) {
        let o = VarInt.read(b, 0).s; // Skip packet ID
        const pv = VarInt.read(b, o); // Protocol version
        o += pv.s;
        const sa = PacketParser.readString(b, o); // Server address
        o += sa.s;
        const pt = b.readUInt16BE(o); // Server port
        o += 2;
        const ns = VarInt.read(b, o); // Next state (1=status, 2=login)
        return { pv: pv.v, sa: sa.v, pt, ns: ns.v };
    }

    /**
     * Handles status request packets
     * @private
     */
    async _status(p, s) {
        if (p.id === 0x00) this._sendStatus(s);      // Status request
        else if (p.id === 0x01) await this._ping(p.d, s); // Ping request
    }

    /**
     * Sends server status/MOTD response
     * @private
     */
    _sendStatus(s) {
        // Get MOTD from handler or use default
        let r = this.motdH ? this.motdH(s.pv) : {
            version: { name: "1.21", protocol: s.pv },
            players: { max: 0, online: 0, sample: [] },
            description: { text: "Minecraft Server" }
        };
        
        // Ensure required fields exist
        r = {
            version: r.version || { name: "1.21", protocol: s.pv },
            players: r.players || { max: 0, online: 0, sample: [] },
            ...r
        };
        
        // Normalize description (handle color codes, newlines, etc.)
        r.description = this._normalizeDescription(r.description);
        
        // Build and send response packet
        const jb = Buffer.from(JSON.stringify(r), 'utf8');
        const pkt = Buffer.concat([VarInt.write(0x00), VarInt.write(jb.length), jb]);
        this._send(s, pkt);
    }

    /**
     * Normalizes description to prevent chat spam and ensure valid formatting
     * @private
     */
    _normalizeDescription(desc) {
        if (!desc) return { text: "Minecraft Server" };
        
        // Handle string descriptions with color codes
        if (typeof desc === 'string') {
            return this._parseColorCodes(desc);
        }
        
        // Handle object descriptions
        const normalized = { ...desc };
        if (!normalized.hasOwnProperty('text')) normalized.text = '';
        
        // Validate color format
        if (normalized.color && typeof normalized.color === 'string') {
            normalized.color = normalized.color.toLowerCase();
            if (normalized.color.startsWith('#') && !/^[0-9A-Fa-f]{6}$/.test(normalized.color.slice(1))) {
                normalized.color = 'white'; // Fallback to white for invalid hex
            }
        }
        
        // Limit newlines to prevent chat spam
        const newlineCount = this._countNewlines(normalized);
        if (newlineCount > 1) {
            return this._limitNewlines(normalized, true);
        }
        
        return normalized;
    }

    /**
     * Parses Minecraft color codes (§) into JSON text components
     * @private
     */
    _parseColorCodes(str) {
        const parts = [];
        let current = { text: '' };
        let i = 0;
        
        while (i < str.length) {
            if (str[i] === '§' && i + 1 < str.length) {
                const code = str[i + 1].toLowerCase();
                if (current.text) parts.push(current);
                
                if (code === 'r') {
                    current = { text: '' }; // Reset formatting
                } else if ('0123456789abcdefklmnor'.includes(code)) {
                    const colorMap = {
                        '0': 'black', '1': 'dark_blue', '2': 'dark_green',
                        '3': 'dark_aqua', '4': 'dark_red', '5': 'dark_purple',
                        '6': 'gold', '7': 'gray', '8': 'dark_gray',
                        '9': 'blue', 'a': 'green', 'b': 'aqua',
                        'c': 'red', 'd': 'light_purple', 'e': 'yellow',
                        'f': 'white'
                    };
                    if (colorMap[code]) {
                        current = { text: '', color: colorMap[code] };
                    } else {
                        current = { text: '' }; // Formatting codes not supported
                    }
                }
                i += 2;
            } else {
                current.text += str[i];
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
    _countNewlines(component) {
        if (typeof component === 'string') {
            return (component.match(/\n/g) || []).length;
        }
        let count = 0;
        if (component.text) count += (component.text.match(/\n/g) || []).length;
        if (Array.isArray(component.extra)) {
            for (const item of component.extra) count += this._countNewlines(item);
        }
        return count;
    }

    /**
     * Limits newlines to prevent excessive chat spam
     * @private
     */
    _limitNewlines(component, allowFirst = true) {
        if (typeof component === 'string') {
            if (!allowFirst) return component.replace(/\n/g, ' ');
            const parts = component.split('\n');
            return parts.length <= 2 ? component : `${parts[0]}\n${parts.slice(1).join(' ')}`;
        }
        const result = { ...component };
        if (result.text) {
            result.text = this._limitNewlines(result.text, allowFirst);
            if (result.text.includes('\n')) allowFirst = false;
        }
        if (Array.isArray(result.extra)) {
            result.extra = result.extra.map(item => this._limitNewlines(item, allowFirst));
        }
        return result;
    }

    /**
     * Handles ping request (immediate or delayed response)
     * @private
     */
    async _ping(pd, s) {
        const pl = pd.slice(VarInt.read(pd, 0).s); // Payload after packet ID
        
        // Use custom handler if set
        if (this.pingH) {
            try {
                const r = this.pingH(pl, s.pv);
                if (r === 'online') this._pong(pl, s);
                else if (r === 'pinging') this._simPing(s);
                return;
            } catch (e) { console.error('Ping handler error:', e); }
        }
        
        // Use default mode
        this.pingM === 'online' ? this._pong(pl, s) : this._simPing(s);
    }

    /**
     * Sends immediate pong response
     * @private
     */
    _pong(pl, s) {
        this._send(s, Buffer.concat([VarInt.write(0x01), pl]));
    }

    /**
     * Simulates delayed ping response (3-5 seconds)
     * @private
     */
    _simPing(s) {
        setTimeout(() => {
            if (!s.c.destroyed) this._send(s, Buffer.concat([VarInt.write(0x01), Buffer.alloc(8)]));
        }, 3000 + Math.random() * 2000);
    }

    /**
     * Handles login phase packets
     * @private
     */
    async _login(p, s) {
        if (p.id === 0x00) await this._loginStart(p.d, s); // Login start
        else if (p.id === 0x01) await this._encResp(p.d, s); // Encryption response
    }

    /**
     * Handles initial login packet (username)
     * @private
     */
    async _loginStart(b, s) {
        const un = PacketParser.readString(b, VarInt.read(b, 0).s);
        s.un = un.v;
        this._sendEncReq(s); // Start encryption handshake
    }

    /**
     * Sends encryption request to client
     * @private
     */
    _sendEncReq(s) {
        s.vt = crypto.randomBytes(4); // 4-byte verification token
        
        let pkt;
        // Different packet format for newer protocol versions
        if (s.pv > 763) {
            pkt = Buffer.concat([
                VarInt.write(0x01),
                PacketParser.writeString(''),
                PacketParser.writeByteArray(this.keys.publicKey),
                PacketParser.writeByteArray(s.vt),
                Buffer.from([0x01]) // Enable encryption flag
            ]);
        } else {
            pkt = Buffer.concat([
                VarInt.write(0x01),
                PacketParser.writeString(''),
                VarInt.write(this.keys.publicKey.length),
                this.keys.publicKey,
                VarInt.write(4),
                s.vt
            ]);
        }
        this._send(s, pkt);
    }

    /**
     * Handles encryption response from client
     * @private
     */
    async _encResp(b, s) {
        const r = this._parseEncResp(b);
        
        // Verify token matches
        if (r.dt.length > 0 && !r.dt.equals(s.vt)) {
            this._dc(s, 'Bad token');
            return;
        }
        
        s.ss = r.ds; // Store shared secret
        const sh = this._hash(s.ss); // Compute server hash for authentication
        
        try {
            // Authenticate with Mojang session server
            s.gp = await this._auth(s.un, sh);
            this._enableEnc(s); // Enable encryption
            
            // Call connection handler for custom disconnect message
            let msg = 'Disconnected.';
            if (this.connH) {
                const r = this.connH(s.gp, s.pv);
                if (r !== undefined && r !== null) msg = r;
            }
            this._dc(s, msg);
        } catch (e) {
            this._dc(s, 'Auth failed');
        }
    }

    /**
     * Parses encryption response packet
     * @private
     */
    _parseEncResp(b) {
        let o = VarInt.read(b, 0).s;
        const ss = PacketParser.readByteArray(b, o); // Encrypted shared secret
        o += ss.s;
        
        let vt = Buffer.alloc(0);
        if (o < b.length) {
            const vtr = PacketParser.readByteArray(b, o); // Encrypted verification token
            vt = vtr.v;
        }
        
        // Decrypt with private key
        const d = d => crypto.privateDecrypt({
            key: this.keys.privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
        }, d);
        
        return { ds: d(ss.v), dt: vt.length > 0 ? d(vt) : vt };
    }

    /**
     * Computes Minecraft authentication hash
     * @private
     */
    _hash(ss) {
        const h = crypto.createHash('sha1');
        h.update(Buffer.alloc(0)); // Server ID (empty for offline mode)
        h.update(ss);              // Shared secret
        h.update(this.keys.publicKey); // Server public key
        const hex = h.digest('hex');
        
        // Convert to signed hex (Minecraft-specific format)
        const bi = BigInt('0x' + hex);
        return bi >= (1n << 159n) ? (bi - (1n << 160n)).toString(16) : bi.toString(16);
    }

    /**
     * Authenticates player with Mojang session server
     * @private
     */
    async _auth(un, sh) {
        const r = await fetch(`https://sessionserver.mojang.com/session/minecraft/hasJoined?username=${un}&serverId=${sh}`);
        if (!r.ok) throw new Error(`Mojang fail: ${r.status}`);
        return r.json();
    }

    /**
     * Enables AES encryption on the connection
     * @private
     */
    _enableEnc(s) {
        // Use shared secret as both key and IV for AES-128-CFB8
        s.cph = crypto.createCipheriv('aes-128-cfb8', s.ss, s.ss);
        s.dcph = crypto.createDecipheriv('aes-128-cfb8', s.ss, s.ss);
    }

    /**
     * Sends packet to client (with length prefix)
     * @private
     */
    _send(s, d) {
        const l = VarInt.write(d.length); // Packet length prefix
        s.write(Buffer.concat([l, d]));
    }

    /**
     * Disconnects client with formatted message
     * @private
     */
    _dc(s, r) {
        // Normalize disconnect message
        const rc = this._normalizeDescription(r);
        const rb = Buffer.from(JSON.stringify(rc), 'utf8');
        const pkt = Buffer.concat([VarInt.write(0x00), VarInt.write(rb.length), rb]);
        this._send(s, pkt);
        
        // Close connection after brief delay
        setTimeout(() => s.c.end(), 100);
    }
}