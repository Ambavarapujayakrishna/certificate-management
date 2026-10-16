const fs = require('fs');
const path = require('path');

// In-memory Map (not a plain object) backed by a JSON file, so labels can never
// collide with Object.prototype properties (e.g. "__proto__").
const STORE_FILE = path.join(__dirname, "..", "data", "keystore.json");
const store = new Map();

function load() {
    if (fs.existsSync(STORE_FILE)) {
        const entries = JSON.parse(fs.readFileSync(STORE_FILE, "utf8"));
        entries.forEach(([k, v]) => store.set(k, v));
    }
}

function persist() {
    fs.mkdirSync(path.dirname(STORE_FILE), { recursive: true });
    fs.writeFileSync(STORE_FILE, JSON.stringify([...store.entries()], null, 2));
}

function get(label) {
    return store.get(label);
}

function list() {
    return [...store.values()];
}

function put(label, value) {
    store.set(label, value);
    persist();
    return value;
}

function update(label, patch) {
    const existing = store.get(label);
    if (!existing) throw new Error(`Unknown key label "${label}"`);
    const next = { ...existing, ...patch };
    store.set(label, next);
    persist();
    return next;
}

load();

module.exports = { get, list, put, update };