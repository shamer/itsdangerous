"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.base64encode = exports.base64decode = void 0;
const fromUrlSafe = (data) => {
    const padding = (-data.length % 4) + 4;
    if (padding) {
        data += '='.repeat(padding);
    }
    return data
        .replace(/-/g, '+')
        .replace(/_/g, '/');
};
const toUrlSafe = (data) => {
    return data
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
};
const base64decode = (data) => {
    return Buffer.from(fromUrlSafe(data), 'base64');
};
exports.base64decode = base64decode;
const base64encode = (data) => {
    const buff = Buffer.from(data.buffer);
    return toUrlSafe(buff.toString('base64'));
};
exports.base64encode = base64encode;
//# sourceMappingURL=base64.js.map