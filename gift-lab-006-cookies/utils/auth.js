function setToken() {
    const prefix = "bugforge-";
    const suffix = generateSuffix();
    return Buffer.from(`${prefix}${suffix}`).toString("base64");
    // For testing
    // return Buffer.from(`bugforge-rls`).toString("base64");
    
}

function generateSuffix(){
    const chars = "abcdefghijklmnopqrstuvwxyz";
    let suffix;

    do {
        const first = chars[Math.floor(Math.random() * chars.length)];
        const second = chars[Math.floor(Math.random() * chars.length)];
        const third = chars[Math.floor(Math.random() * chars.length)];
        suffix = first + second + third;
    } while (suffix === "rls");

    return suffix;
}

module.exports = { setToken };
