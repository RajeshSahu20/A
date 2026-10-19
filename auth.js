const bcrypt = require("bcryptjs");

function requireLogin(req, res, next) {
    if (!req.session || !req.session.studentId) {
        return res.status(401).json({
            success: false,
            message: "Please login first to access PhotoVault."
        });
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.session || !req.session.adminId) {
        return res.status(401).json({
            success: false,
            message: "Admin login required to manage student accounts."
        });
    }

    next();
}

async function hashPassword(password) {
    return bcrypt.hash(password, 12);
}

async function verifyPassword(password, passwordHash) {
    return bcrypt.compare(password, passwordHash);
}

module.exports = {
    requireLogin,
    requireAdmin,
    hashPassword,
    verifyPassword
};

