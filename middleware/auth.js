const jwt = require('jsonwebtoken');

const path=require("path")


const auth = (req, res, next) => {
    console.log("AUTH MIDDLEWARE CALLED for path:", req.path, "method:", req.method);
    // 1. Check for the token in the cookie
    const token = req.cookies.jwt; 

    if (!token) {
        if (req.path.startsWith('/api/') || req.path.startsWith('/user/search/')) {
            return res.status(401).json({ message: "No token provided, please log in." });
        }
        return res.render('login');
    }

    try {
        // 2. Verify the token against your secret
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified; // Attach the user payload to the request
        next(); // Proceed to the protected route handler
    } catch (err) {
        // 3. Handle expired or invalid tokens
        if (req.path.startsWith('/api/')) {
            return res.status(403).json({ message: "Invalid token." });
        }
        return res.render('login');
    }
};

module.exports = auth;
