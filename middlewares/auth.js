

const jwt = require("jsonwebtoken");
require("dotenv").config();

exports.auth = (req,res,next) => {
    try {
        //extract JWT token
        const token = req.body.token;
        if(!token) {
            return res.status(401).json({
                success:false,
                message:"Token does not Exists",
            });
        }

        //verify the token
        try {
            const decode = jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);
            req.user = decode;
            
        } catch (err) {
            return res.status(401).json({
                success:false,
                message:"Token Invalid",
            });
        }
        next();
    } 
    catch (error) {
        return res.status(401).json({
            success:false,
            message:"something went wrong",
        });
    }
}

exports.isStudent = (req,res,next) => {
    try {
        if(req.user.role !== "Student") {
            return res.status(401).json({
                success:false,
                message:"This is a protected route for Students",
            });
        }
        next();
        
    } 
    catch (error) {
        return res.status(500).json({
            success:false,
            message:"User role not matching",
        });
    }
}

exports.isAdmin = (req,res,next) => {
    try {
        if(req.user.role !== "Admin") {
            return res.status(401).json({
                success:false,
                message:"This is a protected route for Admin",
            });
        }
        next();
        
    } 
    catch (error) {
        return res.status(500).json({
            success:false,
            message:"User role not matching",
        });
    }
}