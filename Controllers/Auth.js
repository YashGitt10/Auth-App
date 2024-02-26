

const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
require("dotenv").config();


//signup
exports.signup = async(req,res) => {
    try {
        const {name, email, password, role} = req.body;

        const existingUser = await User.findOne({email});
        if(existingUser) {
            return res.status(400).json({
                success:false,
                message:"User Already Exists",
            });
        }
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password, 10);
        }
        catch(err) {
            return res.status(500).json({
                success:false,
                message:"Err in hashing pass",
            });
        }

        //create
        const user = await User.create({
            name,email,password:hashedPassword,role
        })
        return res.status(200).json({
            success:true,
            message:"User Created Successfully",
        });
    } 
    catch (error) {
        console.error(error);
        return res.status(500).json({
            success:false,
            message:"pls try again later",
        });
    }
}


//login
exports.login = async(req,res) => {
    try {
        const {email, password} = req.body;
        if(!email || !password) {
            return res.status(400).json({
                success:false,
                message:"Pls fill all the details carefully",
            });
        }
        
        let user = await User.findOne({email});

        if(!user) {
            return res.status(401).json({
                success:false,
                message:"User does not Exists",
            });
        }

        const payload = {
            email: user.email,
            id: user._id,
            role: user.role,
        };
        //verfy pass and generate JWT token
        if(await bcrypt.compare(password, user.password)) {
            //pass match
            let token = jwt.sign(payload, process.env.JWT_SECRET, {expiresIn:"2h",});
            console.log(user);
            user = user.toObject();
            user.token = token;
            console.log(user);
            user.password = undefined;
            console.log(user);

            const options = {
                expires: new Date(Date.now() + 3*24*60*60*1000),
                httpOnly:true,
            }
            res.cookie("token", token, options).status(200).json({
                success:true,
                token,
                user,
                message:"User Logged In Successfully",
            });

        }
        else {
            return res.status(403).json({
                success:false,
                message:"Password Incorrect",
            }); 
        }
    } 
    catch (error) {
        console.error(error);
        return res.status(500).json({
            success:false,
            message:"LogIn Failure",
        });
    }
}