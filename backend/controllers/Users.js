import Users from "../models/UserModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

export const getUsers = async(req, res) => {
    try {
        const users = await Users.findAll({
            attributes:['id','name','email']
        });
        res.json(users);
    } catch (error) {
        console.log(error);
    }
}
 
export const Register = async(req, res) => {
    const { name, email, password, confPassword } = req.body;
    if(password !== confPassword) return res.status(400).json({msg: "Password and Confirm Password do not match"});
    const salt = await bcrypt.genSalt();
    const hashPassword = await bcrypt.hash(password, salt);
    try {
        await Users.create({
            name: name,
            email: email,
            password: hashPassword
        });
        res.json({msg: "Registration Successful"});
    } catch (error) {
        console.log(error);
    }
}
 

export const Login = async (req, res) => {
// res.cookie('name', "arif");
// console.log(req.cookie);
// // return;
    try {
        const { email, password } = req.body;

        // Find the user by email
        const user = await Users.findOne({
            where: { email }
        });

        // If user doesn't exist, return error
        if (!user) {
            return res.status(404).json({ msg: "Invalid email or password" });
        }

        // Check if the password is correct
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ msg: "Invalid email or password" });
        }
        

        // Generate access token
        const accessToken = jwt.sign(
            { userId: user.id, name: user.name, email: user.email },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '15m' } // Example: token expires in 15 minutes
        );

        // Generate refresh token
        const refreshToken = jwt.sign(
            { userId: user.id, name: user.name, email: user.email },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '1d' }
        );
        
        // Update refresh token in the database
        await Users.update(
            { refresh_token: refreshToken },
            { where: { id: user.id } }
        );

        // Set refreshToken as a cookie
        res.cookie('refreshToken', refreshToken, {
         domain: "http://localhost:3000/",
            path: '/',
            sameSite: 'None',
            secure: true,
            httpOnly: false,
            secure: false,
            maxAge: 24 * 60 * 60 * 1000 // 1 day in milliseconds
        });
        console.log("Refresh Token Cookie:", req.cookies.refreshToken);
        
        res.json({ accessToken });
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: "Internal server error" });
    }
};
 
export const Logout = async(req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) return res.sendStatus(204);
    const user = await Users.findAll({
        where:{
            refresh_token: refreshToken
        }
    });
    if(!user[0]) return res.sendStatus(204);
    const userId = user[0].id;
    await Users.update({refresh_token: null},{
        where:{
            id: userId
        }
    });
    res.clearCookie('refreshToken');
    return res.sendStatus(200);
}