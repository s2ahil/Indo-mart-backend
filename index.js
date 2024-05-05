// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const dotenv = require("dotenv");
const cors = require('cors')
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");



// Create Express app
const app = express();


dotenv.config();
// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors())

const mongoConnection = async () => {
    try {
        await mongoose.connect(process.env.mongodb_url);

        console.log("connected database");
    }
    catch (err) {
        throw err;
    }
}

mongoConnection()

// Define Product schema
const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    category: { type: String, required: true },
    image_url: { type: String, required: true },
    related_products: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    reviews: [{
        user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        rating: { type: Number, min: 1, max: 5 },
        comment: String,
        date: { type: Date, default: Date.now }
    }]
});

const Product = mongoose.model('Product', productSchema);

// Define User schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    hashed_password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Define Cart schema
const cartSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{
        product_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
        quantity: { type: Number, default: 1 }
    }]
});

const Cart = mongoose.model('Cart', cartSchema);

//admin schema
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
});

const Admin = mongoose.model('Admin', adminSchema);



// Define routes

//auth functionality for admin

const secretAdmin = "myAdminSecret";


function authenticateAdmin(req, res, next) {
    console.log("check kiya");
    const authHeader = req.headers.authorization;
    console.log(authHeader);
    if (authHeader) {
        const token = authHeader.split(" ")[1];

        jwt.verify(token, secretAdmin, (err, admin) => {
            if (err) {
                return res.sendStatus(403);
            }
            console.log("admin token",admin);
            req.admin = admin;
            next();
        });
    } else {
        res.sendStatus(401);
    }
}


const secretUser = "myuserSecret";

function authenticateUser(req, res, next) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(" ")[1];

        // Verify the user token
        jwt.verify(token, secretUser, (err, user) => {
            if (err) {
                return res.sendStatus(403); // Forbidden if token is invalid
            }
            req.user = user; // Set the authenticated user object in the request
            next(); // Proceed to the next middleware
        });
    } else {
        res.sendStatus(401); // Unauthorized if token is missing
    }
}

app.post("/admin/validate-token", (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(401).json({ message: "Token is missing" });
    }

    jwt.verify(token, secretAdmin, (err, admin) => {
        if (err) {
            return res.status(403).json({ message: "Token is invalid" });
        }
        // Token is valid
        res.status(200).json({ message: "Token is valid", admin });
    });
});

// Admin routes , Admin Signup
app.post("/admin/signup", async (req, res) => {
    // logic to sign up admin

    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = await Admin.findOne({ username: username });

    if (admin) {
        res.status(403).json({ message: "admin already exists" });
    } else {
        const newAdmin = new Admin({ username, password: hashedPassword });
        await newAdmin.save();
        console.log(newAdmin._id)
        const token = jwt.sign({ id: newAdmin._id,username,  role: "admin" }, secretAdmin, {
            expiresIn: "1h",
        });

        res.json({ message: "Admin created successfully", token });
    }
});

app.post("/admin/login", async (req, res) => {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username: username });

    if (admin) {
        // Compare the provided password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, admin.password);
        if (passwordMatch) {
            const token = jwt.sign({ username, id:admin._id,role: "admin" }, secretAdmin, {
                expiresIn: "1h",
            });
            res.json({
                message: "Logged in successfully",
                token: token,
            });
        } else {
            // Password does not match
            res.status(403).json({ message: "Incorrect credentials" });
        }
    } else {
        // Admin not found
        res.status(403).json({ message: "Admin not found" });
    }
}

);


// Add product by admin
app.post("/admin/products", authenticateAdmin, async (req, res) => {
    try {
        const { name, description, price, category, image_url } = req.body;
        console.log(req.body)
        console.log(req.admin)
        const createdBy = req.admin.id;

        const product = new Product({ name, description, price, category, image_url, createdBy });
        await product.save();
        res.status(201).json(product);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// user fields 

// User signup
app.post("/users/signup", async (req, res) => {
    // logic to sign up user
    const { username, email, password } = req.body;
    console.log(username)
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.findOne({ email });

    if (user) {
        res.status(403).json({ message: "User already exists" });
    } else {
        const newUser = new User({ username, email, hashed_password: hashedPassword });
        await newUser.save();
        const token = jwt.sign({ id: newUser._id, username, role: "user" }, secretUser, {
            expiresIn: "1h",
        });
        res.json({ message: "User created successfully", token });
    }
});

// User login
app.post("/users/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (user) {
        // Compare the provided password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user.hashed_password);
        if (passwordMatch) {
            const token = jwt.sign({ id: user._id, username: user.username, role: "user" }, secretUser, {
                expiresIn: "1h",
            });
            res.json({
                message: "Logged in successfully",
                token: token,
            });
        } else {
            // Password does not match
            res.status(403).json({ message: "Incorrect credentials" });
        }
    } else {
        // User not found
        res.status(403).json({ message: "User not found" });
    }
});



// Get all products
app.get('/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Get product details
app.get('/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id)
        res.json(product);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Add product review
app.post('/products/:id/reviews',authenticateUser, async (req, res) => {
    try {
        const { user_id, rating, comment } = req.body;
        const review = { user_id, rating, comment };
        const product = await Product.findById(req.params.id);
        product.reviews.push(review);
        await product.save();
        res.status(201).json(product);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Add product to cart
app.post('/cart', authenticateUser, async (req, res) => {
    try {
        const { product_id, quantity } = req.body;
        const { id: user_id } = req.user; // Extract user ID from the authenticated user object
        
        // Check if the product exists
        const product = await Product.findById(product_id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        
        let cart = await Cart.findOne({ user_id });
        if (!cart) {
            cart = new Cart({ user_id, items: [] });
        }
        
        // Check if the product is already in the cart
        const existingItemIndex = cart.items.findIndex(item => item.product_id.toString() === product_id);
        if (existingItemIndex !== -1) {
            // If the product is already in the cart, update the quantity
            cart.items[existingItemIndex].quantity += quantity;
        } else {
            // If the product is not in the cart, add it
            cart.items.push({ product_id, quantity });
        }
        
        await cart.save();
        res.status(201).json(cart);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Get all add to cart items of the current user
app.get('/cart', authenticateUser, async (req, res) => {
    try {
        const { id: user_id } = req.user; // Extract user ID from the authenticated user object

        // Find the cart for the current user
        const cart = await Cart.findOne({ user_id }).populate('items.product_id');

        if (!cart) {
            return res.status(404).json({ message: 'Cart not found' });
        }

        res.json(cart.items);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
