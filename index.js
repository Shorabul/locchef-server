const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const port = process.env.PORT || 3000;

// ------------------- Middleware -------------------
app.use(express.json());
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
}));
app.use(cookieParser());

// ------------------- MongoDB Client -------------------
const client = new MongoClient(process.env.MONGO_URI, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// ------------------- Main Function -------------------
async function run() {
    try {
        await client.connect();

        const db = client.db('local_chef_bazaar_db');

        // ------------------- Collections -------------------
        const usersCollection = db.collection('users');
        const roleRequestsCollection = db.collection('roleRequests');
        const mealsCollection = db.collection('meals');
        const ordersCollection = db.collection('orders');
        const reviewsCollection = db.collection('reviews');
        const favoriteCollection = db.collection('favorites');
        const PaymentsCollection = db.collection('Payments');

        const isProduction = process.env.NODE_ENV === 'production';

        // ------------------- Middleware Functions -------------------
        const verifyToken = (req, res, next) => {
            const token = req.cookies.token;
            if (!token) return res.status(401).send({ message: "Unauthorized" });

            jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
                if (err) return res.status(401).send({ message: "Unauthorized" });
                req.user = decoded;
                next();
            });
        };

        const verifyAdmin = async (req, res, next) => {
            const email = req.user.email;
            const user = await usersCollection.findOne({ email });
            if (user?.role !== "admin") return res.status(403).send({ message: "Forbidden" });
            next();
        };

        // ------------------- Auth Routes -------------------
        app.post("/jwt", async (req, res) => {
            const user = req.body; // { email, role }
            const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "7d" });

            res.cookie("token", token, {
                httpOnly: true,
                secure: true,
                sameSite: "none",
            }).send({ success: true });
        });

        app.post("/logout", (req, res) => {
            res.clearCookie("token", {
                httpOnly: true,
                secure: isProduction,
                sameSite: isProduction ? "none" : "lax",
            }).send({ success: true });
        });

        // ------------------- User Routes -------------------
        app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
            try {
                const result = await usersCollection.find().toArray();
                res.send({ success: true, data: result, total: result.length });
            } catch (error) {
                console.error(error);
                res.status(500).send({ error: 'Failed to fetch users' });
            }
        });

        app.get('/users/:email', verifyToken, async (req, res) => {
            try {
                const result = await usersCollection.findOne({ email: req.params.email });
                res.send(result);
            } catch (error) {
                console.error(error);
                res.status(500).send({ error: 'Failed to fetch users' });
            }
        });

        app.get('/users/:email/role', async (req, res) => {
            try {
                const user = await usersCollection.findOne(
                    { email: req.params.email },
                    { projection: { role: 1, _id: 0 } }
                );
                if (!user) return res.status(404).send({ role: "user" });
                res.send({ role: user.role || 'user' });
            } catch (error) {
                res.status(500).send({ role: "user" });
            }
        });

        app.post('/users', async (req, res) => {
            const user = req.body;
            user.role = 'user';
            user.createAt = new Date();

            const userExists = await usersCollection.findOne({ email: user.email });
            if (userExists) return res.send({ message: 'user exists' });

            const result = await usersCollection.insertOne(user);
            res.send(result);
        });

        app.patch('/users/:email', async (req, res) => {
            try {
                const result = await usersCollection.updateOne(
                    { email: req.params.email },
                    { $set: { status: req.body.status } }
                );
                res.send(result);
            } catch (error) {
                console.error(error);
                res.status(500).send({ error: 'Failed to update user' });
            }
        });

        // ------------------- Role Request Routes -------------------
        app.get('/role-requests', verifyToken, verifyAdmin, async (req, res) => {
            const requests = await roleRequestsCollection.find({}).toArray();
            res.send(requests);
        });

        app.post('/role-requests', verifyToken, async (req, res) => {
            const { userName, userEmail, requestType } = req.body;

            try {
                const exists = await roleRequestsCollection.findOne({
                    userEmail, requestType, requestStatus: "pending"
                });

                if (exists) return res.status(400).send({
                    success: false,
                    message: "You already have a pending request for this role."
                });

                const newRequest = { userName, userEmail, requestType, requestStatus: 'pending', createdAt: new Date() };
                const result = await roleRequestsCollection.insertOne(newRequest);

                await usersCollection.updateOne(
                    { email: userEmail },
                    { $set: { [`roleRequest.${requestType}`]: "pending" } }
                );

                res.send({ success: true, data: result });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Server error" });
            }
        });

        app.patch('/role-requests/:email', verifyToken, verifyAdmin, async (req, res) => {
            const { requestType, action } = req.body;
            const email = req.params.email;

            try {
                if (action === "rejected") {
                    await roleRequestsCollection.updateOne(
                        { userEmail: email },
                        { $set: { requestStatus: "rejected" } }
                    );
                    return res.send({ success: true, message: "Request rejected" });
                }

                if (action === "approved") {
                    let updateFields = { role: requestType };
                    if (requestType === "chef") updateFields.chefId = "chef-" + (Math.floor(1000 + Math.random() * 9000));
                    if (requestType === "admin") updateFields.role = "admin";

                    await usersCollection.updateOne({ email }, { $set: updateFields });
                    await roleRequestsCollection.updateOne({ userEmail: email }, { $set: { requestStatus: "approved" } });

                    return res.send({ success: true, message: "Request approved" });
                }
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Server error" });
            }
        });

        // ------------------- Meals Routes -------------------
        app.get("/meals", async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 10;
                const skip = (page - 1) * limit;
                const sortBy = req.query.sortBy || "_id";
                const order = req.query.order === "desc" ? -1 : 1;

                let fields = {};
                if (req.query.fields) req.query.fields.split(",").forEach(f => fields[f] = 1);

                const filter = {};
                // Featured filter
                if (req.query.featured === "true") filter.featured = true;

                // Search filter
                if (req.query.search) {
                    filter.foodName = { $regex: req.query.search, $options: "i" }; // case-insensitive search
                }

                const meals = await mealsCollection
                    .find(filter)
                    .project(fields)
                    .sort({ [sortBy]: order })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                const total = await mealsCollection.countDocuments(filter);

                res.send({ total, page, limit, pages: Math.ceil(total / limit), data: meals });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to fetch meals" });
            }
        });


        app.get('/meals/chef/:email', verifyToken, async (req, res) => {
            try {
                const result = await mealsCollection.find({ chefEmail: req.params.email }).toArray();
                res.send({ success: true, data: result });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Server error" });
            }
        });

        app.get("/meals/id/:id", verifyToken, async (req, res) => {
            try {
                const result = await mealsCollection.findOne({ _id: new ObjectId(req.params.id) });
                res.send({ success: true, data: result });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to fetch meal" });
            }
        });

        app.post('/meals', verifyToken, async (req, res) => {
            try {
                const meal = req.body;

                // Convert price and deliveryRadius to numbers
                meal.price = parseFloat(meal.price);
                meal.deliveryRadius = parseFloat(meal.deliveryRadius);

                // Convert rating to number (if you have default rating)
                meal.rating = meal.rating ? parseFloat(meal.rating) : 0;

                // Convert ingredients to array if it's a string
                if (typeof meal.ingredients === 'string') {
                    meal.ingredients = meal.ingredients
                        .split(',')
                        .map(item => item.trim())
                        .filter(Boolean);
                }

                meal.createdAt = new Date();

                const result = await mealsCollection.insertOne(meal);
                res.send({ success: true, data: result });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Server error" });
            }
        });


        app.patch("/meals/:id", verifyToken, async (req, res) => {
            try {
                const meal = req.body;

                // Convert price and deliveryRadius to numbers
                meal.price = parseFloat(meal.price);
                meal.deliveryRadius = parseFloat(meal.deliveryRadius);

                const result = await mealsCollection.updateOne(
                    { _id: new ObjectId(req.params.id) },
                    { $set: meal }
                );
                res.send({ success: true, modifiedCount: result.modifiedCount, message: "Meal updated successfully" });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to update meal" });
            }
        });

        app.delete('/meals/:id', verifyToken, async (req, res) => {
            try {
                const result = await mealsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
                res.send({ success: true, data: result });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Server error" });
            }
        });

        // ------------------- Reviews Routes -------------------
        // Get latest reviews (public)
        app.get('/reviews/latest', async (req, res) => {
            try {
                const limit = parseInt(req.query.limit) || 6;
                const reviews = await reviewsCollection
                    .find({})
                    .sort({ createdAt: -1 })
                    .limit(limit)
                    .toArray();
                res.send({ success: true, data: reviews });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to fetch latest reviews" });
            }
        });

        app.get('/reviews/:foodId', verifyToken, async (req, res) => {
            try {
                const reviews = await reviewsCollection.find({ foodId: req.params.foodId }).sort({ createdAt: -1 }).toArray();
                res.send({ success: true, data: reviews });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to fetch reviews" });
            }
        });

        app.get('/reviews/user/:email', verifyToken, async (req, res) => {
            try {
                const reviews = await reviewsCollection.aggregate([
                    { $match: { userEmail: req.params.email } },
                    { $sort: { createdAt: -1 } },
                    {
                        $lookup: {
                            from: "meals",
                            let: { fid: { $toObjectId: "$foodId" } },
                            pipeline: [
                                { $match: { $expr: { $eq: ["$_id", "$$fid"] } } },
                                { $project: { foodName: 1, foodImage: 1, chefName: 1 } }
                            ],
                            as: "mealInfo"
                        }
                    },
                    {
                        $addFields: {
                            foodName: { $arrayElemAt: ["$mealInfo.foodName", 0] },
                        }
                    },
                    // keep all review fields, just drop the raw mealInfo array
                    { $project: { mealInfo: 0 } }
                ]).toArray();

                res.send({ success: true, data: reviews });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to fetch reviews" });
            }
        });



        app.post('/reviews', verifyToken, async (req, res) => {
            try {
                const review = { ...req.body, createdAt: new Date() };
                const result = await reviewsCollection.insertOne(review);

                // ------------------- Update average rating -------------------
                const { foodId, rating } = review;

                // Get all reviews for this meal
                const reviews = await reviewsCollection.find({ foodId }).toArray();

                // Calculate average rating
                const totalRating = reviews.reduce((acc, curr) => acc + parseFloat(curr.rating), 0);
                const avgRating = (totalRating / reviews.length).toFixed(1); // e.g., 4.3

                // Update the meal document
                await mealsCollection.updateOne(
                    { _id: new ObjectId(foodId) },
                    { $set: { rating: parseFloat(avgRating) } }
                );

                res.send({ success: true, data: result, message: 'Review added and meal rating updated' });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to save review" });
            }
        });


        app.patch('/reviews/:id', verifyToken, async (req, res) => {
            try {
                const result = await reviewsCollection.updateOne(
                    { _id: new ObjectId(req.params.id) },
                    { $set: req.body }
                );
                if (result.modifiedCount === 1) res.send({ success: true, message: "Review updated successfully" });
                else res.status(404).send({ success: false, message: "Review not found or no changes made" });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to update review" });
            }
        });

        app.delete('/reviews/:id', verifyToken, async (req, res) => {
            try {
                const result = await reviewsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
                if (result.deletedCount === 1) res.send({ success: true, message: "Review deleted successfully" });
                else res.status(404).send({ success: false, message: "Review not found" });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to delete review" });
            }
        });

        // ------------------- Favorites Routes -------------------
        app.get('/favorites', verifyToken, async (req, res) => {
            try {
                const favorites = await favoriteCollection.find({ userEmail: req.query.userEmail }).toArray();
                res.send({ success: true, data: favorites });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to fetch favorites" });
            }
        });

        app.post('/favorites', verifyToken, async (req, res) => {
            try {
                const favorite = req.body;
                const exists = await favoriteCollection.findOne({ userEmail: favorite.userEmail, foodId: favorite.foodId });
                if (exists) return res.send({ success: false, message: "Meal already in favorites" });

                favorite.createAt = new Date();
                const result = await favoriteCollection.insertOne(favorite);
                res.send({ success: true, data: result, message: "Added to favorites" });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to save favorite" });
            }
        });

        app.delete('/favorites/:id', verifyToken, async (req, res) => {
            try {
                await favoriteCollection.deleteOne({ _id: new ObjectId(req.params.id) });
                res.send({ success: true, message: 'Favorite deleted' });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to delete favorite" });
            }
        });

        // ------------------- Orders Routes -------------------
        app.get('/orders/user/:email', verifyToken, async (req, res) => {
            try {
                const orders = await ordersCollection.find({ userEmail: req.params.email }).toArray();
                res.send({ success: true, data: orders });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to fetch orders" });
            }
        });

        app.get('/orders/chef/:chefId', verifyToken, async (req, res) => {
            try {
                const orders = await ordersCollection.find({ chefId: req.params.chefId }).toArray();
                res.send({ success: true, data: orders });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to fetch chef orders" });
            }
        });

        app.post('/order', verifyToken, async (req, res) => {
            try {
                const order = req.body;
                order.createAt = new Date();
                const result = await ordersCollection.insertOne(order);
                res.send(result);
            } catch (error) {
                res.status(500).send({ success: false, message: "Server error" });
            }
        });

        app.patch('/orders/status/:orderId', verifyToken, async (req, res) => {
            try {
                const result = await ordersCollection.updateOne(
                    { _id: new ObjectId(req.params.orderId) },
                    { $set: { orderStatus: req.body.orderStatus } }
                );
                res.send({ success: true, modifiedCount: result.modifiedCount });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Failed to update order status" });
            }
        });

        app.post('/orders/payment-checkout-session', verifyToken, async (req, res) => {
            const order = req.body;
            const amount = parseInt(order.totalPrice) * 100;

            try {
                const session = await stripe.checkout.sessions.create({
                    line_items: [
                        {
                            price_data: {
                                currency: 'usd',
                                unit_amount: amount,
                                product_data: { name: `Payment for ${order.mealName}` },
                            },
                            quantity: 1,
                        },
                    ],
                    mode: 'payment',
                    customer_email: order.customerEmail,
                    metadata: { orderId: order.orderId },
                    success_url: `${process.env.FRONTEND_URL}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                    cancel_url: `${process.env.FRONTEND_URL}/dashboard/payment-cancelled`,
                });

                res.send({ url: session.url });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: "Payment session creation failed" });
            }
        });


        app.patch('/payment-success', verifyToken, async (req, res) => {
            try {
                const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
                const transactionId = session.payment_intent;
                const orderId = session.metadata.orderId;

                const order = await ordersCollection.findOne({ _id: new ObjectId(orderId) });

                if (!order) {
                    return res.status(404).send({ success: false, message: "Order not found" });
                }

                // STOP duplicates HERE
                if (order.paymentStatus === "paid") {
                    return res.send({
                        success: true,
                        transactionId: order.transactionId,
                        trackingId: order.trackingId
                    });
                }

                const trackingId =
                    "MEAL-" +
                    new Date().toISOString().slice(0, 10).replace(/-/g, "") +
                    "-" +
                    Math.random().toString(36).substring(2, 8).toUpperCase();

                // Update order FIRST
                await ordersCollection.updateOne(
                    { _id: new ObjectId(orderId) },
                    {
                        $set: {
                            paymentStatus: "paid",
                            transactionId,
                            trackingId
                        }
                    }
                );

                // Insert payment ONCE
                await PaymentsCollection.insertOne({
                    orderId: new ObjectId(orderId),
                    userEmail: order.userEmail,
                    chefId: order.chefId,
                    mealName: order.foodName,
                    amount: order.price * order.quantity,
                    currency: "usd",
                    transactionId,
                    paymentMethod: "stripe",
                    paymentStatus: "paid",
                    createdAt: new Date()
                });

                res.send({
                    success: true,
                    transactionId,
                    trackingId
                });
            } catch (error) {
                console.error("Payment success error:", error);
                res.status(500).send({ success: false, error: "Payment process failed" });
            }
        });

        app.get('/payments/user/:email', verifyToken, async (req, res) => {
            try {
                const payments = await PaymentsCollection
                    .find({ userEmail: req.params.email })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send({ success: true, data: payments });
            } catch (error) {
                res.status(500).send({ success: false, message: "Failed to fetch payments" });
            }
        });

        app.get('/payments', verifyToken, verifyAdmin, async (req, res) => {
            const payments = await PaymentsCollection.find().sort({ createdAt: -1 }).toArray();
            res.send({ success: true, data: payments });
        });

        app.get(
            "/admin/platform-stats",
            verifyToken,
            verifyAdmin,
            async (req, res) => {
                try {
                    // Total users
                    const totalUsers = await usersCollection.countDocuments();

                    // Orders stats
                    const ordersPending = await ordersCollection.countDocuments({
                        orderStatus: { $ne: "delivered" },
                    });

                    const ordersDelivered = await ordersCollection.countDocuments({
                        orderStatus: "delivered",
                    });

                    // Total payments (sum of all paid amounts)
                    const paymentResult = await PaymentsCollection.aggregate([
                        {
                            $match: { paymentStatus: "paid" },
                        },
                        {
                            $group: {
                                _id: null,
                                totalAmount: { $sum: "$amount" },
                            },
                        },
                    ]).toArray();

                    const totalPayments =
                        paymentResult.length > 0 ? paymentResult[0].totalAmount : 0;

                    res.send({
                        totalPayments,
                        totalUsers,
                        ordersPending,
                        ordersDelivered,
                    });
                } catch (error) {
                    console.error("Platform stats error:", error);
                    res.status(500).send({
                        success: false,
                        message: "Failed to load platform statistics",
                    });
                }
            }
        );



        // ------------------- MongoDB Ping -------------------
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // await client.close();
    }
}
run().catch(console.dir);

// ------------------- Root Route -------------------
app.get('/', (req, res) => res.send('Hello World!'));

// ------------------- Start Server -------------------
app.listen(port, () => console.log(`Server running on port ${port}`));
