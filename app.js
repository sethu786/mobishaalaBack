const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors')

dotenv.config();



const app = express();
app.use(express.json());
app.use(cors())
const dbPath = path.join(__dirname, 'ecommerce.db');
let db = null;

// Secret Key
const JWT_SECRET = process.env.SECRET_KEY || 'default-very-strong-secret-key';

// Initialize DB and Server
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}/`);
    });
  } catch (error) {
    console.error(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

// Middleware to Authenticate JWT
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization'];
  if (!authHeader) {
    return response.status(401).json({ error: 'Missing Authorization header' });
  }

  const jwtToken = authHeader.split(' ')[1];
  if (!jwtToken) {
    return response.status(401).json({ error: 'Invalid JWT Token' });
  }

  jwt.verify(jwtToken, JWT_SECRET, (error, payload) => {
    if (error) {
      return response.status(401).json({ error: 'Invalid JWT Token' });
    }
    request.username = payload.username;
    next();
  });
};

// Health Check
app.get('/', (req, res) => {
  res.json({ message: 'Server is Live!' });
});

// Register User
app.post('/register/', async (request, response) => {
  const { username, password, name } = request.body;
  try {
    if (!username || !password || !name) {
      return response.status(400).json({ error: 'All fields are required' });
    }

    const checkUserQuery = `SELECT * FROM user WHERE username = ?;`;
    const dbUser = await db.get(checkUserQuery, [username]);

    if (dbUser) {
      return response.status(400).json({ error: 'User already exists' });
    }

    if (password.length < 6) {
      return response.status(400).json({ error: 'Password is too short' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const createUserQuery = `
      INSERT INTO user (username, password, name)
      VALUES (?, ?, ?);
    `;
    await db.run(createUserQuery, [username, hashedPassword, name]);
    response.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Login User
app.post('/login/', async (request, response) => {
  const { username, password } = request.body;
  try {
    if (!username || !password) {
      return response.status(400).json({ error: 'Username and password are required' });
    }

    const userQuery = `SELECT * FROM user WHERE username = ?;`;
    const dbUser = await db.get(userQuery, [username]);

    if (!dbUser) {
      return response.status(400).json({ error: 'Invalid user' });
    }

    const isPasswordMatch = await bcrypt.compare(password, dbUser.password);
    if (!isPasswordMatch) {
      return response.status(400).json({ error: 'Invalid password' });
    }

    const payload = { username };
    const jwtToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '2h' });
    response.json({ jwtToken });
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Get All Products
app.get('/products/', async (request, response) => {
  try {
    const productsQuery = `SELECT * FROM product;`;
    const products = await db.all(productsQuery);
    response.json(products);
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Get Single Product
app.get('/products/:productId/', async (request, response) => {
  const { productId } = request.params;
  try {
    const productQuery = `SELECT * FROM product WHERE id = ?;`;
    const product = await db.get(productQuery, [productId]);
    if (!product) {
      return response.status(404).json({ error: 'Product Not Found' });
    }
    response.json(product);
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Add Product to Cart
// Add Product to Cart (with quantity check)
app.post('/cart/', authenticateToken, async (request, response) => {
  const { productId, quantity } = request.body;
  const { username } = request;
  try {
    if (!productId || quantity <= 0) {
      return response.status(400).json({ error: 'Invalid Product ID or Quantity' });
    }

    // Get the user's ID
    const userQuery = `SELECT * FROM user WHERE username = ?;`;
    const user = await db.get(userQuery, [username]);

    // Check if the product already exists in the user's cart
    const existingCartQuery = `
      SELECT * FROM cart WHERE user_id = ? AND product_id = ?;
    `;
    const existingItem = await db.get(existingCartQuery, [user.id, productId]);

    if (existingItem) {
      // If the item already exists in the cart, update the quantity
      const updateQuantityQuery = `
        UPDATE cart
        SET quantity = quantity + ?
        WHERE user_id = ? AND product_id = ?;
      `;
      await db.run(updateQuantityQuery, [quantity, user.id, productId]);
      return response.json({ message: 'Product quantity updated in cart' });
    } else {
      // If the item does not exist, add it to the cart
      const addToCartQuery = `
        INSERT INTO cart (user_id, product_id, quantity)
        VALUES (?, ?, ?);
      `;
      await db.run(addToCartQuery, [user.id, productId, quantity]);
      return response.json({ message: 'Product added to cart' });
    }
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});


// Get Cart Items
app.get('/cart/', authenticateToken, async (request, response) => {
  const { username } = request;
  try {
    const userQuery = `SELECT * FROM user WHERE username = ?;`;
    const user = await db.get(userQuery, [username]);

    const cartQuery = `
      SELECT product.name, product.price, cart.quantity,product.id
      FROM cart
      INNER JOIN product ON cart.product_id = product.id
      WHERE cart.user_id = ?;
    `;
    const cartItems = await db.all(cartQuery, [user.id]);
    response.json(cartItems);
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Place Order
app.post('/order/', authenticateToken, async (request, response) => {
  const { address, paymentMethod } = request.body;
  const { username } = request;
  try {
    if (!address || !paymentMethod) {
      return response.status(400).json({ error: 'Address and Payment Method required' });
    }

    const userQuery = `SELECT * FROM user WHERE username = ?;`;
    const user = await db.get(userQuery, [username]);

    const createOrderQuery = `
      INSERT INTO orders (user_id, address, payment_method, status)
      VALUES (?, ?, ?, 'Processing');
    `;
    await db.run(createOrderQuery, [user.id, address, paymentMethod]);

    await db.run(`DELETE FROM cart WHERE user_id = ?;`, [user.id]);
    response.json({ message: 'Order placed successfully' });
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Get User Orders
app.get('/orders/', authenticateToken, async (request, response) => {
  const { username } = request;
  try {
    const userQuery = `SELECT * FROM user WHERE username = ?;`;
    const user = await db.get(userQuery, [username]);

    const ordersQuery = `SELECT * FROM orders WHERE user_id = ?;`;
    const orders = await db.all(ordersQuery, [user.id]);
    response.json(orders);
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Get All Unique Product Categories
app.get('/categories/', async (request, response) => {
  try {
    const categoriesQuery = `SELECT DISTINCT category FROM product WHERE category IS NOT NULL;`;
    const categories = await db.all(categoriesQuery);
    response.json(categories.map(item => item.category));
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Delete Product from Cart
app.delete('/cart/:productId/', authenticateToken, async (request, response) => {
  const { productId } = request.params;
  const { username } = request;

  try {
    // Get the user's ID from the database
    const userQuery = `SELECT * FROM user WHERE username = ?;`;
    const user = await db.get(userQuery, [username]);

    // Delete the specific product from the user's cart
    const deleteQuery = `
      DELETE FROM cart
      WHERE user_id = ? AND product_id = ?;
    `;
    const result = await db.run(deleteQuery, [user.id, productId]);

    if (result.changes === 0) {
      return response.status(404).json({ error: 'Product not found in cart' });
    }

    response.json({ message: 'Product removed from cart' });
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

// Update Quantity of an Item in Cart
app.put('/cart/:productId/', authenticateToken, async (request, response) => {
  const { productId } = request.params;
  const { quantity } = request.body;
  const { username } = request;

  try {
    if (quantity <= 0) {
      return response.status(400).json({ error: 'Quantity must be greater than 0' });
    }

    const userQuery = `SELECT * FROM user WHERE username = ?;`;
    const user = await db.get(userQuery, [username]);

    const existingItemQuery = `
      SELECT * FROM cart WHERE user_id = ? AND product_id = ?;
    `;
    const existingItem = await db.get(existingItemQuery, [user.id, productId]);

    if (!existingItem) {
      return response.status(404).json({ error: 'Item not found in cart' });
    }

    const updateQuery = `
      UPDATE cart
      SET quantity = ?
      WHERE user_id = ? AND product_id = ?;
    `;
    await db.run(updateQuery, [quantity, user.id, productId]);
    response.json({ message: 'Cart item quantity updated successfully' });
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});
// GET user profile info
app.get('/profile', authenticateToken, async (request, response) => {
  const { username } = request;

  try {
    const query = `SELECT username, name FROM user WHERE username = ?;`;
    const user = await db.get(query, [username]);

    if (!user) {
      return response.status(404).json({ error: 'User not found' });
    }

    response.json(user); // Will return { username: "...", name: "..." }
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

module.exports = app;
