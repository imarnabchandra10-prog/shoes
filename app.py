import streamlit as st
from pymongo import MongoClient
import bcrypt

# ---------------------------------------
# MongoDB Connection (Using Streamlit Secrets)
# ---------------------------------------
mongo_url = st.secrets["mongo"]["url"]
client = MongoClient(mongo_url)
db = client["shopping_portal"]
users = db["users"]
products = db["products"]
orders = db["orders"]

# ---------------------------------------
# Auto-create Admin on First Run
# ---------------------------------------
def ensure_admin_exists():
    admin_user = st.secrets["admin"]["username"]
    admin_pass = st.secrets["admin"]["password"]
    existing_admin = users.find_one({"username": admin_user, "role": "admin"})

    if not existing_admin:
        hashed_pw = bcrypt.hashpw(admin_pass.encode("utf-8"), bcrypt.gensalt())
        users.insert_one({"username": admin_user, "password": hashed_pw, "role": "admin"})
        print(f"✅ Admin '{admin_user}' created automatically.")
    else:
        print("✅ Admin already exists.")

ensure_admin_exists()

# ---------------------------------------
# Helper Functions
# ---------------------------------------
def create_user(username, password, role):
    if users.find_one({"username": username}):
        st.warning("⚠️ User already exists!")
        return
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    users.insert_one({"username": username, "password": hashed_pw, "role": role})
    st.success(f"✅ User '{username}' created successfully as {role}!")

def login_user(username, password):
    user = users.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return user
    return None

# ---------------------------------------
# Admin Page
# ---------------------------------------
def admin_page():
    st.title("🛒 Admin Dashboard")
    st.subheader("Manage Users & Products")

    # --- Create Users ---
    st.write("### 👥 Create New User")
    new_user = st.text_input("Enter Username", key="new_user")
    new_pass = st.text_input("Enter Password", type="password", key="new_pass")
    role = st.selectbox("Select Role", ["user", "admin"], key="role")
    if st.button("Create User"):
        create_user(new_user, new_pass, role)

    st.divider()

    # --- Add Products ---
    st.write("### 📦 Add New Product")
    pname = st.text_input("Product Name", key="product_name")
    price = st.number_input("Product Price (₹)", min_value=1, key="price")
    if st.button("Add Product"):
        if pname.strip():
            products.insert_one({"name": pname, "price": price})
            st.success(f"✅ Product '{pname}' added successfully!")
        else:
            st.warning("⚠️ Enter a valid product name.")

    st.divider()

    # --- Show Products ---
    st.write("### 🧾 Product List")
    all_products = list(products.find())
    if all_products:
        for p in all_products:
            st.write(f"• {p['name']} — ₹{p['price']}")
    else:
        st.info("No products added yet.")

# ---------------------------------------
# User Page
# ---------------------------------------
def user_page(username):
    st.title(f"Welcome, {username} 👋")
    st.subheader("🛍️ Browse & Buy Products")

    all_products = list(products.find())
    if not all_products:
        st.info("No products available yet.")
        return

    # --- Display Products ---
    for p in all_products:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"**{p['name']}** — ₹{p['price']}")
        with col2:
            if st.button(f"Buy {p['name']}", key=str(p['_id'])):
                orders.insert_one({"username": username, "product": p['name'], "price": p['price']})
                st.success(f"✅ Order placed for {p['name']}!")

    st.divider()

    # --- Order History ---
    st.write("### 🧾 Your Orders")
    user_orders = list(orders.find({"username": username}))
    if user_orders:
        for o in user_orders:
            st.write(f"- {o['product']} — ₹{o['price']}")
    else:
        st.info("You haven’t placed any orders yet.")

# ---------------------------------------
# Login Page
# ---------------------------------------
def login_page():
    st.title("🛒 Shopping Portal Login")
    st.subheader("Login with your credentials")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = login_user(username, password)
        if user:
            st.session_state["user"] = user
            st.success(f"Welcome {user['username']}!")
            st.experimental_rerun()
        else:
            st.error("Invalid username or password.")

# ---------------------------------------
# Main App
# ---------------------------------------
def main():
    st.sidebar.title("Navigation")

    if "user" not in st.session_state:
        login_page()
    else:
        user = st.session_state["user"]
        st.sidebar.write(f"👤 Logged in as: {user['username']} ({user['role']})")

        if st.sidebar.button("Logout"):
            del st.session_state["user"]
            st.success("Logged out successfully!")
            st.experimental_rerun()

        if user["role"] == "admin":
            admin_page()
        else:
            user_page(user["username"])

if __name__ == "__main__":
    main()
