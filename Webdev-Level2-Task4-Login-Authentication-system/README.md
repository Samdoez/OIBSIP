# Login & Authentication System

A full-stack authentication web application built with **Node.js**, **Express**, **EJS**, and **PostgreSQL**, featuring account creation, password hashing with `bcrypt`, server-side session management, protected dashboard access, and Post/Redirect/Get (PRG) flow.

## Features

- **Account Registration (`/createAccount`)**: Validates required fields, name length, email format/domain typos, password rules, confirmation matching, and duplicate emails before inserting into PostgreSQL.
- **Form State Preservation**: Passes `formData` back on failed validation renders so users keep valid inputs without retyping raw passwords.
- **Password Hashing**: Uses `bcrypt` with salted hashing on registration and `bcrypt.compare` on login.
- **Session Authentication**: Uses `express-session` to track authenticated users (`currentUserId`) across requests and protect `/userDashboard`.
- **PRG Pattern & Logout**: Redirects after state-changing actions to avoid duplicate form resubmissions and clears session state on logout.

## Tech Stack

- **Runtime & Framework**: Node.js, Express
- **Templating**: EJS
- **Database**: PostgreSQL (`pg` connection pool)
- **Security & Sessions**: `bcrypt`, `express-session`, `dotenv`

## Project Structure

```text
├── index.js              # Express app, routes, validation, auth, and session setup
├── views/                # EJS templates (registration, login, dashboard)
├── public/               # Static assets (CSS, client-side scripts, images)
├── .env.example          # Sample environment variables
├── .gitignore
└── package.json

PORT=3000
DATABASE_URL=postgresql://username:password@localhost:5432/your_database_name
SESSION_SECRET=replace-with-a-strong-random-secret
SALT_ROUNDS=10

git clone <your-repo-url>
cd Webdev-Level2-Task4-Login-Authentication-system

npm install