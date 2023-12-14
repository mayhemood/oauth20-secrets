# Google OAuth2.0 and Bcrypt (Hash + Salting)
In this project, I have used Google OAuth 2.0 for signing in and signing up. The only data stored in my database is GoogleId. 
There is a local way of signing in and signing up as well, and then user can post secret(s) or view all the secrets.
The identity of users is not revealed with the secrets.

The email for the Google OAuth user is randomly generated with user1@googleauth.com with number incrementing for every user. The database stores a password of ****** which is just to populate the field in the database and not the real google password of the user.

# Prerequisites
* Node.js installed on your system
* PostgreSQL database installed and running
* All the npm dependencies installed. (npm i)

# Development
* Fork this repository to your GitHub account.
* Clone your forked repository to your local machine.
* Make changes to the code as needed.
* Commit your changes and push them to your forked repository.
* Create a pull request to merge your changes into the upstream repository.

# Installation
* Clone the repository.
* Install the required dependencies using "npm i".
* Create the necessary tables in your PostgreSQL database. You can copy the SQL queries from the queries.sql file and execute them in your database management tool.
* Configure the database connection settings in the dbConfig object in the index.js file. Replace the placeholder values with your database credentials.

# Usage
* Run the application using "nodemon index.js".
* Open "localhost:3000" on your browser.

# Contribution
* Fork the repository to your GitHub account.
* Clone your forked repository.
* Create a new branch for your contribution.
* Make your changes, commit them, and push to your forked repository.
* Create a pull request (PR) to the main repository. Provide a descriptive title and details about your changes.
* Your PR will be reviewed, and once approved, it will be merged into the main project.

Thank You!
