# Expense Tracker API

An API that helps you to track your expenses


### start the local host server:
run `python app.py`


### APIs
- create account, POST request- `localhost:2546/api/user`
- login to account, GET request- `localhost:2546/api/login`
- get all users, GET request-  `localhost:2546/api/user`, Admin privelege required
- get logged user details, GET request- `localhost:2546/api/user/1`
- update logged user details, PUT request- `localhost:2546/api/user/1`
- delete user, DELETE request- `localhost:2546/api/user/1`
- add an expense, POST REQUEST- `localhost:2546/api/expenses`
- get all expenses in the database, GET request- `localhost:2546/api/expenses`
- get logged user expenses, GET request- `localhost:2546/api/expenses/1`
- delete expenses, DELETE request- `localhost:2546/api/expenses/<id>`
- get user total expenses, GET request- `localhost:2546/api/expenses/total`
