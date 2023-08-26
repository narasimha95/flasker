from flask import Flask, render_template


# Create a flask instance
app = Flask(__name__)

# create a route decorater
@app.route('/')
def index():
    favorite_pizza = ["pepporoni", "mango", "tomato", "chocolate"]
    stuff = "heloo i am <b> bold </b>"
    first_name = "Narasimha"
    return  render_template('index.html', first_name=first_name,
                            stuff=stuff,
                             favorite_pizza=favorite_pizza)

@app.route('/user/<name>')
def user(name):
    return render_template('user.html', user_name=name)




























# routing for invalid urls
@app.errorhandler(404)
def page_not_found(e):
    return render_template("error.html"), 404