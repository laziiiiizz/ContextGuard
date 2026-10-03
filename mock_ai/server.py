from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/chat', methods=['POST'])
def chat():
    body = request.get_json()
    print('[mock_ai] received:', body)  # prove what actually arrived
    return jsonify({'reply': 'This is a mock AI response.'})


if __name__ == '__main__':
    app.run(port=5001)
