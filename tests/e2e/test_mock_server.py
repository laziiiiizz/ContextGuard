from mock_ai.server import app


def test_chat_route_echoes_a_canned_reply():
    client = app.test_client()
    response = client.post('/chat', json={'messages': [{'role': 'user', 'content': 'hi'}]})
    assert response.status_code == 200
    assert response.get_json()['reply'] == 'This is a mock AI response.'
