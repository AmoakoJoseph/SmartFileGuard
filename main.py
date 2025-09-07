import os
from app import app

if __name__ == '__main__':
    port_str = os.environ.get('PORT') or os.environ.get('APP_PORT') or '5000'
    try:
        port = int(port_str)
    except ValueError:
        port = 5000
    app.run(host='127.0.0.1', port=port, debug=True, use_reloader=False)
